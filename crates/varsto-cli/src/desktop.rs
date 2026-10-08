// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Local control API and desktop interface, served by the background service.
//!
//! The server binds to 127.0.0.1 only. Every API call must carry a per-session
//! token that is written to `service.json` in the device directory (mode 0600)
//! and handed to the browser once through the start URL. The `Host` header is
//! checked against the bound address to defeat DNS rebinding, and no CORS
//! headers are ever sent. This is the first shape of the local control API of
//! the plan (6.8, 6.32); the menu-bar app and the CLI are its clients.

use crate::service::{self, ServiceState};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");

pub struct State {
    pub home: PathBuf,
    pub engine: Option<Engine>,
    pub token: String,
    pub bound: String,
    pub service: ServiceState,
}

pub type Shared = Arc<Mutex<State>>;

/// Bind the server. Returns the server and the bound `host:port`.
pub fn bind(port: u16) -> Result<(Server, String)> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("no ip address"))?;
    Ok((server, format!("127.0.0.1:{}", addr.port())))
}

/// Serve requests until the server is unblocked. Blocks.
pub fn serve_arc(server: Arc<Server>, state: Shared) {
    for request in server.incoming_requests() {
        if let Err(e) = handle(&state, request) {
            eprintln!("request failed: {e:#}");
        }
    }
}

pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let cmd = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let cmd = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let cmd = std::process::Command::new("xdg-open").arg(url).spawn();
    if cmd.is_err() {
        eprintln!("could not open a browser; open the URL by hand");
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn html(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
        .with_header(header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header("Cache-Control", "no-store"))
}

fn text(body: &str, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-store"))
}

fn json_response(status: u16, value: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(value.to_string())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Cache-Control", "no-store"))
}

fn handle(state: &Shared, mut request: Request) -> Result<()> {
    let host_ok = {
        let st = state.lock().unwrap();
        let port = st.bound.rsplit(':').next().unwrap_or("").to_string();
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| {
                h.value.as_str() == st.bound || h.value.as_str() == format!("localhost:{port}")
            })
            .unwrap_or(false)
    };
    if !host_ok {
        return Ok(request.respond(Response::from_string("bad host").with_status_code(400))?);
    }
    let url = request.url().to_string();
    let (path, query) = url
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((url.clone(), String::new()));
    match (request.method(), path.as_str()) {
        (Method::Get, "/") => return Ok(request.respond(html(INDEX_HTML))?),
        (Method::Get, "/app.js") => {
            return Ok(request.respond(text(APP_JS, "text/javascript; charset=utf-8"))?)
        }
        (Method::Get, "/app.css") => {
            return Ok(request.respond(text(APP_CSS, "text/css; charset=utf-8"))?)
        }
        _ => {}
    }
    if !path.starts_with("/api/") {
        return Ok(request.respond(Response::from_string("not found").with_status_code(404))?);
    }
    let token_ok = {
        let st = state.lock().unwrap();
        let in_header = request
            .headers()
            .iter()
            .any(|h| h.field.equiv("X-Varsto-Token") && h.value.as_str() == st.token);
        // Thumbnails are loaded by <img>, which cannot send a header; the
        // session token may come in the query string for that one endpoint.
        let in_query = (path == "/api/thumb" || path == "/api/open")
            && query_param(&query, "token").as_deref() == Some(st.token.as_str());
        in_header || in_query
    };
    if !token_ok {
        return Ok(request.respond(json_response(
            401,
            &json!({"error": "missing or wrong token; reopen the start URL"}),
        ))?);
    }
    if path == "/api/open" {
        // Download a file through the browser; the token may be in the query
        // because this is a plain link. Counts as an access.
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        let result = {
            let mut st = state.lock().unwrap();
            match (&mut st.engine, folder, file) {
                (Some(e), Some(f), Some(p)) => Some(e.read_file(&f, &p).map(|b| (b, p))),
                _ => None,
            }
        };
        return match result {
            Some(Ok((bytes, p))) => {
                let name = p.rsplit('/').next().unwrap_or("file").replace('"', "");
                request.respond(
                    Response::from_data(bytes)
                        .with_header(header("Content-Type", "application/octet-stream"))
                        .with_header(header(
                            "Content-Disposition",
                            &format!("attachment; filename=\"{name}\""),
                        )),
                )?;
                Ok(())
            }
            Some(Err(e)) => {
                request.respond(Response::from_string(e.to_string()).with_status_code(400))?;
                Ok(())
            }
            None => {
                request.respond(
                    Response::from_string("locked or missing parameters").with_status_code(400),
                )?;
                Ok(())
            }
        };
    }
    if path == "/api/thumb" {
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        let bytes = {
            let st = state.lock().unwrap();
            match (&st.engine, folder, file) {
                (Some(e), Some(f), Some(p)) => e.thumbnail(&f, &p).unwrap_or(None),
                _ => None,
            }
        };
        match bytes {
            Some(b) => request.respond(
                Response::from_data(b)
                    .with_header(header("Content-Type", "image/jpeg"))
                    .with_header(header("Cache-Control", "private, max-age=3600")),
            )?,
            None => request.respond(Response::from_string("no thumbnail").with_status_code(404))?,
        }
        return Ok(());
    }
    let mut body = String::new();
    if *request.method() == Method::Post {
        request
            .as_reader()
            .take(1 << 20)
            .read_to_string(&mut body)?;
    }
    let input: Value = if body.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body).unwrap_or(json!({}))
    };
    let method = request.method().clone();
    if method == Method::Post && path == "/api/quit" {
        request.respond(json_response(200, &json!({"ok": true})))?;
        service::request_quit(state);
        return Ok(());
    }
    let result = {
        let mut st = state.lock().unwrap();
        api(&mut st, method, &path, &query, &input)
    };
    match result {
        Ok(v) => Ok(request.respond(json_response(200, &v))?),
        Err(e) => Ok(request.respond(json_response(400, &json!({"error": format!("{e:#}")})))?),
    }
}

fn s(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .ok_or_else(|| anyhow!("missing field {key}"))
}

fn opt(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        kv.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| percent_decode(v))
    })
}

fn percent_decode(v: &str) -> String {
    let bytes = v.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(h) = u8::from_str_radix(&v[i + 1..i + 3], 16) {
                out.push(h);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn api(st: &mut State, method: Method, path: &str, query: &str, input: &Value) -> Result<Value> {
    let has_vault = st.home.join("vault.json").exists();
    let method2 = method.clone();
    match (method, path) {
        (Method::Get, "/api/state") => Ok(json!({
            "home": st.home.display().to_string(),
            "has_vault": has_vault,
            "unlocked": st.engine.is_some(),
            "version": env!("CARGO_PKG_VERSION"),
            "service": st.service.summary(),
        })),
        (Method::Get, "/api/service") => Ok(st.service.summary()),
        (Method::Get, "/api/update/check") => Ok(serde_json::to_value(crate::update::check()?)?),
        (Method::Post, "/api/update") => {
            let c = crate::update::check()?;
            let message = crate::update::apply(&c)?;
            if c.available {
                st.service.restart_requested = true;
            }
            Ok(json!({"ok": true, "updated": c.available, "message": message}))
        }
        (Method::Post, "/api/service/pause") => {
            st.service.paused = input
                .get("paused")
                .and_then(|b| b.as_bool())
                .unwrap_or(true);
            Ok(st.service.summary())
        }
        (Method::Post, "/api/unlock") => {
            let e = Engine::open(&st.home, &s(input, "passphrase")?)?;
            st.engine = Some(e);
            st.service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/lock") => {
            st.engine = None;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/init") => {
            let (e, key) = Engine::init(&st.home, &s(input, "name")?, &s(input, "passphrase")?)?;
            st.engine = Some(e);
            Ok(json!({"ok": true, "vault_key": key}))
        }
        (Method::Post, "/api/share/request") => {
            Ok(json!({"request_code": varsto_core::vault::ShareRequest::code_for(&st.home)?}))
        }
        (Method::Post, "/api/share/accept") => {
            let raw = s(input, "token")?;
            let token = if varsto_core::vault::SealedShareToken::is_sealed(&raw) {
                varsto_core::vault::ShareRequest::open_token(&st.home, &raw)?
            } else {
                varsto_core::vault::ShareToken::decode(&raw)?
            };
            let spec = StorageSpec::LocalDir {
                name: opt(input, "storage_name").unwrap_or_else(|| "shared".into()),
                path: PathBuf::from(s(input, "storage_path")?),
                cold: false,
                carrier: false,
                place: String::new(),
            };
            let e = Engine::accept_share(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &token,
                spec,
            )?;
            st.engine = Some(e);
            varsto_core::vault::ShareRequest::clear(&st.home);
            Ok(json!({"ok": true, "folder": token.name}))
        }
        (Method::Post, "/api/join") => {
            let spec = StorageSpec::LocalDir {
                name: opt(input, "storage_name").unwrap_or_else(|| "primary".into()),
                path: PathBuf::from(s(input, "storage_path")?),
                cold: false,
                carrier: false,
                place: String::new(),
            };
            let e = Engine::join(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &s(input, "vault_key")?,
                spec,
            )?;
            st.engine = Some(e);
            Ok(json!({"ok": true}))
        }
        _ => {
            let service = &mut st.service;
            let engine = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            api_unlocked(engine, service, method2, path, query, input)
        }
    }
}

fn api_unlocked(
    engine: &mut Engine,
    service: &mut ServiceState,
    method: Method,
    path: &str,
    query: &str,
    input: &Value,
) -> Result<Value> {
    match (method, path) {
        (Method::Get, "/api/status") => Ok(serde_json::to_value(engine.status()?)?),
        (Method::Get, "/api/folders") => Ok(Value::Array(
            engine
                .folders()
                .into_iter()
                .map(|(r, m)| json!({"id": r.folder_id.to_string(), "name": r.name, "path": m}))
                .collect(),
        )),
        (Method::Post, "/api/share/create") => {
            let t = engine.share_create(&s(input, "folder")?)?;
            match opt(input, "to").filter(|c| !c.trim().is_empty()) {
                Some(code) => {
                    let sealed = t.seal(&varsto_core::vault::ShareRequest::parse_code(&code)?)?;
                    Ok(json!({"ok": true, "token": sealed.encode(), "folder": sealed.name, "sealed": true}))
                }
                None => Ok(json!({"ok": true, "token": t.encode(), "folder": t.name, "sealed": false})),
            }
        }
        (Method::Get, "/api/replica/token") => {
            Ok(json!({"token": engine.replica_token()?.encode()}))
        }
        (Method::Post, "/api/storage") => {
            let cold = input.get("cold").and_then(|c| c.as_bool()).unwrap_or(false);
            let carrier = input
                .get("carrier")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            match opt(input, "kind").as_deref().unwrap_or("local-dir") {
                "s3" => {
                    let class = opt(input, "storage_class").filter(|c| !c.trim().is_empty());
                    let cold = cold
                        || class
                            .as_deref()
                            .is_some_and(|c| c.contains("GLACIER") || c.contains("ARCHIVE"));
                    engine.add_storage_with_secret(
                        StorageSpec::S3 {
                            name: s(input, "name")?,
                            endpoint: s(input, "endpoint")?.trim_end_matches('/').to_string(),
                            region: opt(input, "region")
                                .filter(|r| !r.trim().is_empty())
                                .unwrap_or_else(|| "us-east-1".into()),
                            bucket: s(input, "bucket")?,
                            prefix: opt(input, "prefix").unwrap_or_default().trim_matches('/').to_string(),
                            access_key_id: s(input, "access_key_id")?,
                            secret_ref: String::new(),
                            path_style: !input.get("virtual_host").and_then(|c| c.as_bool()).unwrap_or(false),
                            storage_class: class,
                            cold,
                            place: opt(input, "place").unwrap_or_default(),
                        },
                        Some(s(input, "secret_access_key")?),
                    )?;
                }
                "rclone" => engine.add_storage(StorageSpec::Rclone {
                    name: s(input, "name")?,
                    remote: s(input, "remote")?,
                    cold,
                    place: opt(input, "place").unwrap_or_default(),
                })?,
                _ => engine.add_storage(StorageSpec::LocalDir {
                    name: s(input, "name")?,
                    path: PathBuf::from(s(input, "path")?),
                    cold,
                    carrier,
                    place: opt(input, "place").unwrap_or_default(),
                })?,
            }
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/folder") => {
            let id = engine.add_folder(&s(input, "name")?, Path::new(&s(input, "path")?))?;
            service.folders_changed = true;
            service.request_sync();
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        (Method::Post, "/api/folder/attach") => {
            let selective = input
                .get("selective")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            let id = engine.attach_folder(
                &s(input, "name_or_id")?,
                Path::new(&s(input, "path")?),
                selective,
            )?;
            service.folders_changed = true;
            service.request_sync();
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        (Method::Post, "/api/sync") => {
            let folder = opt(input, "folder");
            let reports = engine.sync(folder.as_deref())?;
            service.record_sync(&reports);
            Ok(serde_json::to_value(
                reports
                    .into_iter()
                    .map(|(pl, ps)| json!({"pull": pl, "push": ps}))
                    .collect::<Vec<_>>(),
            )?)
        }
        (Method::Post, "/api/fsck") => {
            let verify = input
                .get("verify")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            Ok(serde_json::to_value(engine.fsck(verify)?)?)
        }
        (Method::Get, "/api/ledger") => Ok(serde_json::to_value(engine.ledger_entries()?)?),
        (Method::Get, "/api/files") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.list_files(&folder)?)?)
        }
        (Method::Post, "/api/fetch") => Ok(serde_json::to_value(
            engine.fetch_file(&s(input, "folder")?, &s(input, "path")?)?,
        )?),
        (Method::Get, "/api/p2p") => Ok(json!({"config": engine.p2p_config(), "listen": service.p2p_listen, "peers": service.p2p_peers, "lan_peers": service.p2p_lan_peers, "chunks_from_peers": service.p2p_chunks})),
        (Method::Post, "/api/p2p") => {
            let mut c = engine.p2p_config();
            if let Some(en) = input.get("enabled").and_then(|v| v.as_bool()) {
                c.enabled = en;
            }
            if let Some(p) = input.get("port").and_then(|v| v.as_u64()) {
                c.port = p as u16;
            }
            if let Some(pubs) = input.get("public_addrs").and_then(|v| v.as_str()) {
                c.public_addrs = pubs.split(',').filter_map(|a| a.trim().parse().ok()).collect();
            }
            engine.set_p2p_config(c)?;
            Ok(json!({"ok": true, "note": "restart the background service to apply"}))
        }
        (Method::Get, "/api/policy") => Ok(json!({
            "policies": engine.folders().into_iter().map(|(r, _)| json!({"folder": r.name, "policy": r.policy, "text": r.policy.as_ref().map(|p| p.describe())})).collect::<Vec<_>>(),
            "reports": engine.policy_check()?,
        })),
        (Method::Post, "/api/policy") => {
            let folder = s(input, "folder")?;
            if input.get("clear").and_then(|c| c.as_bool()).unwrap_or(false) {
                engine.set_policy(&folder, None)?;
            } else {
                let mut policy = varsto_core::policy::Policy {
                    min_copies: input.get("min_copies").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    verified_within_days: input.get("verified_within_days").and_then(|v| v.as_u64()).filter(|d| *d > 0).map(|d| d as u32),
                    ..Default::default()
                };
                if let Some(obj) = input.get("places").and_then(|p| p.as_object()) {
                    for (k, v) in obj {
                        if let Some(n) = v.as_u64().filter(|n| *n > 0) {
                            policy.min_per_place.insert(k.clone(), n as u32);
                        }
                    }
                }
                engine.set_policy(&folder, Some(policy))?;
            }
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/move") => Ok(serde_json::to_value(engine.move_file(
            &s(input, "folder")?,
            &s(input, "from")?,
            &s(input, "to")?,
        )?)?),
        (Method::Get, "/api/advice") => {
            let idle_days = query_param(query, "idle_days")
                .and_then(|d| d.parse().ok())
                .unwrap_or(90);
            let folders: Vec<String> = match query_param(query, "folder") {
                Some(f) => vec![f],
                None => engine
                    .folders()
                    .into_iter()
                    .filter(|(_, m)| m.is_some())
                    .map(|(r, _)| r.name)
                    .collect(),
            };
            let mut files = Vec::new();
            for f in &folders {
                for e in engine.list_files(f)? {
                    files.push((f.clone(), e.path, e.size, e.last_accessed_utc, e.modified_utc));
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            Ok(serde_json::to_value(varsto_core::advice::storage_advice(&files, idle_days, now))?)
        }
        (Method::Post, "/api/free") => {
            engine.free_file(&s(input, "folder")?, &s(input, "path")?)?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/selective") => {
            engine.set_selective(
                &s(input, "folder")?,
                input.get("on").and_then(|b| b.as_bool()).unwrap_or(true),
            )?;
            service.folders_changed = true;
            Ok(json!({"ok": true}))
        }
        (Method::Get, "/api/dupes") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.dupes(&folder)?)?)
        }
        _ => Err(anyhow!("unknown API endpoint {path}")),
    }
    .with_context(|| path.to_string())
}
