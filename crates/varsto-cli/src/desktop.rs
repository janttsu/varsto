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
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");
/// Largest single upload through /api/upload (a phone video, not a disk image).
const MAX_UPLOAD: u64 = 1 << 30;

pub struct State {
    pub home: PathBuf,
    pub engine: Option<Engine>,
    pub token: String,
    pub bound: String,
    /// Peer-to-peer traffic counters, read by `/api/p2p/traffic` without the state lock.
    pub traffic: Arc<varsto_core::p2p::Traffic>,
    pub service: ServiceState,
    /// An open pairing offer (this device adding another one).
    pub pair: Option<varsto_core::pair::Offer>,
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
///
/// This thread answers what needs no state itself: the page and its assets
/// and the traffic counters. Everything else goes, in arrival order, to one
/// worker thread, as before. A sync or a fetch holds the state for minutes,
/// and every request behind it waits; the traffic view, most interesting
/// exactly then, must not wait with them. The host name, token and counters
/// it needs never change after start, so they are copied here once.
pub fn serve_arc(server: Arc<Server>, state: Shared) {
    let fixed = {
        let st = state.lock().unwrap();
        Fixed {
            bound: st.bound.clone(),
            token: st.token.clone(),
            traffic: st.traffic.clone(),
        }
    };
    let (tx, rx) = std::sync::mpsc::channel::<Request>();
    let worker = std::thread::Builder::new()
        .name("http-api".into())
        .spawn(move || {
            for request in rx {
                if let Err(e) = handle(&state, request) {
                    eprintln!("request failed: {e:#}");
                }
            }
        });
    if worker.is_err() {
        eprintln!("cannot start the API worker thread");
        return;
    }
    for request in server.incoming_requests() {
        match handle_unlocked(&fixed, request) {
            Ok(None) => {}
            Ok(Some(request)) => {
                if tx.send(request).is_err() {
                    break;
                }
            }
            Err(e) => eprintln!("request failed: {e:#}"),
        }
    }
}

/// What the dispatching thread needs, copied from the state at start.
struct Fixed {
    bound: String,
    token: String,
    traffic: Arc<varsto_core::p2p::Traffic>,
}

/// Answer a request that needs no state, or hand it back for the worker.
fn handle_unlocked(fixed: &Fixed, request: Request) -> Result<Option<Request>> {
    let port = fixed.bound.rsplit(':').next().unwrap_or("");
    let host_ok = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str() == fixed.bound || h.value.as_str() == format!("localhost:{port}"))
        .unwrap_or(false);
    if !host_ok {
        request.respond(Response::from_string("bad host").with_status_code(400))?;
        return Ok(None);
    }
    if *request.method() != Method::Get {
        return Ok(Some(request));
    }
    let path = request.url().split('?').next().unwrap_or("").to_string();
    match path.as_str() {
        "/" => request.respond(html(INDEX_HTML))?,
        "/app.js" => request.respond(text(APP_JS, "text/javascript; charset=utf-8"))?,
        "/app.css" => request.respond(text(APP_CSS, "text/css; charset=utf-8"))?,
        "/api/p2p/traffic" => {
            let token_ok = request
                .headers()
                .iter()
                .any(|h| h.field.equiv("X-Varsto-Token") && h.value.as_str() == fixed.token);
            if !token_ok {
                request.respond(json_response(
                    401,
                    &json!({"error": "missing or wrong token; reopen the start URL"}),
                ))?;
            } else {
                let report = serde_json::to_value(fixed.traffic.report())?;
                request.respond(json_response(200, &report))?;
            }
        }
        _ => return Ok(Some(request)),
    }
    Ok(None)
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
        .with_header(header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
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
        // Thumbnails and the viewer are loaded by <img>/<video>, which cannot
        // send a header; the session token may come in the query string there.
        let in_query = (path == "/api/thumb" || path == "/api/open" || path == "/api/view")
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
    if path == "/api/view" {
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        return crate::view::respond(state, request, folder, file);
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
                    // Phones keep no decrypted thumbnail in the web view's disk cache.
                    .with_header(header(
                        "Cache-Control",
                        if mobile() {
                            "no-store"
                        } else {
                            "private, max-age=3600"
                        },
                    )),
            )?,
            None => request.respond(Response::from_string("no thumbnail").with_status_code(404))?,
        }
        return Ok(());
    }
    if *request.method() == Method::Post && path == "/api/upload" {
        // Raw upload: `POST /api/upload?folder=<name>&path=<relative path>` with the
        // file's bytes as the body (any content type). Writes the file into the
        // folder and pushes it, like /api/write for text.
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        let mut bytes = Vec::new();
        request
            .as_reader()
            .take(MAX_UPLOAD + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_UPLOAD {
            return Ok(request.respond(json_response(
                413,
                &json!({"error": format!("file larger than {} MiB", MAX_UPLOAD >> 20)}),
            ))?);
        }
        let result = {
            let mut st = state.lock().unwrap();
            match (&mut st.engine, folder, file) {
                (None, _, _) => Err(anyhow!("vault is locked")),
                (Some(e), Some(f), Some(p)) => e.write_file(&f, &p, &bytes).map(|r| {
                    json!({"ok": true, "folder": f, "path": p, "bytes": bytes.len(), "push": r})
                }),
                _ => Err(anyhow!("folder and path query parameters required")),
            }
        };
        return match result {
            Ok(v) => Ok(request.respond(json_response(200, &v))?),
            Err(e) => Ok(request.respond(json_response(400, &json!({"error": format!("{e:#}")})))?),
        };
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
    if method == Method::Post && path == "/api/pair/join" {
        // Pairing talks to the other device for up to ~25 seconds; do that
        // without holding the state, then join under it.
        let result = pair_join(state, &input);
        return match result {
            Ok(v) => Ok(request.respond(json_response(200, &v))?),
            Err(e) => Ok(request.respond(json_response(400, &json!({"error": format!("{e:#}")})))?),
        };
    }
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

fn pair_join(state: &Shared, input: &Value) -> Result<Value> {
    let (name, passphrase, code) = (
        s(input, "name")?,
        s(input, "passphrase")?,
        s(input, "code")?,
    );
    if passphrase.chars().count() < 8 {
        bail!("the passphrase needs at least 8 characters");
    }
    if state.lock().unwrap().home.join("vault.json").exists() {
        bail!("this device already holds a vault");
    }
    let bundle = varsto_core::pair::receive(&code, &name, opt(input, "address").as_deref())?;
    let mut st = state.lock().unwrap();
    let (e, notes) = Engine::join_paired(&st.home, &name, &passphrase, &bundle)?;
    st.engine = Some(e);
    st.service.request_sync();
    Ok(json!({"ok": true, "from": bundle.from, "storages": notes}))
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

/// Where folders go when the interface does not ask for a path (phones, and
/// a sensible default on desktops): `VARSTO_FOLDER_ROOT`, else `<home>/../Varsto Folders`.
pub fn folder_root(home: &std::path::Path) -> PathBuf {
    if let Some(r) = std::env::var_os("VARSTO_FOLDER_ROOT") {
        return PathBuf::from(r);
    }
    if let Some(h) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(h).join("Varsto");
    }
    home.join("folders")
}

/// Where "plain files on this device" folders go on a phone (`VARSTO_PLAIN_ROOT`,
/// set by the Android shell to the shared storage); elsewhere the folder root.
pub fn plain_root(home: &std::path::Path) -> PathBuf {
    match std::env::var_os("VARSTO_PLAIN_ROOT") {
        Some(r) => PathBuf::from(r),
        None => folder_root(home),
    }
}

/// Whether the plain root can be written now (on Android only after "all files
/// access" was granted): the directory is created and a probe file written.
fn plain_root_writable(root: &std::path::Path) -> bool {
    if std::fs::create_dir_all(root).is_err() {
        return false;
    }
    let probe = root.join(".varsto-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

fn mobile() -> bool {
    std::env::var_os("VARSTO_MOBILE").is_some()
}

/// The `plain` flag of a folder request: plain files unless the request says
/// otherwise; phones default to "encrypted on this device".
fn wants_plain(input: &Value) -> bool {
    input
        .get("plain")
        .and_then(|b| b.as_bool())
        .unwrap_or(!mobile())
}

/// Directory for a folder the interface did not name a path for.
fn default_folder_path(home: &std::path::Path, name: &str, plain: bool) -> Result<PathBuf> {
    if plain && mobile() {
        let root = plain_root(home);
        if !plain_root_writable(&root) {
            return Err(anyhow!(
                "cannot write to {}; allow all files access first",
                root.display()
            ));
        }
        return Ok(root.join(name));
    }
    Ok(folder_root(home).join(name))
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
            "platform": std::env::consts::OS,
            // Mobile shells set these so the interface can pick folder locations itself.
            "mobile": mobile(),
            "folder_root": folder_root(&st.home).display().to_string(),
            // Phones: where "plain files on this phone" folders go, and whether that is possible now.
            "plain_root": plain_root(&st.home).display().to_string(),
            "plain_root_writable": !mobile() || plain_root_writable(&plain_root(&st.home)),
            "service": st.service.summary(),
            // Set when another device removed (and maybe wiped) this one.
            "removal": varsto_core::engine::removal_notice(&st.home),
        })),
        (Method::Post, "/api/reset") => {
            if opt(input, "confirm").as_deref() != Some("reset") {
                return Err(anyhow!(
                    "send {{\"confirm\": \"reset\"}} to wipe this device's vault configuration"
                ));
            }
            st.engine = None;
            let removed = varsto_core::engine::reset_device(&st.home)?;
            st.service.policies.clear();
            st.service.policy_worst = None;
            Ok(json!({"ok": true, "removed": removed}))
        }
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
            // Folders kept "encrypted on this device" lose their plaintext copies.
            let freed = st
                .engine
                .as_mut()
                .map(|e| e.free_encrypted_folders())
                .unwrap_or_default();
            st.engine = None;
            st.pair = None;
            Ok(
                json!({"ok": true, "freed": freed.into_iter().map(|(f, n, k)| json!({"folder": f, "freed": n, "kept": k})).collect::<Vec<_>>()}),
            )
        }
        (Method::Post, "/api/pair/start") => {
            let e = st
                .engine
                .as_ref()
                .ok_or_else(|| anyhow!("unlock the vault first"))?;
            if let Some(old) = st.pair.take() {
                old.stop();
            }
            let offer = varsto_core::pair::Offer::start(e.pairing_bundle()?)?;
            let status = offer.status();
            st.pair = Some(offer);
            Ok(serde_json::to_value(status)?)
        }
        (Method::Get, "/api/pair/status") => Ok(match &st.pair {
            Some(o) => serde_json::to_value(o.status())?,
            None => json!({"open": false}),
        }),
        (Method::Post, "/api/pair/stop") => {
            if let Some(o) = st.pair.take() {
                o.stop();
            }
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
            // The storage that holds the vault: a directory, or an S3-compatible
            // bucket (the only choice on a phone). The S3 secret travels through the
            // environment for this process because the storage is opened before
            // the vault exists, then goes into the encrypted secret store.
            let storage_name = opt(input, "storage_name")
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "primary".into());
            let kind = opt(input, "kind").unwrap_or_default();
            let mut s3_secret: Option<String> = None;
            let spec = if kind == "s3" || (kind.is_empty() && opt(input, "bucket").is_some()) {
                let secret = s(input, "secret_access_key")?;
                let env_name = format!(
                    "VARSTO_S3_SECRET_{}",
                    storage_name
                        .to_uppercase()
                        .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                );
                std::env::set_var(env_name, &secret);
                s3_secret = Some(secret);
                StorageSpec::S3 {
                    name: storage_name.clone(),
                    endpoint: s(input, "endpoint")?.trim_end_matches('/').to_string(),
                    region: opt(input, "region")
                        .filter(|r| !r.trim().is_empty())
                        .unwrap_or_else(|| "auto".into()),
                    bucket: s(input, "bucket")?,
                    prefix: opt(input, "prefix")
                        .unwrap_or_default()
                        .trim_matches('/')
                        .to_string(),
                    access_key_id: s(input, "access_key_id")?,
                    secret_ref: String::new(),
                    path_style: true,
                    storage_class: None,
                    cold: false,
                    place: opt(input, "place").unwrap_or_else(|| "cloud".into()),
                }
            } else {
                StorageSpec::LocalDir {
                    name: storage_name.clone(),
                    path: PathBuf::from(s(input, "storage_path")?),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                }
            };
            // The key in hex, or the 24 words of the recovery kit.
            let key = s(input, "vault_key")?;
            let key = if key.trim().contains(char::is_whitespace) {
                varsto_core::recovery::key_from_words(&key)?
            } else {
                key.trim().to_string()
            };
            let mut e = Engine::join(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &key,
                spec,
            )?;
            if let Some(secret) = s3_secret {
                e.store_secret(&storage_name, &secret)?;
            }
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
                .map(|(r, m)| json!({"id": r.folder_id.to_string(), "name": r.name, "path": m, "strongroom": r.is_strongroom(), "plain": !engine.folder_is_encrypted_here(&r.folder_id)}))
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
        (Method::Get, "/api/devices") => Ok(json!({
            "devices": engine.devices_list(),
            "key_epoch": engine.key_epoch(),
            "removal": engine.removal(),
        })),
        (Method::Post, "/api/device/revoke") => {
            let device = s(input, "device")?;
            let wipe = input.get("wipe").and_then(|v| v.as_bool()).unwrap_or(false);
            // The interface makes the user type the device's name; so does the API.
            let name = engine
                .devices_list()
                .into_iter()
                .find(|d| d.device_id == device || d.name == device)
                .map(|d| d.name)
                .ok_or_else(|| anyhow!("unknown device {device}"))?;
            if opt(input, "confirm").as_deref() != Some(name.as_str()) {
                bail!("send {{\"confirm\": \"{name}\"}} to remove this device");
            }
            let report = engine.revoke_device(&device, wipe)?;
            service.request_sync();
            Ok(serde_json::to_value(report)?)
        }
        (Method::Get, "/api/replica/token") => {
            Ok(json!({"token": engine.replica_token()?.encode()}))
        }
        (Method::Get, "/api/storage/remove-plan") => Ok(serde_json::to_value(
            engine.plan_storage_removal(&query_param(query, "name").unwrap_or_default())?,
        )?),
        (Method::Post, "/api/storage/remove") => {
            let r = engine.remove_storage(
                &s(input, "name")?,
                input.get("delete_data").and_then(|v| v.as_bool()).unwrap_or(false),
            )?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
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
                "pool" => engine.add_storage(StorageSpec::Pool {
                    name: s(input, "name")?,
                    place: opt(input, "place").unwrap_or_default(),
                    reserve_percent: opt(input, "reserve_percent")
                        .and_then(|r| r.parse().ok())
                        .unwrap_or(varsto_core::pool::DEFAULT_RESERVE_PERCENT),
                    min_reserve_bytes: varsto_core::pool::DEFAULT_MIN_RESERVE_BYTES,
                    disks: vec![],
                    scan_roots: vec![],
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
            let name = s(input, "name")?;
            // No path given (phones, or the user left it empty): a directory named
            // after the folder under this device's Varsto root, or under the shared
            // storage for "plain files on this phone".
            let plain = wants_plain(input);
            let path = match opt(input, "path").filter(|p| !p.trim().is_empty()) {
                Some(p) => PathBuf::from(p),
                None => default_folder_path(engine.home(), &name, plain)?,
            };
            let id = engine.add_folder(&name, &path)?;
            if !plain {
                engine.set_encrypted_here(&name, true)?;
            }
            service.folders_changed = true;
            service.request_sync();
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        (Method::Post, "/api/folder/detach") => {
            engine.detach_folder(&s(input, "name")?)?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/folder/remove") => {
            let purge = input.get("purge").and_then(|v| v.as_bool()).unwrap_or(false);
            let deleted = engine.remove_folder(&s(input, "name")?, purge)?;
            Ok(json!({"ok": true, "objects_deleted": deleted}))
        }
        (Method::Post, "/api/folder/attach") => {
            let selective = input
                .get("selective")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            let name_or_id = s(input, "name_or_id")?;
            let plain = wants_plain(input);
            let path = match opt(input, "path").filter(|p| !p.trim().is_empty()) {
                Some(p) => PathBuf::from(p),
                None => {
                    let name = engine
                        .folders()
                        .into_iter()
                        .find(|(r, _)| r.name == name_or_id || r.folder_id.as_str().starts_with(&name_or_id))
                        .map(|(r, _)| r.name)
                        .unwrap_or_else(|| name_or_id.clone());
                    default_folder_path(engine.home(), &name, plain)?
                }
            };
            let id = engine.attach_folder(&name_or_id, &path, selective || !plain)?;
            if !plain {
                engine.set_encrypted_here(&name_or_id, true)?;
            }
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
        (Method::Post, "/api/fetch") => {
            match engine.fetch_file(&s(input, "folder")?, &s(input, "path")?) {
                Ok(r) => Ok(serde_json::to_value(r)?),
                // The file is on a pool disk that is away: tell the interface which one.
                Err(e) => match varsto_core::pool::pool_error(&e) {
                    Some(varsto_core::pool::PoolError::NeedsDisk { label, disk_id, place }) => Ok(json!({
                        "needs_disk": {"label": label, "disk_id": disk_id, "place": place},
                        "error": e.to_string(),
                    })),
                    _ => Err(e),
                },
            }
        }
        (Method::Get, "/api/disks") => Ok(serde_json::to_value(engine.disks()?)?),
        (Method::Post, "/api/disk/add") => {
            let r = engine.disk_add(
                std::path::Path::new(&s(input, "mount")?),
                &s(input, "pool")?,
                &s(input, "label")?,
            )?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/disk/check") => {
            let full = input.get("full").and_then(|c| c.as_bool()).unwrap_or(false);
            let r = engine.disk_check(&s(input, "label")?, full)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/disk/eject") => {
            let label = s(input, "label")?;
            let mount = engine.disk_eject(&label)?;
            Ok(json!({"ok": true, "label": label, "mount": mount, "safe_to_remove": true, "message": format!("{label}: index written and synced; safe to remove")}))
        }
        (Method::Post, "/api/disk/retire") => {
            let label = s(input, "label")?;
            let only_here = engine.disk_retire(&label)?;
            Ok(json!({"ok": true, "label": label, "retired": true, "objects_only_here": only_here}))
        }
        (Method::Get, "/api/strongroom") => Ok(json!({
            "strongrooms": engine.strongrooms().into_iter().map(|(n, m, u)| json!({"folder": n, "method": m, "unlocked_until": u, "keys": engine.strongroom_keys(&n).unwrap_or_default()})).collect::<Vec<_>>(),
            "conversions": engine.strongroom_conversions().into_iter().map(|(n, switched)| json!({"folder": n, "cleanup_only": switched})).collect::<Vec<_>>(),
        })),
        // The command line touched the security key (it made the new key
        // and its wrap); the conversion runs here, where the folder state is.
        (Method::Post, "/api/strongroom/convert") => {
            let folder = s(input, "folder")?;
            let id = varsto_core::ids::FolderId::from_hex(&s(input, "folder_id")?)?;
            let key = varsto_core::crypto::SecretKey::from_hex(&s(input, "key_hex")?)?;
            let info: varsto_core::strongroom::StrongroomInfo = serde_json::from_value(input.get("info").cloned().unwrap_or_default())?;
            let minutes = input.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15).clamp(1, 24 * 60);
            let r = engine.convert_to_strongroom_with(&folder, &id, &key, info, minutes)?;
            let mut out = serde_json::to_value(r)?;
            if input.get("free").and_then(|v| v.as_bool()).unwrap_or(false) {
                let (freed, kept) = engine.free_folder(&folder)?;
                out["freed"] = json!(freed);
                out["kept"] = json!(kept);
            }
            service.request_sync();
            Ok(out)
        }
        (Method::Post, "/api/strongroom/add-key") => {
            let key: varsto_core::strongroom::EnrolledKey = serde_json::from_value(input.get("key").cloned().unwrap_or_default())?;
            let n = engine.add_strongroom_key_enrolled(&s(input, "folder")?, key)?;
            Ok(json!({"ok": true, "keys": n}))
        }
        (Method::Post, "/api/strongroom/remove-key") => {
            let gone = engine.remove_strongroom_key(&s(input, "folder")?, &s(input, "key")?)?;
            Ok(json!({"ok": true, "removed": gone.short()}))
        }
        (Method::Post, "/api/strongroom/unlock") => {
            let minutes = input.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15).clamp(1, 24 * 60);
            engine.unlock_strongroom_with_key(&s(input, "folder")?, &s(input, "key_hex")?, minutes)?;
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/strongroom/lock") => {
            engine.lock_strongroom(&s(input, "folder")?)?;
            Ok(json!({"ok": true}))
        }
        (Method::Get, "/api/p2p") => Ok(json!({
            "config": engine.p2p_config(),
            "listen": service.p2p_listen,
            "peers": service.p2p_peers,
            "lan_peers": service.p2p_lan_peers,
            "chunks_from_peers": service.p2p_chunks,
            "nat": service.p2p_nat,
            "public": service.p2p_public,
            "reachable": service.p2p_reachable,
            "relays": service.p2p_relays,
            "paths": service.p2p_paths,
            "cert_sha256": service.p2p_cert_sha256,
        })),
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
            if let Some(stun) = input.get("stun").and_then(|v| v.as_str()) {
                // An empty field disables STUN on purpose.
                c.stun = stun.split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect();
            }
            let enabled = c.enabled;
            engine.set_p2p_config(c)?;
            if enabled {
                engine.p2p_identity()?; // the certificate exists before the service restarts
            }
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
        (Method::Post, "/api/mkdir") => {
            engine.mkdir(&s(input, "folder")?, &s(input, "path")?)?;
            Ok(json!({"ok": true}))
        }
        // New files only (the assistant's channel): nothing is overwritten.
        (Method::Post, "/api/write") => Ok(serde_json::to_value(engine.create_file(
            &s(input, "folder")?,
            &s(input, "path")?,
            s(input, "text")?.as_bytes(),
        )?)?),
        (Method::Post, "/api/move") => Ok(serde_json::to_value(engine.move_file(
            &s(input, "folder")?,
            &s(input, "from")?,
            &s(input, "to")?,
        )?)?),
        (Method::Get, "/api/advice") => {
            let idle_days = query_param(query, "idle_days")
                .and_then(|d| d.parse().ok())
                .unwrap_or(90);
            let mut a = engine.placement_advice(idle_days, varsto_core::util::now_utc())?;
            if let Some(f) = query_param(query, "folder") {
                a.idle_files.retain(|x| x.folder == f);
                a.folders.retain(|x| x.folder == f);
                a.suggestions.retain(|x| x.folder == f);
            }
            Ok(serde_json::to_value(a)?)
        }
        (Method::Post, "/api/advice/apply") => {
            let idle_days = input.get("idle_days").and_then(|v| v.as_i64()).unwrap_or(90);
            let r = engine.apply_suggestion(&s(input, "id")?, idle_days)?;
            service.folders_changed = true;
            Ok(serde_json::to_value(r)?)
        }
        (Method::Get, "/api/storage/costs") => Ok(serde_json::to_value(engine.storage_estimates()?)?),
        (Method::Post, "/api/storage/price") => {
            let name = s(input, "name")?;
            let num = |k: &str| input.get(k).and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|t| t.trim().parse().ok())));
            if input.get("clear").and_then(|c| c.as_bool()).unwrap_or(false) {
                engine.set_storage_price(&name, None)?;
            } else {
                engine.set_storage_price(
                    &name,
                    Some(varsto_core::price::StoragePrice {
                        storage_per_gb_month: num("gb_month"),
                        egress_per_gb: num("egress"),
                        retrieval_per_gb: num("retrieval"),
                        minimum_storage_days: num("min_days").map(|d| d as u32),
                        currency: opt(input, "currency").unwrap_or_default(),
                        source: String::new(),
                    }),
                )?;
            }
            Ok(json!({"ok": true, "price": engine.storage_price(&name)}))
        }
        (Method::Get, "/api/verify") => Ok(serde_json::to_value(engine.verify_status())?),
        (Method::Post, "/api/verify") => {
            let mut sched = engine.verify_schedule().clone();
            if let Some(v) = input.get("enabled").and_then(|v| v.as_bool()) {
                sched.enabled = v;
            }
            if let Some(v) = input.get("interval_hours").and_then(|v| v.as_u64()) {
                sched.interval_hours = v as u32;
            }
            if let Some(v) = input.get("max_mib").and_then(|v| v.as_u64()) {
                sched.max_bytes = v.saturating_mul(1024 * 1024);
            }
            if let Some(v) = input.get("max_blocks").and_then(|v| v.as_u64()) {
                sched.max_blocks = v;
            }
            engine.set_verify_schedule(sched)?;
            service.auto_verify = Some(engine.verify_status());
            Ok(serde_json::to_value(engine.verify_status())?)
        }
        (Method::Post, "/api/verify/run") => {
            let r = engine.auto_verify()?;
            service.auto_verify = Some(engine.verify_status());
            if let Ok(reps) = engine.policy_check() {
                service.record_policies(reps);
            }
            Ok(json!({"report": r, "status": engine.verify_status()}))
        }
        (Method::Post, "/api/paths") => {
            // Finder and other file managers: act on absolute paths, one result each.
            let action = s(input, "action")?;
            let paths: Vec<String> = input
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let mut results = Vec::new();
            for p in paths {
                let r = engine.locate_path(std::path::Path::new(&p)).and_then(|(folder, file)| {
                    match action.as_str() {
                        "fetch" => engine.fetch_file(&folder, &file).map(|_| ()),
                        "free" => engine.free_file(&folder, &file),
                        other => Err(anyhow!("unknown action {other}")),
                    }
                    .map(|()| file)
                });
                results.push(match r {
                    Ok(file) => json!({"path": p, "file": file, "ok": true}),
                    Err(e) => json!({"path": p, "ok": false, "error": format!("{e:#}")}),
                });
            }
            Ok(json!({"results": results}))
        }
        (Method::Post, "/api/free") => {
            // Without a path: every fetched file of the folder.
            match opt(input, "path") {
                Some(p) => {
                    engine.free_file(&s(input, "folder")?, &p)?;
                    Ok(json!({"ok": true}))
                }
                None => {
                    let (freed, kept) = engine.free_folder(&s(input, "folder")?)?;
                    Ok(json!({"ok": true, "freed": freed, "kept": kept}))
                }
            }
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
