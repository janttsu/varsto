// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto desktop`: a local graphical interface served to the user's browser.
//!
//! The server binds to 127.0.0.1 only, on a random port unless one is given,
//! and every API call must carry a per-session token that is handed to the
//! page once through the start URL. The `Host` header is checked against the
//! bound address to defeat DNS rebinding. No request from another origin can
//! read the responses (no CORS headers are ever sent). This is the first
//! shape of the local control API of the plan; the real daemon API comes later.

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tiny_http::{Header, Method, Request, Response, Server};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");

struct State {
    home: PathBuf,
    engine: Option<Engine>,
    token: String,
    bound: String,
}

pub fn run(home: PathBuf, port: u16, open_browser: bool, passphrase: Option<String>) -> Result<()> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("no ip address"))?;
    let bound = format!("127.0.0.1:{}", addr.port());
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let url = format!("http://{bound}/?token={token}");
    let mut engine = None;
    if let Some(p) = passphrase.as_deref() {
        if home.join("vault.json").exists() {
            engine = Some(Engine::open(&home, p)?);
        }
    }
    let state = Mutex::new(State {
        home,
        engine,
        token,
        bound: bound.clone(),
    });
    println!("Varsto desktop: {url}");
    println!("Only this computer can reach it. Press Ctrl-C to stop.");
    if open_browser {
        open_in_browser(&url);
    }
    for request in server.incoming_requests() {
        if let Err(e) = handle(&state, request) {
            eprintln!("request failed: {e:#}");
        }
    }
    Ok(())
}

fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let cmd = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let cmd = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let cmd = std::process::Command::new("xdg-open").arg(url).spawn();
    if cmd.is_err() {
        eprintln!("could not open a browser; open the URL above by hand");
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

fn handle(state: &Mutex<State>, mut request: Request) -> Result<()> {
    let host_ok = {
        let st = state.lock().unwrap();
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| {
                h.value.as_str() == st.bound
                    || h.value.as_str()
                        == format!("localhost:{}", st.bound.rsplit(':').next().unwrap_or(""))
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
    // Token check for every API call.
    let token_ok = {
        let st = state.lock().unwrap();
        request
            .headers()
            .iter()
            .any(|h| h.field.equiv("X-Varsto-Token") && h.value.as_str() == st.token)
    };
    if !token_ok {
        return Ok(request.respond(json_response(
            401,
            &json!({"error": "missing or wrong token; reopen the start URL"}),
        ))?);
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
    let result = {
        let mut st = state.lock().unwrap();
        api(&mut st, request.method().clone(), &path, &query, &input)
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
            .map(|(_, v)| v.replace("%2F", "/").replace('+', " "))
    })
}

fn api(st: &mut State, method: Method, path: &str, query: &str, input: &Value) -> Result<Value> {
    let method_for_unlocked = method.clone();
    let has_vault = st.home.join("vault.json").exists();
    match (method, path) {
        (Method::Get, "/api/state") => Ok(json!({
            "home": st.home.display().to_string(),
            "has_vault": has_vault,
            "unlocked": st.engine.is_some(),
            "version": env!("CARGO_PKG_VERSION"),
        })),
        (Method::Post, "/api/unlock") => {
            let e = Engine::open(&st.home, &s(input, "passphrase")?)?;
            st.engine = Some(e);
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
        (Method::Post, "/api/join") => {
            let spec = StorageSpec::LocalDir {
                name: opt(input, "storage_name").unwrap_or_else(|| "primary".into()),
                path: PathBuf::from(s(input, "storage_path")?),
                cold: false,
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
            let engine = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            api_unlocked(engine, method_for_unlocked, path, query, input)
        }
    }
}

fn api_unlocked(
    engine: &mut Engine,
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
        (Method::Post, "/api/storage") => {
            let cold = input.get("cold").and_then(|c| c.as_bool()).unwrap_or(false);
            engine.add_storage(StorageSpec::LocalDir {
                name: s(input, "name")?,
                path: PathBuf::from(s(input, "path")?),
                cold,
            })?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/folder") => {
            let id = engine.add_folder(&s(input, "name")?, Path::new(&s(input, "path")?))?;
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        (Method::Post, "/api/folder/attach") => {
            let id =
                engine.attach_folder(&s(input, "name_or_id")?, Path::new(&s(input, "path")?))?;
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        (Method::Post, "/api/sync") => {
            let folder = opt(input, "folder");
            let reports = engine.sync(folder.as_deref())?;
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
        (Method::Get, "/api/dupes") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.dupes(&folder)?)?)
        }
        _ => Err(anyhow!("unknown API endpoint {path}")),
    }
    .with_context(|| path.to_string())
}
