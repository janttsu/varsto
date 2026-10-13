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
const I18N_JS: &str = include_str!("../ui/i18n.js");
const I18N_FI: &str = include_str!("../ui/i18n/fi.json");
const I18N_SV: &str = include_str!("../ui/i18n/sv.json");

/// The interface language chosen in the page ("en", "fi" or "sv"), for the
/// tray and the menu bar: `home/ui-language`. English when unset.
pub fn ui_language(home: &std::path::Path) -> String {
    std::fs::read_to_string(home.join("ui-language"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|l| matches!(l.as_str(), "en" | "fi" | "sv"))
        .unwrap_or_else(|| "en".to_string())
}
const APP_CSS: &str = include_str!("../ui/app.css");
/// Largest single upload through /api/upload (a phone video, not a disk image).
/// The body is streamed to disk (or encrypted into the block cache as it
/// arrives), never held in memory as a whole.
const MAX_UPLOAD: u64 = 16 << 30;

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
    let path = request.url().split('?').next().unwrap_or("").to_string();
    if *request.method() == Method::Post && path == "/api/activity/report" {
        // A command of this device reports the tasks it runs (answered
        // here, without the state: a sync may hold it).
        let mut request = request;
        let token_ok = request
            .headers()
            .iter()
            .any(|h| h.field.equiv("X-Varsto-Token") && h.value.as_str() == fixed.token);
        let mut body = String::new();
        let read = request
            .as_reader()
            .take(256 * 1024)
            .read_to_string(&mut body);
        #[derive(serde::Deserialize)]
        struct Report {
            pid: u32,
            tasks: Vec<varsto_core::activity::TaskView>,
        }
        let parsed = read
            .ok()
            .and_then(|_| serde_json::from_str::<Report>(&body).ok());
        match (token_ok, parsed) {
            (false, _) => request.respond(json_response(
                401,
                &json!({"error": "missing or wrong token; reopen the start URL"}),
            ))?,
            (true, None) => {
                request.respond(json_response(400, &json!({"error": "bad activity report"})))?
            }
            (true, Some(r)) => {
                varsto_core::activity::merge_external(r.pid, r.tasks);
                request.respond(json_response(200, &json!({"ok": true})))?;
            }
        }
        return Ok(None);
    }
    if *request.method() != Method::Get {
        return Ok(Some(request));
    }
    match path.as_str() {
        "/" => request.respond(html(INDEX_HTML))?,
        "/app.js" => request.respond(text(APP_JS, "text/javascript; charset=utf-8"))?,
        "/i18n.js" => request.respond(text(I18N_JS, "text/javascript; charset=utf-8"))?,
        "/i18n/fi.json" => request.respond(text(I18N_FI, "application/json; charset=utf-8"))?,
        "/i18n/sv.json" => request.respond(text(I18N_SV, "application/json; charset=utf-8"))?,
        "/app.css" => request.respond(text(APP_CSS, "text/css; charset=utf-8"))?,
        "/api/p2p/traffic" | "/api/progress" | "/api/activity" => {
            let token_ok = request
                .headers()
                .iter()
                .any(|h| h.field.equiv("X-Varsto-Token") && h.value.as_str() == fixed.token);
            if !token_ok {
                request.respond(json_response(
                    401,
                    &json!({"error": "missing or wrong token; reopen the start URL"}),
                ))?;
            } else if path == "/api/activity"
                && query_param(request.url().split_once('?').map_or("", |(_, q)| q), "mine")
                    .is_some_and(|v| v == "1")
            {
                // This device's tasks only (the progress bar at the top of
                // the interface): the peers are not asked.
                request.respond(json_response(
                    200,
                    &json!({ "me": varsto_core::activity::local_here() }),
                ))?;
            } else if path == "/api/activity" {
                // What this device and the others are doing now. Asking
                // keeps the service asking the peers for the next 15 s.
                let peers = varsto_core::activity::global();
                peers.watch();
                request.respond(json_response(
                    200,
                    &json!({
                        "me": varsto_core::activity::local_here(),
                        "peers": peers.report(),
                    }),
                ))?;
            } else if path == "/api/progress" {
                // The download running now, answered while it holds the engine.
                let p = serde_json::to_value(varsto_core::progress::current())?;
                let all = serde_json::to_value(varsto_core::progress::all())?;
                request.respond(json_response(
                    200,
                    &json!({ "download": p, "transfers": all }),
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

/// A response header. Values are ASCII without control characters;
/// anything else is dropped from the value rather than tripping the
/// worker thread (a header value never carries user data verbatim).
fn header(name: &str, value: &str) -> Header {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect();
    Header::from_bytes(name.as_bytes(), clean.as_bytes())
        .unwrap_or_else(|_| Header::from_bytes(name.as_bytes(), b"").expect("empty header"))
}

/// `Content-Disposition` for a download: an ASCII fallback name plus the
/// UTF-8 name percent-encoded (RFC 6266 / RFC 8187), so any file name works.
fn attachment(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut enc = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{enc}")
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
        // A scoped MCP key (`mcp_keys`): only the routes the MCP tools
        // need, within the key's folders and levels.
        let key = request
            .headers()
            .iter()
            .find(|h| h.field.equiv(crate::mcp_keys::HEADER))
            .map(|h| h.value.as_str().to_string());
        let Some(key) = key else {
            return Ok(request.respond(json_response(
                401,
                &json!({"error": "missing or wrong token; reopen the start URL"}),
            ))?);
        };
        let home = state.lock().unwrap().home.clone();
        let key = match crate::mcp_keys::check(&home, &key) {
            Ok(k) => k,
            Err(r) => {
                return Ok(request.respond(json_response(
                    401,
                    &json!({"error": match r {
                        crate::mcp_keys::Refused::Expired => "the MCP key has expired: create a new one with varsto mcp key create",
                        crate::mcp_keys::Refused::Unknown => "unknown or revoked MCP key",
                    }}),
                ))?);
            }
        };
        let mut body = String::new();
        if *request.method() == Method::Post {
            request
                .as_reader()
                .take(4 << 20)
                .read_to_string(&mut body)?;
        }
        let input: Value = serde_json::from_str(&body).unwrap_or(json!({}));
        let method = request.method().clone();
        let (status, v) = mcp_api(state, &key, method, &path, &query, &input);
        return Ok(request.respond(json_response(status, &v))?);
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
                let name = p.rsplit('/').next().unwrap_or("file");
                request.respond(
                    Response::from_data(bytes)
                        .with_header(header("Content-Type", "application/octet-stream"))
                        .with_header(header("Content-Disposition", &attachment(name))),
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
        // folder and pushes it, like /api/write for text. The body is streamed:
        // into a temporary file next to the target, or, in a folder kept
        // encrypted on this device, chunked and encrypted into the block cache
        // without holding the state while it arrives.
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        let result = match (folder, file) {
            (Some(f), Some(p)) => upload(state, &mut request, f, p),
            _ => Err(anyhow!("folder and path query parameters required")),
        };
        if let Some(too_big) = result
            .as_ref()
            .err()
            .and_then(|e| e.chain().find_map(|c| c.downcast_ref::<std::io::Error>()))
            .filter(|io| io.kind() == std::io::ErrorKind::FileTooLarge)
        {
            return Ok(request.respond(json_response(413, &json!({"error": too_big.to_string()})))?);
        }
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

/// A request made with an MCP key: checked against the key's scope, then
/// answered like any other, with folder lists cut to the key's folders.
fn mcp_api(
    state: &Shared,
    key: &crate::mcp_keys::McpKey,
    method: Method,
    path: &str,
    query: &str,
    input: &Value,
) -> (u16, Value) {
    use crate::mcp_keys::{allows, route, Need};
    let m = match method {
        Method::Get => "GET",
        Method::Post => "POST",
        _ => "",
    };
    let body_folder = input
        .get("folder")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let Some((need, folder)) = route(m, path, query_param(query, "folder"), body_folder) else {
        return (
            403,
            json!({"error": format!("an MCP key may not use {m} {path}")}),
        );
    };
    let mut st = state.lock().unwrap();
    // Folder names and Strongroom flags, by name and by id.
    let known: Vec<(String, String, bool)> = match st.engine.as_ref() {
        Some(e) => e
            .folders()
            .into_iter()
            .map(|(r, _)| (r.name.clone(), r.folder_id.to_string(), r.is_strongroom()))
            .collect(),
        None => return (503, json!({"error": "vault is locked"})),
    };
    if let Some(f) = &folder {
        let Some((name, _, strong)) = known.iter().find(|(n, id, _)| n == f || id == f) else {
            return (403, json!({"error": format!("no access to folder {f}")}));
        };
        if !allows(&key.scope, name, *strong, need) {
            let what = match need {
                Need::Read => "access to",
                Need::Analyse => "recording analyses in",
                Need::Write => "changes in",
            };
            return (
                403,
                json!({"error": format!("the MCP key {} does not allow {what} folder {name}", key.name)}),
            );
        }
    }
    if path == "/api/mcp/scope" {
        return (
            200,
            json!({"id": key.id, "name": key.name, "scope": key.scope}),
        );
    }
    let visible = |name: &str| {
        known
            .iter()
            .find(|(n, _, _)| n == name)
            .is_some_and(|(n, _, s)| allows(&key.scope, n, *s, Need::Read))
    };
    match api(&mut st, method, path, query, input) {
        Ok(mut v) => {
            let list = if path == "/api/folders" {
                Some(&mut v)
            } else if path == "/api/status" {
                v.get_mut("folders")
            } else {
                None
            };
            if let Some(a) = list.and_then(|l| l.as_array_mut()) {
                a.retain(|f| f["name"].as_str().is_some_and(visible));
            }
            (200, v)
        }
        Err(e) => (400, json!({"error": format!("{e:#}")})),
    }
}

/// Reads at most `left` bytes, then fails: an upload larger than allowed is
/// refused before anything of it is recorded.
struct Capped<R> {
    inner: R,
    left: u64,
    read: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("file larger than {} MiB", MAX_UPLOAD >> 20),
            ));
        }
        self.left -= n as u64;
        self.read += n as u64;
        Ok(n)
    }
}

/// `/api/upload`: stream the request body into `folder/path` and push.
fn upload(state: &Shared, request: &mut Request, folder: String, path: String) -> Result<Value> {
    let writer = {
        let st = state.lock().unwrap();
        match &st.engine {
            None => bail!("vault is locked"),
            Some(e) => e.block_writer(&folder)?,
        }
    };
    // Known for a file picked in the page or sent by the phone app: the
    // block sizes then follow the file size.
    let length = request.body_length().map(|n| n as u64);
    let mut body = Capped {
        inner: request.as_reader(),
        left: MAX_UPLOAD,
        read: 0,
    };
    let push = match writer {
        Some(w) => {
            let staged = w.write_sized(&mut body, length)?;
            let mut st = state.lock().unwrap();
            let e = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            e.commit_staged(&folder, &path, staged)?
        }
        None => {
            let mut st = state.lock().unwrap();
            let e = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            e.write_from_reader(&folder, &path, &mut body)?
        }
    };
    Ok(json!({"ok": true, "folder": folder, "path": path, "bytes": body.read, "push": push}))
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

/// A list of strings (absent: empty).
fn str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn opt(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
}

/// A backup schedule field: "daily", "weekly", "manual", or the form the
/// command line sends (`{"every_hours": N}`). Absent: none given.
fn backup_schedule(v: &Value) -> Result<Option<varsto_core::vault::BackupSchedule>> {
    use varsto_core::vault::BackupSchedule;
    Ok(match v.get("schedule") {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) => Some(match t.as_str() {
            "daily" => BackupSchedule::EveryHours(24),
            "weekly" => BackupSchedule::EveryHours(168),
            "manual" => BackupSchedule::Manual,
            other => return Err(anyhow!("unknown schedule {other}")),
        }),
        Some(other) => Some(serde_json::from_value(other.clone())?),
    })
}

/// A list field: a JSON array of strings, or one comma-separated string.
fn string_list(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(t)) => t
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
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

/// The storage a joining device reaches the vault through, from a setup
/// form: a directory (`storage_path`), or an S3-compatible bucket when
/// `kind` is "s3" or a bucket is given. Returns the spec and the S3 secret.
fn storage_from_input(
    input: &Value,
    storage_name: &str,
    default_place: &str,
) -> Result<(StorageSpec, Option<String>)> {
    let kind = opt(input, "kind").unwrap_or_default();
    if kind == "s3" || (kind.is_empty() && opt(input, "bucket").is_some_and(|b| !b.is_empty())) {
        let secret = s(input, "secret_access_key")?;
        return Ok((
            StorageSpec::S3 {
                name: storage_name.to_string(),
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
                place: opt(input, "place").unwrap_or_else(|| default_place.into()),
            },
            Some(secret),
        ));
    }
    Ok((
        StorageSpec::LocalDir {
            name: storage_name.to_string(),
            path: PathBuf::from(s(input, "storage_path")?),
            cold: false,
            carrier: false,
            place: String::new(),
        },
        None,
    ))
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

/// The S3-compatible providers in the built-in price data, for the Add
/// storage form: endpoints per region and headline prices with their sources.
fn providers_json(now: i64) -> Value {
    json!({
        "providers": varsto_core::providers::s3_providers(now),
        "stale_after_days": varsto_core::providers::STALE_AFTER_DAYS,
    })
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
        // Phones make video frames with their own media framework.
        (Method::Get, "/api/thumbnails/wanted") => {
            let e = st
                .engine
                .as_ref()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            let list: Vec<Value> = e
                .videos_without_thumbnails(20)?
                .into_iter()
                .map(|(folder, path, disk)| json!({"folder": folder, "path": path, "file": disk}))
                .collect();
            Ok(json!({ "videos": list }))
        }
        (Method::Post, "/api/thumbnail") => {
            use base64::Engine as _;
            let picture = base64::engine::general_purpose::STANDARD
                .decode(s(input, "jpeg")?)
                .map_err(|_| anyhow!("jpeg is not base64"))?;
            let folder = s(input, "folder")?;
            let path = s(input, "path")?;
            st.engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?
                .store_thumbnail(&folder, &path, &picture)?;
            Ok(json!({"ok": true}))
        }
        (Method::Get, "/api/ui-language") => Ok(json!({"language": ui_language(&st.home)})),
        (Method::Get, "/api/providers") => Ok(providers_json(varsto_core::util::now_utc())),
        (Method::Post, "/api/ui-language") => {
            let l = s(input, "language")?;
            if !matches!(l.as_str(), "en" | "fi" | "sv") {
                bail!("unknown language {l}");
            }
            std::fs::create_dir_all(&st.home)?;
            std::fs::write(st.home.join("ui-language"), &l)?;
            Ok(json!({"ok": true, "language": l}))
        }
        (Method::Post, "/api/service/restart") => {
            st.service.restart_requested = true;
            Ok(json!({"ok": true}))
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
            // The keys go. Folders kept "encrypted on this device" hold only
            // encrypted blocks; the decrypted copies handed to other apps go.
            st.engine = None;
            st.pair = None;
            let exports = Engine::clear_exports(&st.home);
            Ok(json!({"ok": true, "exports_removed": exports}))
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
            let name = opt(input, "name").filter(|n| !n.trim().is_empty());
            let code = varsto_core::vault::ShareRequest::code_for_named(&st.home, name.as_deref())?;
            Ok(json!({
                "request_code": code,
                "fingerprint": varsto_core::vault::ShareRequest::fingerprint_for(&st.home)?,
            }))
        }
        // Organization: a request code for this device, and joining with an approval token.
        (Method::Post, "/api/org/request") => {
            let name = s(input, "name")?;
            let code = varsto_core::org::OrgRequest::code_for(&st.home, Some(&name))?;
            Ok(json!({
                "request_code": code,
                "fingerprint": varsto_core::org::OrgRequest::fingerprint_for(&st.home)?,
            }))
        }
        (Method::Post, "/api/org/join") => {
            let (e, notes, approval) = Engine::org_join(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &s(input, "token")?,
            )?;
            st.engine = Some(e);
            st.service.request_sync();
            Ok(
                json!({"ok": true, "organization": approval.org_name, "user": approval.user, "notes": notes}),
            )
        }
        (Method::Post, "/api/share/accept") => {
            let raw = s(input, "token")?;
            let token = if varsto_core::vault::SealedShareToken::is_sealed(&raw) {
                varsto_core::vault::ShareRequest::open_token(&st.home, &raw)?
            } else {
                varsto_core::vault::ShareToken::decode(&raw)?
            };
            let storage_name = opt(input, "storage_name")
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "shared".into());
            let (spec, secret) = storage_from_input(input, &storage_name, "")?;
            let e = Engine::accept_share_with_secret(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &token,
                spec,
                secret,
            )?;
            st.engine = Some(e);
            varsto_core::vault::ShareRequest::clear(&st.home);
            Ok(json!({"ok": true, "folder": token.name, "fingerprint": token.fingerprint}))
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
            let joined = Engine::join(
                &st.home,
                &s(input, "name")?,
                &s(input, "passphrase")?,
                &key,
                spec,
            );
            // The secret was needed only while the storage was opened
            // before the vault existed; children must not inherit it.
            std::env::remove_var(format!(
                "VARSTO_S3_SECRET_{}",
                storage_name
                    .to_uppercase()
                    .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
            ));
            let mut e = joined?;
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

/// The interface asks for long work to run in the background service.
fn background(input: &Value) -> bool {
    input
        .get("background")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
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
        // The fingerprint of a request code, shown before the token is sealed.
        (Method::Post, "/api/share/fingerprint") => {
            let r = Engine::share_request_info(&s(input, "code")?)?;
            Ok(json!({"fingerprint": r.fingerprint, "name": r.name}))
        }
        (Method::Post, "/api/share/create") => {
            let folder = s(input, "folder")?;
            let role = match opt(input, "role").filter(|r| !r.trim().is_empty()) {
                Some(r) => varsto_core::share::ShareRole::parse(&r)?,
                None => varsto_core::share::ShareRole::Editor,
            };
            match opt(input, "to").filter(|c| !c.trim().is_empty()) {
                Some(code) => {
                    // The interface sends the words the user confirmed; they
                    // must be the code's.
                    let confirmed = opt(input, "fingerprint").filter(|f| !f.trim().is_empty());
                    let (sealed, req) =
                        engine.share_create_sealed_as(&folder, &code, confirmed.as_deref(), role)?;
                    Ok(json!({"ok": true, "token": sealed.encode(), "folder": sealed.name, "sealed": true, "fingerprint": req.fingerprint, "name": req.name, "role": role.as_str()}))
                }
                None if !role.is_editor() => {
                    bail!("a viewer's token must be sealed to their request code: paste it (a plain token cannot say what its holder may do)")
                }
                None => {
                    let t = engine.share_create_plain(&folder)?;
                    Ok(json!({"ok": true, "token": t.encode_plain()?, "folder": t.name, "sealed": false}))
                }
            }
        }
        (Method::Get, "/api/share/members") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.share_members(&folder)?)?)
        }
        (Method::Post, "/api/share/role") => {
            let role = varsto_core::share::ShareRole::parse(&s(input, "role")?)?;
            let r = engine.share_set_role(&s(input, "folder")?, &s(input, "member")?, role)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/share/revoke") => {
            // Like removing a device: the caller must confirm explicitly.
            if !input.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false) {
                bail!("removing a member needs \"confirm\": true");
            }
            let r = engine.share_revoke(&s(input, "folder")?, &s(input, "member")?)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        // The recovery package checklist: structured sentences ({t, p}) the
        // interface translates, or the English text for "Download as text".
        (Method::Get, "/api/recovery/guide") => {
            let guide = engine.recovery_guide();
            Ok(match query_param(query, "format").as_deref() {
                Some("text") => json!({ "text": varsto_core::recovery_guide::render_text(&guide) }),
                _ => serde_json::to_value(guide)?,
            })
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
        // Organization (section 27). Nothing here exists for a vault without one.
        (Method::Get, "/api/org") => Ok(match engine.org_summary() {
            Some(s) => serde_json::to_value(s)?,
            None => json!({"exists": false}),
        }),
        (Method::Get, "/api/org/log") => Ok(json!({"log": engine.org_log_entries()})),
        (Method::Post, "/api/org/create") => {
            let r = engine.org_create(&s(input, "name")?, &s(input, "user")?)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/org/fingerprint") => {
            let r = varsto_core::org::OrgRequest::parse(&s(input, "code")?)?;
            Ok(json!({"fingerprint": r.fingerprint, "name": r.name, "device_id": r.device.to_string(), "platform": r.platform}))
        }
        (Method::Post, "/api/org/approve") => {
            let fp = opt(input, "fingerprint").filter(|f| !f.trim().is_empty());
            let r = engine.org_approve(&s(input, "code")?, &s(input, "user")?, fp.as_deref())?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/org/add-device") => {
            engine.org_add_device(&s(input, "device")?, &s(input, "user")?)?;
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/org/remove-user") => {
            let user = s(input, "user")?;
            if opt(input, "confirm").as_deref() != Some(user.as_str()) {
                bail!("send {{\"confirm\": \"{user}\"}} to remove this user and every device of theirs");
            }
            let wipe = input.get("wipe").and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.org_remove_user(&user, wipe)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/org/policy") => {
            let p: varsto_core::org::OrgPolicy = serde_json::from_value(input.clone())?;
            engine.org_set_policy(p)?;
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/org/admin") => {
            let device = s(input, "device")?;
            let words = s(input, "root_words")?;
            match s(input, "action")?.as_str() {
                "add" => engine.org_admin_add(&device, &words)?,
                "remove" => engine.org_admin_remove(&device, &words)?,
                other => bail!("unknown action {other}: use add or remove"),
            }
            service.request_sync();
            Ok(json!({"ok": true}))
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
        (Method::Post, "/api/storage/carrier-for") => {
            let names = engine.set_carrier_for(&s(input, "name")?, &string_list(input, "devices"))?;
            Ok(json!({"ok": true, "devices": names}))
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
                    copies: input
                        .get("copies")
                        .and_then(|c| c.as_u64().or_else(|| c.as_str()?.trim().parse().ok()))
                        .unwrap_or(1)
                        .clamp(1, 16) as u32,
                    verify_after_days: varsto_core::pool::DEFAULT_VERIFY_AFTER_DAYS,
                })?,
                _ => {
                    let name = s(input, "name")?;
                    engine.add_storage(StorageSpec::LocalDir {
                        name: name.clone(),
                        path: PathBuf::from(s(input, "path")?),
                        cold,
                        carrier,
                        place: opt(input, "place").unwrap_or_default(),
                    })?;
                    let targets = string_list(input, "carrier_for");
                    if carrier && !targets.is_empty() {
                        engine.set_carrier_for(&name, &targets)?;
                    }
                }
            }
            service.request_sync();
            // The sync this starts copies everything to the new storage and
            // holds the service meanwhile: the page shows this answer at once.
            Ok(json!({"ok": true, "status": engine.status()?}))
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
        (Method::Get, "/api/import/status") => {
            Ok(serde_json::to_value(engine.import_status(None)?)?)
        }
        (Method::Post, "/api/import/dir") => {
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
            let source = PathBuf::from(s(input, "source")?);
            let dest = opt(input, "dest")
                .filter(|p| !p.trim().is_empty())
                .map(PathBuf::from);
            let opts = varsto_core::engine::ImportOptions {
                folder: opt(input, "folder").filter(|f| !f.trim().is_empty()),
                selective: dest.is_none() || flag("selective"),
                dest,
                dry_run: false,
                remove_source: flag("remove_source"),
                no_verify: false,
                default_parent: Some(folder_root(engine.home())),
            };
            let mut src = varsto_core::import::dir::DirSource::open(&source)?;
            let mut r = engine.import_run(&mut src, &opts)?;
            if opts.remove_source {
                r.cleanup = Some(engine.import_cleanup(&r.folder, false)?);
            }
            service.folders_changed = true;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/import/cleanup") => {
            let apply = input.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(serde_json::to_value(
                engine.import_cleanup(&s(input, "folder")?, apply)?,
            )?)
        }
        (Method::Post, "/api/folder/detach") => {
            engine.detach_folder(&s(input, "name")?)?;
            service.folders_changed = true;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/folder/remove") => {
            let purge = input.get("purge").and_then(|v| v.as_bool()).unwrap_or(false);
            let deleted = engine.remove_folder(&s(input, "name")?, purge)?;
            service.folders_changed = true;
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
            let id = engine.attach_folder(&name_or_id, &path, selective)?;
            if !plain {
                engine.set_encrypted_here(&name_or_id, true)?;
            }
            service.folders_changed = true;
            service.request_sync();
            Ok(json!({"ok": true, "id": id.to_string()}))
        }
        // Backups: snapshots of a directory of this device, on storages only.
        (Method::Get, "/api/backups") => Ok(serde_json::to_value(engine.backups()?)?),
        (Method::Get, "/api/backup/snapshots") => {
            let backup = query_param(query, "backup")
                .ok_or_else(|| anyhow!("backup query parameter required"))?;
            Ok(serde_json::to_value(engine.backup_snapshots(&backup)?)?)
        }
        (Method::Post, "/api/backup") => {
            let name = s(input, "name")?;
            let path = PathBuf::from(s(input, "path")?);
            let mut placement: Option<varsto_core::placement::Placement> = match input.get("placement") {
                Some(p) if !p.is_null() => Some(serde_json::from_value(p.clone())?),
                _ => None,
            };
            let storages = string_list(input, "storages");
            if !storages.is_empty() {
                placement = Some(varsto_core::placement::Placement {
                    storages,
                    ..Default::default()
                });
            }
            let opts = varsto_core::engine::BackupOptions {
                retention_days: input
                    .get("retention_days")
                    .and_then(|v| v.as_u64())
                    .map(|d| d.min(u32::MAX as u64) as u32)
                    .unwrap_or(varsto_core::vault::DEFAULT_BACKUP_RETENTION_DAYS),
                schedule: backup_schedule(input)?.unwrap_or_default(),
                placement,
            };
            let id = engine.add_backup(&name, &path, opts)?;
            let initial = input.get("initial").and_then(|v| v.as_bool()).unwrap_or(true);
            // `background`: the interface does not wait for a first snapshot
            // of a large directory; the service takes it on its next run.
            if initial && background(input) {
                engine.request_snapshot(id.as_str())?;
                service.request_sync();
                return Ok(json!({"ok": true, "id": id.to_string(), "snapshot": null, "queued": true}));
            }
            let snapshot = if initial { Some(engine.take_snapshot(id.as_str())?) } else { None };
            Ok(json!({"ok": true, "id": id.to_string(), "snapshot": snapshot}))
        }
        (Method::Post, "/api/backup/take") => {
            let backup = s(input, "backup")?;
            if background(input) {
                engine.request_snapshot(&backup)?;
                service.request_sync();
                return Ok(json!({"ok": true, "backup": backup, "queued": true}));
            }
            Ok(serde_json::to_value(engine.take_snapshot(&backup)?)?)
        }
        (Method::Post, "/api/backup/restore") => {
            let pick = varsto_core::engine::SnapshotPick::parse(
                &opt(input, "snapshot").unwrap_or_else(|| "latest".to_string()),
            )?;
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.restore_snapshot(
                &s(input, "backup")?,
                pick,
                &PathBuf::from(s(input, "to")?),
                &string_list(input, "paths"),
                flag("overwrite"),
                flag("confirm_cold_read"),
            )?;
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/backup/set") => {
            let days = input
                .get("retention_days")
                .and_then(|v| v.as_u64())
                .map(|d| d.min(u32::MAX as u64) as u32);
            engine.set_backup(&s(input, "backup")?, days, backup_schedule(input)?)?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/backup/stop") => {
            engine.stop_backup(&s(input, "backup")?)?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/backup/expire") => {
            let r = engine.backup_upkeep()?;
            service.record_backup_upkeep(&r);
            Ok(serde_json::to_value(r)?)
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
            let report = engine.fsck(verify)?;
            let mut out = serde_json::to_value(&report)?;
            if input
                .get("repair")
                .and_then(|c| c.as_bool())
                .unwrap_or(false)
                && report.repairs_queued > 0
            {
                let mut opts = varsto_core::engine::RepairOptions::manual();
                opts.scan = false;
                out["repair"] = serde_json::to_value(engine.repair(&opts)?)?;
            }
            service.repair = Some(engine.repair_status());
            Ok(out)
        }
        (Method::Get, "/api/repair") => Ok(serde_json::to_value(engine.repair_status())?),
        (Method::Post, "/api/repair") => {
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool());
            let mut opts = varsto_core::engine::RepairOptions::manual();
            opts.dry_run = flag("dry_run").unwrap_or(false);
            opts.from_cold = flag("from_cold").unwrap_or(false);
            opts.scan = flag("scan").unwrap_or(true);
            let r = engine.repair(&opts)?;
            service.repair = Some(engine.repair_status());
            if let Ok(reps) = engine.policy_check() {
                service.record_policies(reps);
            }
            Ok(json!({"report": r, "status": engine.repair_status()}))
        }
        (Method::Get, "/api/ledger") => Ok(serde_json::to_value(engine.ledger_entries()?)?),
        (Method::Get, "/api/ledger/health") => Ok(serde_json::to_value(engine.ledger_health())?),
        (Method::Get, "/api/ledger/status") => {
            let r = engine.ledger_status(true)?;
            service.ledger_health = Some(r.health.clone());
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/ledger/rebuild") => {
            // The interface's button and `varsto ledger rebuild` while the
            // service runs: the same safe restore the service runs by itself.
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool());
            let opts = varsto_core::engine::LedgerRebuildOptions {
                from_storage: flag("from_storage").unwrap_or(false),
                verify: flag("verify"),
                verify_budget_bytes: input
                    .get("verify_budget_mib")
                    .and_then(|v| v.as_u64())
                    .map(|m| m.saturating_mul(1 << 20))
                    .unwrap_or(varsto_core::engine::LedgerRebuildOptions::default().verify_budget_bytes),
                confirm_cold_read: flag("confirm_cold_read").unwrap_or(false),
                automatic: false,
            };
            let r = engine.ledger_rebuild(&opts);
            service.ledger_health = Some(engine.ledger_health());
            let r = r?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Get, "/api/files") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.list_files_with_pending(&folder)?)?)
        }
        (Method::Post, "/api/fetch") => {
            // A large fetch whose blocks are on pool disks: return the plan
            // for the interface to run disk by disk (`/api/fetch/plan/*`),
            // unless it asks for the network.
            let (folder, path) = (s(input, "folder")?, s(input, "path")?);
            if opt(input, "from").as_deref() != Some("network")
                && engine.disks().is_ok_and(|d| !d.is_empty())
            {
                let plan = engine.fetch_plan(&folder, std::slice::from_ref(&path))?;
                if plan.recommend == "disks" {
                    return Ok(json!({ "plan": plan }));
                }
                engine.cancel_fetch_plan()?;
            }
            match engine.fetch_file(&folder, &path) {
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
        (Method::Get, "/api/fetch/plan") => Ok(json!({ "plan": engine.load_fetch_plan() })),
        // The disk of step `step` was inserted: mount it, copy its blocks,
        // write the files that are complete, then sync, unmount and power
        // it off. A disk that is not there is answered with `needs_disk`.
        (Method::Post, "/api/fetch/plan/step") => {
            let k = input.get("step").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let mut plan = engine
                .load_fetch_plan()
                .ok_or_else(|| anyhow!("no fetch plan is running"))?;
            let step = plan
                .steps
                .get(k)
                .cloned()
                .ok_or_else(|| anyhow!("the plan has no step {}", k + 1))?;
            if !step.attached {
                if let Err(e) = crate::drive_mount::mount_known(engine.home(), &step.label) {
                    if let Some(stop) = e.downcast_ref::<varsto_core::blockdev::FsckStopped>() {
                        return Ok(json!({"fsck_failed": stop.outcome, "error": stop.message}));
                    }
                    return Ok(json!({"needs_disk": {"label": step.label, "disk_id": step.disk_id, "place": step.place}, "error": format!("{e:#}")}));
                }
            }
            let (out, mount) = match engine.fetch_plan_step(&mut plan, k) {
                Ok(r) => r,
                Err(e) => {
                    return match varsto_core::pool::pool_error(&e) {
                        Some(varsto_core::pool::PoolError::NeedsDisk { label, disk_id, place }) => Ok(json!({
                            "needs_disk": {"label": label, "disk_id": disk_id, "place": place},
                            "error": e.to_string(),
                        })),
                        _ => Err(e),
                    };
                }
            };
            let unmount = if step.attached {
                Vec::new()
            } else {
                crate::drive_mount::release_mount(&mount)?
            };
            let mut files_done = out.files_done.clone();
            if !plan.steps.iter().any(|s| s.state == "pending") {
                files_done.extend(engine.fetch_plan_write_ready(&mut plan, true)?);
            }
            let finished = plan.files.iter().all(|f| f.done);
            Ok(json!({"outcome": out, "unmount": unmount, "plan": plan, "finished": finished, "files_done": files_done}))
        }
        // Skip a disk (its blocks come from the network), or give up on the
        // disks altogether and fetch the rest from the network.
        (Method::Post, "/api/fetch/plan/skip") | (Method::Post, "/api/fetch/plan/network") => {
            let mut plan = engine
                .load_fetch_plan()
                .ok_or_else(|| anyhow!("no fetch plan is running"))?;
            let all = path.ends_with("/network");
            for (i, st) in plan.steps.clone().iter().enumerate() {
                let this = input.get("step").and_then(|v| v.as_u64()) == Some(i as u64);
                if st.state == "pending" && (all || this) {
                    engine.fetch_plan_skip(&mut plan, i)?;
                }
            }
            let mut files_done = Vec::new();
            if !plan.steps.iter().any(|s| s.state == "pending") {
                files_done = engine.fetch_plan_write_ready(&mut plan, true)?;
            }
            let failed: Vec<Value> = plan
                .files
                .iter()
                .filter(|f| f.error.is_some() && !f.done)
                .map(|f| json!({"path": f.path, "error": f.error}))
                .collect();
            let finished = plan.files.iter().all(|f| f.done);
            Ok(json!({"plan": plan, "finished": finished, "files_done": files_done, "files_failed": failed}))
        }
        (Method::Post, "/api/fetch/plan/cancel") => {
            engine.cancel_fetch_plan()?;
            Ok(json!({"ok": true}))
        }
        // A decrypted copy for another app (phones: open in / share with), on
        // the user's explicit request; removed when the vault locks.
        (Method::Post, "/api/export") => {
            let path = engine.export_file(&s(input, "folder")?, &s(input, "path")?)?;
            Ok(json!({"ok": true, "path": path}))
        }
        // Every disk with its bookkeeping (space, reclaimable, check ages, fsck).
        (Method::Get, "/api/disks") => Ok(serde_json::to_value(engine.disk_report()?)?),
        // The next disk to dock, ranked with reasons, and the reminder setting.
        (Method::Get, "/api/disk/suggest") => {
            let pool = query_param(query, "pool");
            let s = engine.disk_suggestions_for(pool.as_deref())?;
            if pool.is_none() {
                service.disk_suggest = Some(s.clone());
            }
            Ok(json!({"suggestions": s, "settings": engine.disk_suggest_settings()}))
        }
        (Method::Post, "/api/disk/suggest/settings") => {
            let mut st = engine.disk_suggest_settings();
            if let Some(v) = input.get("notify_overdue").and_then(|v| v.as_bool()) {
                st.notify_overdue = v;
            }
            engine.set_disk_suggest_settings(st.clone())?;
            Ok(json!({"ok": true, "settings": st}))
        }
        (Method::Post, "/api/disk/add") => {
            let r = engine.disk_add_at(
                std::path::Path::new(&s(input, "mount")?),
                &s(input, "pool")?,
                &s(input, "label")?,
                &opt(input, "place").unwrap_or_default(),
            )?;
            service.request_sync();
            service.suggest_disks(engine);
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/disk/check") => {
            let full = input.get("full").and_then(|c| c.as_bool()).unwrap_or(false);
            let r = engine.disk_check(&s(input, "label")?, full)?;
            service.request_sync();
            service.suggest_disks(engine);
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/disk/eject") => {
            let label = s(input, "label")?;
            let mount = engine.disk_eject(&label)?;
            service.suggest_disks(engine);
            Ok(json!({"ok": true, "label": label, "mount": mount, "safe_to_remove": true, "message": format!("{label}: index written and synced; safe to remove")}))
        }
        (Method::Post, "/api/disk/retire") => {
            let label = s(input, "label")?;
            let only_here = engine.disk_retire(&label)?;
            service.suggest_disks(engine);
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
        // Re-key: the command line unlocked the folder and wrapped the new
        // key for every enrolled security key; the re-encryption runs here.
        (Method::Post, "/api/strongroom/rekey") => {
            let folder = s(input, "folder")?;
            let id = varsto_core::ids::FolderId::from_hex(&s(input, "folder_id")?)?;
            let key = varsto_core::crypto::SecretKey::from_hex(&s(input, "key_hex")?)?;
            let info: varsto_core::strongroom::StrongroomInfo = serde_json::from_value(input.get("info").cloned().unwrap_or_default())?;
            let minutes = input.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15).clamp(1, 24 * 60);
            engine.unlock_strongroom_with_key(&folder, &s(input, "old_key_hex")?, minutes)?;
            let r = engine.rekey_strongroom_with(&folder, &id, &key, info, minutes)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
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
            let was = (c.enabled, c.port, c.public_addrs.clone(), c.stun.clone());
            if let Some(en) = input.get("enabled").and_then(|v| v.as_bool()) {
                c.enabled = en;
                c.user_disabled = !en;
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
            let same_settings = was.1 == c.port && was.2 == c.public_addrs && was.3 == c.stun;
            engine.set_p2p_config(c)?;
            if enabled {
                engine.p2p_identity()?;
            }
            // Turning it on or off takes effect within a second; a new
            // port, address or STUN list when the service starts again.
            let note = if same_settings || !was.0 || !enabled {
                if enabled { "peer-to-peer is on" } else { "peer-to-peer is off" }
            } else {
                "saved; the new port, addresses or STUN servers apply when the background service starts again"
            };
            Ok(json!({"ok": true, "applied": same_settings || !was.0 || !enabled, "note": note}))
        }
        (Method::Get, "/api/policy") => Ok(json!({
            "policies": engine.folders().into_iter().map(|(r, _)| json!({"folder": r.name, "policy": r.effective_policy(), "default": r.policy.is_none(), "text": r.effective_policy().map(|p| p.describe())})).collect::<Vec<_>>(),
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
        // File analyses (`engine::notes`): what a file contains, recorded by
        // an assistant through MCP or by the user.
        (Method::Get, "/api/analysis") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            let path = query_param(query, "path")
                .ok_or_else(|| anyhow!("path query parameter required"))?;
            Ok(json!({"analysis": engine.analysis(&folder, &path)?}))
        }
        (Method::Get, "/api/analyses") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.analyses(&folder)?)?)
        }
        (Method::Post, "/api/analysis") => {
            let text = input
                .get("analysis")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing field analysis"))?;
            Ok(serde_json::to_value(engine.set_analysis(
                &s(input, "folder")?,
                &s(input, "path")?,
                text,
                &str_list(input, "tags"),
                opt(input, "by").as_deref(),
            )?)?)
        }
        (Method::Post, "/api/analysis/clear") => Ok(json!({
            "cleared": engine.clear_analysis(&s(input, "folder")?, &s(input, "path")?)?
        })),
        (Method::Post, "/api/analysis/search") => {
            let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
            Ok(serde_json::to_value(engine.search_analyses(
                &s(input, "folder")?,
                query,
                &str_list(input, "tags"),
            )?)?)
        }
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
        // Data placement: where each folder is written, moving blocks, disk groups.
        (Method::Get, "/api/placement") => {
            let mut out = Vec::new();
            for (r, _) in engine.folders() {
                out.push(serde_json::to_value(engine.placement(r.folder_id.as_str())?)?);
            }
            Ok(json!({
                "folders": out,
                "storages": engine.storages().iter().map(|s| json!({
                    "name": s.name(), "place": s.place(), "cold": s.is_cold(), "carrier": s.is_carrier(),
                })).collect::<Vec<_>>(),
            }))
        }
        (Method::Post, "/api/placement") => {
            let folder = s(input, "folder")?;
            let storages = string_list(input, "storages");
            let places = string_list(input, "places");
            let every = input.get("every").and_then(|v| v.as_bool()).unwrap_or(false);
            let info = if every || (storages.is_empty() && places.is_empty()) {
                engine.set_placement(&folder, None)?
            } else {
                engine.set_placement(
                    &folder,
                    Some(varsto_core::placement::Placement {
                        storages,
                        places,
                        ..Default::default()
                    }),
                )?
            };
            service.request_sync();
            Ok(serde_json::to_value(info)?)
        }
        (Method::Post, "/api/data/move") => {
            let req = varsto_core::placement::MoveRequest {
                folder: s(input, "folder")?,
                from: s(input, "from")?,
                to: s(input, "to")?,
                idle_days: input.get("idle_days").and_then(|v| v.as_i64()),
                dry_run: input.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false),
                confirm_cold_read: input
                    .get("confirm_cold_read")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            let r = engine.move_data(&req)?;
            if !req.dry_run {
                service.request_sync();
            }
            Ok(serde_json::to_value(r)?)
        }
        (Method::Get, "/api/disk/groups") => Ok(serde_json::to_value(engine.disk_groups()?)?),
        (Method::Post, "/api/disk/group") => {
            let copies = input
                .get("copies")
                .and_then(|c| c.as_u64().or_else(|| c.as_str()?.trim().parse().ok()))
                .ok_or_else(|| anyhow!("copies is required"))?;
            engine.set_pool_copies(&s(input, "pool")?, copies.min(16) as u32)?;
            Ok(serde_json::to_value(engine.disk_groups()?)?)
        }
        (Method::Post, "/api/disk/place") => {
            engine.set_disk_place(&s(input, "label")?, &opt(input, "place").unwrap_or_default())?;
            Ok(serde_json::to_value(engine.disk_groups()?)?)
        }
        (Method::Get, "/api/data/locations") => Ok(serde_json::to_value(engine.data_locations()?)?),
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
            service.repair_if_due(engine);
            if let Ok(reps) = engine.policy_check() {
                service.record_policies(reps);
            }
            Ok(json!({"report": r, "status": engine.verify_status()}))
        }
        (Method::Get, "/api/restic") => {
            let quick = varsto_core::engine::CheckOptions {
                quick: true,
                ..Default::default()
            };
            let c = engine.restic_check(&quick);
            varsto_core::restic::status_value(engine.home(), Some(c))
        }
        (Method::Post, "/api/restic/setup") => {
            let cfg: varsto_core::restic::ResticConfig = serde_json::from_value(
                input
                    .get("config")
                    .cloned()
                    .ok_or_else(|| anyhow!("config missing"))?,
            )?;
            let names: Option<Vec<String>> =
                serde_json::from_value(input.get("folders").cloned().unwrap_or(Value::Null))?;
            let mv = input.get("move").and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.restic_setup(cfg, names.as_deref(), mv)?;
            service.folders_changed = true;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/restic/hold") => {
            // Taken while this request holds the engine: no sync of the
            // mirror is under way once it answers.
            let token = opt(input, "token").ok_or_else(|| anyhow!("token missing"))?;
            let pid = input
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("pid missing"))? as u32;
            Ok(json!({"held": engine.restic_hold(&token, pid)?}))
        }
        (Method::Post, "/api/restic/check") => {
            let opts: varsto_core::engine::CheckOptions = serde_json::from_value(input.clone())?;
            Ok(serde_json::to_value(engine.restic_check(&opts)?)?)
        }
        (Method::Get, "/api/scrub") => Ok(serde_json::to_value(engine.scrub_status())?),
        (Method::Post, "/api/scrub") => {
            let mut sched = engine.scrub_schedule().clone();
            let num = |k: &str| input.get(k).and_then(|v| v.as_u64());
            if let Some(v) = input.get("enabled").and_then(|v| v.as_bool()) {
                sched.enabled = v;
            }
            if let Some(v) = num("interval_hours") {
                sched.interval_hours = v as u32;
            }
            if let Some(v) = num("scrub_days") {
                sched.scrub_days = v as u32;
            }
            if let Some(v) = num("local_mib") {
                sched.max_local_bytes = v.saturating_mul(1024 * 1024);
            }
            if let Some(v) = num("remote_mib") {
                sched.max_remote_bytes = v.saturating_mul(1024 * 1024);
            }
            engine.set_scrub_schedule(sched)?;
            // {"cold": {"deep": true}} with "confirm_cold_read": true.
            if let Some(cold) = input.get("cold").and_then(|c| c.as_object()) {
                let confirmed = input
                    .get("confirm_cold_read")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                for (name, on) in cold {
                    engine.set_scrub_cold(name, on.as_bool().unwrap_or(false), confirmed)?;
                }
            }
            service.scrub = Some(engine.scrub_status());
            Ok(serde_json::to_value(engine.scrub_status())?)
        }
        (Method::Post, "/api/scrub/run") => {
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
            let opts = varsto_core::engine::ScrubOptions {
                storages: input
                    .get("storages")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                local: flag("local"),
                full: flag("full"),
                include_cold: flag("include_cold") && flag("confirm_cold_read"),
                scheduled: false,
            };
            let r = engine.scrub(&opts)?;
            service.scrub = Some(engine.scrub_status());
            service.repair_if_due(engine);
            Ok(json!({"report": r, "status": engine.scrub_status()}))
        }
        (Method::Post, "/api/paths") => {
            // Finder and other file managers: act on absolute paths, one result each.
            let action = s(input, "action")?;
            let paths: Vec<String> = input
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            // One ledger batch for the whole selection.
            let results = crate::filemanager::act(engine, &action, paths)?;
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
            // Turned off: the next sync downloads the placeholders.
            service.request_sync();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_api_lists_bookkeeping_and_suggests_the_next_disk() {
        use varsto_core::pool::{self, DiskSpace};
        use varsto_core::storage::StorageSpec;
        const GIB: u64 = 1 << 30;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mounts = root.join("mounts");
        let disk = mounts.join("blue");
        std::fs::create_dir_all(&disk).unwrap();
        pool::set_fake_space(
            &disk,
            Some(DiskSpace {
                free: 60 * GIB,
                total: 100 * GIB,
            }),
        );
        let (mut engine, _) = Engine::init(&root.join("home"), "laptop", "pass phrase").unwrap();
        engine
            .add_storage(StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("box"),
                cold: false,
                carrier: false,
                place: String::new(),
            })
            .unwrap();
        engine
            .add_storage(StorageSpec::Pool {
                name: "shelf".into(),
                place: "home".into(),
                reserve_percent: 5,
                min_reserve_bytes: 2 * GIB,
                disks: vec![],
                scan_roots: vec![mounts.clone()],
                copies: 1,
                verify_after_days: 180,
            })
            .unwrap();
        let mut service = ServiceState::default();
        let call = |engine: &mut Engine,
                    service: &mut ServiceState,
                    m: Method,
                    path: &str,
                    query: &str,
                    input: Value| {
            api_unlocked(engine, service, m, path, query, &input).unwrap()
        };
        call(
            &mut engine,
            &mut service,
            Method::Post,
            "/api/disk/add",
            "",
            json!({"mount": disk, "pool": "shelf", "label": "Blue 4TB"}),
        );
        // Adding a disk recomputes the suggestions in the service state.
        let cached = service
            .disk_suggest
            .clone()
            .expect("recomputed after the add");
        assert_eq!(cached.attached[0].label, "Blue 4TB");
        assert!(service.summary()["disk_suggest"]["attached"].is_array());

        let disks = call(
            &mut engine,
            &mut service,
            Method::Get,
            "/api/disks",
            "",
            json!({}),
        );
        let d = &disks[0];
        for k in [
            "free_bytes",
            "capacity_bytes",
            "used_bytes",
            "reserve_bytes",
            "space_measured_utc",
            "reclaimable_bytes",
            "pending_delete_bytes",
            "oldest_check_utc",
            "copies_overdue",
            "overdue_share",
            "only_copy_objects",
            "lacking_bytes",
            "fill_potential_bytes",
            "repair_objects",
            "fetch_objects",
            "fsck",
            "last_seen_utc",
            "failing",
        ] {
            assert!(d.get(k).is_some(), "/api/disks lacks {k}: {d}");
        }
        assert_eq!(d["free_bytes"], json!(60 * GIB));
        assert_eq!(d["reserve_bytes"], json!(5 * GIB));
        assert_eq!(d["only_copy_objects"], json!(0));

        let r = call(
            &mut engine,
            &mut service,
            Method::Get,
            "/api/disk/suggest",
            "",
            json!({}),
        );
        assert_eq!(r["settings"]["notify_overdue"], json!(true));
        assert!(
            r["suggestions"]["top"].is_null(),
            "an attached disk is not docked: {r}"
        );
        assert_eq!(
            r["suggestions"]["attached"][0]["command"],
            json!("varsto disk insert \"Blue 4TB\"")
        );
        let r = call(
            &mut engine,
            &mut service,
            Method::Get,
            "/api/disk/suggest",
            "pool=shelf",
            json!({}),
        );
        assert_eq!(r["suggestions"]["attached"].as_array().unwrap().len(), 1);
        assert!(api_unlocked(
            &mut engine,
            &mut service,
            Method::Get,
            "/api/disk/suggest",
            "pool=none",
            &json!({})
        )
        .is_err());
        let r = call(
            &mut engine,
            &mut service,
            Method::Post,
            "/api/disk/suggest/settings",
            "",
            json!({"notify_overdue": false}),
        );
        assert_eq!(r["settings"]["notify_overdue"], json!(false));
        assert!(!engine.disk_suggest_settings().notify_overdue);

        // Retired: listed apart with a warning.
        call(
            &mut engine,
            &mut service,
            Method::Post,
            "/api/disk/retire",
            "",
            json!({"label": "Blue 4TB"}),
        );
        let s = service.disk_suggest.clone().unwrap();
        assert!(s.attached.is_empty());
        assert!(s.excluded[0].retired);
        pool::set_fake_space(&disk, None);
    }

    #[test]
    fn providers_list_for_the_storage_form() {
        let now = 1_791_849_600; // 2026-10-13
        let v = providers_json(now);
        assert_eq!(v["stale_after_days"], 90);
        let list = v["providers"].as_array().unwrap();
        assert!(!list.is_empty());
        for p in list {
            for k in [
                "id",
                "name",
                "kind",
                "currency",
                "storage_per_gb_month",
                "egress_per_gb",
                "egress_free_gb_per_month",
                "put_per_1000",
                "get_per_1000",
                "minimum_storage_days",
                "minimum_object_kb",
                "free_tier",
                "endpoints",
                "last_verified",
                "source_url",
                "stale",
            ] {
                assert!(p.get(k).is_some(), "{} lacks {k}", p["id"]);
            }
            for e in p["endpoints"].as_array().unwrap() {
                assert!(e["endpoint"].as_str().unwrap().starts_with("http"));
                assert!(e["path_style"].is_boolean());
                assert!(e["region"].is_string());
            }
        }
        let aws = list.iter().find(|p| p["id"] == "aws-s3").unwrap();
        assert_eq!(aws["storage_per_gb_month"]["value"], 0.0245);
        assert!(aws["storage_per_gb_month"]["source_url"]
            .as_str()
            .unwrap()
            .starts_with("https://"));
        assert_eq!(aws["stale"], false);
        let later = providers_json(now + 365 * 86_400);
        let aws_later = later["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "aws-s3")
            .unwrap();
        assert_eq!(aws_later["stale"], true);
    }
}
