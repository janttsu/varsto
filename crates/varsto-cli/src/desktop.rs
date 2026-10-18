// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Local control API and desktop interface, served by the background service.
//!
//! The server binds to 127.0.0.1 only. Every API call must carry a per-session
//! token that is written to `service.json` in the device directory (mode 0600)
//! and handed to the browser through a one-time code in the start URL
//! (`/?boot=<code>`, valid for a minute, exchanged by `POST /api/session`).
//! The token is accepted only in a header, never in an address. The `Host` header is
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
const FOLDERS_JS: &str = include_str!("../ui/folders.js");
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
const VIZ_JS: &str = include_str!("../ui/viz.js");
const VIZ_CSS: &str = include_str!("../ui/viz.css");
/// Largest single upload through /api/upload (a phone video, not a disk image).
/// The body is streamed to disk (or encrypted into the block cache as it
/// arrives), never held in memory as a whole.
const MAX_UPLOAD: u64 = 16 << 30;

/// How long a bootstrap code opens the page.
const BOOT_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a download or viewer ticket lives.
const TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Most bootstrap codes and tickets kept at once.
const GRANTS_MAX: usize = 256;

/// Short-lived credentials that stand in for the session token where it must
/// not appear: a one-time bootstrap code in the address the browser opens,
/// and tickets for the plain links of downloads and the viewer.
struct Grants {
    boot: std::collections::BTreeMap<String, std::time::Instant>,
    /// ticket -> (what it opens: route, folder and path, expiry)
    tickets: std::collections::BTreeMap<String, (String, std::time::Instant)>,
}

static GRANTS: Mutex<Grants> = Mutex::new(Grants {
    boot: std::collections::BTreeMap::new(),
    tickets: std::collections::BTreeMap::new(),
});

fn random_hex() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// A new one-time code that `POST /api/session` exchanges for the session
/// token within a minute.
pub fn mint_boot_code() -> String {
    mint_boot_code_in(&GRANTS, std::time::Instant::now())
}

fn mint_boot_code_in(grants: &Mutex<Grants>, now: std::time::Instant) -> String {
    let code = random_hex();
    let mut g = grants.lock().unwrap_or_else(|e| e.into_inner());
    g.boot.retain(|_, t| *t > now);
    while g.boot.len() >= GRANTS_MAX {
        let Some(k) = g.boot.keys().next().cloned() else {
            break;
        };
        g.boot.remove(&k);
    }
    g.boot.insert(code.clone(), now + BOOT_TTL);
    code
}

/// Use a bootstrap code: true once, and only before it expires.
fn redeem_boot_code_in(grants: &Mutex<Grants>, code: &str, now: std::time::Instant) -> bool {
    let mut g = grants.lock().unwrap_or_else(|e| e.into_inner());
    g.boot.retain(|_, t| *t > now);
    g.boot.remove(code).is_some()
}

fn ticket_scope(route: &str, folder: &str, path: &str) -> String {
    format!("{route}\0{folder}\0{path}")
}

fn mint_ticket(route: &str, folder: &str, path: &str) -> String {
    let now = std::time::Instant::now();
    let ticket = random_hex();
    let mut g = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    g.tickets.retain(|_, (_, t)| *t > now);
    while g.tickets.len() >= GRANTS_MAX {
        let Some(k) = g.tickets.keys().next().cloned() else {
            break;
        };
        g.tickets.remove(&k);
    }
    g.tickets.insert(
        ticket.clone(),
        (ticket_scope(route, folder, path), now + TICKET_TTL),
    );
    ticket
}

/// Whether `ticket` opens exactly this route, folder and path (it may be
/// used again within its lifetime: a video asks for ranges).
fn ticket_valid(ticket: &str, route: &str, folder: &str, path: &str) -> bool {
    let now = std::time::Instant::now();
    let mut g = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    g.tickets.retain(|_, (_, t)| *t > now);
    g.tickets
        .get(ticket)
        .is_some_and(|(scope, _)| *scope == ticket_scope(route, folder, path))
}

/// Whether the request carries the session token in `X-Varsto-Token` or as
/// `Authorization: Bearer`. The token is never accepted in the address.
fn header_token_ok(request: &Request, expected: &str) -> bool {
    request.headers().iter().any(|h| {
        (h.field.equiv("X-Varsto-Token") && token_matches(h.value.as_str(), expected))
            || (h.field.equiv("Authorization")
                && h.value
                    .as_str()
                    .strip_prefix("Bearer ")
                    .is_some_and(|t| token_matches(t.trim(), expected)))
    })
}

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
    /// A `varsto://` link the system handed to Varsto (`varsto open-link`),
    /// waiting for the interface to pick it up.
    pub link: Option<String>,
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
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        Fixed {
            bound: st.bound.clone(),
            token: st.token.clone(),
            traffic: st.traffic.clone(),
            state: state.clone(),
            reads: Arc::default(),
        }
    };
    let reads = fixed.reads.clone();
    let (tx, rx) = std::sync::mpsc::channel::<Request>();
    let worker = std::thread::Builder::new()
        .name("http-api".into())
        .spawn(move || {
            for request in rx {
                let (method, url) = (request.method().to_string(), loggable_url(request.url()));
                let t = varsto_core::logging::Timer::start();
                STATUS.with(|s| s.set(0));
                // A panic in a handler answers 500 (the dropped request does)
                // and leaves the worker alive for the next request.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle(&state, request)
                }))
                .unwrap_or_else(|_| {
                    log::error!(method = method, path = url; "api handler panicked");
                    Err(anyhow::anyhow!("handler panicked"))
                });
                let path = url.split('?').next().unwrap_or("");
                if method != "GET" && crate::readcache::drops_answers(path) {
                    // Reads computed while it ran may predate the change.
                    reads.lock().unwrap_or_else(|e| e.into_inner()).invalidate();
                }
                let status = STATUS.with(|s| s.get());
                match result {
                    Ok(()) => log::debug!(method = method, path = url, status = status, ms = t.ms(); "api request"),
                    Err(e) => log::warn!(method = method, path = url, ms = t.ms(); "api request failed: {e:#}"),
                }
            }
        });
    if worker.is_err() {
        log::error!("cannot start the API worker thread");
        return;
    }
    for request in server.incoming_requests() {
        log::trace!(method = request.method().to_string(), path = loggable_url(request.url()); "api request received");
        match handle_unlocked(&fixed, request) {
            Ok(None) => {}
            Ok(Some(request)) => {
                let Some(request) = read_elsewhere(&fixed, request) else {
                    continue;
                };
                // A change is coming: no cached answer from before it (a
                // sync or a check keeps them until it has been answered).
                let change = *request.method() != Method::Get
                    && crate::readcache::drops_answers(
                        request.url().split('?').next().unwrap_or(""),
                    );
                if change {
                    fixed
                        .reads
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .invalidate();
                }
                if tx.send(request).is_err() {
                    break;
                }
            }
            Err(e) => log::warn!("request failed: {e:#}"),
        }
    }
}

/// Reads answered on threads of their own, at most this many at a time.
const MAX_READERS: usize = 32;
static READERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A GET of a route that only reads (`readcache::ROUTES`), with the session
/// token: answered on a thread of its own, so that it neither waits behind
/// the changes queued for the worker nor, while a sync holds the state, for
/// the sync (the last answer is sent, marked stale). Anything else is handed
/// back for the worker.
fn read_elsewhere(fixed: &Fixed, request: Request) -> Option<Request> {
    use std::sync::atomic::Ordering;
    let path = request.url().split('?').next().unwrap_or("");
    if *request.method() != Method::Get
        || !crate::readcache::cacheable(path)
        || !header_token_ok(&request, &fixed.token)
    {
        return Some(request);
    }
    if READERS.fetch_add(1, Ordering::SeqCst) >= MAX_READERS {
        READERS.fetch_sub(1, Ordering::SeqCst);
        return Some(request);
    }
    let (state, reads) = (fixed.state.clone(), fixed.reads.clone());
    let spawned = std::thread::Builder::new()
        .name("http-read".into())
        .spawn(move || {
            struct Done;
            impl Drop for Done {
                fn drop(&mut self) {
                    READERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _done = Done;
            let url = loggable_url(request.url());
            let t = varsto_core::logging::Timer::start();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve_read(&state, &reads, request)
            }));
            match r {
                Ok(Ok(how)) => log::debug!(method = "GET", path = url, answer = how, ms = t.ms(); "api request"),
                Ok(Err(e)) => log::warn!(method = "GET", path = url, ms = t.ms(); "api request failed: {e:#}"),
                Err(_) => log::error!(method = "GET", path = url; "api read handler panicked"),
            }
        });
    if spawned.is_err() {
        READERS.fetch_sub(1, Ordering::SeqCst);
        log::warn!("cannot start a reader thread");
    }
    None
}

/// Answer a read: fresh when the state is free within
/// `readcache::FRESH_WAIT`, else the last answer of the same address.
fn serve_read(
    state: &Shared,
    reads: &Mutex<crate::readcache::ReadCache>,
    request: Request,
) -> Result<&'static str> {
    use crate::readcache::{self, Got};
    let url = request.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    // The address without the token parameters (none are accepted anyway).
    let key = loggable_url(&url);
    match readcache::lock_or_cached(state, reads, &key, readcache::FRESH_WAIT) {
        Got::Fresh(mut st) => {
            let generation = reads.lock().unwrap_or_else(|e| e.into_inner()).generation();
            let result = api(&mut st, Method::Get, path, query, &json!({}));
            drop(st);
            match result {
                Ok(v) => {
                    let body = Arc::new(v.to_string());
                    reads.lock().unwrap_or_else(|e| e.into_inner()).store(
                        &key,
                        generation,
                        body.clone(),
                        std::time::Instant::now(),
                    );
                    request.respond(json_text(200, body.as_str()))?;
                }
                Err(e) => {
                    request.respond(json_response(400, &json!({"error": format!("{e:#}")})))?
                }
            }
            Ok("fresh")
        }
        Got::Cached(age, body) => {
            request.respond(
                json_text(200, &readcache::mark_stale(&body, age))
                    .with_header(header("X-Varsto-Stale", "1"))
                    .with_header(header("X-Varsto-Age-Ms", &age.as_millis().to_string())),
            )?;
            Ok("cached")
        }
    }
}

thread_local! {
    /// Status of the last JSON answer on this thread, for the request log.
    static STATUS: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

/// A request URL for the log: the path and query without the session token.
fn loggable_url(url: &str) -> String {
    match url.split_once('?') {
        None => url.to_string(),
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|kv| {
                    !(kv.starts_with("token=")
                        || kv.starts_with("boot=")
                        || kv.starts_with("ticket="))
                })
                .collect();
            if kept.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{}", kept.join("&"))
            }
        }
    }
}

/// What the dispatching thread needs, copied from the state at start.
struct Fixed {
    bound: String,
    token: String,
    traffic: Arc<varsto_core::p2p::Traffic>,
    state: Shared,
    /// The last answers of the reads (`readcache`), emptied by every change.
    reads: Arc<Mutex<crate::readcache::ReadCache>>,
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
        let token_ok = header_token_ok(&request, &fixed.token);
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
    if *request.method() == Method::Post && path == "/api/session" {
        // The browser trades the one-time code from its start address for
        // the session token, which then lives in sessionStorage only.
        let mut request = request;
        let mut body = String::new();
        let read = request.as_reader().take(4096).read_to_string(&mut body);
        let code = read
            .ok()
            .and_then(|_| serde_json::from_str::<Value>(&body).ok())
            .and_then(|v| v["boot"].as_str().map(str::to_string));
        let ok = code.is_some_and(|c| redeem_boot_code_in(&GRANTS, &c, std::time::Instant::now()));
        if ok {
            request.respond(json_response(200, &json!({"token": fixed.token})))?;
        } else {
            request.respond(json_response(
                401,
                &json!({"error": "the start link was used already or has expired; open Varsto again"}),
            ))?;
        }
        return Ok(None);
    }
    if *request.method() == Method::Post && (path == "/api/session/boot" || path == "/api/ticket") {
        // A client that holds the token asks for a code to open the page
        // with, or for a ticket for a download or viewer link.
        let mut request = request;
        if !header_token_ok(&request, &fixed.token) {
            request.respond(json_response(
                401,
                &json!({"error": "missing or wrong token; reopen the start URL"}),
            ))?;
            return Ok(None);
        }
        if path == "/api/session/boot" {
            request.respond(json_response(200, &json!({"boot": mint_boot_code()})))?;
            return Ok(None);
        }
        let mut body = String::new();
        let _ = request.as_reader().take(65536).read_to_string(&mut body);
        let v: Value = serde_json::from_str(&body).unwrap_or(json!({}));
        let (route, folder, file) = (
            v["route"].as_str().unwrap_or(""),
            v["folder"].as_str().unwrap_or(""),
            v["path"].as_str().unwrap_or(""),
        );
        if !matches!(route, "/api/open" | "/api/view") || folder.is_empty() || file.is_empty() {
            request.respond(json_response(
                400,
                &json!({"error": "route, folder and path required"}),
            ))?;
        } else {
            request.respond(json_response(
                200,
                &json!({"ticket": mint_ticket(route, folder, file)}),
            ))?;
        }
        return Ok(None);
    }
    if *request.method() != Method::Get {
        return Ok(Some(request));
    }
    if path == "/api/events" {
        // A stream of its own thread (`sse`); the token is a header, so the
        // page reads the stream with fetch.
        let query = request
            .url()
            .split_once('?')
            .map_or(String::new(), |(_, q)| q.to_string());
        let token_ok = header_token_ok(&request, &fixed.token);
        if !token_ok {
            request.respond(json_response(
                401,
                &json!({"error": "missing or wrong token; reopen the start URL"}),
            ))?;
            return Ok(None);
        }
        crate::sse::serve(request, &query, fixed.traffic.clone());
        return Ok(None);
    }
    if let Some((bytes, ctype)) = crate::viz::asset(&path) {
        // The visualization's sprites: static, no token.
        request.respond(
            Response::from_data(bytes)
                .with_header(header("Content-Type", ctype))
                .with_header(header("Cache-Control", "private, max-age=300")),
        )?;
        return Ok(None);
    }
    match path.as_str() {
        "/" => request.respond(html(INDEX_HTML))?,
        "/app.js" => request.respond(text(APP_JS, "text/javascript; charset=utf-8"))?,
        "/folders.js" => request.respond(text(FOLDERS_JS, "text/javascript; charset=utf-8"))?,
        "/i18n.js" => request.respond(text(I18N_JS, "text/javascript; charset=utf-8"))?,
        "/i18n/fi.json" => request.respond(text(I18N_FI, "application/json; charset=utf-8"))?,
        "/i18n/sv.json" => request.respond(text(I18N_SV, "application/json; charset=utf-8"))?,
        "/app.css" => request.respond(text(APP_CSS, "text/css; charset=utf-8"))?,
        "/viz.js" => request.respond(text(VIZ_JS, "text/javascript; charset=utf-8"))?,
        "/viz.css" => request.respond(text(VIZ_CSS, "text/css; charset=utf-8"))?,
        "/api/viz" => {
            if !header_token_ok(&request, &fixed.token) {
                request.respond(json_response(
                    401,
                    &json!({"error": "missing or wrong token; reopen the start URL"}),
                ))?;
            } else {
                // The ledger passes behind it take a while on a big vault:
                // not on this thread, which answers the page's assets.
                let (state, traffic) = (fixed.state.clone(), fixed.traffic.clone());
                let spawned =
                    std::thread::Builder::new()
                        .name("http-viz".into())
                        .spawn(move || {
                            let v = crate::viz::snapshot(&state, &traffic);
                            if let Err(e) = request.respond(json_response(200, &v)) {
                                log::debug!("viz answer not sent: {e}");
                            }
                        });
                if spawned.is_err() {
                    log::warn!("cannot start the viz thread");
                }
            }
        }
        "/api/p2p/traffic" | "/api/progress" | "/api/activity" => {
            let token_ok = header_token_ok(&request, &fixed.token);
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
        .with_header(header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header("Cache-Control", "no-store"))
}

fn text(body: &str, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-store"))
}

/// A plain-text answer of an API route: never cached.
fn api_plain(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    STATUS.with(|s| s.set(status));
    Response::from_string(msg)
        .with_status_code(status)
        .with_header(header("Cache-Control", "no-store"))
}

fn json_response(status: u16, value: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    json_text(status, &value.to_string())
}

/// A JSON answer already serialized.
fn json_text(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    STATUS.with(|s| s.set(status));
    Response::from_string(body)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Cache-Control", "no-store"))
}

fn handle(state: &Shared, mut request: Request) -> Result<()> {
    let host_ok = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
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
        (Method::Get, "/folders.js") => {
            return Ok(request.respond(text(FOLDERS_JS, "text/javascript; charset=utf-8"))?)
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
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let in_header = header_token_ok(&request, &st.token);
        // Downloads and the viewer are plain links (<a>, <video>) that cannot
        // send a header: they carry a ticket for exactly that file, never the
        // session token.
        let in_ticket = (path == "/api/open" || path == "/api/view")
            && match (
                query_param(&query, "ticket"),
                query_param(&query, "folder"),
                query_param(&query, "path"),
            ) {
                (Some(t), Some(f), Some(p)) => ticket_valid(&t, &path, &f, &p),
                _ => false,
            };
        in_header || in_ticket
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
        let home = state.lock().unwrap_or_else(|e| e.into_inner()).home.clone();
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
        // Download a file through the browser; a plain link, so it carries a
        // ticket instead of the token. Counts as an access.
        let (folder, file) = (query_param(&query, "folder"), query_param(&query, "path"));
        let result = {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
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
                        .with_header(header("Cache-Control", "no-store"))
                        .with_header(header("Content-Disposition", &attachment(name))),
                )?;
                Ok(())
            }
            Some(Err(e)) => {
                request.respond(api_plain(400, &e.to_string()))?;
                Ok(())
            }
            None => {
                request.respond(api_plain(400, "locked or missing parameters"))?;
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
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            match (&st.engine, folder, file) {
                (Some(e), Some(f), Some(p)) => e.thumbnail(&f, &p).unwrap_or(None),
                _ => None,
            }
        };
        match bytes {
            Some(b) => request.respond(
                Response::from_data(b)
                    .with_header(header("Content-Type", "image/jpeg"))
                    // No decrypted thumbnail in any disk cache.
                    .with_header(header("Cache-Control", "no-store")),
            )?,
            None => request.respond(api_plain(404, "no thumbnail"))?,
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
    if *request.method() == Method::Post && path == "/api/logs/bundle" {
        // `{"save": true}` (the Android shell, which cannot save a download):
        // write the bundle under `home/exports` and answer with its path, for
        // the shell to share. Removed with the other exports at the next start.
        let mut body = String::new();
        let _ = request.as_reader().take(4096).read_to_string(&mut body);
        let save = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("save").and_then(Value::as_bool))
            .unwrap_or(false);
        let (home, state_json) = {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            let v = api(&mut st, Method::Get, "/api/state", "", &json!({})).ok();
            (st.home.clone(), v.map(|v| v.to_string()))
        };
        let extras = bundle_extras(&home, state_json);
        let name = format!("varsto-logs-{}.tar.zst", log_stamp());
        if save {
            let dir = home.join(varsto_core::engine::EXPORT_DIR);
            let target = dir.join(&name);
            let written = std::fs::create_dir_all(&dir)
                .and_then(|_| std::fs::File::create(&target))
                .and_then(|f| varsto_core::logging::bundle(&home, &extras, f))
                .and_then(|mut f| std::io::Write::flush(&mut f));
            return match written {
                Ok(()) => {
                    log::info!(path = target.display().to_string(); "log bundle saved for sharing");
                    Ok(request.respond(json_response(
                        200,
                        &json!({"ok": true, "path": target, "note": BUNDLE_REMINDER}),
                    ))?)
                }
                Err(e) => Ok(request.respond(json_response(
                    500,
                    &json!({"error": format!("log bundle: {e:#}")}),
                ))?),
            };
        }
        return match varsto_core::logging::bundle(&home, &extras, Vec::new()) {
            Ok(bytes) => {
                log::info!(bytes = bytes.len(); "log bundle made for the interface");
                STATUS.with(|s| s.set(200));
                Ok(request.respond(
                    Response::from_data(bytes)
                        .with_header(header("Content-Type", "application/zstd"))
                        .with_header(header("Cache-Control", "no-store"))
                        .with_header(header("Content-Disposition", &attachment(&name))),
                )?)
            }
            Err(e) => Ok(request.respond(json_response(
                500,
                &json!({"error": format!("log bundle: {e:#}")}),
            ))?),
        };
    }
    if *request.method() == Method::Post && path == "/api/qr/scan" {
        // A camera frame (`?w=&h=`, one grey byte a pixel) or an image file
        // (`?image=1`: a screenshot) as the raw body; returns the texts of
        // the QR codes in it. Nothing is kept.
        let result = qr_scan(&mut request, &query);
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
        set_join_step(json!({"active": false}));
        return match result {
            Ok(v) => Ok(request.respond(json_response(200, &v))?),
            Err(e) => Ok(request.respond(json_response(400, &pair_join_error(&e)))?),
        };
    }
    if method == Method::Get && path == "/api/pair/join-status" {
        let v = JOIN_STEP
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| json!({"active": false}));
        return Ok(request.respond(json_response(200, &v))?);
    }
    if method == Method::Post && path == "/api/quit" {
        request.respond(json_response(200, &json!({"ok": true})))?;
        service::request_quit(state);
        return Ok(());
    }
    let post = method == Method::Post;
    let result = {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        api(&mut st, method, &path, &query, &input)
    };
    // Something was changed through the API: open pages load it again.
    if post && result.is_ok() && path != "/api/sync" {
        varsto_core::events::publish("config.changed", json!({"source": "api", "path": path}));
    }
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
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
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
        Ok(v) if path == "/api/status" => {
            // Only the folders the key may read: no devices, no storages, no
            // paths, no vault identity.
            let mut folders = v.get("folders").cloned().unwrap_or(json!([]));
            if let Some(a) = folders.as_array_mut() {
                a.retain(|f| f["name"].as_str().is_some_and(visible));
            }
            (200, json!({ "folders": folders }))
        }
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
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            let e = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            e.commit_staged(&folder, &path, staged)?
        }
        None => {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            let e = st
                .engine
                .as_mut()
                .ok_or_else(|| anyhow!("vault is locked"))?;
            e.write_from_reader(&folder, &path, &mut body)?
        }
    };
    Ok(json!({"ok": true, "folder": folder, "path": path, "bytes": body.read, "push": push}))
}

/// What `pair_join` is doing now, for `GET /api/pair/join-status`.
static JOIN_STEP: Mutex<Option<Value>> = Mutex::new(None);

fn set_join_step(v: Value) {
    *JOIN_STEP.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
}

/// Nothing answered: the message plus what the page lists in its language.
#[derive(Debug)]
struct PairJoinFailed {
    message: String,
    tried: Value,
    found: usize,
}

impl std::fmt::Display for PairJoinFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PairJoinFailed {}

/// The JSON body of a failed `/api/pair/join`.
fn pair_join_error(e: &anyhow::Error) -> Value {
    let mut v = json!({"error": format!("{e:#}")});
    if let Some(f) = e.downcast_ref::<PairJoinFailed>() {
        v["tried"] = f.tried.clone();
        v["found"] = json!(f.found);
    }
    v
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
    if state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .home
        .join("vault.json")
        .exists()
    {
        bail!("this device already holds a vault");
    }
    // The typed address first, then the addresses of the scanned link, then
    // a search of the network; the page polls /api/pair/join-status.
    let offered = str_list(input, "addresses");
    // This device's keys: the other device shows their six words to its
    // person before it lets this one join, and the page shows them here.
    let keys = varsto_core::pair::v3::PairingKeys::generate();
    let words = keys.fingerprint();
    set_join_step(json!({"active": true, "step": "start", "tried": [], "fingerprint": words}));
    let mut tried: Vec<String> = Vec::new();
    let result = varsto_core::pair::receive_with_progress(
        &code,
        &keys.join_keys(&name),
        opt(input, "address").as_deref(),
        &offered,
        &mut |step| match step {
            varsto_core::pair::Step::Trying(a) => {
                tried.push(a.to_string());
                set_join_step(
                    json!({"active": true, "step": "trying", "address": a.to_string(), "tried": tried, "fingerprint": words}),
                );
            }
            varsto_core::pair::Step::Looking => {
                set_join_step(
                    json!({"active": true, "step": "looking", "tried": tried, "fingerprint": words}),
                );
            }
        },
    );
    set_join_step(json!({"active": false}));
    let bundle = match result {
        Ok(b) => b,
        Err(e) => {
            // The page lists what was tried in its own language.
            if let Some(nf) = e.downcast_ref::<varsto_core::pair::NotFound>() {
                return Err(PairJoinFailed {
                    message: e.to_string(),
                    tried: serde_json::to_value(&nf.tried)?,
                    found: nf.found,
                }
                .into());
            }
            return Err(e);
        }
    };
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    let (e, notes) = Engine::join_paired(&st.home, &name, &passphrase, &bundle, keys)?;
    st.engine = Some(e);
    st.service.request_sync();
    Ok(json!({"ok": true, "from": bundle.from, "storages": notes}))
}

/// The URIs to show for a link: one code, or parts when asked (a camera
/// that cannot read the dense code) or when one code cannot hold it.
fn qr_uris(link: &varsto_core::qr::Link, parts: bool) -> Result<Vec<String>> {
    use varsto_core::qr;
    if !parts {
        let uri = link.to_uri()?;
        if qr::code_for(&uri).is_ok() {
            return Ok(vec![uri]);
        }
    }
    link.to_uris(0, qr::PART_CHARS)
}

/// What the interface shows for a link: its kind, the text form and what
/// both sides compare (the fingerprint of a request code).
fn link_info(link: &varsto_core::qr::Link) -> Result<Value> {
    use varsto_core::qr::Link;
    let mut v = json!({"kind": link.kind(), "text": link.text(), "uri": link.to_uri()?});
    match link {
        Link::ShareRequest(code) => {
            let r = Engine::share_request_info(code)?;
            v["fingerprint"] = json!(r.fingerprint);
            v["name"] = json!(r.name);
        }
        Link::ShareToken(t) => {
            v["folder"] = json!(varsto_core::vault::SealedShareToken::decode(t)?.name);
        }
        Link::Pair { code, addresses } => {
            v["code"] = json!(format!("{}-{}-{}", &code[0..3], &code[3..6], &code[6..9]));
            v["addresses"] = json!(addresses);
        }
    }
    Ok(v)
}

/// A pairing offer's status with its `varsto://pair` link.
fn pair_status(st: varsto_core::pair::OfferStatus) -> Result<Value> {
    let mut v = serde_json::to_value(&st)?;
    if st.open {
        v["uri"] = json!(varsto_core::qr::Link::Pair {
            code: st.code.clone(),
            addresses: st.addresses.clone(),
        }
        .to_uri()?);
    }
    Ok(v)
}

fn qr_scan(request: &mut Request, query: &str) -> Result<Value> {
    use varsto_core::qr;
    let texts = if query_param(query, "image").is_some() {
        let mut b = Vec::new();
        request.as_reader().take(32 << 20).read_to_end(&mut b)?;
        qr::decode_image(&b)?
    } else {
        let dim = |k: &str| -> Result<usize> {
            query_param(query, k)
                .and_then(|x| x.parse().ok())
                .filter(|&x: &usize| x > 0 && x <= qr::MAX_IMAGE_SIDE as usize)
                .ok_or_else(|| anyhow!("{k} must be 1 to {}", qr::MAX_IMAGE_SIDE))
        };
        let (w, h) = (dim("w")?, dim("h")?);
        let mut b = Vec::with_capacity(w * h);
        request
            .as_reader()
            .take((w * h) as u64)
            .read_to_end(&mut b)?;
        qr::decode_luma(w, h, &b)?
    };
    Ok(json!({"texts": texts}))
}

fn s(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .ok_or_else(|| anyhow!("missing field {key}"))
}

/// A list of strings (absent: empty).
/// `min_free`: "5%", "10GB", or empty / "default" for the default.
fn min_free_input(v: &Value) -> Result<Option<varsto_core::freespace::MinFree>> {
    let t = v
        .get("min_free")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    if t.is_empty() || t.eq_ignore_ascii_case("default") {
        return Ok(None);
    }
    Ok(Some(varsto_core::freespace::MinFree::parse(t)?))
}

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

/// Folder safety (`varsto_core::engine::folder_safety`): the folder marker,
/// held deletions and the send-only / receive-only modes. `input` names the
/// folder and the action; the command line calls this directly when no
/// service runs.
pub(crate) fn folder_safety_action(engine: &mut Engine, input: &Value) -> Result<Value> {
    let folder = s(input, "folder")?;
    let action = s(input, "action")?;
    Ok(match action.as_str() {
        "pending" => serde_json::to_value(engine.folder_changes(&folder)?)?,
        "repair-marker" => {
            let path = engine.repair_marker(&folder)?;
            json!({"ok": true, "path": path})
        }
        "confirm-deletions" => {
            json!({"ok": true, "deleted": engine.confirm_deletions(&folder)?})
        }
        "discard-deletions" => serde_json::to_value(engine.discard_deletions(&folder)?)?,
        "mode" => {
            let mode: varsto_core::vault::FolderMode = s(input, "mode")?.parse()?;
            engine.set_folder_mode(&folder, mode)?;
            json!({"ok": true, "mode": mode})
        }
        "override" => json!({"ok": true, "files": engine.override_remote(&folder)?}),
        "revert" => serde_json::to_value(engine.revert_local(&folder)?)?,
        "deletion-guard" => {
            let guard = match input.get("guard") {
                None | Some(Value::Null) => None,
                Some(g) => Some(serde_json::from_value::<varsto_core::vault::DeletionGuard>(
                    g.clone(),
                )?),
            };
            engine.set_deletion_guard(&folder, guard)?;
            let now = engine.folder_changes(&folder)?.deletion_guard;
            json!({"ok": true, "deletion_guard": now, "text": now.describe()})
        }
        other => bail!("unknown folder action {other}"),
    })
}

fn opt(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
}

/// A boolean field: `true`, or the strings "true", "1", "on" (a form).
fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim(), "true" | "1" | "on"),
        _ => false,
    }
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

/// Whether a token a request carries is the session token, compared in
/// constant time so that the comparison's duration tells nothing about how
/// many leading bytes were right.
fn token_matches(given: &str, expected: &str) -> bool {
    varsto_core::crypto::ct_eq(given.as_bytes(), expected.as_bytes())
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
                allow_insecure_http: flag(input, "insecure_http"),
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
            min_free: None,
        },
        None,
    ))
}

/// Phones keep their vault in cloud storage only: a local directory, a
/// disk pool or a transferrer (a removable disk) makes no sense on a phone.
fn storage_kind_allowed(kind: &str, on_phone: bool) -> Result<()> {
    if on_phone && !matches!(kind, "s3" | "rclone") {
        bail!("this device can only add S3-compatible buckets and rclone remotes as storages");
    }
    Ok(())
}

fn mobile() -> bool {
    std::env::var_os("VARSTO_MOBILE").is_some()
}

/// `POST /api/folder/attach`: attach a folder of the vault here, kept in
/// full or selective (`selective`), plain or encrypted on a phone (`plain`),
/// both ways, send-only or receive-only (`mode`; section 70). The mode is
/// checked before anything is attached, so a refused one leaves nothing.
fn attach_request(engine: &mut Engine, input: &Value) -> Result<varsto_core::ids::FolderId> {
    let selective = input
        .get("selective")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let name_or_id = s(input, "name_or_id")?;
    let plain = wants_plain(input);
    let mode: Option<varsto_core::vault::FolderMode> = opt(input, "mode")
        .filter(|m| !m.trim().is_empty())
        .map(|m| m.parse())
        .transpose()?;
    if mode == Some(varsto_core::vault::FolderMode::ReceiveOnly) && !plain {
        bail!("receive-only is for folders with plain files; this folder would be kept encrypted on this device");
    }
    let path = match opt(input, "path").filter(|p| !p.trim().is_empty()) {
        Some(p) => PathBuf::from(p),
        None => {
            let name = engine
                .folders()
                .into_iter()
                .find(|(r, _)| {
                    r.name == name_or_id || r.folder_id.as_str().starts_with(&name_or_id)
                })
                .map(|(r, _)| r.name.clone())
                .unwrap_or_else(|| name_or_id.clone());
            default_folder_path(engine.home(), &name, plain)?
        }
    };
    let id = engine.attach_folder(&name_or_id, &path, selective)?;
    if !plain {
        engine.set_encrypted_here(&name_or_id, true)?;
    }
    if let Some(mode) = mode.filter(|m| !m.is_normal()) {
        engine.set_folder_mode(&name_or_id, mode)?;
    }
    Ok(id)
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

/// Decode `%XX` escapes and `+` in a query value. Works on bytes so that a
/// multi-byte character after a `%` cannot split a character boundary.
fn percent_decode(v: &str) -> String {
    let bytes = v.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
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
            // Folder membership of storage format 3 is in this build.
            "format3": cfg!(feature = "format3"),
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
        // The Help page: where this device stands, where the data is and what
        // to do next. Works without a vault and while it is locked too.
        // Sentences come as {t, p} like the recovery guide's; `?format=text`
        // gives the English text of `varsto help-now`.
        (Method::Get, "/api/help") => {
            let observed = help_observed(&st.service);
            let h = match st.engine.as_mut() {
                Some(e) => e.help_state(observed)?,
                None => varsto_core::engine::help_without_vault(&st.home),
            };
            Ok(match query_param(query, "format").as_deref() {
                Some("text") => json!({ "text": varsto_core::help::render_text(&h) }),
                _ => serde_json::to_value(h)?,
            })
        }
        (Method::Get, "/api/logs") => Ok(logs_info(&st.home)),
        (Method::Post, "/api/logs/level") => {
            let level = s(input, "level")?;
            varsto_core::logging::Filter::parse(&level).map_err(|e| anyhow!(e))?;
            let mut cfg = varsto_core::vault::Config::load(&st.home)?;
            cfg.log_level = Some(level.clone());
            cfg.save(&st.home)?;
            // VARSTO_LOG and --log-level still win in this process.
            if !matches!(
                varsto_core::logging::level().map(|l| l.1),
                Some(varsto_core::logging::Source::Env | varsto_core::logging::Source::Flag)
            ) {
                varsto_core::logging::set_level(&level, varsto_core::logging::Source::Config)
                    .map_err(|e| anyhow!(e))?;
            }
            log::info!(level = level; "log level set in the interface");
            let mut v = logs_info(&st.home);
            v["ok"] = json!(true);
            Ok(v)
        }
        (Method::Post, "/api/logs/open") => {
            if mobile() {
                bail!("the log folder cannot be opened on a phone; save a log bundle instead");
            }
            let dir = varsto_core::logging::dir(&st.home);
            varsto_core::logging::files::ensure_dir(&dir)?;
            crate::filemanager::open_with_desktop(&dir)?;
            Ok(json!({"ok": true}))
        }
        (Method::Get, "/api/update/check") => Ok(serde_json::to_value(crate::update::check()?)?),
        (Method::Post, "/api/update") => {
            let c = crate::update::check()?;
            let policy = crate::update::Policy::new(&st.home, false);
            let message = crate::update::apply(&c, &policy)?;
            // The Windows setup program restarts Varsto itself.
            if c.available && !c.installer() {
                st.service.restart_requested = true;
            }
            Ok(json!({"ok": true, "updated": c.available, "message": message}))
        }
        (Method::Get, "/api/update/settings") => Ok(json!({
            "auto": crate::update::auto_update_enabled(&st.home),
            "installs": crate::update::can_install_by_itself(),
        })),
        (Method::Post, "/api/update/settings") => {
            let on = input.get("auto").and_then(|b| b.as_bool()).unwrap_or(true);
            crate::update::set_auto_update(&st.home, on)?;
            Ok(json!({"ok": true, "auto": on}))
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
            let mut e = Engine::open(&st.home, &s(input, "passphrase")?)?;
            // `varsto unlock --with-recovery-key`: the recovery words stay
            // in this process's memory until it stops or is locked.
            if let Some(words) = opt(input, "recovery_words").filter(|w| !w.trim().is_empty()) {
                varsto_core::logging::register_secret(words.trim());
                e.set_recovery_key(Some(varsto_core::membership3::RecoveryKey::from_words(
                    words.trim(),
                )?));
            }
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
            // The joining device's name and six words wait for the person
            // here (`ask` in the status) before anything is sent.
            let offer = f3_api::start_offer(e)?;
            let status = offer.status();
            st.pair = Some(offer);
            pair_status(status)
        }
        (Method::Get, "/api/pair/status") => {
            #[allow(unused_mut)]
            let mut v = match &st.pair {
                Some(o) => pair_status(o.status())?,
                None => json!({"open": false}),
            };
            #[cfg(feature = "format3")]
            f3_api::add_pair_ask(&mut v, st.engine.as_mut());
            Ok(v)
        }
        // QR invitations (section 51): the QR codes of a request code, a
        // sealed token or a pairing link, and what a scanned text is.
        (Method::Post, "/api/qr") => {
            let link = varsto_core::qr::Link::from_text(&s(input, "text")?)?;
            let parts = input["parts"].as_bool().unwrap_or(false);
            let uris = qr_uris(&link, parts)?;
            let codes = uris
                .iter()
                .map(|u| varsto_core::qr::to_svg(u))
                .collect::<Result<Vec<_>>>()?;
            let mut v = link_info(&link)?;
            v["codes"] = serde_json::to_value(&codes)?;
            Ok(v)
        }
        (Method::Post, "/api/link/parse") => {
            // One text, or every part of a split link scanned so far.
            let texts: Vec<String> = match input["texts"].as_array() {
                Some(a) => a
                    .iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect(),
                None => vec![s(input, "text")?],
            };
            let mut asm = varsto_core::qr::Assembler::new();
            let mut last = None;
            for t in &texts {
                let t = t.trim();
                let scanned = if varsto_core::qr::is_link(t) {
                    varsto_core::qr::parse(t)?
                } else {
                    varsto_core::qr::Scanned::Link(varsto_core::qr::Link::from_text(t)?)
                };
                match scanned {
                    varsto_core::qr::Scanned::Link(l) => return link_info(&l),
                    varsto_core::qr::Scanned::Part(p) => {
                        last = Some(p.clone());
                        if let Some(l) = asm.add(p)? {
                            return link_info(&l);
                        }
                    }
                }
            }
            let p = last.ok_or_else(|| anyhow!("nothing scanned"))?;
            let (have, count) = asm.progress();
            Ok(json!({"part": p, "have": have, "count": count}))
        }
        // A link the system opened Varsto with: kept until the interface takes it.
        (Method::Post, "/api/link") => {
            let uri = s(input, "uri")?;
            match varsto_core::qr::parse(&uri)? {
                varsto_core::qr::Scanned::Link(_) => {}
                varsto_core::qr::Scanned::Part(p) => bail!(
                    "this is part {} of {} of a split code: scan it in Varsto (Scan QR code)",
                    p.index,
                    p.count
                ),
            }
            st.link = Some(uri.trim().to_string());
            Ok(json!({"ok": true}))
        }
        (Method::Get, "/api/link") => Ok(match st.link.take() {
            Some(uri) => json!({"uri": uri}),
            None => json!({}),
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
                    allow_insecure_http: flag(input, "insecure_http"),
                }
            } else {
                StorageSpec::LocalDir {
                    name: storage_name.clone(),
                    path: PathBuf::from(s(input, "storage_path")?),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                    min_free: None,
                }
            };
            // The key in hex, or the 24 words of the recovery kit.
            let key = s(input, "vault_key")?;
            let key = if key.trim().contains(char::is_whitespace) {
                varsto_core::recovery::key_from_words(&key)?
            } else {
                zeroize::Zeroizing::new(key.trim().to_string())
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
            // One name per device id everywhere: the traffic view learns the vault's names
            // whenever the interface asks for devices or where the data is.
            if matches!(path, "/api/devices" | "/api/data/locations") {
                let names = engine.known_device_names();
                st.traffic
                    .learn_names(names.iter().map(|(d, n)| (d, n.as_str())));
            }
            api_unlocked(engine, service, method2, path, query, input)
        }
    }
}

/// What the service already knows, for the Help page.
pub fn help_observed(sv: &ServiceState) -> varsto_core::engine::HelpObserved {
    varsto_core::engine::HelpObserved {
        service: Some(varsto_core::help::ServiceIn {
            running: sv.running,
            paused: sv.paused,
            last_error: sv.last_error.clone(),
            p2p_listening: sv.p2p_listen.is_some(),
            p2p_reachable: sv.p2p_reachable,
            peers: sv.p2p_peers.len(),
        }),
        policies: (!sv.policies.is_empty()).then(|| sv.policies.clone()),
        disks: (!sv.disks.is_empty()).then(|| sv.disks.clone()),
        disk_suggest: sv.disk_suggest.clone(),
        repair: sv.repair.clone(),
        scrub: sv.scrub.clone(),
        backup_errors: sv.backup_errors.clone(),
        restic_text: sv.restic_text.clone(),
        quota_full: sv.quota_full.clone(),
    }
}

/// The interface asks for long work to run in the background service.
/// `20261013-133038` (UTC).
pub fn log_stamp() -> String {
    varsto_core::logging::rfc3339_millis(std::time::SystemTime::now())[..19]
        .replace(['-', ':'], "")
        .replace('T', "-")
}

/// Non-log files that go into a bundle: versions, the service's view of
/// things (when it runs) and the local configuration (no secrets in it).
pub fn bundle_extras(home: &std::path::Path, state: Option<String>) -> Vec<(String, Vec<u8>)> {
    let mut extras = Vec::new();
    let (level, source) = varsto_core::logging::level()
        .map(|(l, s)| (l, s.as_str()))
        .unwrap_or_else(|| (varsto_core::logging::DEFAULT_LEVEL.to_string(), "default"));
    let about = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "log_level": level,
        "log_level_source": source,
        "created_utc": varsto_core::util::now_utc(),
    });
    extras.push((
        "about.json".to_string(),
        serde_json::to_vec_pretty(&about).unwrap_or_default(),
    ));
    if let Some(s) = state {
        extras.push(("status.json".to_string(), s.into_bytes()));
    }
    if let Ok(c) = std::fs::read(home.join("config.json")) {
        // Without the restic password source, S3 key ids and the logins in URLs.
        extras.push((
            "config.json".to_string(),
            varsto_core::logging::redact::redact_config_json(&c),
        ));
    }
    extras
}

pub const BUNDLE_REMINDER: &str = "The bundle holds no keys, passphrases or file contents, but it does contain file and folder names, device and storage names. Look through it before you share it.";

/// The interface's view of the log: where, how detailed, how big.
fn logs_info(home: &std::path::Path) -> Value {
    let (bytes, files) = varsto_core::logging::usage(home);
    let (level, source) = varsto_core::logging::level()
        .map(|(l, s)| (l, s.as_str()))
        .unwrap_or_else(|| {
            let (l, s) = varsto_core::logging::resolve_level(None, Some(home));
            (l, s.as_str())
        });
    json!({
        "dir": varsto_core::logging::dir(home).display().to_string(),
        "level": level,
        "source": source,
        "bytes": bytes,
        "files": files,
        "can_open": !mobile(),
    })
}

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
        (Method::Get, "/api/status") => {
            #[allow(unused_mut)]
            let mut v = serde_json::to_value(engine.status()?)?;
            #[cfg(feature = "format3")]
            if let Ok(list) = engine.f3_missing_escrows() {
                if !list.is_empty() {
                    v["recovery_warnings"] = json!(list.iter().map(|m| &m.warning).collect::<Vec<_>>());
                }
            }
            Ok(v)
        }
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
        // Folder membership of storage format 3 (work package 8b). Only a
        // person at the page reaches these; the background service reads
        // requests and never answers one.
        (
            m,
            "/api/folder/requests"
            | "/api/folder/request"
            | "/api/folder/approve"
            | "/api/folder/deny"
            | "/api/folder/members"
            | "/api/folder/role"
            | "/api/folder/resolve-epoch"
            | "/api/recovery/escrow"
            | "/api/pair/answer",
        ) => f3_api::route(engine, service, m, path, query, input),
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
        (Method::Get, "/api/storage/quotas") => Ok(serde_json::to_value(engine.quota_statuses()?)?),
        (Method::Post, "/api/storage/quota") => {
            let name = s(input, "name")?;
            let clear = input.get("clear").and_then(|v| v.as_bool()).unwrap_or(false);
            let status = if clear {
                engine.set_storage_quota(&name, Some(None), Some(None))?
            } else {
                // Empty fields clear that figure; sizes as text ("1TB") or bytes.
                let bytes = match input.get("bytes") {
                    Some(Value::Number(n)) => Some(n.as_u64()),
                    Some(Value::String(t)) if t.trim().is_empty() => Some(None),
                    Some(Value::String(t)) => Some(Some(varsto_core::storage_settings::parse_size(t)?)),
                    _ => None,
                };
                let objects = match input.get("objects") {
                    Some(Value::Number(n)) => Some(n.as_u64()),
                    Some(Value::String(t)) if t.trim().is_empty() => Some(None),
                    Some(Value::String(t)) => Some(Some(t.trim().parse::<u64>().map_err(|_| anyhow!("not a number of objects: {t}"))?)),
                    _ => None,
                };
                engine.set_storage_quota(&name, bytes, objects)?
            };
            service.request_sync();
            Ok(serde_json::to_value(status)?)
        }
        (Method::Get, "/api/storage/drains") => Ok(serde_json::to_value(engine.drain_statuses()?)?),
        (Method::Get, "/api/storage/drain-plan") => {
            let name = query_param(query, "name").unwrap_or_default();
            let opts = varsto_core::engine::DrainOptions {
                remove_when_empty: false,
                budget_bytes_per_day: query_param(query, "budget_gb_per_day")
                    .and_then(|v| v.trim().parse::<f64>().ok())
                    .filter(|g| g.is_finite() && *g > 0.0)
                    .map(|g| (g * 1e9) as u64),
                confirm_cold_read: query_param(query, "confirm_cold_read").as_deref() == Some("true"),
            };
            Ok(serde_json::to_value(engine.drain_plan(&name, &opts)?)?)
        }
        (Method::Post, "/api/storage/drain") => {
            let name = s(input, "name")?;
            if input.get("stop").and_then(|v| v.as_bool()).unwrap_or(false) {
                engine.drain_stop(&name)?;
                service.request_sync();
                return Ok(json!({"ok": true, "stopped": true}));
            }
            let flag = |k: &str| input.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
            let budget = input
                .get("budget_gb_per_day")
                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|t| t.trim().parse().ok())))
                .filter(|g| g.is_finite() && *g > 0.0)
                .map(|g| (g * 1e9) as u64);
            let plan = engine.drain_start(
                &name,
                &varsto_core::engine::DrainOptions {
                    remove_when_empty: flag("remove_when_empty"),
                    budget_bytes_per_day: budget,
                    confirm_cold_read: flag("confirm_cold_read"),
                },
            )?;
            // The service moves the blocks after its next sync.
            service.request_sync();
            Ok(serde_json::to_value(plan)?)
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
            let kind = opt(input, "kind").unwrap_or_else(|| "local-dir".into());
            storage_kind_allowed(&kind, mobile())?;
            match kind.as_str() {
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
                            allow_insecure_http: flag(input, "insecure_http"),
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
                        min_free: None,
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
            // The folder's recovery copy: the words given with the request,
            // or the session copy (`unlock --with-recovery-key`).
            let k1 = opt(input, "recovery_words")
                .filter(|w| !w.trim().is_empty())
                .map(|w| {
                    varsto_core::logging::register_secret(w.trim());
                    varsto_core::membership3::RecoveryKey::from_words(w.trim())
                })
                .transpose()?;
            let id = engine.add_folder_with_recovery(&name, &path, k1)?;
            if !plain {
                engine.set_encrypted_here(&name, true)?;
            }
            // E.g. camera upload: a folder that sends and never applies others' changes.
            if let Some(mode) = opt(input, "mode").filter(|m| !m.trim().is_empty()) {
                engine.set_folder_mode(&name, mode.parse()?)?;
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
                staging: None,
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
        (Method::Post, "/api/folder/remove") if input.get("device").is_some() => {
            f3_api::remove_device(engine, service, input)
        }
        (Method::Post, "/api/folder/remove") => {
            let purge = input.get("purge").and_then(|v| v.as_bool()).unwrap_or(false);
            let deleted = engine.remove_folder(&s(input, "name")?, purge)?;
            service.folders_changed = true;
            Ok(json!({"ok": true, "objects_deleted": deleted}))
        }
        (Method::Post, "/api/folder/attach") => {
            let id = attach_request(engine, input)?;
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
        // The trash: files deleted on any device of the vault.
        (Method::Get, "/api/trash") => {
            let folder = query_param(query, "folder").filter(|f| !f.is_empty());
            Ok(serde_json::to_value(engine.trash_list(folder.as_deref())?)?)
        }
        (Method::Get, "/api/trash/status") => Ok(serde_json::to_value(engine.trash_status()?)?),
        (Method::Post, "/api/trash/restore-plan") => {
            let to = opt(input, "to").filter(|t| !t.trim().is_empty());
            Ok(serde_json::to_value(engine.trash_restore_plan(
                &s(input, "folder")?,
                &string_list(input, "paths"),
                to.as_deref(),
            )?)?)
        }
        (Method::Post, "/api/trash/restore") => {
            let to = opt(input, "to").filter(|t| !t.trim().is_empty());
            let cold = input.get("confirm_cold_read").and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.trash_restore(&s(input, "folder")?, &string_list(input, "paths"), to.as_deref(), cold)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/trash/purge") => {
            let folder = opt(input, "folder").filter(|f| !f.is_empty());
            let all = input.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.trash_purge(folder.as_deref(), &string_list(input, "paths"), all)?;
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/trash/set") => {
            let days = input
                .get("days")
                .and_then(|v| v.as_u64())
                .map(|d| d.min(u32::MAX as u64) as u32);
            let folder = opt(input, "folder").filter(|f| !f.is_empty());
            let storage: Option<Option<String>> = if input.get("no_storage").and_then(|v| v.as_bool()).unwrap_or(false) {
                Some(None)
            } else {
                opt(input, "storage").filter(|n| !n.is_empty()).map(Some)
            };
            let moved = matches!(storage, Some(Some(_)));
            let st = engine.trash_set(days, folder.as_deref(), storage)?;
            if moved {
                // What is in the trash now moves to the new trash storage.
                let r = engine.trash_upkeep()?;
                service.record_trash_upkeep(&r);
            }
            Ok(serde_json::to_value(st)?)
        }
        // The version history of overwritten files.
        (Method::Get, "/api/history") => {
            let folder = query_param(query, "folder").unwrap_or_default();
            let path = query_param(query, "path").unwrap_or_default();
            Ok(serde_json::to_value(engine.history_list(&folder, &path)?)?)
        }
        (Method::Get, "/api/history/status") => {
            Ok(serde_json::to_value(engine.history_status()?)?)
        }
        (Method::Post, "/api/history/restore-plan") | (Method::Post, "/api/history/restore") => {
            let plan_only = path.ends_with("-plan");
            let target = varsto_core::engine::HistoryTarget {
                to: opt(input, "to").filter(|t| !t.trim().is_empty()),
                as_name: opt(input, "as").filter(|t| !t.trim().is_empty()),
            };
            let (folder, path, version) =
                (s(input, "folder")?, s(input, "path")?, s(input, "version")?);
            if plan_only {
                return Ok(serde_json::to_value(
                    engine.history_restore_plan(&folder, &path, &version, &target)?,
                )?);
            }
            let cold = input.get("confirm_cold_read").and_then(|v| v.as_bool()).unwrap_or(false);
            let r = engine.history_restore(&folder, &path, &version, &target, cold)?;
            service.request_sync();
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/history/set") => {
            let days = input
                .get("days")
                .and_then(|v| v.as_u64())
                .map(|d| d.min(u32::MAX as u64) as u32);
            let folder = opt(input, "folder").filter(|f| !f.is_empty());
            let off = input.get("off").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(serde_json::to_value(engine.history_set(days, folder.as_deref(), off)?)?)
        }
        (Method::Post, "/api/trash/upkeep") => {
            let r = engine.trash_upkeep()?;
            service.record_trash_upkeep(&r);
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, "/api/sync") => {
            let folder = opt(input, "folder");
            varsto_core::events::publish("sync.started", json!({"reason": "requested", "folder": folder}));
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
        // Change history of a folder or a file (`varsto changes`).
        (Method::Get, "/api/changes") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            let since_utc = query_param(query, "since")
                .filter(|s| !s.is_empty())
                .map(|s| varsto_core::changes::parse_since(&s, varsto_core::util::now_utc()))
                .transpose()?;
            let q = varsto_core::engine::ChangesQuery {
                path: query_param(query, "path").filter(|s| !s.is_empty()),
                device: query_param(query, "device").filter(|s| !s.is_empty()),
                user: query_param(query, "user").filter(|s| !s.is_empty()),
                since_utc,
                limit: query_param(query, "limit")
                    .and_then(|l| l.parse().ok())
                    .unwrap_or(200),
            };
            Ok(serde_json::to_value(engine.changes(&folder, &q)?)?)
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
            "portmap": service.p2p_portmap,
            "portmap_text": service.p2p_portmap.describe(),
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
            // Router port mapping takes effect at once (the service's loop
            // reads the setting every half second).
            if let Some(pm) = input.get("port_mapping").and_then(|v| v.as_bool()) {
                c.port_mapping = pm;
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
        // Staged moves to disk pools: the open jobs, and pause/resume/cancel.
        (Method::Get, "/api/moves") => Ok(json!({"jobs": engine.move_jobs()})),
        (Method::Post, "/api/move/state") => {
            use varsto_core::staged_move::JobState;
            let state = match s(input, "action")?.as_str() {
                "pause" => JobState::Paused,
                "resume" => JobState::Open,
                "cancel" => JobState::Cancelled,
                other => bail!("unknown action {other}: use pause, resume or cancel"),
            };
            let job = engine.move_job_set_state(&s(input, "id")?, state)?;
            service.move_jobs = engine.move_jobs();
            service.move_jobs.retain(|j| j.state.is_open() || j.state == JobState::Paused);
            service.suggest_disks(engine);
            Ok(json!({"ok": true, "job": job}))
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
        // Every storage of the vault: configured here or only known from other devices.
        (Method::Get, "/api/storage/known") => {
            Ok(serde_json::to_value(engine.storage_directory()?)?)
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
        // Forwarding other devices' blocks to this device's storages (section 70).
        (Method::Get, "/api/forward") => Ok(serde_json::to_value(engine.forward_status())?),
        (Method::Post, "/api/forward") => {
            if let Some(on) = input.get("enabled").and_then(|v| v.as_bool()) {
                engine.set_forwarding(on)?;
            }
            service.forward = Some(engine.forward_status());
            Ok(serde_json::to_value(engine.forward_status())?)
        }
        (Method::Post, "/api/forward/run") => {
            let r = engine.forward(&varsto_core::engine::ForwardOptions::manual())?;
            service.forward = Some(engine.forward_status());
            Ok(serde_json::to_value(r)?)
        }
        // The mailbox for offline pool disks (section 78).
        (Method::Get, "/api/mailbox") => Ok(serde_json::to_value(engine.mailbox_status())?),
        (Method::Post, "/api/mailbox") => {
            let mut s = engine.mailbox_settings();
            if let Some(on) = input.get("enabled").and_then(|v| v.as_bool()) {
                s.enabled = on;
            }
            match input.get("keep_free") {
                Some(Value::Array(list)) => {
                    s.keep_free = list
                        .iter()
                        .filter_map(|v| v.as_str())
                        .filter(|v| !v.trim().is_empty())
                        .map(varsto_core::freespace::MinFree::parse)
                        .collect::<Result<_>>()?;
                }
                Some(Value::String(one)) if one.trim().is_empty() || one == "default" => {
                    s.keep_free.clear();
                }
                Some(Value::String(one)) => {
                    s.keep_free = vec![varsto_core::freespace::MinFree::parse(one)?];
                }
                _ => {}
            }
            engine.set_mailbox_settings(s)?;
            service.mailbox = Some(engine.mailbox_status());
            Ok(serde_json::to_value(engine.mailbox_status())?)
        }
        (Method::Post, "/api/mailbox/run") => {
            let r = engine.mailbox_run(&varsto_core::engine::MailboxOptions::manual())?;
            service.mailbox = Some(engine.mailbox_status());
            Ok(serde_json::to_value(r)?)
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
        (Method::Post, "/api/folder/safety") => {
            let action = s(input, "action")?;
            let out = folder_safety_action(engine, input)?;
            if action != "pending" {
                service.folders_changed = true;
                service.request_sync();
            }
            Ok(out)
        }
        (Method::Post, "/api/folder/min-free") => {
            let m = min_free_input(input)?;
            engine.set_folder_min_free(&s(input, "folder")?, m)?;
            // Space may be enough now: try what waits.
            service.request_sync();
            Ok(json!({"ok": true, "min_free": m.map(|m| m.setting())}))
        }
        (Method::Post, "/api/storage/min-free") => {
            let m = min_free_input(input)?;
            engine.set_storage_min_free(&s(input, "name")?, m)?;
            service.request_sync();
            Ok(json!({"ok": true, "min_free": m.map(|m| m.setting())}))
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
        (Method::Get, "/api/folder/ignore") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(serde_json::to_value(engine.folder_ignore(&folder)?)?)
        }
        (Method::Post, "/api/folder/ignore") => {
            // `synced`: the root .varstoignore as text; `local`: this
            // device's own patterns. Either may be left out.
            let local = input.get("local").and_then(|v| v.as_array()).map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str())
                    .map(str::trim_end)
                    .filter(|p| !p.trim().is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            });
            let synced = opt(input, "synced");
            engine.set_folder_ignore(&s(input, "folder")?, synced.as_deref(), local)?;
            service.request_sync();
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/folder/check-ignore") => {
            // A preview: the texts being edited stand for the saved rules.
            let local: Option<Vec<String>> =
                input.get("local").and_then(|v| v.as_array()).map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str().map(str::to_string))
                        .collect()
                });
            Ok(serde_json::to_value(engine.check_ignore(
                &s(input, "folder")?,
                &s(input, "path")?,
                opt(input, "synced").as_deref(),
                local.as_deref(),
            )?)?)
        }
        (Method::Get, "/api/folder/settings") => {
            let folder = query_param(query, "folder")
                .ok_or_else(|| anyhow!("folder query parameter required"))?;
            Ok(json!({
                "settings": engine.folder_settings(&folder)?,
                "caps": engine.meta_caps(),
            }))
        }
        (Method::Post, "/api/folder/settings") => {
            let folder = s(input, "folder")?;
            let mut st = engine.folder_settings(&folder)?;
            let flag = |k: &str, cur: bool| input.get(k).and_then(|v| v.as_bool()).unwrap_or(cur);
            st.permissions = flag("permissions", st.permissions);
            st.symlinks = flag("symlinks", st.symlinks);
            st.xattrs = flag("xattrs", st.xattrs);
            st.ownership = flag("ownership", st.ownership);
            engine.set_folder_settings(&folder, st)?;
            service.request_sync();
            Ok(json!({"ok": true, "settings": st}))
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

/// Folder membership of storage format 3 in the local API (work package
/// 8b): requests, approval, roles, removal, recovery copies and the pairing
/// question. Without the `format3` feature every route answers that it is
/// not available in this build.
mod f3_api {
    use super::*;

    #[cfg(not(feature = "format3"))]
    pub fn route(
        _engine: &mut Engine,
        _service: &mut ServiceState,
        _method: Method,
        _path: &str,
        _query: &str,
        _input: &Value,
    ) -> Result<Value> {
        bail!("folder membership of storage format 3 is not available in this build of Varsto")
    }

    #[cfg(not(feature = "format3"))]
    pub fn remove_device(
        _engine: &mut Engine,
        _service: &mut ServiceState,
        _input: &Value,
    ) -> Result<Value> {
        bail!("folder membership of storage format 3 is not available in this build of Varsto")
    }

    #[cfg(feature = "format3")]
    pub use real::*;

    #[cfg(feature = "format3")]
    mod real {
        use super::*;
        use std::sync::{Condvar, Mutex as StdMutex};
        use varsto_core::pair::v3::Joiner;

        /// The folders-changed event and a sync request: other devices
        /// fetch the new records at once.
        fn changed(service: &mut ServiceState, folder: &str, what: &str) {
            service.request_sync();
            varsto_core::events::publish("folder.changed", json!({"folder": folder, "what": what}));
        }

        pub fn route(
            engine: &mut Engine,
            service: &mut ServiceState,
            method: Method,
            path: &str,
            query: &str,
            input: &Value,
        ) -> Result<Value> {
            match (method, path) {
                (Method::Get, "/api/folder/requests") => {
                    let folder = query_param(query, "folder");
                    Ok(json!({ "requests": engine.f3_requests(folder.as_deref())? }))
                }
                (Method::Post, "/api/folder/request") => {
                    let role = opt(input, "role").unwrap_or_else(|| "editor".into());
                    let r = engine.f3_folder_request(&s(input, "folder")?, &role)?;
                    changed(service, &r.folder_id, "request");
                    Ok(serde_json::to_value(r)?)
                }
                (Method::Post, "/api/folder/approve") => {
                    // The person compared the six words with the requesting
                    // device; a call that does not say so grants nothing.
                    if input.get("fingerprint_confirmed").and_then(|v| v.as_bool()) != Some(true) {
                        bail!("approving needs \"fingerprint_confirmed\": true, after the six words were compared with the requesting device");
                    }
                    let m = engine.f3_approve(
                        &s(input, "folder")?,
                        &s(input, "device")?,
                        opt(input, "role").as_deref(),
                        opt(input, "fingerprint").as_deref(),
                    )?;
                    changed(service, &m.folder_id, "approve");
                    Ok(serde_json::to_value(m)?)
                }
                (Method::Post, "/api/folder/deny") => {
                    let m = engine.f3_deny(&s(input, "folder")?, &s(input, "device")?)?;
                    changed(service, &m.folder_id, "deny");
                    Ok(serde_json::to_value(m)?)
                }
                (Method::Get, "/api/folder/members") => match query_param(query, "folder") {
                    Some(folder) => Ok(serde_json::to_value(engine.f3_members(&folder)?)?),
                    // No folder named: every folder of the membership records.
                    None => Ok(json!({ "folders": engine.f3_folders()? })),
                },
                (Method::Post, "/api/folder/role") => {
                    let m = engine.f3_set_role(
                        &s(input, "folder")?,
                        &s(input, "device")?,
                        &s(input, "role")?,
                    )?;
                    changed(service, &m.folder_id, "role");
                    Ok(serde_json::to_value(m)?)
                }
                (Method::Post, "/api/folder/resolve-epoch") => {
                    let epoch = input
                        .get("epoch")
                        .and_then(|e| e.as_u64())
                        .and_then(|e| u32::try_from(e).ok())
                        .ok_or_else(|| anyhow!("missing field epoch"))?;
                    let m =
                        engine.f3_resolve_epoch(&s(input, "folder")?, epoch, &s(input, "keep")?)?;
                    changed(service, &m.folder_id, "resolve-epoch");
                    Ok(serde_json::to_value(m)?)
                }
                (Method::Get, "/api/recovery/escrow") => {
                    Ok(json!({ "missing": engine.f3_missing_escrows()? }))
                }
                (Method::Post, "/api/recovery/escrow") => {
                    let words = s(input, "words")?;
                    varsto_core::logging::register_secret(&words);
                    let k1 = varsto_core::membership3::RecoveryKey::from_words(&words)?;
                    let written = engine.f3_write_escrows(opt(input, "folder").as_deref(), &k1)?;
                    if !written.is_empty() {
                        changed(service, "", "escrow");
                    }
                    Ok(json!({ "written": written }))
                }
                (Method::Post, "/api/pair/answer") => answer_pair(engine, input),
                _ => bail!("unknown route {path}"),
            }
        }

        /// Remove a device from a folder: a new folder epoch. The call must
        /// say it was confirmed.
        pub fn remove_device(
            engine: &mut Engine,
            service: &mut ServiceState,
            input: &Value,
        ) -> Result<Value> {
            if input.get("confirm").and_then(|v| v.as_bool()) != Some(true) {
                bail!("removing a device from a folder needs \"confirm\": true; it starts a new folder epoch and the device keeps what it already read");
            }
            let name = opt(input, "folder")
                .or_else(|| opt(input, "name"))
                .ok_or_else(|| anyhow!("missing field folder"))?;
            let r = engine.f3_remove(&name, &s(input, "device")?, None)?;
            changed(service, &r.folder_id, "remove");
            Ok(serde_json::to_value(r)?)
        }

        // ----- pairing: the offering device asks its person --------------

        /// The joining device waiting for the person at this device.
        struct Gate {
            state: StdMutex<GateState>,
            cv: Condvar,
        }

        #[derive(Default)]
        struct GateState {
            ask: Option<Joiner>,
            answer: Option<bool>,
        }

        static GATE: StdMutex<Option<std::sync::Arc<Gate>>> = StdMutex::new(None);

        /// How long the person has to answer.
        const ANSWER_WITHIN: std::time::Duration = std::time::Duration::from_secs(300);

        fn gate() -> Option<std::sync::Arc<Gate>> {
            GATE.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        /// Open a format-3 pairing offer: the joining device's name and
        /// six words are held for the page (`ask` in the status) until the
        /// person answers with `POST /api/pair/answer`; nothing is sent
        /// before.
        pub fn start_offer(e: &Engine) -> Result<varsto_core::pair::Offer> {
            let mut bundle = e.pairing_bundle()?;
            let key = varsto_core::crypto::SecretKey::from_hex(&e.export_vault_key()?)?;
            bundle.vault_key = String::new();
            let g = std::sync::Arc::new(Gate {
                state: StdMutex::new(GateState::default()),
                cv: Condvar::new(),
            });
            *GATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(g.clone());
            let approve: varsto_core::pair::v3::Approve = std::sync::Arc::new(move |j: &Joiner| {
                let mut st = g.state.lock().unwrap_or_else(|e| e.into_inner());
                st.ask = Some(j.clone());
                st.answer = None;
                varsto_core::events::publish(
                    "pair.ask",
                    json!({"name": j.name, "fingerprint": j.fingerprint}),
                );
                let deadline = std::time::Instant::now() + ANSWER_WITHIN;
                let answer = loop {
                    if let Some(a) = st.answer {
                        break a;
                    }
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        break false;
                    }
                    st =
                        g.cv.wait_timeout(st, left)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                };
                st.ask = None;
                answer
            });
            varsto_core::pair::Offer::start_v3(bundle, key, approve)
        }

        /// What the pairing dialog shows: the joining device's name and
        /// words, and the folders this device owns (to tick).
        pub fn add_pair_ask(v: &mut Value, engine: Option<&mut Engine>) {
            let Some(g) = gate() else { return };
            let ask = g
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .ask
                .clone();
            let Some(j) = ask else { return };
            let folders: Vec<Value> = engine
                .and_then(|e| e.f3_folders().ok())
                .unwrap_or_default()
                .into_iter()
                .filter(|f| f.your_role.as_deref() == Some("owner"))
                .map(|f| json!({"id": f.folder_id, "name": f.folder}))
                .collect();
            v["ask"] = json!({"name": j.name, "fingerprint": j.fingerprint, "folders": folders});
        }

        /// The person's answer: with `allow`, the grants for the ticked
        /// folders (by default none) are written first, then the vault key
        /// is sent; without, the joining device is declined.
        fn answer_pair(engine: &mut Engine, input: &Value) -> Result<Value> {
            let g = gate().ok_or_else(|| anyhow!("no pairing offer is open"))?;
            let ask = g
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .ask
                .clone()
                .ok_or_else(|| anyhow!("no device is waiting for an answer"))?;
            let allow = input.get("allow").and_then(|v| v.as_bool()) == Some(true);
            let mut granted = Vec::new();
            if allow {
                let folders: Vec<String> = input
                    .get("folders")
                    .and_then(|f| f.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if !folders.is_empty() {
                    // The words the person saw must still be the joiner's.
                    if let Some(seen) = opt(input, "fingerprint") {
                        if seen.split_whitespace().collect::<Vec<_>>()
                            != ask.fingerprint.split_whitespace().collect::<Vec<_>>()
                        {
                            bail!("the words you saw are not the joining device's words; compare again");
                        }
                    }
                    let role = opt(input, "role").unwrap_or_else(|| "editor".into());
                    engine.f3_pair_grants(
                        &ask.name,
                        &ask.signing_pub,
                        &ask.kem_pub,
                        &folders,
                        &role,
                    )?;
                    granted = folders;
                }
            }
            let mut st = g.state.lock().unwrap_or_else(|e| e.into_inner());
            st.answer = Some(allow);
            g.cv.notify_all();
            drop(st);
            if !granted.is_empty() {
                varsto_core::events::publish("folder.changed", json!({"what": "pair-grant"}));
            }
            Ok(json!({"ok": true, "allowed": allow, "granted": granted}))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn phones_accept_only_s3_and_rclone_storages() {
        for k in ["s3", "rclone"] {
            assert!(super::storage_kind_allowed(k, true).is_ok());
        }
        for k in ["local-dir", "pool", "anything"] {
            assert!(super::storage_kind_allowed(k, true).is_err(), "{k}");
            assert!(super::storage_kind_allowed(k, false).is_ok(), "{k}");
        }
    }

    use super::*;

    /// The attach dialog's choices reach the mount: selective sync and the
    /// direction; a receive-only folder kept encrypted is refused before
    /// anything is attached.
    #[test]
    #[ignore = "f3-switch: port in part B (folder grants in the desktop attach route)"]
    fn attaching_takes_selective_sync_and_the_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let storage = StorageSpec::LocalDir {
            name: "box".into(),
            path: t.join("box"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        };
        std::fs::create_dir_all(t.join("box")).unwrap();
        let pass = "correct horse battery staple";
        let (mut a, key) = Engine::init(&t.join("a"), "phone", pass).unwrap();
        a.add_storage(storage.clone()).unwrap();
        a.add_folder("camera", &t.join("a-camera")).unwrap();
        a.add_folder("notes", &t.join("a-notes")).unwrap();
        a.sync(None).unwrap();
        let mut b = Engine::join(&t.join("b"), "laptop", pass, &key, storage).unwrap();

        let refused = attach_request(
            &mut b,
            &json!({"name_or_id": "notes", "path": t.join("b-notes"), "plain": false, "mode": "receive-only"}),
        );
        assert!(refused.is_err());
        assert!(
            attach_request(&mut b, &json!({"name_or_id": "notes", "mode": "sideways"})).is_err()
        );

        attach_request(
            &mut b,
            &json!({"name_or_id": "camera", "path": t.join("b-camera"), "plain": true, "selective": true, "mode": "send-only"}),
        )
        .unwrap();
        attach_request(
            &mut b,
            &json!({"name_or_id": "notes", "path": t.join("b-notes"), "plain": true}),
        )
        .unwrap();
        let st = b.status().unwrap();
        let of = |n: &str| st.folders.iter().find(|f| f.name == n).unwrap();
        assert!(of("camera").selective);
        assert_eq!(of("camera").mode, varsto_core::vault::FolderMode::SendOnly);
        assert!(!of("notes").selective);
        assert_eq!(of("notes").mode, varsto_core::vault::FolderMode::Normal);
    }

    /// A real server on a free port with a locked (engine-less) state.
    fn test_server() -> (u16, String, tempfile::TempDir) {
        let (port, token, tmp, _) = test_server_state();
        (port, token, tmp)
    }

    /// [`test_server`] and its state, for a test that holds it.
    fn test_server_state() -> (u16, String, tempfile::TempDir, Shared) {
        let tmp = tempfile::tempdir().unwrap();
        let (server, bound) = bind(0).unwrap();
        let token = random_hex();
        let state: Shared = Arc::new(Mutex::new(State {
            home: tmp.path().to_path_buf(),
            engine: None,
            token: token.clone(),
            bound: bound.clone(),
            traffic: Arc::default(),
            service: ServiceState::default(),
            pair: None,
            link: None,
        }));
        let server = Arc::new(server);
        let kept = state.clone();
        std::thread::spawn(move || serve_arc(server, state));
        (
            bound.rsplit(':').next().unwrap().parse().unwrap(),
            token,
            tmp,
            kept,
        )
    }

    #[test]
    fn reads_are_answered_while_a_long_operation_holds_the_state() {
        let (port, token, _tmp, state) = test_server_state();
        let h = [("X-Varsto-Token", token.as_str())];
        // Once answered fresh, the service summary is kept.
        let (st, head, fresh) = raw(port, "GET", "/api/service", &h, "");
        assert_eq!(st, 200);
        assert!(!head.contains("x-varsto-stale"));
        // A sync (here: the test) holds the state for two seconds.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = {
            let state = state.clone();
            std::thread::spawn(move || {
                let _g = state.lock().unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_secs(2));
            })
        };
        held_rx.recv().unwrap();
        let t = std::time::Instant::now();
        let (st, head, body) = raw(port, "GET", "/api/service", &h, "");
        let took = t.elapsed();
        assert_eq!(st, 200);
        assert!(
            took < std::time::Duration::from_millis(1000),
            "took {took:?}"
        );
        assert!(head.contains("x-varsto-stale: 1"), "{head}");
        assert!(head.contains("x-varsto-age-ms:"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let f: Value = serde_json::from_str(&fresh).unwrap();
        assert_eq!(v["stale"], true);
        assert!(v["stale_ms"].as_u64().is_some());
        assert_eq!(v["running"], f["running"]);
        // Several reads at once do not queue behind each other either.
        let many: Vec<_> = (0..4)
            .map(|_| {
                let token = token.clone();
                std::thread::spawn(move || {
                    let t = std::time::Instant::now();
                    let h = [("X-Varsto-Token", token.as_str())];
                    let st = raw(port, "GET", "/api/service", &h, "").0;
                    (st, t.elapsed())
                })
            })
            .collect();
        for m in many {
            let (st, took) = m.join().unwrap();
            assert_eq!(st, 200);
            assert!(
                took < std::time::Duration::from_millis(1000),
                "took {took:?}"
            );
        }
        // The page's assets and the activity are not held up meanwhile.
        let t = std::time::Instant::now();
        assert_eq!(raw(port, "GET", "/app.js", &[], "").0, 200);
        assert_eq!(raw(port, "GET", "/api/activity?mine=1", &h, "").0, 200);
        assert!(t.elapsed() < std::time::Duration::from_millis(1000));
        holder.join().unwrap();
        // Free again: fresh.
        let (st, head, _) = raw(port, "GET", "/api/service", &h, "");
        assert_eq!(st, 200);
        assert!(!head.contains("x-varsto-stale"));
    }

    #[test]
    fn a_change_through_the_api_drops_the_cached_reads() {
        let (port, token, _tmp, state) = test_server_state();
        let h = [("X-Varsto-Token", token.as_str())];
        assert_eq!(raw(port, "GET", "/api/state", &h, "").0, 200);
        // Any request that is not a GET may have changed something (this
        // one is refused, which does not matter).
        assert_eq!(raw(port, "POST", "/api/no-such-change", &h, "{}").0, 400);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = {
            let state = state.clone();
            std::thread::spawn(move || {
                let _g = state.lock().unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(800));
            })
        };
        held_rx.recv().unwrap();
        // Nothing cached any more: the read waits for the state, and its
        // answer is fresh.
        let t = std::time::Instant::now();
        let (st, head, _) = raw(port, "GET", "/api/state", &h, "");
        assert_eq!(st, 200);
        assert!(!head.contains("x-varsto-stale"));
        assert!(t.elapsed() >= std::time::Duration::from_millis(500));
        holder.join().unwrap();
    }

    /// One raw request; returns (status, lowercase head, body).
    fn raw(
        port: u16,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, String, String) {
        use std::io::{Read, Write};
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        c.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let text = String::from_utf8_lossy(&out).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head.to_lowercase(), body.to_string())
    }

    #[test]
    fn boot_code_opens_the_session_once() {
        let (port, token, _tmp) = test_server();
        let h = [("X-Varsto-Token", token.as_str())];
        let (st, _, body) = raw(port, "POST", "/api/session/boot", &h, "{}");
        assert_eq!(st, 200);
        let code = serde_json::from_str::<Value>(&body).unwrap()["boot"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(code.len(), 64);
        let ask = json!({"boot": code}).to_string();
        let (st, head, body) = raw(port, "POST", "/api/session", &[], &ask);
        assert_eq!(st, 200);
        assert!(head.contains("cache-control: no-store"));
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["token"],
            token.as_str()
        );
        // The second use, a wrong code and no code are refused.
        assert_eq!(raw(port, "POST", "/api/session", &[], &ask).0, 401);
        assert_eq!(
            raw(port, "POST", "/api/session", &[], r#"{"boot":"00"}"#).0,
            401
        );
        assert_eq!(raw(port, "POST", "/api/session", &[], "{}").0, 401);
        // Asking for a code needs the token.
        assert_eq!(raw(port, "POST", "/api/session/boot", &[], "{}").0, 401);
    }

    #[test]
    fn expired_boot_code_is_refused() {
        // A store of its own: redeeming "in the future" purges every code
        // that would have expired by then, which must not touch the codes
        // other tests are using at the same time.
        let grants = Mutex::new(Grants {
            boot: std::collections::BTreeMap::new(),
            tickets: std::collections::BTreeMap::new(),
        });
        let now = std::time::Instant::now();
        let code = mint_boot_code_in(&grants, now);
        assert!(!redeem_boot_code_in(
            &grants,
            &code,
            now + BOOT_TTL + std::time::Duration::from_secs(1)
        ));
        let code = mint_boot_code_in(&grants, now);
        assert!(redeem_boot_code_in(
            &grants,
            &code,
            now + std::time::Duration::from_secs(30)
        ));
        assert!(!redeem_boot_code_in(
            &grants,
            &code,
            now + std::time::Duration::from_secs(31)
        ));
    }

    #[test]
    fn the_token_is_never_accepted_in_the_address() {
        let (port, token, _tmp) = test_server();
        for route in [
            "/api/thumb",
            "/api/open",
            "/api/view",
            "/api/events",
            "/api/state",
        ] {
            let target = format!("{route}?folder=a&path=b&token={token}");
            assert_eq!(raw(port, "GET", &target, &[], "").0, 401, "{route}");
        }
        // The header forms work: the locked vault has no thumbnail (404).
        let t = "/api/thumb?folder=a&path=b";
        assert_eq!(
            raw(port, "GET", t, &[("X-Varsto-Token", &token)], "").0,
            404
        );
        let bearer = format!("Bearer {token}");
        let (st, head, _) = raw(port, "GET", t, &[("Authorization", &bearer)], "");
        assert_eq!(st, 404);
        assert!(head.contains("cache-control: no-store"));
        assert_eq!(
            raw(port, "GET", t, &[("Authorization", "Bearer nope")], "").0,
            401
        );
        // Malformed escapes in a query do not stop the server.
        assert_eq!(
            raw(
                port,
                "GET",
                "/api/thumb?folder=%a%C3%A9&path=%&token=%a%C3%A9",
                &[],
                ""
            )
            .0,
            401
        );
        assert_eq!(
            raw(port, "GET", t, &[("X-Varsto-Token", &token)], "").0,
            404
        );
    }

    /// A GET with the token; returns (status, lowercase head, raw body).
    fn get_bytes(port: u16, token: &str, target: &str) -> (u16, String, Vec<u8>) {
        use std::io::{Read, Write};
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nX-Varsto-Token: {token}\r\n\r\n");
        c.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let at = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete response");
        let head = String::from_utf8_lossy(&out[..at]).to_lowercase();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head, out[at + 4..].to_vec())
    }

    /// The page may show pictures from blob: addresses: thumbnails are fetched
    /// with the session header and shown from a blob (an `img` cannot send a
    /// header), so a policy without `blob:` in `img-src` blanks every one.
    #[test]
    fn the_page_policy_lets_thumbnail_blobs_load() {
        let (port, _token, _tmp) = test_server();
        let (st, head, _) = raw(port, "GET", "/", &[], "");
        assert_eq!(st, 200);
        let csp = head
            .lines()
            .find(|l| l.starts_with("content-security-policy:"))
            .expect("a content security policy");
        let img = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("img-src"))
            .expect("an img-src directive");
        assert!(img.split(' ').any(|s| s == "blob:"), "{img}");
        assert!(img.split(' ').any(|s| s == "'self'"), "{img}");
        // Still no remote pictures.
        assert!(!img.contains("http"), "{img}");
    }

    /// `/api/thumb` answers real JPEGs of the right size, again and again
    /// (every request reads the storage; nothing empty is ever kept).
    #[test]
    fn thumb_endpoint_serves_decodable_pictures() {
        let (port, token, tmp, state) = test_server_state();
        let root = tmp.path();
        let (mut engine, _) = Engine::init(&root.join("dev"), "laptop", "pass phrase 123").unwrap();
        engine
            .add_storage(StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("box"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            })
            .unwrap();
        let pics = root.join("pics");
        std::fs::create_dir_all(&pics).unwrap();
        engine.add_folder("pics", &pics).unwrap();
        image::RgbImage::from_fn(640, 480, |x, y| image::Rgb([x as u8, y as u8, 40]))
            .save(pics.join("a b.png"))
            .unwrap();
        image::RgbImage::from_fn(300, 500, |x, y| image::Rgb([y as u8, x as u8, 90]))
            .save(pics.join("c.jpg"))
            .unwrap();
        engine.push("pics").unwrap();
        state.lock().unwrap().engine = Some(engine);
        for (path, w, h) in [("a%20b.png", 256, 192), ("c.jpg", 154, 256)] {
            let target = format!("/api/thumb?folder=pics&path={path}");
            for round in 0..3 {
                let (st, head, body) = get_bytes(port, &token, &target);
                assert_eq!(st, 200, "{path} round {round}");
                assert!(head.contains("content-type: image/jpeg"), "{head}");
                assert!(
                    head.contains(&format!("content-length: {}", body.len())),
                    "{head}"
                );
                assert!(body.len() > 200, "{path}: {} bytes", body.len());
                assert_eq!(&body[..2], &[0xff, 0xd8]);
                let img = image::load_from_memory(&body).unwrap().to_rgb8();
                assert!(
                    (img.width() as i64 - w).abs() <= 1 && (img.height() as i64 - h).abs() <= 1,
                    "{path}: {}x{}",
                    img.width(),
                    img.height()
                );
            }
        }
        // Not a picture: no thumbnail, and an honest 404 (the page then
        // shows its placeholder).
        assert_eq!(
            get_bytes(port, &token, "/api/thumb?folder=pics&path=nope.png").0,
            404
        );
    }

    #[test]
    fn tickets_open_exactly_one_file() {
        let (port, token, _tmp) = test_server();
        let h = [("X-Varsto-Token", token.as_str())];
        let ask = json!({"route": "/api/open", "folder": "Docs", "path": "a b.txt"}).to_string();
        let (st, _, body) = raw(port, "POST", "/api/ticket", &h, &ask);
        assert_eq!(st, 200);
        let t = serde_json::from_str::<Value>(&body).unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_string();
        // Past authentication (the locked vault answers 400), for the same
        // file only and only on the route it was made for.
        assert_eq!(
            raw(
                port,
                "GET",
                &format!("/api/open?folder=Docs&path=a%20b.txt&ticket={t}"),
                &[],
                ""
            )
            .0,
            400
        );
        assert_eq!(
            raw(
                port,
                "GET",
                &format!("/api/open?folder=Docs&path=other&ticket={t}"),
                &[],
                ""
            )
            .0,
            401
        );
        assert_eq!(
            raw(
                port,
                "GET",
                &format!("/api/view?folder=Docs&path=a%20b.txt&ticket={t}"),
                &[],
                ""
            )
            .0,
            401
        );
        assert_eq!(
            raw(port, "GET", &format!("/api/state?ticket={t}"), &[], "").0,
            401
        );
        assert_eq!(raw(port, "POST", "/api/ticket", &[], &ask).0, 401);
    }

    #[test]
    fn percent_decode_survives_malformed_escapes() {
        assert_eq!(percent_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%C3%A4"), "\u{e4}");
        assert_eq!(percent_decode("a+b%20c%41"), "a b cA");
        assert_eq!(percent_decode("%\u{e9}\u{e9}"), "%\u{e9}\u{e9}");
        assert_eq!(
            query_param("token=%a\u{e9}&x=1", "token").unwrap(),
            "%a\u{e9}"
        );
    }

    #[test]
    fn session_tokens_match_exactly_and_only_exactly() {
        // Correctness of the constant-time comparison; its timing is the
        // property of `crypto::ct_eq`, tested there.
        let token = "0123456789abcdef0123456789abcdef";
        assert!(token_matches(token, token));
        assert!(!token_matches("", token));
        assert!(!token_matches(token, ""));
        assert!(!token_matches(&token[..31], token));
        assert!(!token_matches(&format!("{token}0"), token));
        assert!(!token_matches("0123456789abcdef0123456789abcdeF", token));
        assert!(!token_matches("x123456789abcdef0123456789abcdef", token));
    }

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
        let (mut engine, _) =
            Engine::init(&root.join("home"), "laptop", "pass phrase 123").unwrap();
        engine
            .add_storage(StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("box"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
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
    fn help_api_answers_without_a_vault_locked_and_open() {
        use varsto_core::storage::StorageSpec;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let mut st = State {
            home: home.clone(),
            engine: None,
            token: "t".into(),
            bound: "127.0.0.1:0".into(),
            traffic: Arc::default(),
            service: ServiceState {
                running: true,
                ..Default::default()
            },
            pair: None,
            link: None,
        };
        let get = |st: &mut State, query: &str| {
            api(st, Method::Get, "/api/help", query, &json!({})).unwrap()
        };

        // No vault: create one or pair, on the setup screen.
        let h = get(&mut st, "");
        assert_eq!(h["phase"], "no_vault");
        assert_eq!(h["steps"][0]["id"], "create_vault");
        assert_eq!(h["steps"][0]["action"]["page"], "setup");
        assert_eq!(h["steps"][0]["action"]["target"], "init");
        assert!(h["steps"][0]["title"]["t"].is_string());
        let t = get(&mut st, "format=text");
        assert!(t["text"].as_str().unwrap().contains("WHAT TO DO NEXT"));

        // A vault, locked.
        let (engine, _) = Engine::init(&home, "laptop", "pass phrase 123").unwrap();
        drop(engine);
        let h = get(&mut st, "");
        assert_eq!(h["phase"], "locked");
        assert_eq!(h["steps"][0]["id"], "unlock");
        assert_eq!(h["headline"]["p"]["device"], "laptop");

        // Open, no storage: add a storage; then a folder.
        st.engine = Some(Engine::open(&home, "pass phrase 123").unwrap());
        let h = get(&mut st, "");
        assert_eq!(h["phase"], "ready");
        assert_eq!(h["steps"][0]["id"], "add_storage");
        assert_eq!(h["steps"][0]["action"]["target"], "addstorage");
        assert_eq!(h["figures"]["devices"], 1);
        st.engine
            .as_mut()
            .unwrap()
            .add_storage(StorageSpec::LocalDir {
                name: "box".into(),
                path: tmp.path().join("box"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            })
            .unwrap();
        let h = get(&mut st, "");
        assert_eq!(h["steps"][0]["id"], "add_folder");
        assert_eq!(h["storages"][0]["name"], "box");
        assert_eq!(h["summary"][1]["p"]["names"], "box");

        // Paused in the service: resume first.
        st.service.paused = true;
        let h = get(&mut st, "");
        assert_eq!(h["steps"][0]["id"], "resume");
        assert!(h["attention"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == "service"));
    }

    /// Every sentence the Help page can show has a Finnish and a Swedish
    /// translation (the templates are the English string literals of
    /// `help.rs` given to `t0`/`tx` and the buttons' labels).
    #[test]
    fn status_carries_the_protection_of_each_folder() {
        use varsto_core::storage::StorageSpec;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let (mut engine, _) = Engine::init(&home, "laptop", "pass phrase 123").unwrap();
        engine
            .add_storage(StorageSpec::LocalDir {
                name: "box".into(),
                path: tmp.path().join("box"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            })
            .unwrap();
        let docs = tmp.path().join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("a.bin"), vec![7u8; 50_000]).unwrap();
        engine.add_folder("docs", &docs).unwrap();
        engine.push("docs").unwrap();
        let mut st = State {
            home,
            engine: Some(engine),
            token: "t".into(),
            bound: "127.0.0.1:0".into(),
            traffic: Arc::default(),
            service: ServiceState::default(),
            pair: None,
            link: None,
        };
        let v = api(&mut st, Method::Get, "/api/status", "", &json!({})).unwrap();
        let f = &v["folders"][0];
        assert_eq!(f["name"], "docs");
        let p = &f["protection"];
        // One directory is one of the user's own disks: all there, no cloud.
        assert_eq!(p["state"], "disks");
        assert_eq!(p["pct"], json!(100.0));
        assert_eq!(p["disks"]["pct"], json!(100.0));
        assert_eq!(p["cloud"]["pct"], json!(0.0));
        assert_eq!(p["cloud"]["bytes"], json!(0));
        let (total, size) = (
            p["total_bytes"].as_u64().unwrap(),
            f["bytes"].as_u64().unwrap(),
        );
        assert!(total > 0 && total <= size, "{total} of {size}");
        assert!(p["total_blocks"].as_u64().unwrap() >= 1);
        for k in ["verified_pct", "verified_bytes", "blocks"] {
            assert!(p["disks"].get(k).is_some(), "disks lacks {k}: {p}");
        }
        assert!(f["last_change_utc"].is_i64());
        assert_eq!(
            p["policy_state"], "violated",
            "default policy wants a cloud copy: {p}"
        );
    }

    /// `/api/mailbox`: the status and the settings (section 78).
    #[test]
    fn the_mailbox_api_shows_the_status_and_changes_the_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let (engine, _) = Engine::init(&home, "laptop", "pass phrase 123").unwrap();
        let mut st = State {
            home,
            engine: Some(engine),
            token: "t".into(),
            bound: "127.0.0.1:0".into(),
            traffic: Arc::default(),
            service: ServiceState::default(),
            pair: None,
            link: None,
        };
        let v = api(&mut st, Method::Get, "/api/mailbox", "", &json!({})).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["keep_free"], json!(["15%", "50000000000"]));
        assert_eq!(v["keep_free_text"], "15 % or 50.0 GB, whichever is more");
        assert_eq!(v["groups"], json!([]));
        let v = api(
            &mut st,
            Method::Post,
            "/api/mailbox",
            "",
            &json!({"keep_free": ["10GB", "5%"], "enabled": false}),
        )
        .unwrap();
        assert_eq!(v["enabled"], false);
        assert_eq!(v["keep_free"], json!(["10000000000", "5%"]));
        assert!(st.service.mailbox.is_some());
        assert!(api(
            &mut st,
            Method::Post,
            "/api/mailbox",
            "",
            &json!({"keep_free": ["lots"]})
        )
        .is_err());
        let v = api(
            &mut st,
            Method::Post,
            "/api/mailbox",
            "",
            &json!({"keep_free": "default", "enabled": true}),
        )
        .unwrap();
        assert_eq!(v["keep_free"], json!(["15%", "50000000000"]));
        let r = api(&mut st, Method::Post, "/api/mailbox/run", "", &json!({})).unwrap();
        assert_eq!(r["staged"], 0);
        assert_eq!(r["enabled"], true);
    }

    #[test]
    fn help_sentences_are_translated() {
        let src = include_str!("../../varsto-core/src/help.rs");
        let src = &src[..src.find("pub fn render_text").unwrap()];
        let mut found = Vec::new();
        for marker in ["t0(", "tx(", ".act("] {
            for (at, _) in src.match_indices(marker) {
                // Not the helpers' own definitions.
                if src[..at].ends_with("fn ") {
                    continue;
                }
                let rest = &src[at + marker.len()..];
                // t0/tx with a literal (not a variable): the first literal;
                // act: the last one in the call (the label).
                if !rest.trim_start().starts_with('"') {
                    continue;
                }
                let call = if marker == ".act(" {
                    let end = [rest.find("\")\n"), rest.find("\").")]
                        .into_iter()
                        .flatten()
                        .min()
                        .unwrap();
                    &rest[..end + 1]
                } else {
                    rest
                };
                let mut lits = Vec::new();
                let mut r = call;
                while let Some(q) = r.find('"') {
                    let body = &r[q + 1..];
                    let end = body.find('"').unwrap();
                    lits.push(&body[..end]);
                    r = &body[end + 1..];
                    if marker != ".act(" {
                        break;
                    }
                }
                if let Some(l) = lits.last() {
                    found.push(l.to_string());
                }
            }
        }
        assert!(found.len() > 150, "{}", found.len());
        for (lang, dict) in [("fi", I18N_FI), ("sv", I18N_SV)] {
            let d: Value = serde_json::from_str(dict).unwrap();
            let missing: Vec<&String> = found
                .iter()
                .filter(|t| t.len() > 1 && d["strings"].get(t.as_str()).is_none())
                .collect();
            assert!(missing.is_empty(), "{lang} lacks {missing:?}");
        }
    }

    /// Double-quoted string literals of a script (escapes resolved for `\"`
    /// only), leaving out `//` comments.
    fn js_literals(src: &str) -> Vec<String> {
        let b: Vec<char> = src.chars().collect();
        let (mut out, mut i) = (Vec::new(), 0);
        while i < b.len() {
            if b[i] == '/' && b.get(i + 1) == Some(&'/') && (i == 0 || b[i - 1] != ':') {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            } else if b[i] == '"' {
                let mut lit = String::new();
                i += 1;
                while i < b.len() && b[i] != '"' && b[i] != '\n' {
                    if b[i] == '\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    lit.push(b[i]);
                    i += 1;
                }
                out.push(lit);
                i += 1;
            } else {
                i += 1;
            }
        }
        out
    }

    /// Visible text and `title`, `placeholder`, `aria-label` and `alt` values
    /// of the static page.
    fn html_texts(page: &str) -> Vec<String> {
        let mut page = page.to_string();
        for tag in ["script", "style"] {
            while let Some(a) = page.find(&format!("<{tag}")) {
                let end = page[a..].find(&format!("</{tag}>")).unwrap() + a + tag.len() + 3;
                page.replace_range(a..end, "");
            }
        }
        let norm = |t: &str| {
            t.replace("&amp;", "&")
                .replace("&middot;", "\u{b7}")
                .replace("&larr;", "\u{2190}")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut out = Vec::new();
        for chunk in page.split('<').skip(1) {
            let (tag, text) = chunk.split_once('>').unwrap_or((chunk, ""));
            out.push(norm(text));
            for attr in ["title", "placeholder", "aria-label", "alt"] {
                if let Some(a) = tag.find(&format!(" {attr}=\"")) {
                    let rest = &tag[a + attr.len() + 3..];
                    out.push(norm(&rest[..rest.find('"').unwrap_or(rest.len())]));
                }
            }
        }
        out.retain(|t| t.chars().filter(|c| c.is_ascii_alphabetic()).count() >= 2);
        out
    }

    /// A sentence-like literal the interface might show: capitalised words
    /// with ordinary punctuation, no code or paths.
    fn looks_like_ui_text(l: &str) -> bool {
        let mut c = l.chars();
        let (a, b) = (c.next(), c.next());
        // A literal ending in a space is the start of a message the script completes.
        matches!((a, b), (Some(a), Some(b)) if a.is_ascii_uppercase() && b.is_ascii_lowercase())
            && l.contains(' ')
            && !l.ends_with(' ')
            && l.chars()
                .all(|c| c.is_ascii_alphabetic() || " ',.()-:?!".contains(c))
    }

    #[test]
    fn interface_translations_cover_the_page() {
        // Names, examples and technical terms that stay as they are, and
        // literals that are not shown (comments, fonts, browser errors) or
        // that the script completes with a pattern (a prefix before a
        // number or a name).
        const SAME: &[&str] = &[
            "*.tmp",
            "Android",
            "DEEP_ARCHIVE, GLACIER_IR, STANDARD_IA",
            "Documents",
            "Linux",
            "OK",
            "Varsto",
            "Varsto v",
            "Windows",
            "box",
            "dana",
            "data-01",
            "eu-central-1",
            "fr-par",
            "hetzner:backup/varsto",
            "iOS",
            "laptop",
            "macOS",
            "my-laptop",
            "phone",
            "reset",
            "shelf",
            "varsto",
            "varsto mcp grant",
            "varsto org request",
            "work-laptop",
            "Archive is almost full",
            "Attach disk C",
            "Could not reach the Varsto service (",
            "Every file in the trash (",
            "Failed to fetch",
            "Helvetica Neue",
            "Home NAS",
            "Laptop backup",
            "Load failed",
            "Segoe UI",
            "Suggested next",
            "The camera could not be opened (",
            "/Volumes/box",
            "https://s3.fr-par.scw.cloud",
            "/Users/me/Documents",
            "/media/me/data-01",
            "https://s3.eu-central-1.amazonaws.com",
            "/Users/me/Pictures",
            "/Volumes/Old drive/Photos",
            "/Users/me/Varsto/Photos",
            "stun.example.net:3478",
            "Documents: a verification is about to age out",
        ];
        // Messages put together from parts are translated by patterns (a
        // whole text) or parts (inside a text); the ones the page builds
        // from counts and names must stay covered.
        const COMPOSED: &[&str] = &[
            r"^1 file$",
            r"^(\d+) files$",
            r"^(\d+) blocks$",
            r"^(\d+) folders$",
            r"^(\d+) storages$",
            r"^(\d+) devices$",
            r"^(\d+) active$",
            "^via ([^\u{b7}]+)$",
            r"^(\d+) ledger batches$",
            r"^added ([\d.\-/: ]+)$",
            r"next in (\d+) s",
            "this device is an administrator",
            r"(\d+) people\b",
            r"(\d+) administrators\b",
            "(^|; )not on this device(?=;|$)",
            "(^|; )on this device(?=;|$)",
            r"every block of this folder is on storage ([^;]+)",
        ];
        let page_texts = html_texts(INDEX_HTML);
        assert!(page_texts.len() > 400, "{}", page_texts.len());
        let mut used: Vec<String> = page_texts;
        for src in [APP_JS, FOLDERS_JS, VIZ_JS] {
            used.extend(
                js_literals(src)
                    .into_iter()
                    .filter(|l| looks_like_ui_text(l)),
            );
        }
        assert!(used.len() > 800, "{}", used.len());
        for (lang, dict) in [("fi", I18N_FI), ("sv", I18N_SV)] {
            let d: Value = serde_json::from_str(dict).unwrap();
            let top: Vec<&String> = d.as_object().unwrap().keys().collect();
            // i18n.js reads only these three; a string next to them is never shown.
            assert_eq!(
                top,
                ["parts", "patterns", "strings"],
                "{lang}: keys outside the known three"
            );
            let strings = d["strings"].as_object().unwrap();
            assert!(
                strings
                    .values()
                    .all(|v| v.as_str().is_some_and(|t| !t.is_empty())),
                "{lang}"
            );
            let pairs: Vec<&str> = ["patterns", "parts"]
                .iter()
                .flat_map(|k| d[*k].as_array().unwrap())
                .map(|p| {
                    let p = p.as_array().unwrap();
                    assert!(
                        p.len() == 2 && p.iter().all(Value::is_string),
                        "{lang}: {p:?}"
                    );
                    p[0].as_str().unwrap()
                })
                .collect();
            let missing: Vec<&String> = used
                .iter()
                .filter(|t| !SAME.contains(&t.as_str()) && !strings.contains_key(t.as_str()))
                // Messages with a number or name in them are matched by a pattern.
                .filter(|t| {
                    !pairs
                        .iter()
                        .any(|p| p.starts_with('^') && p.contains(t.trim_end_matches(['(', ' '])))
                })
                .collect();
            assert!(missing.is_empty(), "{lang} lacks {missing:?}");
            for c in COMPOSED {
                assert!(pairs.contains(c), "{lang} lacks the pattern {c}");
            }
        }
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

    // ----- folder membership of storage format 3 (work package 8b) ----------

    /// A vault of two devices on one directory storage, and the folder
    /// `docs` in the membership records of the first.
    #[cfg(feature = "format3")]
    fn f3_pair(t: &std::path::Path) -> (Engine, Engine, String) {
        let storage = StorageSpec::LocalDir {
            name: "box".into(),
            path: t.join("box"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        };
        std::fs::create_dir_all(t.join("box")).unwrap();
        let pass = "correct horse battery staple";
        let (mut a, key) = Engine::init(&t.join("a"), "alpha", pass).unwrap();
        a.add_storage(storage.clone()).unwrap();
        let b = Engine::join(&t.join("b"), "bravo", pass, &key, storage).unwrap();
        let id = a.f3_folder_create("docs", None).unwrap();
        (a, b, id)
    }

    #[cfg(feature = "format3")]
    fn f3_call(
        engine: &mut Engine,
        service: &mut ServiceState,
        m: Method,
        path: &str,
        query: &str,
        input: Value,
    ) -> Result<Value> {
        api_unlocked(engine, service, m, path, query, &input)
    }

    #[cfg(feature = "format3")]
    #[test]
    fn folder_membership_endpoints() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut a, mut b, folder_id) = f3_pair(tmp.path());
        let (mut sa, mut sb) = (ServiceState::default(), ServiceState::default());
        let seen = varsto_core::events::bus().last_id();

        // The requesting device asks; the owner lists the request with the words.
        let asked = f3_call(
            &mut b,
            &mut sb,
            Method::Post,
            "/api/folder/request",
            "",
            json!({"folder": "docs", "role": "viewer"}),
        )
        .unwrap();
        let words = asked["fingerprint"].as_str().unwrap().to_string();
        let bravo = asked["device_id"].as_str().unwrap().to_string();
        let listed = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/folder/requests",
            "",
            json!({}),
        )
        .unwrap();
        assert_eq!(listed["requests"].as_array().unwrap().len(), 1);
        assert_eq!(listed["requests"][0]["device"], "bravo");
        assert_eq!(listed["requests"][0]["fingerprint"], json!(words));
        let one = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/folder/requests",
            "folder=docs",
            json!({}),
        )
        .unwrap();
        assert_eq!(one["requests"].as_array().unwrap().len(), 1);

        // Approving needs the confirmation, and the words must be the request's.
        for body in [
            json!({"folder": "docs", "device": bravo}),
            json!({"folder": "docs", "device": bravo, "fingerprint_confirmed": false}),
            json!({"folder": "docs", "device": bravo, "fingerprint_confirmed": "true"}),
        ] {
            let e = f3_call(
                &mut a,
                &mut sa,
                Method::Post,
                "/api/folder/approve",
                "",
                body,
            )
            .unwrap_err();
            assert!(format!("{e:#}").contains("fingerprint_confirmed"), "{e:#}");
        }
        let e = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/approve",
            "",
            json!({"folder": "docs", "device": bravo, "fingerprint_confirmed": true, "fingerprint": "one two three four five six"}),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("request changed"), "{e:#}");
        // Nothing was granted by the refusals.
        let m = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/folder/members",
            "folder=docs",
            json!({}),
        )
        .unwrap();
        assert_eq!(m["participants"].as_array().unwrap().len(), 1);

        let m = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/approve",
            "",
            json!({"folder": "docs", "device": bravo, "role": "viewer", "fingerprint": words, "fingerprint_confirmed": true}),
        )
        .unwrap();
        assert_eq!(m["folder_id"], json!(folder_id));
        let roles: Vec<(String, String)> = m["participants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["device"].as_str().unwrap().to_string(),
                    p["role"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert!(
            roles.contains(&("bravo".into(), "viewer".into())),
            "{roles:?}"
        );
        assert!(sa.sync_requested, "other devices fetch the records at once");

        // Every folder, and the role of the requesting device on its own side.
        let all = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/folder/members",
            "",
            json!({}),
        )
        .unwrap();
        assert_eq!(all["folders"].as_array().unwrap().len(), 1);
        let mine = f3_call(
            &mut b,
            &mut sb,
            Method::Get,
            "/api/folder/members",
            "folder=docs",
            json!({}),
        )
        .unwrap();
        assert_eq!(mine["your_role"], "viewer");

        // A role change, by an owner only.
        let e = f3_call(
            &mut b,
            &mut sb,
            Method::Post,
            "/api/folder/role",
            "",
            json!({"folder": "docs", "device": bravo, "role": "editor"}),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("not an owner"), "{e:#}");
        let m = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/role",
            "",
            json!({"folder": "docs", "device": bravo, "role": "editor"}),
        )
        .unwrap();
        assert!(m["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["device"] == "bravo" && p["role"] == "editor"));
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/role",
            "",
            json!({"folder": "docs", "device": bravo, "role": "boss"})
        )
        .is_err());

        // Deny: a second request, answered with a refusal.
        let key = a.export_vault_key().unwrap();
        let mut c = Engine::join(
            &tmp.path().join("c"),
            "charlie",
            "correct horse battery staple",
            &key,
            a.storages()[0].clone(),
        )
        .unwrap();
        let mut sc = ServiceState::default();
        let asked = f3_call(
            &mut c,
            &mut sc,
            Method::Post,
            "/api/folder/request",
            "",
            json!({"folder": "docs"}),
        )
        .unwrap();
        let charlie = asked["device_id"].as_str().unwrap().to_string();
        let m = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/deny",
            "",
            json!({"folder": "docs", "device": charlie}),
        )
        .unwrap();
        assert!(m["denied"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["device"] == "charlie"));
        assert!(m["pending"].as_array().unwrap().is_empty());

        // Removing needs "confirm"; then a new folder epoch starts.
        let e = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/remove",
            "",
            json!({"folder": "docs", "device": bravo}),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("confirm"), "{e:#}");
        let r = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/remove",
            "",
            json!({"folder": "docs", "device": bravo, "confirm": true}),
        )
        .unwrap();
        assert_eq!(r["epoch"], 1);
        assert_eq!(r["removed"], "bravo");
        let m = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/folder/members",
            "folder=docs",
            json!({}),
        )
        .unwrap();
        assert_eq!(m["epoch"], 1);
        assert!(!m["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["device"] == "bravo"));
        // The vault's own folder removal keeps working on the same path.
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/remove",
            "",
            json!({"name": "nothing"})
        )
        .is_err());

        // Nothing to resolve without two epochs under one number.
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/resolve-epoch",
            "",
            json!({"folder": "docs", "epoch": 1, "keep": "alpha"})
        )
        .is_err());
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/folder/resolve-epoch",
            "",
            json!({"folder": "docs", "keep": "alpha"})
        )
        .is_err());

        // Recovery copies: listed, written with the words, then none left.
        let missing = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/recovery/escrow",
            "",
            json!({}),
        )
        .unwrap();
        let n = missing["missing"].as_array().unwrap().len();
        assert!(n >= 2, "epochs 0 and 1 lack a copy: {missing}");
        assert_eq!(missing["missing"][0]["folder"], "docs");
        assert!(missing["missing"][0]["warning"]
            .as_str()
            .unwrap()
            .contains("has no recovery copy: run varsto recovery escrow docs"));
        let st = f3_call(&mut a, &mut sa, Method::Get, "/api/status", "", json!({})).unwrap();
        assert_eq!(st["recovery_warnings"].as_array().unwrap().len(), n);
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/recovery/escrow",
            "",
            json!({"words": "abandon abandon"})
        )
        .is_err());
        assert!(f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/recovery/escrow",
            "",
            json!({})
        )
        .is_err());
        let words = varsto_core::membership3::RecoveryKey::generate()
            .words()
            .unwrap()
            .to_string();
        let w = f3_call(
            &mut a,
            &mut sa,
            Method::Post,
            "/api/recovery/escrow",
            "",
            json!({"words": words}),
        )
        .unwrap();
        assert_eq!(w["written"].as_array().unwrap().len(), n);
        let missing = f3_call(
            &mut a,
            &mut sa,
            Method::Get,
            "/api/recovery/escrow",
            "",
            json!({}),
        )
        .unwrap();
        assert!(missing["missing"].as_array().unwrap().is_empty());
        let st = f3_call(&mut a, &mut sa, Method::Get, "/api/status", "", json!({})).unwrap();
        assert!(st.get("recovery_warnings").is_none());

        // The page hears about it.
        let kinds: Vec<String> = match varsto_core::events::bus().since(seen) {
            varsto_core::events::Since::Events(v) => v.into_iter().map(|e| e.kind).collect(),
            other => panic!("{other:?}"),
        };
        assert!(kinds.iter().any(|k| k == "folder.changed"), "{kinds:?}");
    }

    /// The service announces requests (`folder.request`) and never answers one.
    #[cfg(feature = "format3")]
    #[test]
    fn the_service_announces_requests_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut a, mut b, _) = f3_pair(tmp.path());
        let mut sb = ServiceState::default();
        let mut service = ServiceState::default();
        let seen = varsto_core::events::bus().last_id();
        service.watch_folder_requests(&mut a);
        f3_call(
            &mut b,
            &mut sb,
            Method::Post,
            "/api/folder/request",
            "",
            json!({"folder": "docs"}),
        )
        .unwrap();
        service.watch_folder_requests(&mut a);
        service.watch_folder_requests(&mut a);
        let n = match varsto_core::events::bus().since(seen) {
            varsto_core::events::Since::Events(v) => v
                .iter()
                .filter(|e| e.kind == "folder.request" && e.data["device"] == "bravo")
                .count(),
            other => panic!("{other:?}"),
        };
        assert_eq!(n, 1, "announced once");
        // Still pending: the service granted nothing.
        assert_eq!(a.f3_requests(None).unwrap().len(), 1);
        assert_eq!(a.f3_members("docs").unwrap().participants.len(), 1);
    }

    /// A device that joins by pairing, as the offering side sees it.
    #[cfg(feature = "format3")]
    fn f3_joiner(
        name: &'static str,
        code: String,
        port: u16,
    ) -> (std::thread::JoinHandle<Result<(), String>>, String) {
        use varsto_core::pair::v3;
        let sk = varsto_core::crypto::SigningKey::generate();
        let dk = varsto_core::kem::DecapsKey::generate();
        let sk_pub = sk.public().to_bytes();
        let device = hex::encode(varsto_core::membership3::device_id(&sk.public()));
        let h = std::thread::spawn(move || {
            let keys = v3::JoinKeys {
                name,
                signing_pub: sk_pub,
                kem: &dk,
            };
            let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
            v3::fetch(&code, &keys, addr)
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        (h, device)
    }

    /// The pairing question on the offering side: the joining device's name
    /// and words wait for the person; nothing is sent before the answer;
    /// ticked folders are granted before the vault key goes out.
    #[cfg(feature = "format3")]
    #[test]
    fn pairing_asks_the_person_and_grants_only_ticked_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut a, _b, _) = f3_pair(tmp.path());
        a.f3_folder_create("photos", None).unwrap();
        let mut st = State {
            home: tmp.path().join("a"),
            engine: Some(a),
            token: String::new(),
            bound: "127.0.0.1:0".into(),
            traffic: Arc::default(),
            service: ServiceState::default(),
            pair: None,
            link: None,
        };
        let wait_ask = |st: &mut State| -> Value {
            for _ in 0..200 {
                let s = api(st, Method::Get, "/api/pair/status", "", &json!({})).unwrap();
                if s.get("ask").is_some() {
                    return s["ask"].clone();
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            panic!("no question");
        };
        let started = api(
            &mut st,
            Method::Post,
            "/api/pair/start",
            "",
            &json!({"format": 3}),
        )
        .unwrap();
        let code = started["code"].as_str().unwrap().to_string();
        let port = started["port"].as_u64().unwrap() as u16;

        // The joining device waits; the question names it and lists the owned folders.
        let (h, device) = f3_joiner("phone", code.clone(), port);
        let ask = wait_ask(&mut st);
        assert_eq!(ask["name"], "phone");
        assert_eq!(ask["fingerprint"].as_str().unwrap().split(' ').count(), 6);
        let mut names: Vec<&str> = ask["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["docs", "photos"]);
        assert!(!h.is_finished(), "nothing is sent before the answer");
        // Words that are not the joiner's refuse the grants and leave the question open.
        let e = api(
            &mut st,
            Method::Post,
            "/api/pair/answer",
            "",
            &json!({"allow": true, "folders": ["docs"], "fingerprint": "a b c d e f"}),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("compare again"), "{e:#}");
        assert!(!h.is_finished());
        // Ticking one folder grants it and no other.
        let done = api(
            &mut st,
            Method::Post,
            "/api/pair/answer",
            "",
            &json!({"allow": true, "folders": ["docs"], "fingerprint": ask["fingerprint"]}),
        )
        .unwrap();
        assert_eq!(done["granted"], json!(["docs"]));
        h.join().unwrap().unwrap();
        let a = st.engine.as_mut().unwrap();
        let docs = a.f3_members("docs").unwrap();
        assert!(
            docs.participants
                .iter()
                .any(|p| p.device_id == device && p.role == "editor"),
            "{docs:?}"
        );
        let photos = a.f3_members("photos").unwrap();
        assert!(!photos.participants.iter().any(|p| p.device_id == device));

        // A second device is declined: no grants, and it learns so.
        let started = api(
            &mut st,
            Method::Post,
            "/api/pair/start",
            "",
            &json!({"format": 3}),
        )
        .unwrap();
        let code2 = started["code"].as_str().unwrap().to_string();
        let port2 = started["port"].as_u64().unwrap() as u16;
        let (h2, device2) = f3_joiner("tablet", code2, port2);
        wait_ask(&mut st);
        let done = api(
            &mut st,
            Method::Post,
            "/api/pair/answer",
            "",
            &json!({"allow": false, "folders": ["docs"]}),
        )
        .unwrap();
        assert_eq!(done["allowed"], false);
        assert!(h2.join().unwrap().is_err());
        let a = st.engine.as_mut().unwrap();
        assert!(!a
            .f3_members("docs")
            .unwrap()
            .participants
            .iter()
            .any(|p| p.device_id == device2));
        // With no question open there is nothing to answer.
        assert!(api(
            &mut st,
            Method::Post,
            "/api/pair/answer",
            "",
            &json!({"allow": true})
        )
        .is_err());
    }

    /// The folder access card: every element the script reaches exists in
    /// the page, approving always goes through the confirmation box, and the
    /// pairing question is answered through the API (no browser needed).
    #[test]
    fn folder_access_page_is_wired() {
        for id in [
            "f3card",
            "f3recovery",
            "f3recovery-names",
            "f3recovery-go",
            "f3folders",
        ] {
            assert!(
                INDEX_HTML.contains(&format!("id=\"{id}\"")),
                "page lacks {id}"
            );
            assert!(
                APP_JS.contains(&format!("$(\"{id}\")")),
                "script lacks {id}"
            );
        }
        // The card starts hidden: a build or vault without membership shows nothing.
        let card = &INDEX_HTML[INDEX_HTML.find("id=\"f3card\"").unwrap()..];
        assert!(card[..card.find('>').unwrap()].contains("hidden"));
        // Approve: the box must be ticked before the button works, and the
        // request carries the confirmation the API insists on.
        assert!(APP_JS.contains("ok.disabled = true; cb.onchange"));
        assert!(APP_JS.contains("r.values.match !== \"yes\""));
        assert!(APP_JS.contains("fingerprint_confirmed: true"));
        // Removal names its consequence and sends the confirmation.
        assert!(APP_JS.contains("starts a new folder epoch"));
        assert!(APP_JS.contains("confirm: true"));
        // The events and the pairing question.
        for k in [
            "folder.request",
            "folder.changed",
            "pair.ask",
            "/api/pair/answer",
        ] {
            assert!(APP_JS.contains(k), "script lacks {k}");
        }
    }

    /// A build without the feature answers every route with the same text.
    #[cfg(not(feature = "format3"))]
    #[test]
    fn folder_membership_routes_say_not_available() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut a, _key) = Engine::init(
            &tmp.path().join("a"),
            "alpha",
            "correct horse battery staple",
        )
        .unwrap();
        let mut service = ServiceState::default();
        for (m, path) in [
            (Method::Get, "/api/folder/requests"),
            (Method::Post, "/api/folder/request"),
            (Method::Post, "/api/folder/approve"),
            (Method::Post, "/api/folder/deny"),
            (Method::Get, "/api/folder/members"),
            (Method::Post, "/api/folder/role"),
            (Method::Post, "/api/folder/resolve-epoch"),
            (Method::Get, "/api/recovery/escrow"),
            (Method::Post, "/api/recovery/escrow"),
        ] {
            let e = api_unlocked(
                &mut a,
                &mut service,
                m,
                path,
                "",
                &json!({"folder": "docs", "device": "x"}),
            )
            .unwrap_err();
            assert!(
                format!("{e:#}").contains("not available in this build"),
                "{path}: {e:#}"
            );
        }
        let e = api_unlocked(
            &mut a,
            &mut service,
            Method::Post,
            "/api/folder/remove",
            "",
            &json!({"folder": "docs", "device": "x", "confirm": true}),
        )
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("not available in this build"),
            "{e:#}"
        );
    }
}
