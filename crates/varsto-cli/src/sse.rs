// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `GET /api/events`: the service's events (`varsto_core::events`) as
//! Server-Sent Events, so that the interface follows syncs, tasks,
//! transfers, peers and changes instead of asking every few seconds.
//!
//! The session token comes in the `X-Varsto-Token` header or, for the
//! browser's `EventSource` (which cannot set headers), as `?token=` like
//! the viewer's links. A client that reconnects sends `Last-Event-ID` (or
//! `?last_id=`) and gets what it missed from the ring, or a `reset` event
//! when it fell too far behind. A comment line goes out every 15 seconds
//! when nothing else did, so that proxies and the browser keep the
//! connection open.
//!
//! Besides the numbered events of the bus, a connection can ask for two
//! unnumbered ones that only matter while a page shows them:
//! `?traffic=1` adds `traffic` (the peer traffic report, every second) and
//! `?peers=1` adds `activity.peers` (what the other devices are doing, when
//! it changed; the service keeps asking them while such a connection is
//! open).
//!
//! The sampler thread (`spawn_sampler`) turns what has no event of its own
//! into events, at most once a second: this device's tasks
//! (`activity.started`, `activity.progress`, `activity.finished`), the
//! transfers (`transfers`), and peers seen or gone (`peer.connected`,
//! `peer.disconnected`).

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_http::{Header, Request, Response};
use varsto_core::events::{self, Since};

/// Connections served at once; more get 503 (a page open in many tabs).
pub const MAX_CLIENTS: usize = 16;
/// A comment goes out after this long without anything else.
pub const KEEPALIVE: Duration = Duration::from_secs(15);
/// A peer seen within this long counts as connected.
const PEER_SEEN: i64 = 60;

static CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Connections open now.
pub fn clients() -> usize {
    CLIENTS.load(Ordering::Relaxed)
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("ascii header")
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

/// Serve `GET /api/events` on a thread of its own (the token was checked).
pub fn serve(request: Request, query: &str, traffic: Arc<varsto_core::p2p::Traffic>) {
    if CLIENTS.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
        CLIENTS.fetch_sub(1, Ordering::SeqCst);
        let _ = request.respond(
            Response::from_string("too many event streams open")
                .with_status_code(503)
                .with_header(header("Retry-After", "10")),
        );
        return;
    }
    let last = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Last-Event-ID"))
        .map(|h| h.value.as_str().trim().to_string())
        .or_else(|| query_param(query, "last_id"))
        .and_then(|v| v.parse::<u64>().ok());
    let watch_traffic = query_param(query, "traffic").as_deref() == Some("1");
    let watch_peers = query_param(query, "peers").as_deref() == Some("1");
    let spawned = std::thread::Builder::new()
        .name("http-events".into())
        .spawn(move || {
            // The response head goes out at once and the stream stays ours:
            // no length, no chunking, every event flushed as it is written.
            let response = Response::empty(200)
                .with_header(header("Content-Type", "text/event-stream; charset=utf-8"))
                .with_header(header("Cache-Control", "no-store"))
                .with_header(header("X-Content-Type-Options", "nosniff"));
            let mut stream = request.upgrade("varsto-events", response);
            let _ = run(
                &mut stream,
                last,
                watch_traffic,
                watch_peers,
                &traffic,
                &SHUTDOWN,
            );
            CLIENTS.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        CLIENTS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Set when the service stops: the streams end.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Write the stream until the client goes away or `stop` is set.
pub fn run(
    out: &mut dyn Write,
    last: Option<u64>,
    watch_traffic: bool,
    watch_peers: bool,
    traffic: &varsto_core::p2p::Traffic,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let bus = events::bus();
    let send = |out: &mut dyn Write, text: &str| -> std::io::Result<()> {
        out.write_all(text.as_bytes())?;
        out.flush()
    };
    send(out, "retry: 3000\n\n")?;
    let newest = bus.last_id();
    // What the page needs to start: where the numbers are, this device's
    // tasks and the transfers.
    let hello = json!({
        "last_id": newest,
        "activity": varsto_core::activity::local_here(),
        "transfers": transfers_now(),
    });
    send(out, &unnumbered("hello", &hello))?;
    let mut at = match last {
        None => newest,
        Some(l) => match bus.since(l) {
            Since::Events(v) => {
                for e in &v {
                    send(out, &e.sse())?;
                }
                v.last().map(|e| e.id).unwrap_or(l)
            }
            Since::Reset(n) => {
                send(out, &unnumbered("reset", &json!({"last_id": n})))?;
                n
            }
        },
    };
    let mut last_write = Instant::now();
    let mut last_traffic = Instant::now() - Duration::from_secs(2);
    let mut last_peers: Option<Value> = None;
    let mut last_peer_check = Instant::now() - Duration::from_secs(2);
    let mut last_watch = Instant::now() - Duration::from_secs(60);
    while !stop.load(Ordering::Relaxed) {
        match bus.wait(at, Duration::from_millis(500)) {
            Since::Events(v) => {
                for e in &v {
                    send(out, &e.sse())?;
                    at = e.id;
                    last_write = Instant::now();
                }
            }
            Since::Reset(n) => {
                send(out, &unnumbered("reset", &json!({"last_id": n})))?;
                at = n;
                last_write = Instant::now();
            }
        }
        if watch_traffic && last_traffic.elapsed() >= Duration::from_secs(1) {
            last_traffic = Instant::now();
            let report = serde_json::to_value(traffic.report()).unwrap_or(Value::Null);
            send(out, &unnumbered("traffic", &report))?;
            last_write = Instant::now();
        }
        if watch_peers {
            let peers = varsto_core::activity::global();
            // Asking keeps the service asking the peers (`WATCH_FOR`).
            if last_watch.elapsed() >= Duration::from_secs(10) {
                last_watch = Instant::now();
                peers.watch();
            }
            if last_peer_check.elapsed() >= Duration::from_secs(1) {
                last_peer_check = Instant::now();
                let report = serde_json::to_value(peers.report()).unwrap_or(Value::Null);
                // Ages tick every second: compare without them.
                let key = strip_ages(&report);
                if last_peers.as_ref() != Some(&key) {
                    last_peers = Some(key);
                    send(
                        out,
                        &unnumbered("activity.peers", &json!({ "peers": report })),
                    )?;
                    last_write = Instant::now();
                }
            }
        }
        if last_write.elapsed() >= KEEPALIVE {
            send(out, ": keepalive\n\n")?;
            last_write = Instant::now();
        }
    }
    Ok(())
}

/// An event without a number: it is not replayed after a reconnect.
fn unnumbered(kind: &str, data: &Value) -> String {
    format!(
        "event: {kind}\ndata: {}\n\n",
        serde_json::to_string(&json!({ "kind": kind, "data": data })).unwrap_or_default()
    )
}

fn strip_ages(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(k, _)| k.as_str() != "age_secs" && k.as_str() != "updated_utc")
                .map(|(k, v)| (k.clone(), strip_ages(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(strip_ages).collect()),
        other => other.clone(),
    }
}

fn transfers_now() -> Value {
    json!({
        "download": varsto_core::progress::current(),
        "transfers": varsto_core::progress::all(),
    })
}

/// What the sampler saw last.
#[derive(Default)]
pub struct Sampler {
    tasks: BTreeMap<u64, Value>,
    transfers: Option<Value>,
    peers: BTreeMap<String, Value>,
}

impl Sampler {
    /// Compare with the last look and publish what changed.
    pub fn sample(&mut self, traffic: &varsto_core::p2p::Traffic) {
        // This device's tasks.
        let now: BTreeMap<u64, Value> = varsto_core::activity::local_here()
            .tasks
            .into_iter()
            .map(|t| (t.id, serde_json::to_value(&t).unwrap_or(Value::Null)))
            .collect();
        for (id, t) in &now {
            match self.tasks.get(id) {
                None => {
                    events::publish("activity.started", t.clone());
                }
                Some(before) if task_moved(before, t) => {
                    events::publish("activity.progress", t.clone());
                }
                _ => {}
            }
        }
        for (id, t) in &self.tasks {
            if !now.contains_key(id) {
                events::publish(
                    "activity.finished",
                    json!({"id": id, "kind": t["kind"], "subject": t["subject"]}),
                );
            }
        }
        self.tasks = now;
        // Transfers (downloads and uploads of files), when anything moved.
        let tr = transfers_now();
        if self.transfers.as_ref() != Some(&tr) {
            let idle =
                tr["transfers"].as_array().is_none_or(|a| a.is_empty()) && tr["download"].is_null();
            let was_idle = self.transfers.as_ref().is_none_or(|p| {
                p["transfers"].as_array().is_none_or(|a| a.is_empty()) && p["download"].is_null()
            });
            if !(idle && was_idle) {
                events::publish("transfers", tr.clone());
            }
            self.transfers = Some(tr);
        }
        // Peers seen within the last minute.
        let report = traffic.report();
        let now_utc = varsto_core::util::now_utc();
        let seen: BTreeMap<String, Value> = report
            .peers
            .iter()
            .filter(|p| p.active > 0 || p.last_seen_utc.is_some_and(|t| now_utc - t < PEER_SEEN))
            .map(|p| {
                (
                    p.device.to_string(),
                    json!({"device": p.device, "name": p.name, "path": p.path, "addr": p.addr}),
                )
            })
            .collect();
        for (d, p) in &seen {
            if !self.peers.contains_key(d) {
                events::publish("peer.connected", p.clone());
            }
        }
        for (d, p) in &self.peers {
            if !seen.contains_key(d) {
                events::publish("peer.disconnected", p.clone());
            }
        }
        self.peers = seen;
    }
}

/// Worth an `activity.progress`: more done, another step, total or file.
fn task_moved(a: &Value, b: &Value) -> bool {
    ["done", "total", "phase", "detail", "percent"]
        .iter()
        .any(|k| a[*k] != b[*k])
}

/// Look every second until `stop` (the service runs one).
pub fn spawn_sampler(traffic: Arc<varsto_core::p2p::Traffic>, stop: Arc<AtomicBool>) {
    let _ = std::thread::Builder::new()
        .name("events-sampler".into())
        .spawn(move || {
            let mut s = Sampler::default();
            while !stop.load(Ordering::Relaxed) {
                // Only while someone listens; the first look after a quiet
                // spell publishes the tasks running then.
                if clients() > 0 {
                    s.sample(&traffic);
                } else {
                    s = Sampler::default();
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects what the stream writes; fails writes after `stop_after`
    /// bytes, as a closed connection does.
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn stream(last: Option<u64>, ms: u64) -> String {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (b2, s2) = (buf.clone(), stop.clone());
        let t = std::thread::spawn(move || {
            let traffic = varsto_core::p2p::Traffic::new();
            run(&mut Sink(b2), last, true, false, &traffic, &s2).unwrap();
        });
        std::thread::sleep(Duration::from_millis(ms));
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        let out = buf.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn hello_then_new_events_and_resume_from_the_last_seen() {
        let first = events::publish("test.sse", json!({"n": 1}));
        // A fresh client: hello, nothing old, then what comes.
        let h = std::thread::spawn(|| stream(None, 1500));
        std::thread::sleep(Duration::from_millis(300));
        let second = events::publish("test.sse", json!({"n": 2}));
        let text = h.join().unwrap();
        assert!(
            text.starts_with("retry: 3000\n\nevent: hello\ndata: {"),
            "{text}"
        );
        assert!(!text.contains(&format!("id: {first}\n")), "{text}");
        assert!(
            text.contains(&format!("id: {second}\nevent: test.sse\ndata: ")),
            "{text}"
        );
        // Traffic was asked for: one report a second.
        assert!(text.contains("event: traffic\ndata: "), "{text}");
        // Reconnecting after the first: the second is replayed.
        let text = stream(Some(first), 200);
        assert!(
            text.contains(&format!("id: {second}\nevent: test.sse")),
            "{text}"
        );
        // A number from before a restart: reset.
        let text = stream(Some(u64::MAX / 2), 200);
        assert!(text.contains("event: reset\n"), "{text}");
    }

    #[test]
    fn keepalive_after_a_quiet_spell() {
        // Shortened: the constant is 15 s; here the loop is checked to write
        // a comment only after it (nothing in under a second).
        let text = stream(None, 700);
        assert!(!text.contains(": keepalive"));
    }

    #[test]
    fn the_sampler_turns_tasks_into_events() {
        let traffic = varsto_core::p2p::Traffic::new();
        let mut s = Sampler::default();
        let before = events::bus().last_id();
        let task = varsto_core::activity::start(
            varsto_core::activity::UPLOAD,
            "sampler-test",
            100,
            varsto_core::activity::Unit::Bytes,
        );
        // Tasks show after a short quiet time (`activity::QUIET`).
        std::thread::sleep(Duration::from_millis(2100));
        s.sample(&traffic);
        task.advance(40);
        s.sample(&traffic);
        s.sample(&traffic); // nothing moved: no event
        drop(task);
        s.sample(&traffic);
        let Since::Events(v) = events::bus().since(before) else {
            panic!()
        };
        let mine: Vec<&events::Event> = v
            .iter()
            .filter(|e| e.kind.starts_with("activity.") && (e.data["subject"] == "sampler-test"))
            .collect();
        let kinds: Vec<&str> = mine.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["activity.started", "activity.progress", "activity.finished"],
            "{v:?}"
        );
        assert_eq!(mine[1].data["done"], 40);
    }
}
