// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The network front: axum HTTP + WebSocket routes, the UDP loop, and the
//! sweeper. Every route answers with and without the `/rv` prefix (Caddy
//! `handle_path /rv/*` strips it, `handle /rv/*` keeps it).

use crate::control::{Ctx, Hub, SessionId};
use crate::limits::{Buckets, Class, RateLimit};
use crate::proto::{
    self, DeleteSlot, ErrorAnswer, ErrorCode, Health, Info, Lookup, PutSlot, ToClient, Token,
};
use crate::registry::{LookupEncoder, Registry};
use crate::relay::{Caps, RelayTable, Side, SpliceLimits, TagBytes, Throttle};
use crate::udp::Observed;
use crate::Config;
use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::stream;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};

/// Counters for `/health`.
#[derive(Debug, Default)]
pub struct Counters {
    pub relay_bytes: AtomicU64,
    pub udp_answered: AtomicU64,
    pub refused: AtomicU64,
    pub rate_limited: AtomicU64,
    /// Control messages dropped because the connection did not read.
    pub control_dropped: AtomicU64,
    /// Control connections closed for not reading.
    pub control_slow: AtomicU64,
    /// Relay sessions ended by a spent tag quota.
    pub quota_stopped: AtomicU64,
}

/// The state every route shares. Locks are std mutexes held for a few
/// map operations, never across an await.
pub struct Shared {
    pub cfg: Config,
    pub registry: Mutex<Registry>,
    pub hub: Mutex<Hub>,
    pub relays: Mutex<RelayTable>,
    pub observed: Mutex<Observed>,
    pub limiter: Arc<dyn RateLimit>,
    pub counters: Counters,
    /// The global relay rate, when capped.
    pub throttle: Option<Throttle>,
    /// Relay bytes per tag and window.
    pub tag_bytes: TagBytes,
    shutdown: watch::Sender<bool>,
    /// Per-process salt for the hashed addresses of debug logs.
    salt: [u8; 16],
    /// Control connections' queues, and how many messages each lost.
    senders: Mutex<HashMap<SessionId, (mpsc::Sender<ToClient>, u32)>>,
    waiting: Mutex<HashMap<u64, (Side, oneshot::Sender<DuplexStream>)>>,
    next_session: AtomicU64,
    started: Instant,
    udp_announced: Vec<String>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    /// The `/health` counters now.
    pub fn health(&self) -> Health {
        let c = self.registry.lock().unwrap().counts();
        Health {
            uptime: self.started.elapsed().as_secs(),
            tags: c.tags as u64,
            slots: c.slots as u64,
            pair_offers: c.pair_offers as u64,
            controls: self.hub.lock().unwrap().len() as u64,
            relays: self.relays.lock().unwrap().active() as u64,
            relay_bytes: self.counters.relay_bytes.load(Ordering::Relaxed),
            udp_answered: self.counters.udp_answered.load(Ordering::Relaxed),
            refused: self.counters.refused.load(Ordering::Relaxed),
            rate_limited: self.counters.rate_limited.load(Ordering::Relaxed),
        }
    }

    fn info(&self) -> Info {
        Info {
            v: proto::VERSION,
            server: concat!("varsto-rendezvous ", env!("CARGO_PKG_VERSION")).to_string(),
            udp: self.udp_announced.clone(),
            relay: self.cfg.relay,
            limits: self.cfg.limits.clone(),
            time: unix_now(),
        }
    }

    fn deliver(&self, out: Vec<(SessionId, ToClient)>) {
        let mut senders = self.senders.lock().unwrap();
        let mut slow = Vec::new();
        for (id, m) in out {
            if let Some((tx, lost)) = senders.get_mut(&id) {
                // A connection that does not read its messages loses them,
                // and is closed once it has lost too many.
                if tx.try_send(m).is_err() {
                    *lost += 1;
                    self.counters
                        .control_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    if *lost > self.cfg.control_drop_max {
                        slow.push(id);
                    }
                }
            }
        }
        for id in slow {
            // Dropping the sender ends the connection's loop.
            if senders.remove(&id).is_some() {
                self.counters.control_slow.fetch_add(1, Ordering::Relaxed);
                log::debug!("control {id} closed: not reading");
            }
        }
    }

    /// A short, salted hash for debug logs (never the address itself).
    fn hash_ip(&self, ip: IpAddr) -> String {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&self.salt);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(&crate::limits::ip_key(ip));
        hex::encode(&h.finalize().as_bytes()[..4])
    }

    /// Ask every open connection to finish.
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// The totals as one log line (no tags, no addresses).
    pub fn stats_line(&self) -> String {
        format!(
            "stats {} dropped={} slow_closed={} quota_stopped={}",
            self.health().line(),
            self.counters.control_dropped.load(Ordering::Relaxed),
            self.counters.control_slow.load(Ordering::Relaxed),
            self.counters.quota_stopped.load(Ordering::Relaxed),
        )
    }
}

/// A bound server, not yet serving.
pub struct Bound {
    pub http_addr: SocketAddr,
    pub udp_addr: Option<SocketAddr>,
    pub shared: Arc<Shared>,
    listener: tokio::net::TcpListener,
    udp: Option<Arc<tokio::net::UdpSocket>>,
}

/// Bind the TCP listener and the UDP socket.
pub async fn bind(cfg: Config) -> Result<Bound> {
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("listen on {}", cfg.listen))?;
    let http_addr = listener.local_addr()?;
    let udp = match cfg.udp {
        Some(a) => Some(Arc::new(
            tokio::net::UdpSocket::bind(a)
                .await
                .with_context(|| format!("UDP on {a}"))?,
        )),
        None => None,
    };
    let udp_addr = match &udp {
        Some(u) => Some(u.local_addr()?),
        None => None,
    };
    let udp_announced = if !cfg.public_udp.is_empty() {
        cfg.public_udp.clone()
    } else {
        udp_addr.map(|a| vec![a.to_string()]).unwrap_or_default()
    };
    let shared = Arc::new(Shared {
        registry: Mutex::new(Registry::new(cfg.max_slots, cfg.max_bytes)),
        hub: Mutex::new(Hub::default()),
        relays: Mutex::new(RelayTable::new(cfg.limits.relay_per_tag)),
        observed: Mutex::new(Observed::default()),
        limiter: Arc::new(Buckets::new(cfg.rates.clone())),
        counters: Counters::default(),
        throttle: (cfg.relay_total_rate > 0).then(|| Throttle::new(cfg.relay_total_rate)),
        tag_bytes: TagBytes::new(cfg.relay_tag_bytes, cfg.relay_tag_window),
        shutdown: watch::channel(false).0,
        salt: proto::random_token(),
        senders: Mutex::new(HashMap::new()),
        waiting: Mutex::new(HashMap::new()),
        next_session: AtomicU64::new(1),
        started: Instant::now(),
        udp_announced,
        cfg,
    });
    Ok(Bound {
        http_addr,
        udp_addr,
        shared,
        listener,
        udp,
    })
}

impl Bound {
    /// Serve until `stop` completes.
    pub async fn run(self, stop: impl std::future::Future<Output = ()> + Send + 'static) {
        let shared = self.shared.clone();
        if let Some(udp) = self.udp.clone() {
            tokio::spawn(udp_loop(udp, shared.clone()));
        }
        tokio::spawn(sweeper(shared.clone()));
        let app = router(shared.clone());
        let mut down = shared.shutdown.subscribe();
        let serve = axum::serve(
            self.listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = down.wait_for(|v| *v).await;
        });
        // After the stop signal open connections are asked to finish and get
        // `grace` to do so; then the server stops anyway.
        let stopper = {
            let shared = shared.clone();
            async move {
                stop.await;
                log::info!("shutting down");
                shared.begin_shutdown();
                tokio::time::sleep(shared.cfg.grace).await;
            }
        };
        tokio::select! {
            r = serve => {
                if let Err(e) = r {
                    log::error!("http server: {e}");
                }
            }
            () = stopper => log::info!("grace period over, closing"),
        }
    }
}

/// The routes, at the root and under `/rv`.
pub fn router(shared: Arc<Shared>) -> Router {
    let inner = Router::new()
        .route(proto::PATH_INFO, get(info))
        .route(proto::PATH_HEALTH, get(health))
        .route(proto::PATH_PUT, post(put))
        .route(proto::PATH_DELETE, post(delete))
        .route(proto::PATH_LOOKUP, post(lookup))
        .route(proto::PATH_CONTROL, get(control))
        .route(&format!("{}/{{token}}", proto::PATH_RELAY), get(relay))
        .layer(DefaultBodyLimit::max(proto::MAX_BODY));
    Router::new()
        .merge(inner.clone())
        .nest("/rv", inner)
        .with_state(shared)
}

fn refuse(shared: &Shared, e: ErrorCode) -> Response {
    if e == ErrorCode::RateLimited {
        shared.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
    } else {
        shared.counters.refused.fetch_add(1, Ordering::Relaxed);
    }
    let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST);
    let body = serde_json::to_string(&ErrorAnswer {
        error: e,
        message: String::new(),
    })
    .unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}

fn json<T: serde::Serialize>(v: &T) -> Response {
    let body = serde_json::to_string(v).unwrap_or_default();
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}

/// The client's address: the connection's, or behind a proxy on loopback
/// the last `X-Forwarded-For` entry (the one the proxy added).
fn client_ip(shared: &Shared, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if shared.cfg.trust_proxy && peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn limited(shared: &Shared, class: Class, ip: IpAddr) -> bool {
    !shared.limiter.allow_ip(class, ip, Instant::now())
}

async fn info(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if limited(&shared, Class::Meta, client_ip(&shared, peer, &headers)) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    json(&shared.info())
}

async fn health(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if limited(&shared, Class::Meta, client_ip(&shared, peer, &headers)) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    (
        StatusCode::OK,
        [
            ("content-type", "text/plain"),
            ("cache-control", "no-store"),
        ],
        format!("{}\n", shared.health().line()),
    )
        .into_response()
}

fn parse<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, ErrorCode> {
    if body.len() > proto::MAX_BODY {
        return Err(ErrorCode::TooLarge);
    }
    serde_json::from_slice(body).map_err(|_| ErrorCode::BadRequest)
}

async fn put(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = Instant::now();
    if !shared
        .limiter
        .allow_ip(Class::Put, client_ip(&shared, peer, &headers), now)
    {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    let p: PutSlot = match parse(&body) {
        Ok(p) => p,
        Err(e) => return refuse(&shared, e),
    };
    if !shared.limiter.allow_tag(Class::Put, &p.tag.0, now) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    let r = shared.registry.lock().unwrap().put(&p, unix_now());
    match r {
        Ok(a) => json(&a),
        Err(e) => refuse(&shared, e),
    }
}

async fn delete(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if limited(&shared, Class::Put, client_ip(&shared, peer, &headers)) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    let d: DeleteSlot = match parse(&body) {
        Ok(d) => d,
        Err(e) => return refuse(&shared, e),
    };
    let r = shared.registry.lock().unwrap().delete(&d, unix_now());
    match r {
        Ok(()) => json(&serde_json::json!({})),
        Err(e) => refuse(&shared, e),
    }
}

async fn lookup(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = Instant::now();
    if !shared
        .limiter
        .allow_ip(Class::Lookup, client_ip(&shared, peer, &headers), now)
    {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    let l: Lookup = match parse(&body) {
        Ok(l) => l,
        Err(e) => return refuse(&shared, e),
    };
    if let Err(e) = l.verify() {
        return refuse(&shared, e);
    }
    if !shared.limiter.allow_tag(Class::Lookup, &l.tag.0, now) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    // The snap shares the registry's blobs. The JSON is written as the
    // socket takes it, one small chunk at a time, so this request does not
    // allocate the whole answer (a full tag is about 11 MiB).
    let snap = shared
        .registry
        .lock()
        .unwrap()
        .lookup_snap(&l.tag.0, unix_now());
    let enc = LookupEncoder::from_snap(snap);
    let stream = stream::unfold(enc, |mut enc| async move {
        enc.next_chunk()
            .map(|bytes| (Ok::<Bytes, Infallible>(Bytes::from(bytes)), enc))
    });
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Control channel.

async fn control(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(&shared, peer, &headers);
    if limited(&shared, Class::Control, ip) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    {
        let hub = shared.hub.lock().unwrap();
        if hub.len() >= shared.cfg.max_controls {
            drop(hub);
            return refuse(&shared, ErrorCode::Unavailable);
        }
        if hub.count_ip(ip) >= shared.cfg.max_controls_per_ip {
            drop(hub);
            return refuse(&shared, ErrorCode::RateLimited);
        }
    }
    ws.max_message_size(proto::MAX_CONTROL_MSG)
        .max_frame_size(proto::MAX_CONTROL_MSG)
        .on_upgrade(move |socket| control_session(shared, ip, socket))
}

async fn control_session(shared: Arc<Shared>, ip: IpAddr, mut socket: WebSocket) {
    let id = shared.next_session.fetch_add(1, Ordering::Relaxed);
    let challenge = {
        let mut c = [0u8; 32];
        c[..16].copy_from_slice(&proto::random_token());
        c[16..].copy_from_slice(&proto::random_token());
        c
    };
    let udp_token: Token = proto::random_token();
    let first = shared
        .hub
        .lock()
        .unwrap()
        .open(id, ip, challenge, udp_token, unix_now());
    shared.observed.lock().unwrap().register(udp_token);
    let (tx, mut rx) = mpsc::channel::<ToClient>(64);
    shared.senders.lock().unwrap().insert(id, (tx, 0));
    log::debug!("control {} opened from {}", id, shared.hash_ip(ip));
    let idle = Duration::from_secs(proto::CONTROL_IDLE_SECS);
    let mut down = shared.shutdown.subscribe();
    let mut ping = tokio::time::interval(shared.cfg.control_ping.max(Duration::from_millis(50)));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    if send_json(&mut socket, &first).await {
        loop {
            tokio::select! {
                _ = down.changed() => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                _ = ping.tick() => {
                    if socket.send(Message::Ping(Vec::new().into())).await.is_err() { break; }
                }
                m = tokio::time::timeout(idle, socket.recv()) => {
                    let text = match m {
                        Ok(Some(Ok(Message::Text(t)))) => t,
                        Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                        Ok(Some(Ok(Message::Binary(_)))) => break,
                        _ => break,
                    };
                    let msg = match proto::parse_to_server(text.as_str()) {
                        Ok(m) => m,
                        Err(e) => {
                            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
                            let _ = send_json(&mut socket, &ToClient::Error { id: None, error: e, message: String::new() }).await;
                            if e == ErrorCode::Version { break; }
                            continue;
                        }
                    };
                    let out = handle_control(&shared, id, ip, msg);
                    shared.deliver(out);
                }
                out = rx.recv() => {
                    match out {
                        Some(m) => if !send_json(&mut socket, &m).await { break },
                        None => break,
                    }
                }
            }
        }
    }
    shared.senders.lock().unwrap().remove(&id);
    // One lock at a time: `handle_control` takes them in the order
    // registry, relays, observed, hub.
    let closed = shared.hub.lock().unwrap().close(id);
    if let Some(s) = closed {
        shared.observed.lock().unwrap().unregister(&s.udp_token);
    }
    log::debug!("control {id} closed");
}

fn handle_control(
    shared: &Shared,
    id: SessionId,
    ip: IpAddr,
    msg: proto::ToServer,
) -> Vec<(SessionId, ToClient)> {
    use proto::ToServer;
    let now = Instant::now();
    if let ToServer::Punch { id: n, tag, .. } | ToServer::Relay { id: n, tag, .. } = &msg {
        if !shared.limiter.allow_ip(Class::Coordinate, ip, now)
            || !shared.limiter.allow_tag(Class::Coordinate, &tag.0, now)
        {
            shared.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return vec![(
                id,
                ToClient::Error {
                    id: Some(*n),
                    error: ErrorCode::RateLimited,
                    message: String::new(),
                },
            )];
        }
    }
    if let ToServer::Relay { id: n, tag, .. } = &msg {
        if shared.tag_bytes.exhausted(&tag.0, now) {
            shared.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return vec![(
                id,
                ToClient::Error {
                    id: Some(*n),
                    error: ErrorCode::RateLimited,
                    message: "relay quota of this vault is used up for now".into(),
                },
            )];
        }
    }
    let relay_full = shared.relays.lock().unwrap().active() >= shared.cfg.max_relays;
    let registry = shared.registry.lock().unwrap();
    let mut relays = shared.relays.lock().unwrap();
    let observed = shared.observed.lock().unwrap();
    let mut ctx = Ctx {
        registry: &registry,
        relays: &mut relays,
        observed: &observed,
        now_unix: unix_now(),
        now,
        relay_enabled: shared.cfg.relay && shared.cfg.limits.relay_rate > 0 && !relay_full,
    };
    let out = shared.hub.lock().unwrap().handle(id, msg, &mut ctx);
    for (_, m) in &out {
        if matches!(m, ToClient::Error { .. }) {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
        }
    }
    out
}

async fn send_json(socket: &mut WebSocket, m: &ToClient) -> bool {
    let Ok(text) = serde_json::to_string(m) else {
        return false;
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

// ---------------------------------------------------------------------------
// Relay.

async fn relay(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    if limited(&shared, Class::Relay, client_ip(&shared, peer, &headers)) {
        return refuse(&shared, ErrorCode::RateLimited);
    }
    let mut t: Token = [0u8; 16];
    if token.len() != 32
        || token.bytes().any(|b| b.is_ascii_uppercase())
        || hex::decode_to_slice(&token, &mut t).is_err()
    {
        return refuse(&shared, ErrorCode::NotFound);
    }
    let taken = shared.relays.lock().unwrap().take(&t, Instant::now());
    let Some((session, side)) = taken else {
        return refuse(&shared, ErrorCode::NotFound);
    };
    ws.max_message_size(proto::MAX_RELAY_FRAME)
        .max_frame_size(proto::MAX_RELAY_FRAME)
        .on_upgrade(move |socket| relay_side(shared, session, side, socket))
}

/// Pump a WebSocket's binary frames to and from a byte stream; returns the
/// other end of that stream.
fn ws_stream(mut socket: WebSocket, mut down: watch::Receiver<bool>) -> DuplexStream {
    let (mut ours, theirs) = tokio::io::duplex(proto::MAX_RELAY_FRAME * 2);
    tokio::spawn(async move {
        let mut buf = vec![0u8; proto::MAX_RELAY_FRAME];
        loop {
            tokio::select! {
                _ = down.changed() => break,
                m = socket.recv() => match m {
                    Some(Ok(Message::Binary(b))) => {
                        if ours.write_all(&b).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => break,
                },
                n = ours.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if socket.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() { break; }
                    }
                },
            }
        }
        let _ = ours.shutdown().await;
        let _ = socket.send(Message::Close(None)).await;
    });
    theirs
}

async fn relay_side(shared: Arc<Shared>, session: u64, side: Side, socket: WebSocket) {
    let stream = ws_stream(socket, shared.shutdown.subscribe());
    // The first side to arrive waits for the other; the second splices.
    // Looking and registering happen under one lock: two sides arriving at
    // once would otherwise both register, one overwriting the other.
    let rx = {
        let mut w = shared.waiting.lock().unwrap();
        match w.remove(&session) {
            Some((s, tx)) if s != side => {
                drop(w);
                let _ = tx.send(stream);
                return;
            }
            Some(other) => {
                w.insert(session, other);
                return;
            }
            None => {
                let (tx, rx) = oneshot::channel();
                w.insert(session, (side, tx));
                rx
            }
        }
    };
    let other = tokio::time::timeout(Duration::from_secs(proto::RELAY_JOIN_SECS), rx).await;
    shared.waiting.lock().unwrap().remove(&session);
    if let Ok(Ok(other)) = other {
        let lim = SpliceLimits {
            rate: shared.cfg.limits.relay_rate,
            idle: Duration::from_secs(shared.cfg.limits.relay_idle),
        };
        let (a, b) = if side == Side::A {
            (stream, other)
        } else {
            (other, stream)
        };
        let (tag, now) = (
            shared.relays.lock().unwrap().tag_of(session),
            Instant::now(),
        );
        let quota = tag.map(|t| shared.tag_bytes.cell(&t, now));
        let caps = Caps {
            total: shared.throttle.as_ref(),
            quota: quota.as_deref(),
        };
        let (ab, ba) =
            crate::relay::splice_with(a, b, lim, &shared.counters.relay_bytes, caps).await;
        if quota.as_deref().is_some_and(|q| q.exhausted()) {
            shared
                .counters
                .quota_stopped
                .fetch_add(1, Ordering::Relaxed);
        }
        log::debug!("relay session ended: {} bytes", ab + ba);
    }
    shared.relays.lock().unwrap().finish(session);
}

// ---------------------------------------------------------------------------
// UDP and housekeeping.

async fn udp_loop(sock: Arc<tokio::net::UdpSocket>, shared: Arc<Shared>) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, src)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if !shared
            .limiter
            .allow_ip(Class::Udp, src.ip(), Instant::now())
        {
            shared.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let answer = {
            let mut obs = shared.observed.lock().unwrap();
            crate::udp::handle_datagram(&mut obs, src, &buf[..n], Instant::now())
        };
        if let Some(a) = answer {
            if sock.send_to(&a, src).await.is_ok() {
                shared.counters.udp_answered.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn sweeper(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(shared.cfg.sweep_every.max(Duration::from_millis(50)));
    let mut last_stats = Instant::now();
    loop {
        tick.tick().await;
        shared.tag_bytes.prune(Instant::now());
        let every = shared.cfg.stats_every;
        if !every.is_zero() && last_stats.elapsed() >= every {
            last_stats = Instant::now();
            log::info!("{}", shared.stats_line());
        }
        let gone = shared.registry.lock().unwrap().expire(unix_now());
        shared.relays.lock().unwrap().expire(Instant::now());
        shared.limiter.prune(Instant::now());
        if gone > 0 {
            log::debug!("{gone} slots expired");
        }
    }
}
