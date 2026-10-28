// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The rendezvous service as the peer-to-peer runtime uses it
//! (`alpha-0-format.md` section 83.9): one [`Rendezvous`] per running
//! service keeps
//!
//! - a control connection with this device's slot claimed (thread
//!   `p2p-rv-control`, reconnecting after 5 s and doubling to 5 minutes,
//!   a ping every 25 s), which answers the server's `punch_go` by punching
//!   and its `relay_offer` by serving the relayed session with the TLS
//!   responder;
//! - a worker (thread `p2p-rv-worker`) that writes this device's peer
//!   record to its slot whenever it changes and every 6 h, reads the
//!   vault's slots at start and every 3 minutes (the service merges what
//!   it found into the saved directory), and observes from the QUIC socket
//!   every 25 s;
//! - the asking side's two routes: a QUIC dial after a coordinated punch
//!   ([`Rendezvous::punch_addr`]) and a relayed TLS session
//!   ([`Rendezvous::request`]), kept for reuse while it is busy.
//!
//! It is additive (section 79): every call has a timeout of a few seconds
//! and runs off the hot path, and a failure is logged as a
//! `p2p: rendezvous ...` line and shown in the status, nothing more.

use super::{exchange, quic, v3, PeerInfo};
use crate::ids::DeviceId;
use crate::record::{Id16, Parts};
use crate::rendezvous::proto::{self, Hex, ToClient, ToServer};
use crate::rendezvous::{
    fetch_peers, publish_peer_at, BaseUrl, Control, RelayStream, RvClient, Slot, Tag, Token,
    VaultKeys,
};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// What answers a relayed session for this device (the service: TLS
/// responder and snapshot, `p2p::serve_relayed`).
pub type ServeRelayed = Arc<dyn Fn(RelayStream) + Send + Sync>;

/// Everything a [`Rendezvous`] needs, from the engine and the service.
pub struct Setup {
    /// The base URL (`p2p.rendezvous`).
    pub url: String,
    /// The vault's tag, slots and seals (`Engine::rendezvous_keys`).
    pub vault: VaultKeys,
    /// This device's owner key of its slot (`Engine::rendezvous_owner`).
    pub owner: SigningKey,
    /// This device.
    pub me: Id16,
    /// The QUIC node: observes go out of its socket and punches with it.
    pub quic: Option<Arc<quic::Node>>,
    /// Serves a session relayed to us; `None` answers no relay offers.
    pub serve: Option<ServeRelayed>,
}

/// The rendezvous state for `varsto p2p status`, `GET /api/p2p` and the
/// Peers page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousStatus {
    /// The base URL, `None` when the rendezvous is off.
    pub url: Option<String>,
    /// `off`, `connecting`, `on` (the control connection is up) or
    /// `unreachable` (the last attempt failed; it is tried again).
    pub state: String,
    /// The address the server saw our QUIC socket at.
    pub observed: Option<SocketAddr>,
    pub last_error: Option<String>,
    /// Our clock minus the server's, in seconds, when it is off by more
    /// than the replay window (writes would be refused as stale).
    pub clock_skew: Option<i64>,
    /// Peers reached through the rendezvous relay since start.
    pub relayed_peers: usize,
    /// The vault's slots the last lookup found (this device's included).
    pub slots_seen: usize,
    /// Relayed sessions open now (asked by us or served).
    pub relay_sessions: usize,
}

impl Default for RendezvousStatus {
    fn default() -> RendezvousStatus {
        RendezvousStatus::off()
    }
}

impl RendezvousStatus {
    /// The rendezvous is turned off.
    pub fn off() -> RendezvousStatus {
        RendezvousStatus {
            url: None,
            state: "off".into(),
            observed: None,
            last_error: None,
            clock_skew: None,
            relayed_peers: 0,
            slots_seen: 0,
            relay_sessions: 0,
        }
    }

    /// One line for the status displays.
    pub fn describe(&self) -> String {
        let Some(url) = &self.url else {
            return "off".into();
        };
        let mut s = format!("{} ({url})", self.state);
        if let Some(a) = self.observed {
            s.push_str(&format!(", seen as {a}"));
        }
        if self.relay_sessions > 0 {
            s.push_str(&format!(", relaying {} sessions", self.relay_sessions));
        }
        if let Some(k) = self.clock_skew {
            s.push_str(&format!(", this clock is {k} s off the server's"));
        }
        s
    }
}

/// How often the record is written again when it has not changed.
const REFRESH: Duration = crate::rendezvous::PEER_REFRESH;
/// How often the vault's slots are read.
const FETCH: Duration = crate::rendezvous::PEER_FETCH;
/// Observe and ping intervals (section 83.5, 83.6).
const OBSERVE_EVERY: Duration = Duration::from_secs(proto::OBSERVE_INTERVAL_SECS);
const PING_EVERY: Duration = Duration::from_secs(25);
/// How long an observe waits for its answer.
const OBSERVE_WAIT: Duration = Duration::from_millis(1500);
/// A punch or relay request waits this long for the server's answer.
const ASK_WAIT: Duration = Duration::from_secs(5);
/// Reconnect waits.
const RECONNECT_MIN: Duration = Duration::from_secs(5);
const RECONNECT_MAX: Duration = Duration::from_secs(300);
/// A failed write or read of the slots is tried again after this long.
const RETRY: Duration = Duration::from_secs(60);
/// A punched address is reused for this long before the server is asked
/// again.
const PUNCHED_TTL: Duration = Duration::from_secs(60);
/// An idle relayed session is kept this long (the answering side closes
/// one idle for 30 s).
const SESSION_IDLE: Duration = Duration::from_secs(20);
/// Most kept relayed sessions per peer.
const SESSIONS_PER_PEER: usize = 8;
/// Punch datagrams after a `punch_go` to us: every quarter second for
/// three seconds (section 15).
const PUNCHES: u32 = 12;
const PUNCH_GAP: Duration = Duration::from_millis(250);

/// The asking side's TLS session inside a relayed stream.
type RelayedTls = quinn::rustls::StreamOwned<quinn::rustls::ClientConnection, RelayStream>;
/// A kept session: the stream, its exporter value, since when idle.
type Session = (RelayedTls, [u8; 32], Instant);

/// A punch or relay request handed to the control thread.
struct Ask {
    relay: bool,
    tag: Tag,
    slot: Slot,
    reply: mpsc::Sender<std::result::Result<ToClient, String>>,
}

#[derive(Default)]
struct RecordState {
    parts: Option<Parts>,
    dirty: bool,
    published: Option<Instant>,
    retry_at: Option<Instant>,
    last_ts: u64,
}

#[derive(Default)]
struct StateInner {
    tried: bool,
    last_error: Option<String>,
    /// Our clock minus the server's (seconds), from the last challenge.
    skew: i64,
    observed: Option<(SocketAddr, Instant)>,
    slots_seen: usize,
}

struct Shared {
    url: String,
    base: BaseUrl,
    http: Arc<RvClient>,
    vault: VaultKeys,
    owner: SigningKey,
    me: Id16,
    my_slot: Slot,
    quic: Option<Arc<quic::Node>>,
    serve: Option<ServeRelayed>,
    stop: AtomicBool,
    connected: AtomicBool,
    claimed: AtomicBool,
    relay_offered: AtomicBool,
    udp_token: Mutex<Option<Token>>,
    state: Mutex<StateInner>,
    record: Mutex<RecordState>,
    found: Mutex<Option<Vec<(Slot, Parts)>>>,
    fetch_now: AtomicBool,
    observe_now: AtomicBool,
    observed_changed: AtomicBool,
    asks: Mutex<mpsc::Sender<Ask>>,
    punched: Mutex<HashMap<Id16, (SocketAddr, Instant)>>,
    sessions: Mutex<HashMap<Id16, Vec<Session>>>,
    turns: Mutex<HashMap<Id16, usize>>,
    turns_cv: std::sync::Condvar,
    relayed_peers: Mutex<BTreeSet<Id16>>,
    serving: AtomicUsize,
    asking: AtomicUsize,
}

fn log(what: &str) {
    log::info!("p2p: rendezvous {what}");
}

/// The rendezvous runtime of a service; stops when dropped.
pub struct Rendezvous {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Rendezvous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rendezvous")
            .field("url", &self.shared.url)
            .finish_non_exhaustive()
    }
}

impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

/// Sleep up to `d` in short steps, ending early when `stop` is set.
fn pause(stop: &AtomicBool, d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100).min(until - Instant::now()));
    }
}

impl Rendezvous {
    /// Start the control connection and the worker for `setup`. Fails only
    /// on a base URL that does not parse; an unreachable server is retried
    /// in the background.
    pub fn start(setup: Setup) -> Result<Arc<Rendezvous>> {
        let http = RvClient::new(&setup.url)?;
        let base = http.base().clone();
        let (tx, rx) = mpsc::channel();
        let my_slot = setup.vault.slot(&setup.me);
        let shared = Arc::new(Shared {
            url: setup.url,
            base,
            http,
            my_slot,
            me: setup.me,
            vault: setup.vault,
            owner: setup.owner,
            quic: setup.quic,
            serve: setup.serve,
            stop: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            relay_offered: AtomicBool::new(true),
            udp_token: Mutex::new(None),
            state: Mutex::default(),
            record: Mutex::default(),
            found: Mutex::new(None),
            fetch_now: AtomicBool::new(true),
            observe_now: AtomicBool::new(false),
            observed_changed: AtomicBool::new(false),
            asks: Mutex::new(tx),
            punched: Mutex::default(),
            sessions: Mutex::default(),
            turns: Mutex::default(),
            turns_cv: std::sync::Condvar::new(),
            relayed_peers: Mutex::default(),
            serving: AtomicUsize::new(0),
            asking: AtomicUsize::new(0),
        });
        {
            let s = shared.clone();
            std::thread::Builder::new()
                .name("p2p-rv-control".into())
                .spawn(move || control_loop(&s, rx))?;
        }
        {
            let s = shared.clone();
            std::thread::Builder::new()
                .name("p2p-rv-worker".into())
                .spawn(move || worker_loop(&s))?;
        }
        log(&format!("on: {}", shared.url));
        Ok(Arc::new(Rendezvous { shared }))
    }

    /// The base URL in use.
    pub fn url(&self) -> &str {
        &self.shared.url
    }

    /// Stop both threads (they end within a second or two).
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }

    /// The record to keep in this device's slot: the peer record's parts
    /// exactly as a storage got them (`Engine::peer_record_parts`). Written
    /// in the background when it differs from the one written last.
    pub fn set_record(&self, parts: Parts) {
        let mut r = self.shared.record.lock().unwrap();
        if r.parts.as_ref() != Some(&parts) {
            r.parts = Some(parts);
            r.dirty = true;
            r.retry_at = None;
        }
    }

    /// Records the last lookup of the vault's slots found (other devices'
    /// slots only), once: hand them to `Engine::merge_rendezvous_records`.
    pub fn take_found(&self) -> Option<Vec<(Slot, Parts)>> {
        self.shared.found.lock().unwrap().take()
    }

    /// Read the vault's slots soon (a device turned up, a peer is lost).
    pub fn fetch_soon(&self) {
        self.shared.fetch_now.store(true, Ordering::Relaxed);
    }

    /// The address the server last saw our QUIC socket at (within the
    /// last ten minutes): it goes into `udp_public` of our record.
    pub fn observed(&self) -> Option<SocketAddr> {
        let st = self.shared.state.lock().unwrap();
        st.observed
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(600))
            .map(|(a, _)| a)
    }

    /// Did the observed address change since the last call? (The record
    /// should then go out again.)
    pub fn take_observed_change(&self) -> bool {
        self.shared.observed_changed.swap(false, Ordering::Relaxed)
    }

    /// Whether the control connection is up.
    pub fn connected(&self) -> bool {
        self.shared.connected.load(Ordering::Relaxed)
    }

    /// A coordinated punch can be asked for: the control connection is
    /// up, our slot is claimed (the server lets a vault's devices punch
    /// each other only), and the server saw our QUIC socket lately.
    pub fn can_punch(&self) -> bool {
        let s = &self.shared;
        s.quic.is_some()
            && s.connected.load(Ordering::Relaxed)
            && s.claimed.load(Ordering::Relaxed)
            && s.state.lock().unwrap().observed.is_some_and(|(_, at)| {
                at.elapsed() < Duration::from_secs(proto::OBSERVED_MAX_AGE_SECS)
            })
    }

    /// The relay can be asked for: the control connection is up, our slot
    /// is claimed and the server offers a relay.
    pub fn can_relay(&self) -> bool {
        let s = &self.shared;
        s.connected.load(Ordering::Relaxed)
            && s.claimed.load(Ordering::Relaxed)
            && s.relay_offered.load(Ordering::Relaxed)
    }

    pub fn status(&self) -> RendezvousStatus {
        let s = &self.shared;
        let st = s.state.lock().unwrap();
        let connected = s.connected.load(Ordering::Relaxed);
        let state = if s.stop.load(Ordering::Relaxed) {
            "off"
        } else if connected {
            "on"
        } else if st.tried && st.last_error.is_some() {
            "unreachable"
        } else {
            "connecting"
        };
        RendezvousStatus {
            url: Some(s.url.clone()),
            state: state.into(),
            observed: st
                .observed
                .filter(|(_, at)| at.elapsed() < Duration::from_secs(600))
                .map(|(a, _)| a),
            last_error: st.last_error.clone(),
            clock_skew: (st.skew.unsigned_abs() > proto::REPLAY_WINDOW_SECS).then_some(st.skew),
            relayed_peers: s.relayed_peers.lock().unwrap().len(),
            slots_seen: st.slots_seen,
            relay_sessions: s.serving.load(Ordering::Relaxed) + s.asking.load(Ordering::Relaxed),
        }
    }

    /// Send `relay` or `punch` for (`tag`, `slot`) over the control
    /// connection and wait for the server's answer.
    fn ask(&self, relay: bool, tag: Tag, slot: Slot) -> Result<ToClient> {
        if !self.connected() {
            bail!("rendezvous not connected");
        }
        let (tx, rx) = mpsc::channel();
        self.shared
            .asks
            .lock()
            .unwrap()
            .send(Ask {
                relay,
                tag,
                slot,
                reply: tx,
            })
            .map_err(|_| anyhow!("rendezvous stopped"))?;
        match rx.recv_timeout(ASK_WAIT) {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) => bail!("rendezvous refused: {e}"),
            Err(_) => bail!("no answer from the rendezvous"),
        }
    }

    /// The address to dial `device` at over QUIC after the server had both
    /// sides punch (section 83.6): asked again after a minute.
    pub fn punch_addr(&self, device: &DeviceId) -> Result<SocketAddr> {
        let d = crate::record::id16(device).ok_or_else(|| anyhow!("not a device id"))?;
        if let Some((a, at)) = self.shared.punched.lock().unwrap().get(&d) {
            if at.elapsed() < PUNCHED_TTL {
                return Ok(*a);
            }
        }
        let slot = self.shared.vault.slot(&d);
        match self.ask(false, self.shared.vault.tag(), slot)? {
            ToClient::PunchGo { peer, .. } => {
                let a: SocketAddr = peer
                    .parse()
                    .map_err(|_| anyhow!("rendezvous gave no address"))?;
                log(&format!("punch to {} at {a}", device.short()));
                self.shared
                    .punched
                    .lock()
                    .unwrap()
                    .insert(d, (a, Instant::now()));
                Ok(a)
            }
            other => bail!("unexpected answer {other:?}"),
        }
    }

    /// Open a relayed stream to the holder of (`tag`, `slot`).
    fn open_relay(&self, tag: Tag, slot: Slot) -> Result<RelayStream> {
        match self.ask(true, tag, slot)? {
            ToClient::RelayReady { token, .. } => RelayStream::open(&self.shared.base, &token.0),
            other => bail!("unexpected answer {other:?}"),
        }
    }

    /// One request to `p` through the rendezvous relay: the pinned TLS
    /// session of section 75 inside a relayed stream, kept for the next
    /// request while it is fresh.
    pub fn request(&self, client: &v3::Client, p: &PeerInfo, path: &str) -> Result<(u16, Vec<u8>)> {
        let d = crate::record::id16(&p.device).ok_or_else(|| anyhow!("not a device id"))?;
        // The server allows a few sessions per vault: requests to one peer
        // share at most `SESSIONS_AT_ONCE` of them, the rest wait their turn.
        let _turn = Turn::take(&self.shared, d)?;
        let host = SocketAddr::from(([0, 0, 0, 0], 0));
        let ask = |s, e: [u8; 32]| {
            let headers = format!("X-Varsto-Auth: {}\r\n", client.token(&e, &p.device, path));
            exchange(s, host, path, &headers).map(|r| (r, e))
        };
        let kept = {
            let mut m = self.shared.sessions.lock().unwrap();
            let v = m.entry(d).or_default();
            v.retain(|(_, _, at)| at.elapsed() < SESSION_IDLE);
            v.pop()
        };
        if let Some((s, e, _)) = kept {
            if let Ok(((status, body, keep), e)) = ask(s, e) {
                self.keep(d, keep, e);
                return Ok((status, body));
            }
        }
        let stream = self.open_relay(self.shared.vault.tag(), self.shared.vault.slot(&d))?;
        let _counted = Counted::new(&self.shared.asking);
        let (s, e) = v3::tls::connect_stream(client.identity(), stream, &p.cert_sha256)?;
        s.sock.set_read_timeout(Some(v3::tls::RESPONSE_IDLE))?;
        let ((status, body, keep), e) = ask(s, e)?;
        self.keep(d, keep, e);
        if self.shared.relayed_peers.lock().unwrap().insert(d) {
            log(&format!("relays to {}", p.device.short()));
        }
        Ok((status, body))
    }

    fn keep(&self, d: Id16, s: Option<RelayedTls>, e: [u8; 32]) {
        if let Some(s) = s {
            let mut m = self.shared.sessions.lock().unwrap();
            let v = m.entry(d).or_default();
            if v.len() < SESSIONS_PER_PEER {
                v.push((s, e, Instant::now()));
            }
        }
    }
}

/// Relayed sessions asked for at once per peer (the server allows four
/// per vault, `relay_per_tag`).
const SESSIONS_AT_ONCE: usize = 2;
/// How long a request waits for its turn on a relayed session.
const TURN_WAIT: Duration = Duration::from_secs(30);

/// One of the `SESSIONS_AT_ONCE` turns of a peer, while it lives.
struct Turn<'a> {
    s: &'a Shared,
    d: Id16,
}

impl<'a> Turn<'a> {
    fn take(s: &'a Shared, d: Id16) -> Result<Turn<'a>> {
        let until = Instant::now() + TURN_WAIT;
        let mut busy = s.turns.lock().unwrap();
        while busy.get(&d).copied().unwrap_or(0) >= SESSIONS_AT_ONCE {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the rendezvous relay to this peer is busy");
            }
            busy = s.turns_cv.wait_timeout(busy, left).unwrap().0;
        }
        *busy.entry(d).or_default() += 1;
        Ok(Turn { s, d })
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut busy = self.s.turns.lock().unwrap();
        if let Some(n) = busy.get_mut(&self.d) {
            *n = n.saturating_sub(1);
        }
        self.s.turns_cv.notify_all();
    }
}

/// Counts something open while it lives.
struct Counted<'a>(&'a AtomicUsize);

impl<'a> Counted<'a> {
    fn new(c: &'a AtomicUsize) -> Counted<'a> {
        c.fetch_add(1, Ordering::Relaxed);
        Counted(c)
    }
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn note_error(s: &Shared, what: &str, e: &dyn std::fmt::Display) {
    let msg = format!("{what}: {e}");
    let mut st = s.state.lock().unwrap();
    st.tried = true;
    if st.last_error.as_deref() != Some(msg.as_str()) {
        log(&msg);
    }
    st.last_error = Some(msg);
}

// ---------------------------------------------------------------------------
// The control connection.

fn control_loop(s: &Arc<Shared>, asks: mpsc::Receiver<Ask>) {
    let mut wait = RECONNECT_MIN;
    while !s.stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let outcome = run_control(s, &asks);
        s.connected.store(false, Ordering::Relaxed);
        s.claimed.store(false, Ordering::Relaxed);
        *s.udp_token.lock().unwrap() = None;
        if s.stop.load(Ordering::Relaxed) {
            break;
        }
        if let Err(e) = outcome {
            note_error(s, "control connection", &format!("{e:#}"));
        }
        // Questions asked while it was down get no answer (their senders
        // drop): the callers move on to the next route.
        while asks.try_recv().is_ok() {}
        if started.elapsed() > Duration::from_secs(60) {
            wait = RECONNECT_MIN;
        }
        pause(&s.stop, wait);
        wait = (wait * 2).min(RECONNECT_MAX);
    }
    s.connected.store(false, Ordering::Relaxed);
}

fn claims_for(s: &Shared, c: &Control) -> Vec<proto::Claim> {
    let published = s.record.lock().unwrap().published.is_some();
    if published {
        vec![c.claim(s.vault.tag(), s.my_slot, &s.owner)]
    } else {
        Vec::new()
    }
}

fn take_welcome(s: &Shared, udp_token: Token, claimed: &[(Tag, Slot)]) {
    let fresh = s.udp_token.lock().unwrap().replace(udp_token) != Some(udp_token);
    if fresh {
        // A new connection: tell the server where our socket is at once.
        s.observe_now.store(true, Ordering::Relaxed);
    }
    let ours = claimed
        .iter()
        .any(|(t, sl)| *t == s.vault.tag() && *sl == s.my_slot);
    s.claimed.store(ours, Ordering::Relaxed);
}

fn run_control(s: &Arc<Shared>, asks: &mpsc::Receiver<Ask>) -> Result<()> {
    let mut c = Control::open(&s.base)?;
    {
        let mut st = s.state.lock().unwrap();
        st.skew = crate::rendezvous::now() as i64 - c.server_time() as i64;
        st.tried = true;
    }
    let claims = claims_for(s, &c);
    let w = c.hello(claims, ASK_WAIT)?;
    take_welcome(s, w.udp_token, &w.claimed);
    s.connected.store(true, Ordering::Relaxed);
    s.state.lock().unwrap().last_error = None;
    log("control connection up");
    let ids = AtomicU32::new(1);
    let mut pending: HashMap<u32, (mpsc::Sender<std::result::Result<ToClient, String>>, Instant)> =
        HashMap::new();
    let mut last_ping = Instant::now();
    let mut last_claim: Option<Instant> = None;
    while !s.stop.load(Ordering::Relaxed) {
        // Claim our slot once the worker has written it (again every few
        // seconds while the server has not taken it).
        if !s.claimed.load(Ordering::Relaxed)
            && last_claim.is_none_or(|t| t.elapsed() > Duration::from_secs(5))
            && s.record.lock().unwrap().published.is_some()
        {
            last_claim = Some(Instant::now());
            let claims = claims_for(s, &c);
            c.send(&ToServer::Claim { claims })?;
        }
        while let Ok(a) = asks.try_recv() {
            let id = ids.fetch_add(1, Ordering::Relaxed);
            let (tag, slot) = (Hex(a.tag), Hex(a.slot));
            let m = if a.relay {
                ToServer::Relay { id, tag, slot }
            } else {
                ToServer::Punch { id, tag, slot }
            };
            c.send(&m)?;
            pending.insert(id, (a.reply, Instant::now()));
        }
        if last_ping.elapsed() >= PING_EVERY {
            last_ping = Instant::now();
            let id = ids.fetch_add(1, Ordering::Relaxed);
            c.send(&ToServer::Ping { id })?;
        }
        pending.retain(|_, (_, at)| at.elapsed() < ASK_WAIT * 2);
        let Some(msg) = c.recv(Duration::from_millis(200))? else {
            continue;
        };
        match msg {
            ToClient::Welcome { udp_token, claimed } => {
                let claimed: Vec<(Tag, Slot)> =
                    claimed.into_iter().map(|(t, s)| (t.0, s.0)).collect();
                take_welcome(s, udp_token.0, &claimed);
            }
            ToClient::PunchGo { id: Some(n), .. } | ToClient::RelayReady { id: n, .. } => {
                if let Some((reply, _)) = pending.remove(&n) {
                    let _ = reply.send(Ok(msg));
                }
            }
            ToClient::Error {
                id: Some(n),
                error,
                message,
            } => {
                if let Some((reply, _)) = pending.remove(&n) {
                    let _ = reply.send(Err(if message.is_empty() {
                        error.to_string()
                    } else {
                        format!("{error} ({message})")
                    }));
                }
            }
            ToClient::Error {
                id: None, error, ..
            } => log(&format!("said {error}")),
            ToClient::PunchGo {
                id: None,
                tag,
                slot,
                peer,
            } => {
                if tag.0 != s.vault.tag() || slot.0 != s.my_slot {
                    continue;
                }
                punch_back(s, &peer);
            }
            ToClient::RelayOffer { token, tag, slot } => {
                if tag.0 != s.vault.tag() || slot.0 != s.my_slot {
                    continue;
                }
                serve_offer(s, token.0);
            }
            ToClient::Pong { .. } | ToClient::Challenge { .. } => {}
        }
    }
    c.close();
    Ok(())
}

/// Another device of the vault dials us at `peer` after a coordinated
/// punch: punch towards it for three seconds, so both NAT mappings open.
fn punch_back(s: &Arc<Shared>, peer: &str) {
    let (Some(node), Ok(a)) = (s.quic.clone(), peer.parse::<SocketAddr>()) else {
        return;
    };
    log(&format!("punching back towards {a}"));
    let stop = s.clone();
    let _ = std::thread::Builder::new()
        .name("p2p-rv-punch".into())
        .spawn(move || {
            for _ in 0..PUNCHES {
                if stop.stop.load(Ordering::Relaxed) {
                    break;
                }
                node.punch(a);
                std::thread::sleep(PUNCH_GAP);
            }
        });
}

/// Someone asked the server for a relayed session to us: take it and hand
/// it to the TLS responder (which admits only our directory's devices).
fn serve_offer(s: &Arc<Shared>, token: Token) {
    let Some(serve) = s.serve.clone() else {
        return;
    };
    let s = s.clone();
    let _ = std::thread::Builder::new()
        .name("p2p-rv-serve".into())
        .spawn(move || match RelayStream::open(&s.base, &token) {
            Ok(stream) => {
                let _counted = Counted::new(&s.serving);
                serve(stream);
            }
            Err(e) => log(&format!("relay offer not taken: {e:#}")),
        });
}

// ---------------------------------------------------------------------------
// The worker: record, lookups, observes.

fn worker_loop(s: &Arc<Shared>) {
    let mut next_fetch = Instant::now();
    let mut next_observe = Instant::now();
    let mut next_info = Instant::now();
    while !s.stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= next_info {
            match s.http.info() {
                Ok(i) => {
                    s.relay_offered.store(i.relay, Ordering::Relaxed);
                    next_info = now + Duration::from_secs(3600);
                }
                Err(e) => {
                    note_error(s, "info", &e);
                    next_info = now + RETRY;
                }
            }
        }
        publish_due(s);
        if now >= next_fetch || s.fetch_now.swap(false, Ordering::Relaxed) {
            next_fetch = match fetch(s) {
                Ok(()) => now + FETCH,
                Err(()) => now + RETRY.min(FETCH),
            };
        }
        if now >= next_observe || s.observe_now.swap(false, Ordering::Relaxed) {
            next_observe = now + OBSERVE_EVERY;
            observe(s);
        }
        pause(&s.stop, Duration::from_millis(500));
    }
}

fn publish_due(s: &Shared) {
    let (parts, ts) = {
        let r = s.record.lock().unwrap();
        let Some(parts) = r.parts.clone() else {
            return;
        };
        if r.retry_at.is_some_and(|t| Instant::now() < t) {
            return;
        }
        if !r.dirty && r.published.is_some_and(|t| t.elapsed() < REFRESH) {
            return;
        }
        // The server's clock decides the replay window: write in its time.
        let skew = s.state.lock().unwrap().skew;
        let now = (crate::rendezvous::now() as i64 - skew).max(0) as u64;
        (parts, now.max(r.last_ts + 1))
    };
    match publish_peer_at(&s.http, &s.vault, &s.owner, &s.me, &parts, ts) {
        Ok(_) => {
            let mut r = s.record.lock().unwrap();
            r.last_ts = ts;
            r.published = Some(Instant::now());
            r.retry_at = None;
            if r.parts.as_ref() == Some(&parts) {
                r.dirty = false;
            }
            log::debug!("p2p: rendezvous record written");
        }
        Err(e) => {
            // Stale: another process of this device wrote later; move on.
            let mut r = s.record.lock().unwrap();
            if e.code() == Some(proto::ErrorCode::Stale) {
                r.last_ts = ts + 1;
            }
            r.retry_at = Some(Instant::now() + RETRY);
            drop(r);
            note_error(s, "record not written", &e);
        }
    }
}

fn fetch(s: &Shared) -> std::result::Result<(), ()> {
    match fetch_peers(&s.http, &s.vault) {
        Ok((found, bad)) => {
            if bad > 0 {
                log(&format!("{bad} slots did not open"));
            }
            let seen = found.len();
            let others: Vec<(Slot, Parts)> = found
                .into_iter()
                .filter(|(sl, _)| *sl != s.my_slot)
                .collect();
            s.state.lock().unwrap().slots_seen = seen;
            *s.found.lock().unwrap() = Some(others);
            Ok(())
        }
        Err(e) => {
            note_error(s, "lookup", &e);
            Err(())
        }
    }
}

fn observe(s: &Shared) {
    let Some(node) = &s.quic else { return };
    let Some(token) = *s.udp_token.lock().unwrap() else {
        return;
    };
    let addrs = match s.http.udp_addrs() {
        Ok(a) => a,
        Err(e) => {
            note_error(s, "no UDP endpoint", &e);
            return;
        }
    };
    let Some(server) = addrs
        .into_iter()
        .find(|a| a.is_ipv4() == node.local_addr.is_ipv4())
    else {
        return;
    };
    match node.observe(server, Some(&token), OBSERVE_WAIT) {
        Some(a) => {
            let mut st = s.state.lock().unwrap();
            if st.observed.map(|(o, _)| o) != Some(a) {
                log(&format!("sees us at {a}"));
                s.observed_changed.store(true, Ordering::Relaxed);
            }
            st.observed = Some((a, Instant::now()));
        }
        None => log::debug!("p2p: rendezvous observe got no answer"),
    }
}
