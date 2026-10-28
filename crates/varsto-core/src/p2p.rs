// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer-to-peer transfer of encrypted blocks, torrent-style: every device
//! that holds a file can serve its chunks as the same ciphertext objects the
//! storages hold (chunk keys and nonces are deterministic per folder), and a
//! device that needs a chunk pulls it from whichever peer or storage has it,
//! verifying every object against its content-addressed name. Peers on the
//! LAN are found with a multicast beacon; peers across the internet through
//! a signed peer record each device publishes in the vault's own storage with
//! the addresses it can be reached at and the pin of its certificate. The
//! objects are ciphertext already; both transports run TLS 1.3 with pinned
//! certificates from the accepted peer records, and every request carries a
//! token bound to its TLS connection (`v3`), so a listener learns nothing
//! and a stranger does not even complete the handshake.
//!
//! Two transports share one request handler (`v3::Responder`): TLS over TCP
//! (LAN and user-forwarded ports) and QUIC over UDP (`quic`), which crosses NATs with
//! STUN-learned addresses (`stun`), punch datagrams and, failing that, a
//! relay through one of the user's own reachable devices. There are no
//! trackers and no vendor servers: the user's storage is the rendezvous.

pub mod portmap;
pub mod quic;
pub mod rendezvous;
pub mod stun;
pub mod traffic;
pub mod v3;

pub use traffic::Traffic;

use crate::crypto;
use crate::ids::{DeviceId, FolderId, ObjectName, VaultId};
use crate::vault::FolderKeys;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const BEACON_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);
pub const BEACON_PORT: u16 = 17892;

fn now() -> i64 {
    crate::util::now_utc()
}

/// One line in the service log about a path decision, a punch or a relay:
/// the events a user needs when a transfer does not cross a NAT. Per-request
/// chatter is logged at debug and trace level (`crate::logging`).
pub(crate) fn log(what: &str) {
    log::info!("{what}");
}

/// Where one chunk lives inside a plaintext file on this device.
#[derive(Clone, Debug)]
pub struct Piece {
    pub folder: FolderId,
    pub chunk: crate::ids::ChunkId,
    /// Folder key epoch of the chunk (see `vault::FolderKeys`).
    pub epoch: u32,
    pub path: PathBuf,
    pub offset: u64,
    pub len: u64,
}

/// Everything a device needs to serve its chunks without the engine: the
/// per-folder keys and an index from object name to file piece. Rebuilt by
/// the service after every sync.
pub struct Snapshot {
    pub vault_id: VaultId,
    pub device_id: DeviceId,
    pub folder_keys: BTreeMap<FolderId, FolderKeys>,
    pub pieces: BTreeMap<ObjectName, Piece>,
    /// Roots holding objects as single files (the block cache), served
    /// verbatim.
    pub local_roots: Vec<PathBuf>,
    /// Blocks in packs on local-directory storages: the pack file, offset
    /// and length, served verbatim.
    pub packed: BTreeMap<ObjectName, (PathBuf, u64, u64)>,
    /// Revoked devices: refused even if they still hold a valid token.
    pub revoked: std::collections::BTreeSet<DeviceId>,
    /// Devices told what this one is doing (`/p2p/activity`): in an
    /// organization the devices of the same user; `None` for every device
    /// of the vault.
    pub activity_audience: Option<std::collections::BTreeSet<DeviceId>>,
    /// The newest batch this device holds of every full device (its own:
    /// the newest a storage confirmed), answered on `/p2p/heads` and
    /// `/p2p/changed` with proofs (`v3::heads`); empty for a device that
    /// signs no vault batches.
    pub heads: Vec<v3::HeadRef>,
    /// The local ledger directory, where the batches proved and handed
    /// over on `/p2p/ledger/` are read from.
    pub ledger_dir: Option<PathBuf>,
}

crate::redacted_opaque!(Snapshot);

impl Snapshot {
    /// Produce the ciphertext object for `name`, from a stored copy or by
    /// re-encrypting the piece (deterministic, so the bytes are identical).
    pub fn object(&self, name: &ObjectName) -> Result<Option<Vec<u8>>> {
        if name.as_str().len() < 2 || !name.as_str().bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("malformed object name");
        }
        // Blocks, and whole packs a mailbox staged (named by their id).
        for root in &self.local_roots {
            for top in ["chunks", "packs"] {
                let p = root.join(top).join(&name.as_str()[..2]).join(name.as_str());
                if let Ok(bytes) = std::fs::read(&p) {
                    if ObjectName::from_bytes(&crypto::hash(&bytes)) == *name {
                        return Ok(Some(bytes));
                    }
                }
            }
        }
        if let Some((path, offset, len)) = self.packed.get(name) {
            let read = || -> std::io::Result<Vec<u8>> {
                let mut f = std::fs::File::open(path)?;
                f.seek(SeekFrom::Start(*offset))?;
                let mut b = vec![0u8; *len as usize];
                f.read_exact(&mut b)?;
                Ok(b)
            };
            if let Ok(bytes) = read() {
                if ObjectName::from_bytes(&crypto::hash(&bytes)) == *name {
                    return Ok(Some(bytes));
                }
            }
        }
        if let Some(bytes) = served::get(name) {
            return Ok(Some(bytes.to_vec()));
        }
        let Some(piece) = self.pieces.get(name) else {
            return Ok(None);
        };
        let Some(fk) = self.folder_keys.get(&piece.folder) else {
            return Ok(None);
        };
        let mut f = match std::fs::File::open(&piece.path) {
            Ok(f) => f,
            Err(_) => return Ok(None), // moved or freed since the snapshot
        };
        f.seek(SeekFrom::Start(piece.offset))?;
        let mut plain = vec![0u8; piece.len as usize];
        if f.read_exact(&mut plain).is_err() {
            return Ok(None);
        }
        if crate::ids::ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain)) != piece.chunk {
            return Ok(None); // file changed since the snapshot
        }
        // Packing is deterministic for a zstd version (`crate::pack`), so
        // the object comes out as stored unless another version packed it.
        let ct =
            crate::chunk_seal::seal_chunk(fk, &self.vault_id, &piece.chunk, piece.epoch, &plain)?;
        if ObjectName::from_bytes(&crypto::hash(&ct)) != *name {
            return Ok(None);
        }
        served::put(name, &ct);
        Ok(Some(ct))
    }
}

/// Objects compressed and encrypted again for peers lately. Several devices
/// catching up at once ask for the same blocks; the second one gets the
/// bytes without the compression. Bounded by `VARSTO_P2P_CACHE_MB`
/// (default 64 MiB, 0 turns it off); oldest out first.
mod served {
    use crate::ids::ObjectName;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex, OnceLock};

    #[derive(Default)]
    struct Cache {
        map: HashMap<ObjectName, Arc<Vec<u8>>>,
        order: VecDeque<ObjectName>,
        bytes: usize,
    }

    fn cache() -> &'static Mutex<Cache> {
        static C: OnceLock<Mutex<Cache>> = OnceLock::new();
        C.get_or_init(Mutex::default)
    }

    fn cap() -> usize {
        static CAP: OnceLock<usize> = OnceLock::new();
        *CAP.get_or_init(|| {
            std::env::var("VARSTO_P2P_CACHE_MB")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(64)
                << 20
        })
    }

    pub(super) fn get(name: &ObjectName) -> Option<Arc<Vec<u8>>> {
        cache().lock().unwrap().map.get(name).cloned()
    }

    pub(super) fn put(name: &ObjectName, bytes: &[u8]) {
        let cap = cap();
        if bytes.len() > cap / 4 {
            return;
        }
        let mut c = cache().lock().unwrap();
        if c.map.contains_key(name) {
            return;
        }
        while c.bytes + bytes.len() > cap {
            let Some(old) = c.order.pop_front() else {
                break;
            };
            if let Some(b) = c.map.remove(&old) {
                c.bytes -= b.len();
            }
        }
        c.bytes += bytes.len();
        c.order.push_back(name.clone());
        c.map.insert(name.clone(), Arc::new(bytes.to_vec()));
    }
}

/// Requests the HTTP server answers at the same time: twice the cores
/// (producing an object is reading, compressing and encrypting), between 8
/// and 32, so a peer that keeps a deep window of requests is kept busy.
fn serve_threads() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cores * 2).clamp(8, 32)
}

/// A listening socket with TCP keep-alive, which accepted connections
/// inherit: peers keep their connections open between requests, and one
/// that vanished (closed laptop, NAT mapping gone) is noticed and its
/// connection closed within a few minutes instead of never.
fn listener(addr: SocketAddr) -> Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, TcpKeepalive, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60));
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    ))]
    let ka = ka.with_interval(Duration::from_secs(15));
    sock.set_tcp_keepalive(&ka)?;
    sock.set_tcp_nodelay(true)?;
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    Ok(sock.into())
}

/// The serving side: HTTP/1.1 on `addr`, answering `/p2p/object/<name>` and
/// `/p2p/info` for authenticated peers. A thread per connection, which a
/// peer keeps open between requests (keep-alive); producing objects (read,
/// compress, encrypt) is limited to `serve_threads()` at a time. A
/// connection idle for `CONN_IDLE` is closed, and at most `MAX_CONNS` are
/// open at once. (tiny_http's connection pool queued a new connection behind
/// long-lived ones, so a kept-alive peer could wait for a connection that
/// was never served.)
pub struct Server {
    listener: std::net::TcpListener,
    pub addr: SocketAddr,
    traffic: Arc<Traffic>,
    /// TLS 1.3 with pinned certificates on every connection, and requests
    /// authenticated by `v3::Responder` (no plain HTTP).
    tls: Arc<v3::tls::TcpTls>,
}

/// The headers of one request that authentication looks at.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestHeaders {
    /// `X-Varsto-Auth` (the connection-bound token).
    pub auth: String,
    /// `X-Varsto-For` (the device a relay asks for).
    pub for_device: String,
}

/// Answers one request on a connection: `(status, body, peer)`.
type Handler<'a> =
    dyn Fn(Option<&Snapshot>, &str, &RequestHeaders) -> (u16, Vec<u8>, Option<DeviceId>) + 'a;

const CONN_IDLE: Duration = Duration::from_secs(30);
const MAX_CONNS: usize = 256;
const MAX_HEAD: usize = 32 * 1024;
/// A request head must arrive whole within this long of its first byte, and
/// a new connection must start one within this long of being accepted
/// (a slow trickle of bytes held a thread for the whole idle time).
const HEAD_DEADLINE: Duration = Duration::from_secs(5);
/// Connections of one address that sit with an unfinished request head.
const MAX_HEADS_PER_IP: usize = 8;

/// Connections per address that hold a request head that has begun but not
/// ended: an address over the limit has the next one closed at once. A
/// complete head normally arrives in one piece, so a peer that opens many
/// parallel connections (the fetch window is 32) is never held back; a
/// trickle of bytes (a slowloris) fills the few slots and the 5 second
/// deadline empties them.
#[derive(Default)]
struct PerIp {
    heads: Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
}

struct HeadSlot {
    owner: Arc<PerIp>,
    ip: std::net::IpAddr,
}

impl PerIp {
    fn enter(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<HeadSlot> {
        let mut m = self.heads.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= MAX_HEADS_PER_IP {
            return None;
        }
        *n += 1;
        Some(HeadSlot {
            owner: self.clone(),
            ip,
        })
    }
}

impl Drop for HeadSlot {
    fn drop(&mut self) {
        let mut m = self.owner.heads.lock().unwrap();
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// Counting semaphore for the expensive part of an answer.
struct Slots {
    free: Mutex<usize>,
    cv: std::sync::Condvar,
}

impl Slots {
    fn take(&self) -> SlotGuard<'_> {
        let mut f = self.free.lock().unwrap();
        while *f == 0 {
            f = self.cv.wait(f).unwrap();
        }
        *f -= 1;
        SlotGuard(self)
    }
}

struct SlotGuard<'a>(&'a Slots);

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap() += 1;
        self.0.cv.notify_one();
    }
}

impl Server {
    /// Listen on `addr`, serving TLS 1.3 only with the pinned certificates
    /// and the connection-bound tokens of `v3` (format 3 design, section
    /// 8). A client that does not speak TLS gets an alert and nothing else.
    pub fn bind(addr: SocketAddr, tls: Arc<v3::tls::TcpTls>) -> Result<Server> {
        let listener = listener(addr).with_context(|| format!("bind p2p listener on {addr}"))?;
        let addr = listener.local_addr().unwrap_or(addr);
        Ok(Server {
            listener,
            addr,
            traffic: Arc::default(),
            tls,
        })
    }

    /// Count what we serve in `traffic` (shared with the QUIC node and the
    /// peer table) instead of counters of our own.
    pub fn with_traffic(mut self, traffic: Arc<Traffic>) -> Server {
        self.traffic = traffic;
        self
    }

    /// Serve until `stop` is set. The snapshot can be swapped at any time.
    pub fn run(
        &self,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let slots = Arc::new(Slots {
            free: Mutex::new(serve_threads()),
            cv: std::sync::Condvar::new(),
        });
        let open = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(PerIp::default());
        if self.listener.set_nonblocking(true).is_err() {
            return;
        }
        while !stop.load(Ordering::Relaxed) {
            let (sock, remote) = match self.listener.accept() {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            if open.load(Ordering::Relaxed) >= MAX_CONNS {
                continue; // dropped: closed at once
            }
            open.fetch_add(1, Ordering::Relaxed);
            let (snapshot, stop, slots, conns, traffic, heads) = (
                snapshot.clone(),
                stop.clone(),
                slots.clone(),
                open.clone(),
                self.traffic.clone(),
                heads.clone(),
            );
            let tls = self.tls.clone();
            let spawned = std::thread::Builder::new()
                .name("p2p-conn".into())
                .spawn(move || {
                    // Counted down when the thread ends, however it ends.
                    struct Done(Arc<AtomicUsize>);
                    impl Drop for Done {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    let _done = Done(conns);
                    if prepare_socket(&sock).is_err() {
                        return;
                    }
                    let _ = tls.serve(sock, remote, |stream, handler| {
                        serve_connection(
                            stream, remote, &snapshot, &stop, &slots, &traffic, &heads, handler,
                            false,
                        )
                    });
                });
            if spawned.is_err() {
                open.fetch_sub(1, Ordering::Relaxed);
                log("could not start a thread for a peer connection");
            }
        }
    }
}

/// Socket options of an accepted connection: blocking, no delay, a short
/// read timeout so the loop below can watch its deadlines.
fn prepare_socket(sock: &TcpStream) -> std::io::Result<()> {
    sock.set_nonblocking(false)?;
    sock.set_nodelay(true)?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    sock.set_write_timeout(Some(Duration::from_secs(60)))
}

/// Requests on one connection, one after another, until the peer closes it,
/// asks to close, stays idle for `CONN_IDLE`, or the server stops. `sock`
/// is the TLS session over the TCP stream.
#[allow(clippy::too_many_arguments)]
fn serve_connection<S: Read + Write + CloseWrite>(
    mut sock: S,
    remote: SocketAddr,
    snapshot: &Mutex<Option<Arc<Snapshot>>>,
    stop: &std::sync::atomic::AtomicBool,
    slots: &Slots,
    traffic: &Traffic,
    heads: &Arc<PerIp>,
    handler: &Handler<'_>,
    relayed: bool,
) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut idle_since = Instant::now();
    let mut first_request = true;
    let mut head_slot: Option<HeadSlot> = None;
    loop {
        // One request head (GET only, no body). From its first byte it has
        // `HEAD_DEADLINE` to arrive; a connection that never starts one is
        // given the same time at first and `CONN_IDLE` between requests.
        let mut head_since: Option<Instant> = (!buf.is_empty()).then(Instant::now);
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if buf.len() > MAX_HEAD {
                return Ok(());
            }
            let too_slow = match head_since {
                Some(t) => t.elapsed() > HEAD_DEADLINE,
                None if first_request => idle_since.elapsed() > HEAD_DEADLINE,
                None => idle_since.elapsed() > CONN_IDLE,
            };
            if stop.load(std::sync::atomic::Ordering::Relaxed) || too_slow {
                return Ok(());
            }
            match sock.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    head_since.get_or_insert_with(Instant::now);
                    buf.extend_from_slice(&chunk[..n]);
                    // A head that has begun and is not whole holds a slot of
                    // its address until it is.
                    if head_slot.is_none() && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        head_slot = heads.enter(remote.ip());
                        if head_slot.is_none() {
                            return Ok(()); // too many unfinished heads from this address
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        };
        // A whole head arrived: the slot, if it held one, is free again.
        drop(head_slot.take());
        first_request = false;
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        buf.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let (method, target, version) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        let mut hdrs = RequestHeaders::default();
        let mut connection = String::new();
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                let k = k.trim();
                if k.eq_ignore_ascii_case("X-Varsto-Auth") {
                    hdrs.auth = v.trim().to_string();
                } else if k.eq_ignore_ascii_case("X-Varsto-For") {
                    hdrs.for_device = v.trim().to_string();
                } else if k.eq_ignore_ascii_case("Connection") {
                    connection = v.trim().to_ascii_lowercase();
                }
            }
        }
        let keep = match version {
            "HTTP/1.1" => !connection.contains("close"),
            "HTTP/1.0" => connection.contains("keep-alive"),
            _ => false,
        };
        let path = target.split('?').next().unwrap_or("").to_string();
        let (status, body, peer) = if method == "GET" {
            let snap = snapshot.lock().unwrap().clone();
            let _slot = slots.take();
            handler(snap.as_deref(), &path, &hdrs)
        } else {
            (405, b"method not allowed".to_vec(), None)
        };
        let _active = peer.as_ref().map(|d| traffic.begin(d));
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let mut out = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n{}\r\n",
            body.len(),
            if keep { "" } else { "Connection: close\r\n" }
        )
        .into_bytes();
        out.extend_from_slice(&body);
        sock.write_all(&out)?;
        sock.flush()?;
        if let Some(d) = &peer {
            traffic.record(
                d,
                traffic::Direction::Out,
                body.len() as u64,
                is_object(&path, status),
                &if relayed {
                    RV_LABEL.to_string()
                } else {
                    Route::Tcp(remote).label()
                },
                (!relayed).then_some(remote),
            );
        }
        if !keep {
            sock.close_write();
            return Ok(());
        }
        idle_since = Instant::now();
    }
}

/// Ending the sending side of a served connection, so that what was
/// written reaches the client before the connection closes.
pub(crate) trait CloseWrite {
    fn close_write(&mut self);
}

impl CloseWrite for TcpStream {
    fn close_write(&mut self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

/// The path name of a session relayed by the rendezvous service (section
/// 83.7), in the status displays and the traffic counters.
pub const RV_LABEL: &str = "relayed via rendezvous";

/// How long the TLS handshake of a relayed session may take: the other
/// side may join the relay up to 15 s after us.
const RELAYED_HANDSHAKE: Duration = Duration::from_secs(25);

/// Serve one session relayed by the rendezvous service (the answering side
/// of section 83.7): the same TLS handshake (only certificates of the
/// directory are admitted), tokens and requests as a TCP connection, until
/// the asker closes it, it stays idle, or `stop` is set.
pub fn serve_relayed(
    tls: &v3::tls::TcpTls,
    stream: crate::rendezvous::RelayStream,
    snapshot: &Mutex<Option<Arc<Snapshot>>>,
    stop: &std::sync::atomic::AtomicBool,
    traffic: &Traffic,
) -> Result<()> {
    // Short reads, so the loop watches its deadlines and `stop`.
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let slots = Slots {
        free: Mutex::new(serve_threads().min(4)),
        cv: std::sync::Condvar::new(),
    };
    let heads = Arc::new(PerIp::default());
    let remote = SocketAddr::from(([0, 0, 0, 0], 0));
    tls.serve_stream(stream, remote, RELAYED_HANDSHAKE, |s, handler| {
        serve_connection(
            s, remote, snapshot, stop, &slots, traffic, &heads, handler, true,
        )
    })
}

/// Answer `path` for `dev`, whose request was authenticated already (by its
/// certificate and its connection-bound token, `v3::Responder`). Paths:
/// `/p2p/info`, `/p2p/object/<name>` and `/p2p/activity`; `/p2p/changed`,
/// `/p2p/heads` and `/p2p/ledger/` are the responder's own.
pub(crate) fn serve_as(
    snap: &Snapshot,
    path: &str,
    dev: DeviceId,
) -> (u16, Vec<u8>, Option<DeviceId>) {
    if snap.revoked.contains(&dev) {
        return (403, b"forbidden".to_vec(), None);
    }
    // A request that carries this device's own id came from this device
    // itself (an address of ours listed for another device, a stale record
    // of our own): not a peer, never counted. The caller learns the address
    // is its own from the body.
    if dev == snap.device_id {
        return (403, SELF_ANSWER.to_vec(), None);
    }
    if path == "/p2p/activity" {
        // What this device is doing now; in an organization only for the
        // devices of the same user.
        if snap
            .activity_audience
            .as_ref()
            .is_some_and(|a| !a.contains(&dev))
        {
            return (403, b"not shared with this device".to_vec(), Some(dev));
        }
        let body = serde_json::to_vec(&crate::activity::local(&snap.device_id)).unwrap_or_default();
        return (200, body, Some(dev));
    }
    let (status, body) = answer(snap, path);
    (status, body, Some(dev))
}

/// The body of the refusal given to a request from this very device.
pub(crate) const SELF_ANSWER: &[u8] = b"self";

/// A whole object went over the wire (not an info answer or an error).
pub(crate) fn is_object(path: &str, status: u16) -> bool {
    status == 200 && path.starts_with("/p2p/object/")
}

/// Set when another device of the vault said it has published something
/// new (`/p2p/changed`): the service then syncs at once instead of at its
/// next interval.
static CHANGE_HEARD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a peer announced a change since the last call.
pub fn take_change_heard() -> bool {
    CHANGE_HEARD.swap(false, std::sync::atomic::Ordering::SeqCst)
}

/// A peer said it published something new.
pub(crate) fn note_change_heard() {
    CHANGE_HEARD.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn answer(snap: &Snapshot, path: &str) -> (u16, Vec<u8>) {
    if path == "/p2p/info" {
        let body = serde_json::json!({
            "device": snap.device_id.to_string(),
            "pieces": snap.pieces.len(),
            "local_roots": snap.local_roots.len(),
        });
        return (200, body.to_string().into_bytes());
    }
    if let Some(name) = path.strip_prefix("/p2p/object/") {
        let Ok(name) = ObjectName::from_hex(name) else {
            return (400, b"bad name".to_vec());
        };
        return match snap.object(&name) {
            Ok(Some(bytes)) => (200, bytes),
            Ok(None) => (404, b"not here".to_vec()),
            Err(e) => (500, format!("{e}").into_bytes()),
        };
    }
    (404, b"not found".to_vec())
}

/// Private, loopback and link-local addresses: a path over them is "direct-lan".
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// The order routes to a peer are tried in: TCP (LAN addresses first, as
/// the record lists them), then QUIC, then relays. QUIC was measured first
/// for addresses beyond the LAN and was slower there than a new TCP
/// connection per request (October 2026, cloud machines in three
/// countries), so TCP stays first and QUIC is the way through NATs.
#[cfg(test)]
fn order_routes(tcp: &[SocketAddr], udp: &[SocketAddr], relays: Vec<Route>) -> Vec<Route> {
    order_routes_with(tcp, udp, None, relays, None)
}

/// `order_routes` with the rendezvous routes (section 83.9): a QUIC dial
/// after a server-coordinated punch right after the record's QUIC
/// addresses, the rendezvous relay after every peer relay.
fn order_routes_with(
    tcp: &[SocketAddr],
    udp: &[SocketAddr],
    rv_punch: Option<Route>,
    relays: Vec<Route>,
    rv_relay: Option<Route>,
) -> Vec<Route> {
    let mut out: Vec<Route> = tcp.iter().map(|a| Route::Tcp(*a)).collect();
    out.extend(udp.iter().map(|a| Route::Quic(*a)));
    out.extend(rv_punch);
    out.extend(relays);
    out.extend(rv_relay);
    out
}

/// A peer we can ask for objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddr {
    pub device: DeviceId,
    pub addr: SocketAddr,
    #[serde(default)]
    pub name: String,
}

/// Everything the client side knows about one device, merged from its
/// accepted peer record and from signed LAN beacons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub device: DeviceId,
    pub name: String,
    /// TLS over TCP, LAN first.
    pub tcp: Vec<SocketAddr>,
    /// QUIC over UDP, public first.
    pub udp: Vec<SocketAddr>,
    pub cert_sha256: String,
    pub relay_via: Vec<DeviceId>,
    pub nat: stun::Nat,
    pub reachable: bool,
}

impl PeerInfo {
    /// A peer heard on the LAN: its TCP address, and the same port over UDP
    /// when its certificate is known (the two listeners share the number).
    fn add_lan(&mut self, addr: SocketAddr) {
        if !self.tcp.contains(&addr) {
            self.tcp.insert(0, addr);
        }
        if !self.cert_sha256.is_empty() && !self.udp.contains(&addr) {
            self.udp.push(addr);
        }
    }
}

/// The path the last attempt to a peer used, for the status displays.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub device: DeviceId,
    pub name: String,
    /// `direct-lan`, `direct`, `relayed via <name>`, `unreachable` or `untried`.
    pub path: String,
    pub addr: Option<SocketAddr>,
    /// The peer answered as a device of the vault (200, or 404 for an object).
    pub ok: bool,
    pub checked_utc: i64,
}

/// The outcome of the last request to one peer: route (none when every
/// route failed), status answered, and when.
type Attempt = (Option<Route>, u16, Instant);

/// How one request reached (or failed to reach) a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Route {
    Tcp(SocketAddr),
    Quic(SocketAddr),
    Relay(DeviceId, String, SocketAddr),
    /// The connection the peer keeps open with us as its relay.
    Registered(SocketAddr),
    /// QUIC to the address the rendezvous service observed for the peer,
    /// both sides punching at once (`punch`, section 83.6).
    RvPunch,
    /// A session relayed by the rendezvous service (section 83.7).
    Rendezvous,
}

impl Route {
    fn label(&self) -> String {
        match self {
            Route::Tcp(a) | Route::Quic(a) | Route::Registered(a) if is_lan(a.ip()) => {
                "direct-lan".into()
            }
            Route::Tcp(_) | Route::Quic(_) | Route::Registered(_) | Route::RvPunch => {
                "direct".into()
            }
            Route::Relay(dev, name, _) => format!(
                "relayed via {}",
                if name.is_empty() { dev.short() } else { name }
            ),
            Route::Rendezvous => RV_LABEL.into(),
        }
    }
    /// The address the route dials; none for the rendezvous routes (the
    /// punched address is the server's to tell, a relay has none).
    fn addr(&self) -> Option<SocketAddr> {
        match self {
            Route::Tcp(a) | Route::Quic(a) | Route::Relay(_, _, a) | Route::Registered(a) => {
                Some(*a)
            }
            Route::RvPunch | Route::Rendezvous => None,
        }
    }
    /// For the log: transport and address, and the relay's name.
    fn describe(&self) -> String {
        match self {
            Route::Tcp(a) => format!("tcp {a}"),
            Route::Quic(a) => format!("quic {a}"),
            Route::Registered(a) => format!("quic {a}, its registration with us"),
            Route::Relay(dev, name, a) => format!(
                "relay {} at {a}",
                if name.is_empty() { dev.short() } else { name }
            ),
            Route::RvPunch => "quic after a rendezvous punch".into(),
            Route::Rendezvous => "rendezvous relay".into(),
        }
    }
}

/// One request and its response on `s` (the TLS session over a TCP
/// stream); `headers` are the extra header lines, each ending
/// in CRLF. The stream comes back when it can carry another request (a
/// `Content-Length` body, no `Connection: close`).
pub(crate) fn exchange<S: Read + Write>(
    mut s: S,
    addr: SocketAddr,
    path: &str,
    headers: &str,
) -> Result<(u16, Vec<u8>, Option<S>)> {
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{headers}Connection: keep-alive\r\n\r\n")
            .as_bytes(),
    )?;
    s.flush()?;
    let mut raw: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut buf = vec![0u8; 64 * 1024];
    let sep = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = s.read(&mut buf)?;
        if n == 0 {
            bail!("peer closed the connection before answering");
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    log::trace!("response head: {}", head.replace("\r\n", " | "));
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_ascii_lowercase())
        })
    };
    let close = header("connection").is_some_and(|v| v.contains("close"));
    let chunked = header("transfer-encoding").is_some_and(|v| v.contains("chunked"));
    let length = header("content-length").and_then(|v| v.parse::<usize>().ok());
    let mut body = raw.split_off(sep + 4);
    match (chunked, length) {
        (false, Some(len)) => {
            if len > 64 << 20 {
                bail!("peer answer of {len} bytes is too large");
            }
            while body.len() < len {
                let want = (len - body.len()).min(buf.len());
                let n = s.read(&mut buf[..want])?;
                if n == 0 {
                    bail!("peer closed the connection mid-answer");
                }
                body.extend_from_slice(&buf[..n]);
            }
            body.truncate(len);
            Ok((status, body, (!close).then_some(s)))
        }
        // No length: the body ends with the connection (bounded like the
        // length-prefixed case).
        _ => {
            std::io::Read::by_ref(&mut s)
                .take(64 << 20)
                .read_to_end(&mut body)?;
            let body = if chunked {
                decode_chunked(&body)?
            } else {
                body
            };
            Ok((status, body, None))
        }
    }
}

/// Decode an HTTP/1.1 chunked body (`<hex size>\r\n<data>\r\n ... 0\r\n\r\n`).
pub fn decode_chunked(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0;
    loop {
        let line_end = body[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("malformed chunked body"))?;
        let size_str = std::str::from_utf8(&body[pos..pos + line_end])
            .map_err(|_| anyhow!("malformed chunk size"))?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| anyhow!("malformed chunk size"))?;
        pos += line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size)
            .filter(|e| *e + 2 <= body.len())
            .ok_or_else(|| anyhow!("truncated chunked body"))?;
        if &body[end..end + 2] != b"\r\n" {
            bail!("malformed chunked body");
        }
        out.extend_from_slice(&body[pos..end]);
        pos = end + 2;
    }
    Ok(out)
}

/// Client side: a set of peers tried in turn for each object, the ones that
/// answered recently first. Objects are verified by name by the caller.
/// Per peer the paths are tried in order: TCP to its known addresses, QUIC
/// to its UDP addresses while punching, then a relay from its record. The
/// outcome is remembered for a minute so a dead peer costs one timeout per
/// minute and a live one goes straight to the path that worked.
pub struct Peers {
    pub me: DeviceId,
    pub peers: Vec<PeerInfo>,
    quic: Option<Arc<quic::Node>>,
    /// Per TCP address: did the last attempt answer, and when.
    state: Mutex<BTreeMap<SocketAddr, (bool, Instant)>>,
    /// Per device: the last route (or failure), the status it answered, and when.
    routes: Mutex<BTreeMap<DeviceId, Attempt>>,
    pub timeout: Duration,
    /// Where downloads are counted: the QUIC node's counters when it runs.
    traffic: Arc<Traffic>,
    /// Per device: how its object requests went (`ObjectStats`), so that
    /// peers that have what is asked, and answer fast, are asked first.
    objects: Mutex<BTreeMap<DeviceId, ObjectStats>>,
    /// Addresses that proved to be this device itself: never tried again.
    selfs: Mutex<std::collections::BTreeSet<SocketAddr>>,
    /// This device's identity and its kept TLS sessions (TLS over TCP and
    /// connection-bound tokens, `v3`); the same client across rebuilds
    /// keeps the sessions.
    client: Arc<v3::Client>,
    /// Built from the directory saved on this device only (a vault just
    /// opened): the engine reads the storages' records before it syncs.
    saved_only: bool,
    /// Our own IPv4 subnets, when they are known for certain: a private
    /// address of a peer outside all of them is not tried (it is the
    /// peer's LAN, not ours). `None` tries every address.
    subnets: Option<Vec<(Ipv4Addr, u8)>>,
    /// The rendezvous service, when it is on (section 83): a coordinated
    /// punch and its relay are the last routes to a peer.
    rv: Option<Arc<rendezvous::Rendezvous>>,
}

crate::redacted_opaque!(Peers);

/// The subnets of this host's interfaces, or `None` when an address
/// outside them may still be reachable: no interface list, or a tunnel
/// (VPN) that may route other private networks.
fn own_subnets() -> Option<Vec<(Ipv4Addr, u8)>> {
    let ifaces = crate::netif::interfaces();
    let ranked = crate::netif::rank(&ifaces);
    // `interfaces` falls back to one address with a guessed /24 mask.
    if ranked.is_empty() || ifaces.iter().any(|f| f.name == "default") {
        return None;
    }
    if ranked.iter().any(|c| c.kind == crate::netif::Kind::Overlay) {
        return None;
    }
    Some(
        ifaces
            .iter()
            .filter(|f| f.up && !f.loopback && f.prefix > 0)
            .map(|f| (f.ip, f.prefix))
            .collect(),
    )
}

/// Whether `addr` can be tried from a host on `subnets`: anything but a
/// private IPv4 address on none of them (loopback, link-local, public and
/// IPv6 addresses always are).
fn on_our_side(addr: &SocketAddr, subnets: Option<&[(Ipv4Addr, u8)]>) -> bool {
    let (Some(nets), IpAddr::V4(ip)) = (subnets, addr.ip()) else {
        return true;
    };
    if !ip.is_private() {
        return true;
    }
    nets.iter()
        .any(|(net, prefix)| crate::netif::same_subnet(ip, *net, *prefix))
}

/// How a peer answered object requests lately.
#[derive(Clone, Debug, Default)]
struct ObjectStats {
    /// Requests in a row it did not have the object for (404), since its
    /// last hit. A peer that lacks one block of a file usually lacks the rest.
    miss_streak: u32,
    /// Smoothed seconds per successful object request.
    secs: f64,
}

impl ObjectStats {
    /// Lower is asked first. A miss streak outweighs any speed difference;
    /// within the same streak, faster peers go first; a peer never measured
    /// sits in the middle so that it gets tried.
    fn rank(&self) -> (u32, u64) {
        let speed = if self.secs > 0.0 {
            (self.secs * 1e6) as u64
        } else {
            50_000
        };
        (self.miss_streak.min(8), speed)
    }
}

const ROUTE_TTL: Duration = Duration::from_secs(60);
/// What routes are raced with (`Peers::race`): small, and answered by any
/// device of the vault.
const RACE_PATH: &str = "/p2p/info";
/// Raced routes start this far apart, in their order (`order_routes`).
const RACE_STAGGER: Duration = Duration::from_millis(300);

/// One request over `route` to `p`, with no bookkeeping: what the raced
/// routes run on their own threads (`Peers::race`). `relay_cert` is the
/// relay's pinned certificate for a relayed route.
#[allow(clippy::too_many_arguments)]
fn attempt_route(
    client: &v3::Client,
    quic: Option<&quic::Node>,
    rv: Option<&rendezvous::Rendezvous>,
    route: &Route,
    relay_cert: Option<&str>,
    p: &PeerInfo,
    path: &str,
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    match route {
        Route::RvPunch => {
            let node = quic.ok_or_else(|| anyhow!("no QUIC node"))?;
            let rv = rv.ok_or_else(|| anyhow!("no rendezvous"))?;
            let a = rv.punch_addr(&p.device)?;
            node.request_with(a, &p.cert_sha256, path, true, &|e: &[u8; 32]| {
                client.token(e, &p.device, path)
            })
        }
        Route::Rendezvous => rv
            .ok_or_else(|| anyhow!("no rendezvous"))?
            .request(client, p, path),
        Route::Tcp(a) => client.tcp_get(*a, &p.cert_sha256, &p.device, path, timeout),
        Route::Quic(a) => {
            let node = quic.ok_or_else(|| anyhow!("no QUIC node"))?;
            node.request_with(*a, &p.cert_sha256, path, true, &|e: &[u8; 32]| {
                client.token(e, &p.device, path)
            })
        }
        Route::Registered(_) => {
            let node = quic.ok_or_else(|| anyhow!("no QUIC node"))?;
            node.request_registrant_with(&p.device, path, &|e: &[u8; 32]| {
                client.token(e, &p.device, path)
            })
        }
        Route::Relay(relay, _, a) => {
            let node = quic.ok_or_else(|| anyhow!("no QUIC node"))?;
            let cert = relay_cert.ok_or_else(|| anyhow!("relay record unknown"))?;
            let via = format!("/p2p/via/{}{}", p.device, path);
            node.request_with(*a, cert, &via, true, &|e: &[u8; 32]| {
                client.token(e, relay, &via)
            })
        }
    }
}
/// A peer that refused our certificate (its directory did not name us
/// yet: we published our record after its last read, and our knock makes
/// it read the records again) rests this long only.
const REFUSED_REST: Duration = Duration::from_secs(3);

/// An error of a peer that answered but refused this device's certificate
/// in the TLS handshake (TCP or QUIC).
fn refused_us(e: &str) -> bool {
    [
        "AccessDenied",
        "ApplicationVerificationFailure",
        "CertificateUnknown",
        "BadCertificate",
    ]
    .iter()
    .any(|m| e.contains(m))
}

/// When to note a failure so that it rests `rest` instead of `ROUTE_TTL`.
fn failed_at(rest: Duration) -> Instant {
    let now = Instant::now();
    now.checked_sub(ROUTE_TTL.saturating_sub(rest))
        .unwrap_or(now)
}

impl Peers {
    /// The peers of the directory (accepted peer records of trusted full
    /// devices; never this device or its certificate), LAN addresses heard
    /// in signed beacons for those of them only (a beacon suggests an
    /// address; the pinned handshake decides), TLS over TCP and
    /// connection-bound tokens, with QUIC when a node runs
    /// (`quic::Node::start_v3`). The node's handshake admits the
    /// certificates of the directory from now on (`set_known`).
    pub fn build_v3(
        client: Arc<v3::Client>,
        directory: &v3::PeerDirectory,
        lan: &[PeerAddr],
        quic: Option<Arc<quic::Node>>,
    ) -> Self {
        let mut infos = directory.infos();
        for p in lan {
            if let Some(i) = infos.iter_mut().find(|i| i.device == p.device) {
                i.add_lan(p.addr);
            }
        }
        Self::with_infos(client, infos, quic)
    }

    /// A table over `infos` as they are (the directory's, or a test's).
    pub(crate) fn with_infos(
        client: Arc<v3::Client>,
        infos: Vec<PeerInfo>,
        quic: Option<Arc<quic::Node>>,
    ) -> Self {
        if let Some(node) = &quic {
            node.set_known(infos.clone());
        }
        let traffic = quic
            .as_ref()
            .map(|n| n.traffic().clone())
            .unwrap_or_default();
        traffic.learn_names(infos.iter().map(|i| (&i.device, i.name.as_str())));
        Peers {
            me: client.me().clone(),
            peers: infos,
            quic,
            state: Mutex::new(BTreeMap::new()),
            routes: Mutex::new(BTreeMap::new()),
            timeout: Duration::from_millis(1500),
            traffic,
            objects: Mutex::default(),
            selfs: Mutex::default(),
            client,
            saved_only: false,
            subnets: own_subnets(),
            rv: None,
        }
    }

    /// Reach peers through the rendezvous service too (a coordinated
    /// punch, then its relay, after every other route).
    pub fn with_rendezvous(mut self, rv: Option<Arc<rendezvous::Rendezvous>>) -> Peers {
        self.rv = rv;
        self
    }

    /// Mark a table built from the directory saved on this device only.
    pub fn from_saved_directory(mut self) -> Peers {
        self.saved_only = true;
        self
    }

    /// Built from the saved directory only (`from_saved_directory`).
    pub fn is_from_saved(&self) -> bool {
        self.saved_only
    }

    /// Count downloads in `traffic` (the service's counters).
    pub fn with_traffic(mut self, traffic: Arc<Traffic>) -> Peers {
        traffic.learn_names(self.peers.iter().map(|i| (&i.device, i.name.as_str())));
        self.traffic = traffic;
        self
    }

    pub fn traffic(&self) -> &Arc<Traffic> {
        &self.traffic
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Carry the remembered routes and address states over from the table
    /// this one replaces, so a rebuild (every sync) forgets nothing.
    /// A peer found unreachable whose record has changed since (new
    /// addresses, or a relay it registered with) is tried again at once
    /// instead of resting: the new route may be the one that works.
    pub fn inherit(&self, previous: &Peers) {
        let mut routes = previous.routes.lock().unwrap().clone();
        routes.retain(|dev, (route, _, _)| {
            if route.is_some() {
                return true;
            }
            let old = previous.peers.iter().find(|p| &p.device == dev);
            let new = self.peers.iter().find(|p| &p.device == dev);
            match (old, new) {
                (Some(o), Some(n)) => {
                    o.tcp == n.tcp && o.udp == n.udp && o.relay_via == n.relay_via
                }
                _ => true,
            }
        });
        *self.routes.lock().unwrap() = routes;
        *self.state.lock().unwrap() = previous.state.lock().unwrap().clone();
        *self.objects.lock().unwrap() = previous.objects.lock().unwrap().clone();
        *self.selfs.lock().unwrap() = previous.selfs.lock().unwrap().clone();
    }

    /// The rendezvous service this table reaches peers through, if any.
    pub fn rendezvous(&self) -> Option<&Arc<rendezvous::Rendezvous>> {
        self.rv.as_ref()
    }

    /// Whether `addr` is known to be this device itself.
    pub fn is_self_addr(&self, addr: SocketAddr) -> bool {
        self.selfs.lock().unwrap().contains(&addr)
    }

    /// Peers worth asking now: unreachable ones rest for a minute, the ones
    /// with a working route go first.
    fn ordered(&self) -> Vec<PeerInfo> {
        let routes = self.routes.lock().unwrap();
        let mut v: Vec<PeerInfo> = self
            .peers
            .iter()
            .filter(|p| match routes.get(&p.device) {
                Some((None, _, when)) => when.elapsed() > ROUTE_TTL,
                _ => true,
            })
            .cloned()
            .collect();
        v.sort_by_key(|p| match routes.get(&p.device) {
            Some((Some(_), _, _)) => 0,
            _ => 1,
        });
        v
    }

    fn remember(&self, device: &DeviceId, route: Option<Route>, status: u16) {
        self.routes
            .lock()
            .unwrap()
            .insert(device.clone(), (route, status, Instant::now()));
    }

    fn debug(&self, what: &str) {
        log::debug!("{what}");
    }

    fn try_tcp(&self, addr: SocketAddr, path: &str, p: &PeerInfo) -> Result<(u16, Vec<u8>)> {
        let result = self
            .client
            .tcp_get(addr, &p.cert_sha256, &p.device, path, self.timeout);
        self.debug(&format!(
            "tcp {addr} {path} -> {}",
            match &result {
                Ok((s, b)) => format!("HTTP {s}, {} bytes", b.len()),
                Err(e) => format!("error: {e}"),
            }
        ));
        let ok = result.is_ok();
        let when = match &result {
            Err(e) if refused_us(&format!("{e:#}")) => failed_at(REFUSED_REST),
            _ => Instant::now(),
        };
        self.state.lock().unwrap().insert(addr, (ok, when));
        result
    }

    /// One request over QUIC to the device `responder` at `addr` (a relay,
    /// for a `/p2p/via/` path), with a token bound to the connection it
    /// goes out on, naming `path` and `responder`.
    fn try_quic(
        &self,
        addr: SocketAddr,
        cert: &str,
        path: &str,
        responder: &DeviceId,
    ) -> Result<(u16, Vec<u8>)> {
        let node = self.quic.as_ref().ok_or_else(|| anyhow!("no QUIC node"))?;
        let c = &self.client;
        let result = node.request_with(addr, cert, path, true, &|exporter: &[u8; 32]| {
            c.token(exporter, responder, path)
        });
        self.debug(&format!(
            "quic {addr} {path} -> {}",
            match &result {
                Ok((s, b)) => format!("{s}, {} bytes", b.len()),
                Err(e) => format!("error: {e:#}"),
            }
        ));
        result
    }

    /// A request to `p` on the connection it keeps with us as its relay.
    fn try_registrant(&self, p: &PeerInfo, path: &str) -> Result<(u16, Vec<u8>)> {
        let node = self.quic.as_ref().ok_or_else(|| anyhow!("no QUIC node"))?;
        let c = &self.client;
        node.request_registrant_with(&p.device, path, &|exporter: &[u8; 32]| {
            c.token(exporter, &p.device, path)
        })
    }

    /// Ask a specific peer once, over a given route; the error says why the
    /// route gave nothing (including "resting" for one that just failed).
    fn over(&self, route: &Route, path: &str, p: &PeerInfo) -> Result<(u16, Vec<u8>)> {
        match route {
            Route::Tcp(a) => {
                // A TCP address that just failed rests for a minute.
                if let Some((false, when)) = self.state.lock().unwrap().get(a) {
                    if when.elapsed() < ROUTE_TTL {
                        bail!("resting after a failure");
                    }
                }
                if self.is_self_addr(*a) {
                    bail!("that address is this device itself");
                }
                let (status, body) = self.try_tcp(*a, path, p)?;
                if status == 403 && body == SELF_ANSWER {
                    log(&format!("{a} answered as this very device; not used again"));
                    self.selfs.lock().unwrap().insert(*a);
                    bail!("that address is this device itself");
                }
                Ok((status, body))
            }
            Route::Quic(a) => {
                if self.is_self_addr(*a) {
                    bail!("that address is this device itself");
                }
                let (status, body) = self.try_quic(*a, &p.cert_sha256, path, &p.device)?;
                if status == 403 && body == SELF_ANSWER {
                    log(&format!("{a} answered as this very device; not used again"));
                    self.selfs.lock().unwrap().insert(*a);
                    bail!("that address is this device itself");
                }
                Ok((status, body))
            }
            Route::Registered(_) => self.try_registrant(p, path),
            Route::RvPunch | Route::Rendezvous => attempt_route(
                &self.client,
                self.quic.as_deref(),
                self.rv.as_deref(),
                route,
                None,
                p,
                path,
                self.timeout,
            ),
            Route::Relay(relay, _, a) => {
                let cert = self
                    .peers
                    .iter()
                    .find(|r| &r.device == relay)
                    .map(|r| r.cert_sha256.clone())
                    .ok_or_else(|| anyhow!("relay record unknown"))?;
                let via = format!("/p2p/via/{}{}", p.device, path);
                self.try_quic(*a, &cert, &via, relay)
            }
        }
    }

    /// Why `route` is not to be tried now (`over` would refuse it at once),
    /// or `None`.
    fn not_ready(&self, route: &Route) -> Option<&'static str> {
        match route {
            Route::Tcp(a) => {
                if let Some((false, when)) = self.state.lock().unwrap().get(a) {
                    if when.elapsed() < ROUTE_TTL {
                        return Some("resting after a failure");
                    }
                }
                self.is_self_addr(*a)
                    .then_some("that address is this device itself")
            }
            Route::Quic(a) => self
                .is_self_addr(*a)
                .then_some("that address is this device itself"),
            Route::Registered(_) | Route::Relay(..) | Route::RvPunch | Route::Rendezvous => None,
        }
    }

    /// Ask `RACE_PATH` over every route in `routes` at once, the n-th
    /// starting `RACE_STAGGER` × n late (so the first, usually the LAN,
    /// wins without the others costing anything when it answers): the
    /// first route that answers as a device of the vault, with its answer.
    /// Failures go to `tried`; TCP outcomes are remembered as `try_tcp`
    /// does. Routes still running when one answered finish in the
    /// background and are ignored.
    fn race(
        &self,
        p: &PeerInfo,
        routes: &[Route],
        tried: &mut Vec<String>,
    ) -> Option<(Route, u16, Vec<u8>)> {
        let (tx, rx) = std::sync::mpsc::channel::<(usize, Result<(u16, Vec<u8>)>)>();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        for (i, route) in routes.iter().enumerate() {
            let relay_cert = match route {
                Route::Relay(relay, _, _) => self
                    .peers
                    .iter()
                    .find(|r| &r.device == relay)
                    .map(|r| r.cert_sha256.clone()),
                _ => None,
            };
            let (client, quic, rv, route, peer, tx, done, timeout) = (
                self.client.clone(),
                self.quic.clone(),
                self.rv.clone(),
                route.clone(),
                p.clone(),
                tx.clone(),
                done.clone(),
                self.timeout,
            );
            let spawned = std::thread::Builder::new()
                .name("p2p-route".into())
                .spawn(move || {
                    let wait = RACE_STAGGER * i as u32;
                    if !wait.is_zero() {
                        std::thread::sleep(wait);
                    }
                    if done.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    let got = attempt_route(
                        &client,
                        quic.as_deref(),
                        rv.as_deref(),
                        &route,
                        relay_cert.as_deref(),
                        &peer,
                        RACE_PATH,
                        timeout,
                    );
                    let _ = tx.send((i, got));
                });
            if let Err(e) = spawned {
                tried.push(format!("{}: no thread: {e}", routes[i].describe()));
            }
        }
        drop(tx);
        // Ends when every thread has sent or given up (each attempt is
        // bounded by its own transport timeouts).
        while let Ok((i, got)) = rx.recv() {
            let r = &routes[i];
            match got {
                Ok((403, body))
                    if body == SELF_ANSWER
                        && !matches!(r, Route::Relay(..) | Route::RvPunch | Route::Rendezvous) =>
                {
                    if let Some(a) = r.addr() {
                        log(&format!("{a} answered as this very device; not used again"));
                        self.selfs.lock().unwrap().insert(a);
                    }
                    tried.push(format!(
                        "{}: that address is this device itself",
                        r.describe()
                    ));
                }
                Ok((s, b)) => {
                    done.store(true, std::sync::atomic::Ordering::Relaxed);
                    if let Route::Tcp(a) = r {
                        self.state
                            .lock()
                            .unwrap()
                            .insert(*a, (true, Instant::now()));
                    }
                    return Some((r.clone(), s, b));
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if let Route::Tcp(a) = r {
                        let when = if refused_us(&msg) {
                            failed_at(REFUSED_REST)
                        } else {
                            Instant::now()
                        };
                        self.state.lock().unwrap().insert(*a, (false, when));
                    }
                    tried.push(format!("{}: {msg}", r.describe()));
                }
            }
        }
        None
    }

    /// Every route to `p`, in the order they are tried.
    fn candidate_routes(&self, p: &PeerInfo) -> Vec<Route> {
        let mut relays = Vec::new();
        let quic = self.quic.is_some() && !p.cert_sha256.is_empty();
        if quic {
            for relay in &p.relay_via {
                let Some(r) = self.peers.iter().find(|r| &r.device == relay) else {
                    continue;
                };
                if r.cert_sha256.is_empty() {
                    continue;
                }
                for a in &r.udp {
                    relays.push(Route::Relay(relay.clone(), r.name.clone(), *a));
                }
            }
        }
        let selfs = self.selfs.lock().unwrap().clone();
        // A private address on none of our subnets is the peer's own LAN
        // seen from elsewhere: dialling it costs a timeout and reaches
        // nothing (or a stranger with the same address).
        let nets = self.subnets.as_deref();
        let tcp: Vec<SocketAddr> = p
            .tcp
            .iter()
            .filter(|a| !selfs.contains(a) && on_our_side(a, nets))
            .copied()
            .collect();
        let udp: Vec<SocketAddr> = p
            .udp
            .iter()
            .filter(|a| !selfs.contains(a) && on_our_side(a, nets))
            .copied()
            .collect();
        // The rendezvous service: a punch it coordinates after the record's
        // own QUIC addresses, its relay after the peer relays (section 83.9).
        let (rv_punch, rv_relay) = match &self.rv {
            Some(rv) if !p.cert_sha256.is_empty() => (
                (quic && rv.can_punch()).then_some(Route::RvPunch),
                rv.can_relay().then_some(Route::Rendezvous),
            ),
            _ => (None, None),
        };
        let mut routes = order_routes_with(
            &tcp,
            if quic { &udp } else { &[] },
            rv_punch,
            relays,
            rv_relay,
        );
        // A peer that keeps its relay registration with us is reached on
        // that connection first: it is open already, and behind a symmetric
        // NAT nothing else reaches it from here.
        if let Some(a) = self
            .quic
            .as_ref()
            .and_then(|n| n.registrant_addr(&p.device))
        {
            routes.insert(0, Route::Registered(a));
        }
        routes
    }

    /// One request to peer `p`: the route that worked last time first, then
    /// every candidate in order. Records the outcome and logs every change
    /// of path, so the service log tells how a NAT was (not) crossed.
    fn fetch(&self, p: &PeerInfo, path: &str) -> Option<(u16, Vec<u8>, Route)> {
        let _active = self.traffic.begin(&p.device);
        let t = crate::logging::Timer::start();
        let got = self.fetch_uncounted(p, path);
        let chatty = path.starts_with("/p2p/object/");
        let level = if chatty && got.as_ref().is_some_and(|g| g.0 == 200 || g.0 == 404) {
            log::Level::Trace
        } else {
            log::Level::Debug
        };
        if log::log_enabled!(level) {
            let peer = if p.name.is_empty() {
                p.device.short().to_string()
            } else {
                p.name.clone()
            };
            match &got {
                Some((status, body, route)) => {
                    log::log!(level, peer = peer, path = path, status = *status, bytes = body.len(), route = route.label(), ms = t.ms(); "p2p request")
                }
                None => {
                    log::log!(level, peer = peer, path = path, ms = t.ms(); "p2p request: no route reached the peer")
                }
            }
        }
        if let Some((status, body, route)) = &got {
            self.traffic.record(
                &p.device,
                traffic::Direction::In,
                body.len() as u64,
                is_object(path, *status),
                &route.label(),
                route.addr(),
            );
        }
        got
    }

    fn fetch_uncounted(&self, p: &PeerInfo, path: &str) -> Option<(u16, Vec<u8>, Route)> {
        let who = if p.name.is_empty() {
            p.device.short().to_string()
        } else {
            p.name.clone()
        };
        // The route that worked last time goes first, however long ago:
        // falling back to the candidate list costs a timeout per dead
        // address before the working one is reached again.
        let last = match self.routes.lock().unwrap().get(&p.device) {
            Some((Some(r), _, _)) => Some(r.clone()),
            _ => None,
        };
        if let Some(r) = last {
            match self.over(&r, path, p) {
                Ok((s, b)) => {
                    // Requests run side by side: one may have switched the
                    // peer to a better route meanwhile; keep that one.
                    let mut routes = self.routes.lock().unwrap();
                    match routes.get(&p.device) {
                        Some((Some(cur), _, _)) if *cur != r => {}
                        _ => {
                            routes.insert(p.device.clone(), (Some(r.clone()), s, Instant::now()));
                        }
                    }
                    return Some((s, b, r));
                }
                Err(e) => log(&format!("{who}: {} lost: {e:#}", r.describe())),
            }
        }
        let mut tried = Vec::new();
        // Routes that cannot be used now are noted, not tried.
        let mut ready = Vec::new();
        for r in self.candidate_routes(p) {
            match self.not_ready(&r) {
                Some(why) => tried.push(format!("{}: {why}", r.describe())),
                None => ready.push(r),
            }
        }
        if ready.len() > 1 {
            // Several routes: race them with a small request (staggered,
            // the first one ahead), then ask the real thing on the winner.
            // One at a time, every dead address would cost its timeout first.
            if let Some((r, s, b)) = self.race(p, &ready, &mut tried) {
                let got = if path == RACE_PATH {
                    Ok((s, b))
                } else {
                    // The peer counted the probe's answer; so do we.
                    self.traffic.record(
                        &p.device,
                        traffic::Direction::In,
                        b.len() as u64,
                        false,
                        &r.label(),
                        r.addr(),
                    );
                    self.over(&r, path, p)
                };
                match got {
                    Ok((s, b)) => {
                        log(&format!("{who}: {} answered {s}", r.describe()));
                        self.remember(&p.device, Some(r.clone()), s);
                        return Some((s, b, r));
                    }
                    Err(e) => tried.push(format!("{}: {e:#}", r.describe())),
                }
            }
        } else {
            for r in ready {
                match self.over(&r, path, p) {
                    Ok((s, b)) => {
                        log(&format!("{who}: {} answered {s}", r.describe()));
                        self.remember(&p.device, Some(r.clone()), s);
                        return Some((s, b, r));
                    }
                    Err(e) => tried.push(format!("{}: {e:#}", r.describe())),
                }
            }
        }
        log(&format!(
            "{who}: unreachable ({})",
            if tried.is_empty() {
                "no route to try".to_string()
            } else {
                tried.join("; ")
            }
        ));
        if !tried.is_empty() && tried.iter().all(|t| refused_us(t)) {
            // It answered and refused us: it reads our record soon.
            self.routes
                .lock()
                .unwrap()
                .insert(p.device.clone(), (None, 0, failed_at(REFUSED_REST)));
        } else {
            self.remember(&p.device, None, 0);
        }
        None
    }

    /// Fetch one object from the first peer that has it. Peers with a
    /// working route come first (`ordered`), and among them the ones that
    /// had the objects asked lately and answered fastest: asking a peer
    /// that lacks the object through a relay before one on the LAN that has
    /// it would cost a round trip for every block.
    pub fn get(&self, name: &ObjectName) -> Option<(DeviceId, Vec<u8>)> {
        let path = format!("/p2p/object/{name}");
        let mut order = self.ordered();
        {
            let routes = self.routes.lock().unwrap();
            let stats = self.objects.lock().unwrap();
            order.sort_by_key(|p| {
                let routed = matches!(routes.get(&p.device), Some((Some(_), _, _)));
                let rank = stats.get(&p.device).cloned().unwrap_or_default().rank();
                (!routed, rank)
            });
        }
        for p in order {
            let t = Instant::now();
            let got = self.fetch(&p, &path);
            let mut stats = self.objects.lock().unwrap();
            let e = stats.entry(p.device.clone()).or_default();
            match got {
                Some((200, body, _)) if ObjectName::from_bytes(&crypto::hash(&body)) == *name => {
                    let secs = t.elapsed().as_secs_f64();
                    e.secs = if e.secs > 0.0 {
                        e.secs * 0.8 + secs * 0.2
                    } else {
                        secs
                    };
                    e.miss_streak = 0;
                    return Some((p.device, body));
                }
                Some((404, _, _)) => e.miss_streak = e.miss_streak.saturating_add(1),
                _ => {}
            }
        }
        None
    }

    /// Tell every peer that this device published something new (a folder,
    /// changed files), so that it syncs now, with this device's head list
    /// (`v3::heads`): each answer carries the peer's own list and proofs of
    /// what it holds beyond ours, returned per peer. Best effort: a peer
    /// that does not answer finds the change at its next interval anyway.
    pub fn notify_changed(&self, mine: &[v3::HeadRef]) -> Vec<(DeviceId, v3::HeadsAnswer)> {
        v3::notify_changed(self, mine)
    }

    /// One request to one peer, over the route that worked last: `None`
    /// when the device is not in the table, rests after a failure, or no
    /// route reached it. For small requests (`/p2p/activity`).
    pub fn ask(&self, device: &DeviceId, path: &str) -> Option<(u16, Vec<u8>)> {
        let p = self.ordered().into_iter().find(|p| &p.device == device)?;
        self.fetch(&p, path).map(|(s, b, _)| (s, b))
    }

    /// One request to every peer worth asking now: `(device, status, body)`
    /// of those that answered.
    pub fn ask_each(&self, path: &str) -> Vec<(DeviceId, u16, Vec<u8>)> {
        self.ordered()
            .into_iter()
            .filter_map(|p| {
                self.fetch(&p, path)
                    .map(|(s, b, _)| (p.device.clone(), s, b))
            })
            .collect()
    }

    /// Which peers answer right now, and over which path.
    pub fn probe(&self) -> Vec<PeerStatus> {
        let path = "/p2p/info";
        self.peers
            .iter()
            .map(|p| {
                let _ = self.fetch(p, path);
                self.status_of(p)
            })
            .collect()
    }

    fn status_of(&self, p: &PeerInfo) -> PeerStatus {
        let routes = self.routes.lock().unwrap();
        // `ok` means the peer answered as a vault device: 200, or 404 for an
        // object it does not hold. A 403 means the path works but we do not.
        let (path, addr, ok, when) = match routes.get(&p.device) {
            Some((Some(r), status, when)) => {
                (r.label(), r.addr(), matches!(status, 200 | 404), Some(when))
            }
            Some((None, _, when)) => ("unreachable".to_string(), None, false, Some(when)),
            None => ("untried".to_string(), None, false, None),
        };
        PeerStatus {
            device: p.device.clone(),
            name: p.name.clone(),
            path,
            addr,
            ok,
            checked_utc: when
                .map(|w| now() - w.elapsed().as_secs() as i64)
                .unwrap_or(0),
        }
    }

    /// The last known path to every peer, without probing.
    pub fn status(&self) -> Vec<PeerStatus> {
        self.peers.iter().map(|p| self.status_of(p)).collect()
    }
}

/// Non-loopback IPv4 addresses of this host, for the peer record.
pub fn local_ipv4_addrs() -> Vec<IpAddr> {
    // Portable trick: a UDP socket "connected" to a public address reveals
    // the interface address the OS would use, without sending anything.
    let mut out = Vec::new();
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("192.0.2.1:9").is_ok() {
            if let Ok(a) = s.local_addr() {
                if !a.ip().is_loopback() {
                    out.push(a.ip());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_bodies_are_decoded_within_bounds() {
        assert_eq!(decode_chunked(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), b"abc");
        for bad in [
            &b"1\r\nA"[..],
            b"5\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabcXX0\r\n\r\n",
            b"zz\r\n",
            b"3\r\nab",
        ] {
            assert!(decode_chunked(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn peers_that_have_objects_and_answer_fast_rank_first() {
        let fast = ObjectStats {
            miss_streak: 0,
            secs: 0.002,
        };
        let slow = ObjectStats {
            miss_streak: 0,
            secs: 0.2,
        };
        let lacking = ObjectStats {
            miss_streak: 3,
            secs: 0.001,
        };
        let unknown = ObjectStats::default();
        let mut v = [lacking.rank(), slow.rank(), unknown.rank(), fast.rank()];
        v.sort();
        assert_eq!(
            v,
            [fast.rank(), unknown.rank(), slow.rank(), lacking.rank()]
        );
    }

    fn snap(me: &DeviceId) -> Snapshot {
        Snapshot {
            vault_id: crate::ids::VaultId::random(),
            device_id: me.clone(),
            folder_keys: BTreeMap::new(),
            pieces: BTreeMap::new(),
            local_roots: Vec::new(),
            packed: BTreeMap::new(),
            revoked: Default::default(),
            activity_audience: None,
            heads: Vec::new(),
            ledger_dir: None,
        }
    }

    #[test]
    fn revoked_devices_are_refused_even_when_authenticated() {
        let (good, gone) = (DeviceId::random(), DeviceId::random());
        let mut s = snap(&DeviceId::random());
        s.revoked = [gone.clone()].into_iter().collect();
        assert_eq!(serve_as(&s, "/p2p/info", good.clone()).0, 200);
        assert_eq!(serve_as(&s, "/p2p/info", gone).0, 403);
    }

    #[test]
    fn activity_is_told_to_devices_of_the_audience_only() {
        let me = DeviceId::random();
        let (same_user, other_user) = (DeviceId::random(), DeviceId::random());
        let mut s = snap(&me);
        let path = "/p2p/activity";
        let (status, body, _) = serve_as(&s, path, other_user.clone());
        assert_eq!(status, 200);
        let a: crate::activity::DeviceActivity = serde_json::from_slice(&body).unwrap();
        assert_eq!(a.device, me.to_string());
        assert!(a.state == "idle" || a.state == "busy");
        // An organization: only the devices of the same user.
        s.activity_audience = Some([same_user.clone()].into_iter().collect());
        assert_eq!(serve_as(&s, path, same_user).0, 200);
        let (status, body, _) = serve_as(&s, path, other_user);
        assert_eq!(status, 403);
        assert!(!String::from_utf8_lossy(&body).contains("idle"));
    }

    #[test]
    fn a_request_from_this_very_device_is_refused_and_never_counted() {
        let (me, other) = (DeviceId::random(), DeviceId::random());
        let s = snap(&me);
        for path in ["/p2p/info", "/p2p/activity", "/p2p/object/00"] {
            let (status, body, peer) = serve_as(&s, path, me.clone());
            assert_eq!((status, body.as_slice(), peer), (403, SELF_ANSWER, None));
        }
        // Another device of the vault is answered and counted as before.
        let (status, _, peer) = serve_as(&s, "/p2p/info", other.clone());
        assert_eq!((status, peer), (200, Some(other)));
    }

    #[test]
    fn unfinished_request_heads_are_limited_per_address() {
        let heads = Arc::new(PerIp::default());
        let ip: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let held: Vec<_> = (0..MAX_HEADS_PER_IP)
            .map(|_| heads.enter(ip).unwrap())
            .collect();
        assert!(heads.enter(ip).is_none(), "the ninth is refused");
        assert!(heads.enter("192.0.2.8".parse().unwrap()).is_some());
        drop(held);
        assert!(heads.enter(ip).is_some(), "slots are given back");
    }

    #[test]
    fn chunked_bodies_decode() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"zz\r\n").is_err());
    }

    #[test]
    fn peer_record_addresses_put_the_router_mapping_after_the_lan() {
        let rec = v3::PeerBody {
            device: [3u8; 16],
            seq: 1,
            name: "laptop".into(),
            port: 17893,
            lan_addrs: vec!["192.168.1.5".parse().unwrap()],
            public_addrs: vec!["198.51.100.2:17893".parse().unwrap()],
            udp_public: vec!["203.0.113.7:40000".parse().unwrap()],
            udp_local: vec!["192.168.1.5:17893".parse().unwrap()],
            mapped_tcp: vec!["203.0.113.7:17893".parse().unwrap()],
            mapped_udp: vec!["203.0.113.7:17894".parse().unwrap()],
            cert_sha256: [0xab; 32],
            nat: stun::Nat::Cone,
            relay_via: vec![[4u8; 16]],
            reachable: false,
            heads: Vec::new(),
            pushed: Vec::new(),
        };
        // A port the router forwards comes right after the LAN for TCP and
        // first for QUIC.
        assert_eq!(
            rec.tcp_addrs(),
            vec![
                "192.168.1.5:17893".parse::<SocketAddr>().unwrap(),
                "203.0.113.7:17893".parse().unwrap(),
                "198.51.100.2:17893".parse().unwrap()
            ]
        );
        let udp = rec.udp_addrs();
        assert_eq!(udp[0], "203.0.113.7:17894".parse().unwrap());
        assert_eq!(udp[1], rec.udp_public[0]);
        let info = rec.info();
        assert_eq!(info.cert_sha256, "ab".repeat(32));
        assert_eq!(info.relay_via, vec![DeviceId::from_bytes(&[4u8; 16])]);
        // Equal apart from the seq: nothing to republish.
        let mut later = rec.clone();
        later.seq = 7;
        assert!(later.same_as(&rec));
        later.reachable = true;
        assert!(!later.same_as(&rec));
    }

    #[test]
    fn routes_are_labelled_by_address_kind() {
        let lan: SocketAddr = "192.168.0.9:1".parse().unwrap();
        let pubaddr: SocketAddr = "203.0.113.9:1".parse().unwrap();
        assert_eq!(Route::Tcp(lan).label(), "direct-lan");
        assert_eq!(Route::Quic(pubaddr).label(), "direct");
        let r = Route::Relay(DeviceId::from_bytes(&[1u8; 16]), "home".into(), pubaddr);
        assert_eq!(r.label(), "relayed via home");
        assert!(is_lan("127.0.0.1".parse().unwrap()));
        assert!(is_lan("fe80::1".parse().unwrap()));
        assert!(!is_lan("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn routes_are_tried_tcp_then_quic_then_relays() {
        let lan: SocketAddr = "192.168.1.5:17893".parse().unwrap();
        let wide: SocketAddr = "203.0.113.5:17893".parse().unwrap();
        let relay = Route::Relay(
            DeviceId::from_hex("00112233445566778899aabbccddeeff").unwrap(),
            "r".into(),
            wide,
        );
        let got = order_routes(&[lan, wide], &[wide, lan], vec![relay.clone()]);
        assert_eq!(
            got,
            vec![
                Route::Tcp(lan),
                Route::Tcp(wide),
                Route::Quic(wide),
                Route::Quic(lan),
                relay.clone()
            ]
        );
        assert_eq!(order_routes(&[lan], &[], vec![]), vec![Route::Tcp(lan)]);
        // The rendezvous: its punch after the record's QUIC addresses, its
        // relay after the peer relays.
        let got = order_routes_with(
            &[lan],
            &[wide],
            Some(Route::RvPunch),
            vec![relay.clone()],
            Some(Route::Rendezvous),
        );
        assert_eq!(
            got,
            vec![
                Route::Tcp(lan),
                Route::Quic(wide),
                Route::RvPunch,
                relay,
                Route::Rendezvous
            ]
        );
        assert_eq!(Route::Rendezvous.label(), "relayed via rendezvous");
        assert_eq!(Route::Rendezvous.addr(), None);
    }

    #[test]
    fn private_addresses_off_our_subnets_are_not_dialled() {
        let nets = [(Ipv4Addr::new(192, 168, 1, 20), 24u8)];
        let ours: SocketAddr = "192.168.1.5:17893".parse().unwrap();
        let theirs: SocketAddr = "192.168.7.5:17893".parse().unwrap();
        let corp: SocketAddr = "10.1.2.3:17893".parse().unwrap();
        let public: SocketAddr = "203.0.113.5:17893".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:17893".parse().unwrap();
        let v6: SocketAddr = "[fd00::5]:17893".parse().unwrap();
        assert!(on_our_side(&ours, Some(&nets)));
        assert!(!on_our_side(&theirs, Some(&nets)));
        assert!(!on_our_side(&corp, Some(&nets)));
        assert!(on_our_side(&public, Some(&nets)));
        assert!(on_our_side(&lo, Some(&nets)));
        assert!(on_our_side(&v6, Some(&nets)));
        // Subnets not known for certain (a VPN, no interface list): all are tried.
        assert!(on_our_side(&theirs, None));
    }
}
