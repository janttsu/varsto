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
    /// Blocks of files a pull wrote since this snapshot was built, served
    /// like `pieces` (`FreshPieces`).
    pub fresh: Arc<FreshPieces>,
}

crate::redacted_opaque!(Snapshot);

/// Pieces of the files a pull has written since the snapshot was last
/// built, with the folder keys to seal them: served like the snapshot's
/// own pieces, so another device pulling the same folder at the same time
/// can fetch from this one the blocks it already wrote instead of asking
/// the writer for everything (swarming). The engine adds every file it
/// puts in place during a pull and empties the set when it builds the
/// next snapshot, which then covers those files. A piece is checked
/// against its chunk id when it is read, as the snapshot's are, so a file
/// changed or moved since is never served.
#[derive(Default)]
pub struct FreshPieces {
    inner: Mutex<FreshInner>,
}

#[derive(Default)]
struct FreshInner {
    pieces: std::collections::HashMap<ObjectName, Piece>,
    keys: BTreeMap<FolderId, Arc<FolderKeys>>,
}

crate::redacted_opaque!(FreshPieces);

/// At most this many fresh pieces are kept (about 200 bytes each); past
/// it, new ones wait for the next snapshot.
const FRESH_MAX: usize = 1 << 20;

impl FreshPieces {
    /// Whether the keys of `folder` are held already.
    pub fn has_keys(&self, folder: &FolderId) -> bool {
        self.inner.lock().unwrap().keys.contains_key(folder)
    }

    /// Serve `pieces` of `folder` (keys given once per folder; without
    /// them, pieces of a folder whose keys were never given are dropped).
    pub fn add(
        &self,
        folder: &FolderId,
        keys: Option<FolderKeys>,
        pieces: impl IntoIterator<Item = (ObjectName, Piece)>,
    ) {
        let mut g = self.inner.lock().unwrap();
        if let Some(k) = keys {
            g.keys.insert(folder.clone(), Arc::new(k));
        }
        if !g.keys.contains_key(folder) {
            return;
        }
        for (name, piece) in pieces {
            if g.pieces.len() >= FRESH_MAX {
                break;
            }
            g.pieces.insert(name, piece);
        }
    }

    /// Forget every piece (a new snapshot covers them).
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.pieces.clear();
        g.keys.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().pieces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, name: &ObjectName) -> Option<(Piece, Arc<FolderKeys>)> {
        let g = self.inner.lock().unwrap();
        let piece = g.pieces.get(name)?.clone();
        let keys = g.keys.get(&piece.folder)?.clone();
        Some((piece, keys))
    }
}

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
        if let Some(piece) = self.pieces.get(name) {
            if let Some(fk) = self.folder_keys.get(&piece.folder) {
                if let Some(ct) = self.seal_piece(name, piece, fk)? {
                    return Ok(Some(ct));
                }
            }
        }
        // A block of a file a pull wrote after this snapshot was built.
        match self.fresh.get(name) {
            Some((piece, fk)) => self.seal_piece(name, &piece, &fk),
            None => Ok(None),
        }
    }

    /// The object of `piece`, read from its file and sealed again; `None`
    /// when the file no longer holds the chunk there.
    fn seal_piece(
        &self,
        name: &ObjectName,
        piece: &Piece,
        fk: &FolderKeys,
    ) -> Result<Option<Vec<u8>>> {
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

/// While a pull is running, serve at most a few objects at a time so the
/// upload does not fill the link the download is using. One object left
/// the other reader waiting when two devices pulled the same folder.
/// Off: the ordinary slot cap applies and this permit is not taken.
const SERVING_CAP: usize = 4;
static SERVING_LIMITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SERVING_HELD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn limit_serving(on: bool) {
    SERVING_LIMITED.store(on, std::sync::atomic::Ordering::Release);
}

/// A permit for one served object while [`limit_serving`] is on.
/// At most [`SERVING_CAP`] of these are held at once.
pub(super) struct ServeBudget {
    held: bool,
}

impl ServeBudget {
    pub(super) fn acquire() -> Self {
        use std::sync::atomic::Ordering;
        loop {
            if !SERVING_LIMITED.load(Ordering::Acquire) {
                return ServeBudget { held: false };
            }
            let n = SERVING_HELD.load(Ordering::Acquire);
            if n >= SERVING_CAP {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            if SERVING_HELD
                .compare_exchange(n, n + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return ServeBudget { held: true };
            }
        }
    }
}

impl Drop for ServeBudget {
    fn drop(&mut self) {
        if self.held {
            SERVING_HELD.fetch_sub(1, std::sync::atomic::Ordering::Release);
        }
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
/// open at once. A connection that has not finished the TLS handshake also
/// counts toward `MAX_UNAUTH_PER_IP` for its address, so one address cannot
/// hold every slot before it authenticates. (tiny_http's connection pool
/// queued a new connection behind long-lived ones, so a kept-alive peer
/// could wait for a connection that was never served.)
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
/// Connections of one address that have not finished the TLS handshake.
/// One device opens at most the fetch window (32) of fresh sessions at
/// once, and a second device behind the same address may do the same; the
/// place is freed when the handshake finishes, so an authenticated
/// connection does not count. The next one past this is closed at once,
/// and one address cannot take every slot of `MAX_CONNS`.
const MAX_UNAUTH_PER_IP: usize = 64;

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

/// Connections per address still in the TLS handshake. Same accounting as
/// [`PerIp`], for the time before the peer is authenticated.
#[derive(Default)]
struct Unauth {
    n: Mutex<std::collections::HashMap<IpAddr, usize>>,
}

struct UnauthSlot {
    owner: Arc<Unauth>,
    ip: IpAddr,
}

impl Unauth {
    fn enter(self: &Arc<Self>, ip: IpAddr) -> Option<UnauthSlot> {
        let mut m = self.n.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= MAX_UNAUTH_PER_IP {
            return None;
        }
        *n += 1;
        Some(UnauthSlot {
            owner: self.clone(),
            ip,
        })
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) {
        let mut m = self.owner.n.lock().unwrap();
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
        let unauth = Arc::new(Unauth::default());
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
            // Held only until the handshake finishes (the closure drops it
            // before serving). Over the cap the socket is dropped here, so
            // the address cannot fill the listener before it authenticates.
            let Some(handshake) = unauth.enter(remote.ip()) else {
                continue;
            };
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
                    let _ = tls.serve(sock, remote, move |stream, handler| {
                        drop(handshake);
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
            let _budget = ServeBudget::acquire();
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
    /// The seq of the record this came from: a newer one (the device
    /// started again, or moved) ends a rest (`Peers::inherit`).
    pub seq: u64,
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
    /// Per TCP address: how the last attempt went (`AddrState`).
    state: Mutex<BTreeMap<SocketAddr, AddrState>>,
    /// Per device: the last route (or failure), the status it answered, and when.
    routes: Mutex<BTreeMap<DeviceId, Attempt>>,
    /// Per device: failures in a row, its rest, its last answer (`Health`).
    health: Mutex<BTreeMap<DeviceId, Health>>,
    /// Held while `get` tries a resting peer once more (`revive`), so that
    /// one request does it and the others wait for its outcome.
    reviving: Mutex<()>,
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
    /// Object requests to it in flight now.
    inflight: u32,
    /// After a miss: when it is asked first again (`PROBE_BASE`), to see
    /// whether it holds the objects by now.
    probe_at: Option<Instant>,
}

impl ObjectStats {
    /// Lower is asked first. A miss streak outweighs any speed difference;
    /// among peers with the same streak the one expected to answer first
    /// goes first: seconds per object times the requests it has in flight
    /// plus one, so several peers that hold the objects share the requests
    /// by their speed. A peer whose probe is due (one that lacked the last
    /// objects, or was never measured) goes first, once per probe.
    fn rank(&self, now: Instant) -> (u32, u64) {
        if self.probe_due(now) {
            return (0, 0);
        }
        let secs = if self.secs > 0.0 { self.secs } else { 0.05 };
        let wait = secs * f64::from(self.inflight.saturating_add(1));
        (self.miss_streak.min(8), (wait * 1e6) as u64)
    }

    fn probe_due(&self, now: Instant) -> bool {
        (self.miss_streak > 0 || self.secs <= 0.0) && self.probe_at.is_none_or(|t| now >= t)
    }

    /// The wait before the next probe after `miss_streak` misses in a row.
    fn probe_wait(&self) -> Duration {
        (PROBE_BASE * (1u32 << self.miss_streak.clamp(1, 8).saturating_sub(1))).min(PROBE_MAX)
    }
}

const ROUTE_TTL: Duration = Duration::from_secs(60);
/// A peer that answered less than `ROUTE_TTL` ago and then failed is having
/// a blip (a restart, a closed connection, one lost handshake), not gone:
/// it rests this long, doubling per failure in a row up to `ROUTE_TTL`. A
/// minute's rest after one failed request used to end a pull part-way:
/// every block asked for in that minute was given up without asking.
const BLIP_REST: Duration = Duration::from_secs(1);
/// A peer that never answered rests `ROUTE_TTL` after its first failure,
/// doubling per failure in a row up to this: a device that left the vault
/// long ago (its records stay) costs an attempt now and then, not one per
/// minute. A sign of life, a new record or an explicit sync ends the rest.
const DEAD_REST_MAX: Duration = Duration::from_secs(15 * 60);
/// When no peer that is not resting had an object, `Peers::get` tries a
/// peer that rests after a blip once more, one request at a time, at most
/// this often (doubling per failure in a row); requests that arrive while
/// it is tried wait for that answer.
const REVIVE_GAP: Duration = Duration::from_secs(1);
/// Failures in a row up to which `Peers::get` waits for the next revival
/// instead of giving the object up at once, and `Peers::wake` ends the rest
/// of a peer that never answered.
const REVIVE_WAIT_FAILURES: u32 = 2;
/// `REVIVE_WAIT_FAILURES`, for the tests of `v3`.
#[cfg(test)]
pub(crate) fn tests_revive_wait_failures() -> u32 {
    REVIVE_WAIT_FAILURES
}

/// Requests `Peers::ask_each` has in flight at once.
const ASK_PARALLEL: usize = 8;
/// A peer that lacked the objects asked lately is asked first again after
/// this long, doubling per miss in a row up to `PROBE_MAX`: another device
/// pulling the same folder holds more of it every second.
const PROBE_BASE: Duration = Duration::from_millis(250);
const PROBE_MAX: Duration = Duration::from_secs(30);

/// How reachable one device has been (`Peers::health`).
#[derive(Clone, Debug, Default)]
struct Health {
    /// Not asked before this (unless woken, or revived by `get`).
    rest_until: Option<Instant>,
    /// Attempts in a row in which no route reached it.
    failures: u32,
    /// When it last answered.
    last_ok: Option<Instant>,
    /// When `get` (or a sign of life) last ended or tried its rest.
    revived: Option<Instant>,
}

impl Health {
    fn resting(&self, now: Instant) -> bool {
        self.rest_until.is_some_and(|t| now < t)
    }

    fn answered(&mut self) {
        *self = Health {
            last_ok: Some(Instant::now()),
            ..Health::default()
        };
    }

    /// Answered within `ROUTE_TTL` of `now`.
    fn was_live(&self, now: Instant) -> bool {
        self.last_ok
            .is_some_and(|t| now.saturating_duration_since(t) < ROUTE_TTL)
    }

    /// No route reached it: rest by how it has been doing (see
    /// `BLIP_REST`, `DEAD_REST_MAX`); `refused` (it refused our
    /// certificate, so it reads our record soon) rests `REFUSED_REST`.
    fn failed(&mut self, refused: bool) {
        let now = Instant::now();
        self.failures = self.failures.saturating_add(1);
        let doubling = 1u32 << (self.failures.min(11) - 1);
        let rest = if refused {
            REFUSED_REST
        } else if self.was_live(now) {
            (BLIP_REST * doubling).min(ROUTE_TTL)
        } else if self.last_ok.is_some() {
            ROUTE_TTL
        } else {
            (ROUTE_TTL * doubling).min(DEAD_REST_MAX)
        };
        self.rest_until = Some(now + rest);
    }
}

/// Per TCP address: did the last attempt answer, when, and when it last
/// answered. A failed address rests `ROUTE_TTL`, or `BLIP_REST` when it
/// answered within `ROUTE_TTL` before the failure.
#[derive(Clone, Copy, Debug)]
struct AddrState {
    ok: bool,
    at: Instant,
    last_ok: Option<Instant>,
}

impl AddrState {
    fn resting(&self) -> bool {
        if self.ok {
            return false;
        }
        let blip = self
            .last_ok
            .is_some_and(|t| self.at.saturating_duration_since(t) < ROUTE_TTL);
        self.at.elapsed() < if blip { BLIP_REST } else { ROUTE_TTL }
    }
}

/// How one object request to one peer went (`Peers::ask_object`).
enum Lookup {
    Got(Vec<u8>),
    /// It answered that it does not hold the object (404).
    Lacks,
    /// No answer, or an answer that is not the object.
    Failed,
}

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
            health: Mutex::default(),
            reviving: Mutex::new(()),
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
    /// addresses, a relay it registered with, or a newer record: it
    /// started again and published) is tried again at once instead of
    /// resting: the new route may be the one that works.
    pub fn inherit(&self, previous: &Peers) {
        let changed = |dev: &DeviceId| {
            let old = previous.peers.iter().find(|p| &p.device == dev);
            let new = self.peers.iter().find(|p| &p.device == dev);
            match (old, new) {
                (Some(o), Some(n)) => {
                    o.tcp != n.tcp || o.udp != n.udp || o.relay_via != n.relay_via || o.seq != n.seq
                }
                _ => false,
            }
        };
        let mut routes = previous.routes.lock().unwrap().clone();
        routes.retain(|dev, (route, _, _)| route.is_some() || !changed(dev));
        let mut health = previous.health.lock().unwrap().clone();
        let mut state = previous.state.lock().unwrap().clone();
        for (dev, h) in health.iter_mut() {
            if h.rest_until.is_some() && changed(dev) {
                h.rest_until = None;
                h.failures = 0;
                if let Some(p) = self.peers.iter().find(|p| &p.device == dev) {
                    state.retain(|a, st| st.ok || !p.tcp.contains(a));
                }
            }
        }
        *self.routes.lock().unwrap() = routes;
        *self.health.lock().unwrap() = health;
        *self.state.lock().unwrap() = state;
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

    /// Peers worth asking now: resting ones are left out (`Health`); the
    /// ones with a working route go first, then the ones that answered
    /// most recently, then those that failed fewest times in a row (a
    /// device that never answered comes last).
    fn ordered(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        let routes = self.routes.lock().unwrap();
        let health = self.health.lock().unwrap();
        let mut v: Vec<PeerInfo> = self
            .peers
            .iter()
            .filter(|p| !health.get(&p.device).is_some_and(|h| h.resting(now)))
            .cloned()
            .collect();
        v.sort_by_key(|p| {
            let routed = matches!(routes.get(&p.device), Some((Some(_), _, _)));
            let h = health.get(&p.device).cloned().unwrap_or_default();
            (!routed, std::cmp::Reverse(h.last_ok), h.failures)
        });
        v
    }

    /// Whether `device` rests now (a failed attempt, `Health`).
    pub fn is_resting(&self, device: &DeviceId) -> bool {
        self.health
            .lock()
            .unwrap()
            .get(device)
            .is_some_and(|h| h.resting(Instant::now()))
    }

    /// End the rest of `device`'s failed TCP addresses, so that the next
    /// attempt dials them.
    fn clear_addr_failures(&self, p: &PeerInfo) {
        self.state
            .lock()
            .unwrap()
            .retain(|a, st| st.ok || !p.tcp.contains(a));
    }

    /// Before an explicit sync: end the rest of every peer worth one more
    /// attempt now, so a sync right after a peer restarted asks it instead
    /// of giving its blocks up: those that answered before, and those that
    /// failed at most `REVIVE_WAIT_FAILURES` times in a row (one that never
    /// answered and failed more keeps resting). Returns how many.
    pub fn wake(&self) -> usize {
        let mut woken = Vec::new();
        {
            let now = Instant::now();
            let mut health = self.health.lock().unwrap();
            for (dev, h) in health.iter_mut() {
                if h.resting(now) && (h.last_ok.is_some() || h.failures <= REVIVE_WAIT_FAILURES) {
                    h.rest_until = None;
                    woken.push(dev.clone());
                }
            }
        }
        for p in self.peers.iter().filter(|p| woken.contains(&p.device)) {
            self.clear_addr_failures(p);
        }
        woken.len()
    }

    /// A sign of life from `device` (a signed LAN beacon, a request it
    /// made to us): a rest it has is ended, at most every `ROUTE_TTL / 2`,
    /// so a device whose beacons reach us but whose port does not is not
    /// dialled every few seconds. True when a rest ended.
    pub fn heard_from(&self, device: &DeviceId) -> bool {
        let now = Instant::now();
        {
            let mut health = self.health.lock().unwrap();
            let Some(h) = health.get_mut(device) else {
                return false;
            };
            if !h.resting(now)
                || h.revived
                    .is_some_and(|t| now.saturating_duration_since(t) < ROUTE_TTL / 2)
            {
                return false;
            }
            h.rest_until = None;
            h.revived = Some(now);
        }
        if let Some(p) = self.peers.iter().find(|p| &p.device == device) {
            self.clear_addr_failures(p);
        }
        true
    }

    /// Note the outcome of a request to `device`: the route it answered
    /// on, or `None` when no route reached it (`refused`: it refused our
    /// certificate). An answer ends any rest; a failure starts one.
    fn remember(&self, device: &DeviceId, route: Option<Route>, status: u16, refused: bool) {
        let ok = route.is_some();
        let at = if refused {
            failed_at(REFUSED_REST)
        } else {
            Instant::now()
        };
        self.routes
            .lock()
            .unwrap()
            .insert(device.clone(), (route, status, at));
        let mut health = self.health.lock().unwrap();
        let h = health.entry(device.clone()).or_default();
        if ok {
            h.answered();
        } else {
            h.failed(refused);
        }
    }

    /// The device answered over the route it already had.
    fn answered(&self, device: &DeviceId) {
        self.health
            .lock()
            .unwrap()
            .entry(device.clone())
            .or_default()
            .answered();
    }

    /// Note how a request to the TCP address `addr` went.
    fn note_addr(&self, addr: SocketAddr, ok: bool, refused: bool) {
        let mut state = self.state.lock().unwrap();
        let last_ok = state.get(&addr).and_then(|s| s.last_ok);
        let now = Instant::now();
        state.insert(
            addr,
            AddrState {
                ok,
                at: if refused {
                    failed_at(REFUSED_REST)
                } else {
                    now
                },
                last_ok: if ok { Some(now) } else { last_ok },
            },
        );
    }

    fn addr_resting(&self, addr: &SocketAddr) -> bool {
        self.state
            .lock()
            .unwrap()
            .get(addr)
            .is_some_and(|s| s.resting())
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
        let refused = matches!(&result, Err(e) if refused_us(&format!("{e:#}")));
        self.note_addr(addr, result.is_ok(), refused);
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
                // A TCP address that just failed rests (`AddrState`).
                if self.addr_resting(a) {
                    bail!("resting after a failure");
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
                if self.addr_resting(a) {
                    return Some("resting after a failure");
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
                        self.note_addr(*a, true, false);
                    }
                    return Some((r.clone(), s, b));
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if let Route::Tcp(a) = r {
                        self.note_addr(*a, false, refused_us(&msg));
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
        let began = Instant::now();
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
                    drop(routes);
                    self.answered(&p.device);
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
                        self.remember(&p.device, Some(r.clone()), s, false);
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
                        self.remember(&p.device, Some(r.clone()), s, false);
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
        // A request that ran beside this one may have reached it meanwhile
        // (over the route this one lost, or another): then this failure
        // says nothing about the device.
        let reached = self
            .routes
            .lock()
            .unwrap()
            .get(&p.device)
            .is_some_and(|(r, _, at)| r.is_some() && *at > began);
        if !reached {
            // It answered and refused us: it reads our record soon.
            let refused = !tried.is_empty() && tried.iter().all(|t| refused_us(t));
            self.remember(&p.device, None, 0, refused);
        }
        None
    }

    /// Fetch one object from a peer that has it. Peers with a working
    /// route come first (`ordered`), and among them the ones that had the
    /// objects asked lately, ranked by when they are expected to answer
    /// (`ObjectStats::rank`): asking a peer that lacks the object through a
    /// relay before one on the LAN that has it would cost a round trip for
    /// every block, and with two peers that hold the folder (the writer and
    /// another device pulling it too) the requests are shared between them
    /// instead of all going to the first. A peer that lacked the objects is
    /// asked first again now and then (`PROBE_BASE`), as it may hold them
    /// by now. When no peer that is not resting had the object, a peer that
    /// rests after a blip is tried once more (`revive`).
    pub fn get(&self, name: &ObjectName) -> Option<(DeviceId, Vec<u8>)> {
        let path = format!("/p2p/object/{name}");
        let mut order = self.ordered();
        {
            let now = Instant::now();
            let routes = self.routes.lock().unwrap();
            let mut stats = self.objects.lock().unwrap();
            order.sort_by_key(|p| {
                let routed = matches!(routes.get(&p.device), Some((Some(_), _, _)));
                let rank = stats.get(&p.device).cloned().unwrap_or_default().rank(now);
                (!routed, rank)
            });
            // A probe that is due is taken by this request: the requests
            // running beside it do not all ask the same lacking peer.
            if let Some(first) = order.first() {
                let st = stats.entry(first.device.clone()).or_default();
                if st.probe_due(now) {
                    st.probe_at = Some(now + st.probe_wait());
                }
            }
        }
        for p in &order {
            if let Lookup::Got(body) = self.ask_object(p, &path, name) {
                return Some((p.device.clone(), body));
            }
        }
        // Nobody reachable had it. A peer resting after a blip (it answered
        // a moment ago, then a request failed: a restart, a lost
        // connection) is asked once more instead of the block being given
        // up for the rest of its rest.
        let mut resting: Vec<(PeerInfo, Health)> = {
            let now = Instant::now();
            let health = self.health.lock().unwrap();
            self.peers
                .iter()
                .filter_map(|p| {
                    let h = health.get(&p.device)?;
                    (h.resting(now) && h.last_ok.is_some()).then(|| (p.clone(), h.clone()))
                })
                .collect()
        };
        resting.sort_by_key(|(_, h)| std::cmp::Reverse(h.last_ok));
        for (p, _) in resting.into_iter().take(2) {
            if let Some(body) = self.revive(&p, &path, name) {
                return Some((p.device.clone(), body));
            }
        }
        None
    }

    /// One object request to `p`, with its bookkeeping (`ObjectStats`).
    fn ask_object(&self, p: &PeerInfo, path: &str, name: &ObjectName) -> Lookup {
        self.objects
            .lock()
            .unwrap()
            .entry(p.device.clone())
            .or_default()
            .inflight += 1;
        let t = Instant::now();
        let got = self.fetch(p, path);
        let mut stats = self.objects.lock().unwrap();
        let e = stats.entry(p.device.clone()).or_default();
        e.inflight = e.inflight.saturating_sub(1);
        match got {
            Some((200, body, _)) if ObjectName::from_bytes(&crypto::hash(&body)) == *name => {
                let secs = t.elapsed().as_secs_f64();
                e.secs = if e.secs > 0.0 {
                    e.secs * 0.8 + secs * 0.2
                } else {
                    secs
                };
                e.miss_streak = 0;
                e.probe_at = None;
                Lookup::Got(body)
            }
            // An answer that is not the object (404, or a refusal) is a
            // miss: the peer is asked first again only after its probe wait.
            Some((status, _, _)) => {
                e.miss_streak = e.miss_streak.saturating_add(1);
                e.probe_at = Some(Instant::now() + e.probe_wait());
                if status == 404 {
                    Lookup::Lacks
                } else {
                    Lookup::Failed
                }
            }
            None => Lookup::Failed,
        }
    }

    /// Ask `p`, which rests after failing, for the object once more: one
    /// request at a time (the others wait here for its outcome and then go
    /// straight to it when it answered), at most every `REVIVE_GAP`
    /// doubling per failure in a row. While it failed at most
    /// `REVIVE_WAIT_FAILURES` times in a row and answered within a
    /// minute, a request waits for the next try rather than giving the
    /// object up: a peer that restarts is back within a second or two.
    fn revive(&self, p: &PeerInfo, path: &str, name: &ObjectName) -> Option<Vec<u8>> {
        for _ in 0..=REVIVE_WAIT_FAILURES {
            let one = self.reviving.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let wait = {
                let mut health = self.health.lock().unwrap();
                let h = health.entry(p.device.clone()).or_default();
                if !h.resting(now) {
                    // Another request revived it meanwhile.
                    Duration::ZERO
                } else {
                    let gap = REVIVE_GAP * (1u32 << h.failures.clamp(1, 7).saturating_sub(1));
                    let next = h.revived.map(|t| t + gap).unwrap_or(now);
                    if next <= now {
                        // It keeps resting for the others until it answers.
                        h.revived = Some(now);
                        Duration::ZERO
                    } else if h.failures <= REVIVE_WAIT_FAILURES && h.was_live(now) {
                        next - now
                    } else {
                        return None;
                    }
                }
            };
            if wait.is_zero() {
                self.clear_addr_failures(p);
                let got = self.ask_object(p, path, name);
                drop(one);
                return match got {
                    Lookup::Got(body) => Some(body),
                    Lookup::Lacks | Lookup::Failed => None,
                };
            }
            drop(one);
            std::thread::sleep(wait);
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
    /// of those that answered, in the order `ordered` gives. The requests
    /// run side by side, at most `ASK_PARALLEL` at once, so that peers that
    /// are gone cost one timeout together instead of one each in turn.
    pub fn ask_each(&self, path: &str) -> Vec<(DeviceId, u16, Vec<u8>)> {
        let order = self.ordered();
        let mut out = Vec::new();
        for group in order.chunks(ASK_PARALLEL) {
            let answers: Vec<Option<(u16, Vec<u8>, Route)>> = std::thread::scope(|s| {
                let running: Vec<_> = group
                    .iter()
                    .map(|p| s.spawn(move || self.fetch(p, path)))
                    .collect();
                running
                    .into_iter()
                    .map(|h| h.join().ok().flatten())
                    .collect()
            });
            for (p, got) in group.iter().zip(answers) {
                if let Some((status, body, _)) = got {
                    out.push((p.device.clone(), status, body));
                }
            }
        }
        out
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
        let now = Instant::now();
        let stats = |miss_streak, secs| ObjectStats {
            miss_streak,
            secs,
            ..ObjectStats::default()
        };
        let fast = stats(0, 0.002);
        let slow = stats(0, 0.2);
        let mut lacking = stats(3, 0.001);
        lacking.probe_at = Some(now + Duration::from_secs(5));
        // Never measured: asked first once (a probe), then in the middle.
        let mut unknown = ObjectStats::default();
        assert_eq!(unknown.rank(now), (0, 0));
        unknown.probe_at = Some(now + Duration::from_secs(5));
        let mut v = [
            lacking.rank(now),
            slow.rank(now),
            unknown.rank(now),
            fast.rank(now),
        ];
        v.sort();
        assert_eq!(
            v,
            [
                fast.rank(now),
                unknown.rank(now),
                slow.rank(now),
                lacking.rank(now)
            ]
        );
    }

    #[test]
    fn two_peers_that_hold_the_objects_share_the_requests_and_a_lacking_one_is_probed() {
        let now = Instant::now();
        // Two equally fast holders (the writer and another reader): the one
        // with fewer requests in flight is asked first, so they share.
        let writer = ObjectStats {
            secs: 0.01,
            inflight: 3,
            ..ObjectStats::default()
        };
        let reader = ObjectStats {
            secs: 0.01,
            inflight: 1,
            ..ObjectStats::default()
        };
        assert!(reader.rank(now) < writer.rank(now));
        // A much slower holder (a relay) does not take requests from a fast
        // one with a few in flight.
        let relay = ObjectStats {
            secs: 0.5,
            ..ObjectStats::default()
        };
        assert!(writer.rank(now) < relay.rank(now));
        // A peer that lacked the last objects goes last until its probe is
        // due, then first among equals; the wait doubles per miss.
        let mut behind = ObjectStats {
            miss_streak: 1,
            secs: 0.01,
            ..ObjectStats::default()
        };
        behind.probe_at = Some(now + behind.probe_wait());
        assert!(behind.rank(now) > writer.rank(now));
        assert!(behind.rank(now + PROBE_BASE) <= writer.rank(now + PROBE_BASE));
        behind.miss_streak = 3;
        assert_eq!(behind.probe_wait(), PROBE_BASE * 4);
        behind.miss_streak = 100;
        assert_eq!(behind.probe_wait(), PROBE_MAX);
    }

    #[test]
    fn a_peer_that_was_answering_rests_a_second_after_a_failure_a_dead_one_longer() {
        let now = Instant::now();
        let mut live = Health::default();
        live.answered();
        live.failed(false);
        let rest = live.rest_until.unwrap() - now;
        assert!(rest <= BLIP_REST + Duration::from_millis(50), "{rest:?}");
        live.failed(false);
        assert!(live.rest_until.unwrap() - now > BLIP_REST);
        // Never answered: a minute, then doubling, at most 15 minutes.
        let mut dead = Health::default();
        dead.failed(false);
        assert!(dead.rest_until.unwrap() - now >= ROUTE_TTL);
        dead.failed(false);
        assert!(dead.rest_until.unwrap() - now >= 2 * ROUTE_TTL);
        for _ in 0..20 {
            dead.failed(false);
        }
        assert!(dead.rest_until.unwrap() - now <= DEAD_REST_MAX + Duration::from_secs(1));
        // A refusal of our certificate rests only a few seconds.
        let mut refused = Health::default();
        refused.failed(true);
        assert!(refused.rest_until.unwrap() - now <= REFUSED_REST + Duration::from_millis(50));
        // An address that answered a moment ago rests a second, not a minute.
        let t = Instant::now();
        let blip = AddrState {
            ok: false,
            at: t,
            last_ok: Some(t),
        };
        let gone = AddrState {
            ok: false,
            at: t,
            last_ok: None,
        };
        assert!(blip.resting() && gone.resting());
        let later = AddrState {
            at: t - BLIP_REST,
            last_ok: Some(t - BLIP_REST),
            ..blip
        };
        assert!(!later.resting());
        assert!(AddrState {
            at: t - BLIP_REST,
            ..gone
        }
        .resting());
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
            fresh: Default::default(),
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
    fn unauthenticated_connections_are_limited_per_address() {
        let slots = Arc::new(Unauth::default());
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let held: Vec<_> = (0..MAX_UNAUTH_PER_IP)
            .map(|_| slots.enter(ip).unwrap())
            .collect();
        assert!(
            slots.enter(ip).is_none(),
            "one more unauthenticated connection is refused"
        );
        assert!(slots.enter("192.0.2.8".parse().unwrap()).is_some());
        drop(held);
        assert!(
            slots.enter(ip).is_some(),
            "a finished handshake gives the slot back"
        );
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
