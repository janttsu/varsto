// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer-to-peer transfer of encrypted blocks, torrent-style: every device
//! that holds a file can serve its chunks as the same ciphertext objects the
//! storages hold (chunk keys and nonces are deterministic per folder), and a
//! device that needs a chunk pulls it from whichever peer or storage has it,
//! verifying every object against its content-addressed name. Peers on the
//! LAN are found with a multicast beacon; peers across the internet through
//! a rendezvous record each device publishes in the vault's own storage with
//! the addresses it can be reached at. The objects are ciphertext already,
//! and every request carries a proof of vault membership derived from the
//! master key, so a listener learns nothing and a stranger gets nothing.
//!
//! Two transports share one request handler: plain HTTP over TCP (LAN and
//! user-forwarded ports) and QUIC over UDP (`quic`), which crosses NATs with
//! STUN-learned addresses (`stun`), punch datagrams and, failing that, a
//! relay through one of the user's own reachable devices. There are no
//! trackers and no vendor servers: the user's storage is the rendezvous.

pub mod quic;
pub mod stun;

use crate::crypto::{self, SecretKey};
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
const AUTH_WINDOW_SECS: i64 = 300;

/// Key every device of the vault derives for peer authentication.
pub fn peer_key(master: &SecretKey) -> SecretKey {
    master.derive("p2p-auth", &[])
}

/// Vault identifier as seen on the wire: a keyed hash, so a listener cannot
/// link beacons to a vault id it saw elsewhere.
pub fn wire_vault_tag(master: &SecretKey, vault: &VaultId) -> String {
    hex::encode(
        &crypto::keyed_hash(&master.derive("p2p-tag", &[]), vault.as_str().as_bytes())[..12],
    )
}

fn now() -> i64 {
    crate::util::now_utc()
}

/// One line in the service log about a path decision, a punch or a relay:
/// the events a user needs when a transfer does not cross a NAT. Per-request
/// chatter stays behind `VARSTO_P2P_DEBUG`.
pub(crate) fn log(what: &str) {
    eprintln!("p2p: {what}");
}

/// `X-Varsto-Peer: <device>:<ts>:<mac>` where mac = keyed_hash(peer_key, device || ts || path).
pub fn auth_header(key: &SecretKey, device: &DeviceId, path: &str) -> String {
    let ts = now();
    let mac = hex::encode(crypto::keyed_hash(
        key,
        format!("{}|{}|{}", device.as_str(), ts, path).as_bytes(),
    ));
    format!("{}:{}:{}", device.as_str(), ts, mac)
}

pub fn verify_auth(key: &SecretKey, header: &str, path: &str) -> Option<DeviceId> {
    let mut parts = header.splitn(3, ':');
    let (dev, ts, mac) = (parts.next()?, parts.next()?, parts.next()?);
    let ts: i64 = ts.parse().ok()?;
    if (now() - ts).abs() > AUTH_WINDOW_SECS {
        return None;
    }
    let expected = hex::encode(crypto::keyed_hash(
        key,
        format!("{dev}|{ts}|{path}").as_bytes(),
    ));
    // Constant-time comparison of equal-length hex strings.
    if expected.len() != mac.len()
        || expected
            .bytes()
            .zip(mac.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return None;
    }
    DeviceId::from_hex(dev).ok()
}

/// Where one chunk lives inside a plaintext file on this device.
#[derive(Clone, Debug)]
pub struct Piece {
    pub folder: FolderId,
    pub chunk: crate::ids::ChunkId,
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
    pub peer_key: SecretKey,
    pub folder_keys: BTreeMap<FolderId, FolderKeys>,
    pub pieces: BTreeMap<ObjectName, Piece>,
    /// Roots of local-directory storages whose objects can be served verbatim.
    pub local_roots: Vec<PathBuf>,
}

impl Snapshot {
    /// Produce the ciphertext object for `name`, from a stored copy or by
    /// re-encrypting the piece (deterministic, so the bytes are identical).
    pub fn object(&self, name: &ObjectName) -> Result<Option<Vec<u8>>> {
        for root in &self.local_roots {
            let p = root
                .join("chunks")
                .join(&name.as_str()[..2])
                .join(name.as_str());
            if let Ok(bytes) = std::fs::read(&p) {
                if ObjectName::from_bytes(&crypto::hash(&bytes)) == *name {
                    return Ok(Some(bytes));
                }
            }
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
        let ct = crypto::encrypt_with_nonce(
            &fk.chunk_key(&piece.chunk),
            &fk.chunk_nonce(&piece.chunk),
            &fk.chunk_aad(&self.vault_id, &piece.chunk, piece.len),
            &crate::pack::pack(&plain),
        )?;
        if ObjectName::from_bytes(&crypto::hash(&ct)) != *name {
            return Ok(None);
        }
        Ok(Some(ct))
    }
}

/// The serving side: HTTP on `addr`, answering `/p2p/object/<name>` and
/// `/p2p/info` for authenticated peers.
pub struct Server {
    server: tiny_http::Server,
    pub addr: SocketAddr,
}

impl Server {
    pub fn bind(addr: SocketAddr) -> Result<Server> {
        let server = tiny_http::Server::http(addr)
            .map_err(|e| anyhow!("bind p2p listener on {addr}: {e}"))?;
        let addr = server.server_addr().to_ip().unwrap_or(addr);
        Ok(Server { server, addr })
    }

    /// Serve until `stop` is set. The snapshot can be swapped at any time.
    pub fn run(
        &self,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let Ok(Some(req)) = self.server.recv_timeout(Duration::from_millis(500)) else {
                continue;
            };
            let snap = snapshot.lock().unwrap().clone();
            let _ = Self::handle(req, snap);
        }
    }

    fn handle(req: tiny_http::Request, snap: Option<Arc<Snapshot>>) -> Result<()> {
        let path = req.url().split('?').next().unwrap_or("").to_string();
        let auth = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Varsto-Peer"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_default();
        let (status, body) = handle(snap.as_deref(), &path, &auth);
        req.respond(
            tiny_http::Response::from_data(body)
                .with_status_code(status)
                .with_chunked_threshold(usize::MAX),
        )?;
        Ok(())
    }
}

/// Answer one peer request, whatever transport carried it: `(status, body)`.
/// Paths: `/p2p/info` and `/p2p/object/<name>`. No snapshot means the
/// service is locked.
pub fn handle(snap: Option<&Snapshot>, path: &str, auth: &str) -> (u16, Vec<u8>) {
    let Some(snap) = snap else {
        return (503, b"locked".to_vec());
    };
    if verify_auth(&snap.peer_key, auth, path).is_none() {
        return (403, b"forbidden".to_vec());
    }
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

/// A peer we can ask for objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddr {
    pub device: DeviceId,
    pub addr: SocketAddr,
    #[serde(default)]
    pub name: String,
}

/// Rendezvous record a device publishes in the vault's storage:
/// `vault/peers/<device>.enc`, encrypted under the device registry key.
/// Version 1 added the UDP/QUIC fields; version 0 records (no `version`
/// field) are still read, with the new fields empty.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    #[serde(default)]
    pub version: u32,
    pub device: DeviceId,
    pub name: String,
    /// TCP and UDP port (the same number for both transports).
    pub port: u16,
    pub lan_addrs: Vec<IpAddr>,
    /// Addresses the user configured (forwarded port, public IP, VPN).
    pub public_addrs: Vec<SocketAddr>,
    pub updated_utc: i64,
    /// UDP addresses STUN servers saw for our socket.
    #[serde(default)]
    pub udp_public: Vec<SocketAddr>,
    /// UDP addresses on our own interfaces.
    #[serde(default)]
    pub udp_local: Vec<SocketAddr>,
    /// Hex SHA-256 of the device's QUIC certificate; empty before `p2p enable`.
    #[serde(default)]
    pub cert_sha256: String,
    /// NAT guess from STUN: none, cone, symmetric or unknown.
    #[serde(default)]
    pub nat: stun::Nat,
    /// Reachable devices this device keeps a relay registration with.
    #[serde(default)]
    pub relay_via: Vec<DeviceId>,
    /// A public address answered our own probe, or the user configured one:
    /// other devices can connect directly, and may relay through us.
    #[serde(default)]
    pub reachable: bool,
}

impl PeerRecord {
    pub const PREFIX: &'static str = "vault/peers/";
    pub const VERSION: u32 = 1;
    pub fn storage_key(device: &DeviceId) -> String {
        format!("{}{}.enc", Self::PREFIX, device)
    }
    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "peer-record",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.device),
            &serde_json::to_vec(self)?,
        )
    }
    pub fn open(blob: &[u8], vault: &VaultId, device: &DeviceId, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, device), blob)?;
        let rec: PeerRecord = serde_json::from_slice(&plain)?;
        if &rec.device != device {
            bail!("peer record device mismatch");
        }
        Ok(rec)
    }
    /// TCP addresses, LAN first.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self
            .lan_addrs
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect();
        out.extend(self.public_addrs.iter().cloned());
        out
    }
    /// UDP (QUIC) addresses, public first: a LAN peer was already tried over TCP.
    pub fn udp_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for a in self
            .udp_public
            .iter()
            .chain(self.public_addrs.iter())
            .chain(self.udp_local.iter())
        {
            if !out.contains(a) {
                out.push(*a);
            }
        }
        out
    }
    /// Equal apart from the timestamp: nothing worth republishing.
    pub fn same_as(&self, other: &PeerRecord) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.updated_utc = 0;
        b.updated_utc = 0;
        a == b
    }
}

/// Everything the client side knows about one device, merged from its
/// record and from LAN beacons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub device: DeviceId,
    pub name: String,
    /// HTTP over TCP, LAN first.
    pub tcp: Vec<SocketAddr>,
    /// QUIC over UDP, public first.
    pub udp: Vec<SocketAddr>,
    pub cert_sha256: String,
    pub relay_via: Vec<DeviceId>,
    pub nat: stun::Nat,
    pub reachable: bool,
}

impl PeerInfo {
    pub fn from_record(rec: &PeerRecord) -> PeerInfo {
        PeerInfo {
            device: rec.device.clone(),
            name: rec.name.clone(),
            tcp: rec.addrs(),
            udp: rec.udp_addrs(),
            cert_sha256: rec.cert_sha256.clone(),
            relay_via: rec.relay_via.clone(),
            nat: rec.nat,
            reachable: rec.reachable,
        }
    }
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
#[derive(Clone, Debug)]
enum Route {
    Tcp(SocketAddr),
    Quic(SocketAddr),
    Relay(DeviceId, String, SocketAddr),
}

impl Route {
    fn label(&self) -> String {
        match self {
            Route::Tcp(a) | Route::Quic(a) if is_lan(a.ip()) => "direct-lan".into(),
            Route::Tcp(_) | Route::Quic(_) => "direct".into(),
            Route::Relay(dev, name, _) => format!(
                "relayed via {}",
                if name.is_empty() { dev.short() } else { name }
            ),
        }
    }
    fn addr(&self) -> SocketAddr {
        match self {
            Route::Tcp(a) | Route::Quic(a) | Route::Relay(_, _, a) => *a,
        }
    }
    /// For the log: transport and address, and the relay's name.
    fn describe(&self) -> String {
        match self {
            Route::Tcp(a) => format!("tcp {a}"),
            Route::Quic(a) => format!("quic {a}"),
            Route::Relay(dev, name, a) => format!(
                "relay {} at {a}",
                if name.is_empty() { dev.short() } else { name }
            ),
        }
    }
}

/// Minimal HTTP GET over a fresh TCP connection (no dependency, short timeouts).
fn http_get(addr: SocketAddr, path: &str, auth: &str, timeout: Duration) -> Result<(u16, Vec<u8>)> {
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(timeout))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nX-Varsto-Peer: {auth}\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed peer response"))?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
        eprintln!("p2p: response head: {}", head.replace("\r\n", " | "));
    }
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let body = &raw[sep + 4..];
    let chunked = head.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    Ok((
        status,
        if chunked {
            decode_chunked(body)?
        } else {
            body.to_vec()
        },
    ))
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
        if pos + size > body.len() {
            bail!("truncated chunked body");
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2;
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
    pub key: SecretKey,
    pub me: DeviceId,
    pub peers: Vec<PeerInfo>,
    quic: Option<Arc<quic::Node>>,
    /// Per TCP address: did the last attempt answer, and when.
    state: Mutex<BTreeMap<SocketAddr, (bool, Instant)>>,
    /// Per device: the last route (or failure), the status it answered, and when.
    routes: Mutex<BTreeMap<DeviceId, Attempt>>,
    pub timeout: Duration,
}

const ROUTE_TTL: Duration = Duration::from_secs(60);

impl Peers {
    /// TCP-only peers from plain addresses (LAN beacons, tests).
    pub fn new(key: SecretKey, me: DeviceId, peers: Vec<PeerAddr>) -> Self {
        Self::build(key, me, &[], &peers, None)
    }

    /// Peers from rendezvous records plus LAN beacons, with QUIC when a node runs.
    pub fn build(
        key: SecretKey,
        me: DeviceId,
        records: &[PeerRecord],
        lan: &[PeerAddr],
        quic: Option<Arc<quic::Node>>,
    ) -> Self {
        let mut infos: Vec<PeerInfo> = records
            .iter()
            .filter(|r| r.device != me)
            .map(PeerInfo::from_record)
            .collect();
        for p in lan.iter().filter(|p| p.device != me) {
            match infos.iter_mut().find(|i| i.device == p.device) {
                Some(i) => i.add_lan(p.addr),
                None => infos.push(PeerInfo {
                    device: p.device.clone(),
                    name: p.name.clone(),
                    tcp: vec![p.addr],
                    udp: Vec::new(),
                    cert_sha256: String::new(),
                    relay_via: Vec::new(),
                    nat: stun::Nat::Unknown,
                    reachable: false,
                }),
            }
        }
        if let Some(node) = &quic {
            node.set_known(infos.clone());
        }
        Peers {
            key,
            me,
            peers: infos,
            quic,
            state: Mutex::new(BTreeMap::new()),
            routes: Mutex::new(BTreeMap::new()),
            timeout: Duration::from_millis(1500),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Carry the remembered routes and address states over from the table
    /// this one replaces, so a rebuild (every sync) forgets nothing.
    pub fn inherit(&self, previous: &Peers) {
        *self.routes.lock().unwrap() = previous.routes.lock().unwrap().clone();
        *self.state.lock().unwrap() = previous.state.lock().unwrap().clone();
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
        if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
            eprintln!("p2p: {what}");
        }
    }

    fn try_tcp(&self, addr: SocketAddr, path: &str, auth: &str) -> Result<(u16, Vec<u8>)> {
        let result = http_get(addr, path, auth, self.timeout);
        self.debug(&format!(
            "tcp {addr} {path} -> {}",
            match &result {
                Ok((s, b)) => format!("HTTP {s}, {} bytes", b.len()),
                Err(e) => format!("error: {e}"),
            }
        ));
        let ok = result.is_ok();
        self.state
            .lock()
            .unwrap()
            .insert(addr, (ok, Instant::now()));
        result
    }

    fn try_quic(
        &self,
        addr: SocketAddr,
        cert: &str,
        path: &str,
        auth: &str,
    ) -> Result<(u16, Vec<u8>)> {
        let node = self.quic.as_ref().ok_or_else(|| anyhow!("no QUIC node"))?;
        let result = node.request(addr, cert, path, auth, true);
        self.debug(&format!(
            "quic {addr} {path} -> {}",
            match &result {
                Ok((s, b)) => format!("{s}, {} bytes", b.len()),
                Err(e) => format!("error: {e:#}"),
            }
        ));
        result
    }

    /// Ask a specific peer once, over a given route; the error says why the
    /// route gave nothing (including "resting" for one that just failed).
    fn over(&self, route: &Route, path: &str, auth: &str, p: &PeerInfo) -> Result<(u16, Vec<u8>)> {
        match route {
            Route::Tcp(a) => {
                // A TCP address that just failed rests for a minute.
                if let Some((false, when)) = self.state.lock().unwrap().get(a) {
                    if when.elapsed() < ROUTE_TTL {
                        bail!("resting after a failure");
                    }
                }
                self.try_tcp(*a, path, auth)
            }
            Route::Quic(a) => self.try_quic(*a, &p.cert_sha256, path, auth),
            Route::Relay(relay, _, a) => {
                let cert = self
                    .peers
                    .iter()
                    .find(|r| &r.device == relay)
                    .map(|r| r.cert_sha256.clone())
                    .ok_or_else(|| anyhow!("relay record unknown"))?;
                let via = format!("/p2p/via/{}{}", p.device, path);
                self.try_quic(*a, &cert, &via, auth)
            }
        }
    }

    /// Every route to `p`, in the order they are tried.
    fn candidate_routes(&self, p: &PeerInfo) -> Vec<Route> {
        let mut out: Vec<Route> = p.tcp.iter().map(|a| Route::Tcp(*a)).collect();
        if self.quic.is_some() && !p.cert_sha256.is_empty() {
            out.extend(p.udp.iter().map(|a| Route::Quic(*a)));
            for relay in &p.relay_via {
                let Some(r) = self.peers.iter().find(|r| &r.device == relay) else {
                    continue;
                };
                if r.cert_sha256.is_empty() {
                    continue;
                }
                for a in &r.udp {
                    out.push(Route::Relay(relay.clone(), r.name.clone(), *a));
                }
            }
        }
        out
    }

    /// One request to peer `p`: the route that worked last time first, then
    /// every candidate in order. Records the outcome and logs every change
    /// of path, so the service log tells how a NAT was (not) crossed.
    fn fetch(&self, p: &PeerInfo, path: &str, auth: &str) -> Option<(u16, Vec<u8>, Route)> {
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
            match self.over(&r, path, auth, p) {
                Ok((s, b)) => {
                    self.remember(&p.device, Some(r.clone()), s);
                    return Some((s, b, r));
                }
                Err(e) => log(&format!("{who}: {} lost: {e:#}", r.describe())),
            }
        }
        let mut tried = Vec::new();
        for r in self.candidate_routes(p) {
            match self.over(&r, path, auth, p) {
                Ok((s, b)) => {
                    log(&format!("{who}: {} answered {s}", r.describe()));
                    self.remember(&p.device, Some(r.clone()), s);
                    return Some((s, b, r));
                }
                Err(e) => tried.push(format!("{}: {e:#}", r.describe())),
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
        self.remember(&p.device, None, 0);
        None
    }

    /// Fetch one object from the first peer that has it.
    pub fn get(&self, name: &ObjectName) -> Option<(DeviceId, Vec<u8>)> {
        let path = format!("/p2p/object/{name}");
        for p in self.ordered() {
            let auth = auth_header(&self.key, &self.me, &path);
            if let Some((200, body, _)) = self.fetch(&p, &path, &auth) {
                if ObjectName::from_bytes(&crypto::hash(&body)) == *name {
                    return Some((p.device, body));
                }
            }
        }
        None
    }

    /// Which peers answer right now, and over which path.
    pub fn probe(&self) -> Vec<PeerStatus> {
        let path = "/p2p/info";
        self.peers
            .iter()
            .map(|p| {
                let auth = auth_header(&self.key, &self.me, path);
                let _ = self.fetch(p, path, &auth);
                self.status_of(p)
            })
            .collect()
    }

    fn status_of(&self, p: &PeerInfo) -> PeerStatus {
        let routes = self.routes.lock().unwrap();
        // `ok` means the peer answered as a vault device: 200, or 404 for an
        // object it does not hold. A 403 means the path works but we do not.
        let (path, addr, ok, when) = match routes.get(&p.device) {
            Some((Some(r), status, when)) => (
                r.label(),
                Some(r.addr()),
                matches!(status, 200 | 404),
                Some(when),
            ),
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

/// LAN discovery: `VARSTO1 <tag> <device> <port>` every few seconds to a
/// multicast group; listeners learn (device, sender ip:port).
pub struct Beacon {
    sock: UdpSocket,
    tag: String,
    device: DeviceId,
    port: u16,
}

impl Beacon {
    pub fn new(tag: String, device: DeviceId, port: u16) -> Result<Beacon> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, BEACON_PORT))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))
            .context("bind beacon socket")?;
        let _ = sock.join_multicast_v4(&BEACON_GROUP, &Ipv4Addr::UNSPECIFIED);
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        Ok(Beacon {
            sock,
            tag,
            device,
            port,
        })
    }
    pub fn announce(&self) {
        let msg = format!(
            "VARSTO1 {} {} {}",
            self.tag,
            self.device.as_str(),
            self.port
        );
        let _ = self
            .sock
            .send_to(msg.as_bytes(), (BEACON_GROUP, BEACON_PORT));
    }
    /// Collect peers heard for `dur`; only beacons with our vault tag count.
    pub fn listen(&self, dur: Duration) -> Vec<PeerAddr> {
        let deadline = Instant::now() + dur;
        let mut out: Vec<PeerAddr> = Vec::new();
        let mut buf = [0u8; 256];
        while Instant::now() < deadline {
            let Ok((n, from)) = self.sock.recv_from(&mut buf) else {
                continue;
            };
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            let parts: Vec<&str> = msg.split_whitespace().collect();
            if parts.len() != 4 || parts[0] != "VARSTO1" || parts[1] != self.tag {
                continue;
            }
            let (Ok(device), Ok(port)) = (DeviceId::from_hex(parts[2]), parts[3].parse::<u16>())
            else {
                continue;
            };
            if device == self.device {
                continue;
            }
            let addr = SocketAddr::new(from.ip(), port);
            if !out.iter().any(|p| p.addr == addr) {
                out.push(PeerAddr {
                    device,
                    addr,
                    name: String::new(),
                });
            }
        }
        out
    }
}

/// Non-loopback IPv4 addresses of this host, for the rendezvous record.
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
    fn chunked_bodies_decode() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"zz\r\n").is_err());
    }

    #[test]
    fn peer_records_seal_open_and_read_old_versions() {
        let key = SecretKey::random();
        let vault = VaultId::from_bytes(&[9u8; 16]);
        let dev = DeviceId::from_bytes(&[3u8; 16]);
        let relay = DeviceId::from_bytes(&[4u8; 16]);
        let rec = PeerRecord {
            version: PeerRecord::VERSION,
            device: dev.clone(),
            name: "laptop".into(),
            port: 17893,
            lan_addrs: vec!["192.168.1.5".parse().unwrap()],
            public_addrs: vec![],
            updated_utc: 1_700_000_000,
            udp_public: vec!["203.0.113.7:40000".parse().unwrap()],
            udp_local: vec!["192.168.1.5:17893".parse().unwrap()],
            cert_sha256: "ab".repeat(32),
            nat: stun::Nat::Cone,
            relay_via: vec![relay.clone()],
            reachable: false,
        };
        let blob = rec.seal(&vault, &key).unwrap();
        let back = PeerRecord::open(&blob, &vault, &dev, &key).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.udp_addrs().len(), 2);
        assert_eq!(back.udp_addrs()[0], rec.udp_public[0]);
        // Another device id or key does not open it.
        assert!(PeerRecord::open(&blob, &vault, &relay, &key).is_err());
        assert!(PeerRecord::open(&blob, &vault, &dev, &SecretKey::random()).is_err());
        // Same content, new timestamp: nothing to republish.
        let mut later = rec.clone();
        later.updated_utc += 600;
        assert!(later.same_as(&rec));
        later.reachable = true;
        assert!(!later.same_as(&rec));

        // A version 0 record written by alpha.4 has none of the new fields.
        let old = serde_json::json!({
            "device": dev.to_string(), "name": "desk", "port": 17893,
            "lan_addrs": ["10.0.0.2"], "public_addrs": ["198.51.100.9:17893"], "updated_utc": 1
        });
        let old: PeerRecord = serde_json::from_value(old).unwrap();
        assert_eq!(old.version, 0);
        assert_eq!(old.nat, stun::Nat::Unknown);
        assert!(old.cert_sha256.is_empty() && old.udp_public.is_empty() && !old.reachable);
        assert_eq!(old.addrs().len(), 2);
        let info = PeerInfo::from_record(&old);
        assert_eq!(info.udp, old.public_addrs);
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
    fn auth_header_roundtrip_and_tamper() {
        let k = SecretKey::random();
        let d = DeviceId::from_bytes(&[1u8; 16]);
        let h = auth_header(&k, &d, "/p2p/object/abc");
        assert_eq!(verify_auth(&k, &h, "/p2p/object/abc"), Some(d.clone()));
        assert_eq!(verify_auth(&k, &h, "/p2p/object/abd"), None);
        assert_eq!(
            verify_auth(&SecretKey::random(), &h, "/p2p/object/abc"),
            None
        );
        let mut bad = h.clone();
        bad.pop();
        assert_eq!(verify_auth(&k, &bad, "/p2p/object/abc"), None);
    }
}
