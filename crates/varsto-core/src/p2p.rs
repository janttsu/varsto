// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer-to-peer transfer of encrypted blocks, torrent-style: every device
//! that holds a file can serve its chunks as the same ciphertext objects the
//! storages hold (chunk keys and nonces are deterministic per folder), and a
//! device that needs a chunk pulls it from whichever peer or storage has it,
//! verifying every object against its content-addressed name. Peers on the
//! LAN are found with a multicast beacon; peers across the internet through
//! a rendezvous record each device publishes in the vault's own storage with
//! the addresses it can be reached at. Transport is plain HTTP: the objects
//! are ciphertext already, and every request carries a proof of vault
//! membership derived from the master key, so a listener learns nothing and
//! a stranger gets nothing.
//!
//! What this does not do yet: NAT traversal. Across the internet a peer is
//! reachable only if it listens on a public address (a forwarded port, a
//! public IP, a VPN). Relays and hole punching are planned.

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
        let Some(snap) = snap else {
            return Ok(
                req.respond(tiny_http::Response::from_string("locked").with_status_code(503))?
            );
        };
        let auth = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Varsto-Peer"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_default();
        if verify_auth(&snap.peer_key, &auth, &path).is_none() {
            return Ok(
                req.respond(tiny_http::Response::from_string("forbidden").with_status_code(403))?
            );
        }
        if path == "/p2p/info" {
            let body = serde_json::json!({"device": snap.device_id.to_string(), "pieces": snap.pieces.len(), "local_roots": snap.local_roots.len()});
            return Ok(req.respond(tiny_http::Response::from_string(body.to_string()))?);
        }
        if let Some(name) = path.strip_prefix("/p2p/object/") {
            let Ok(name) = ObjectName::from_hex(name) else {
                return Ok(req.respond(
                    tiny_http::Response::from_string("bad name").with_status_code(400),
                )?);
            };
            return match snap.object(&name)? {
                Some(bytes) => Ok(req.respond(
                    tiny_http::Response::from_data(bytes).with_chunked_threshold(usize::MAX),
                )?),
                None => Ok(req
                    .respond(tiny_http::Response::from_string("not here").with_status_code(404))?),
            };
        }
        Ok(req.respond(tiny_http::Response::from_string("not found").with_status_code(404))?)
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub device: DeviceId,
    pub name: String,
    pub port: u16,
    pub lan_addrs: Vec<IpAddr>,
    pub public_addrs: Vec<SocketAddr>,
    pub updated_utc: i64,
}

impl PeerRecord {
    pub const PREFIX: &'static str = "vault/peers/";
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
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self
            .lan_addrs
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect();
        out.extend(self.public_addrs.iter().cloned());
        out
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
pub struct Peers {
    pub key: SecretKey,
    pub me: DeviceId,
    pub peers: Vec<PeerAddr>,
    state: Mutex<BTreeMap<SocketAddr, (bool, Instant)>>,
    pub timeout: Duration,
}

impl Peers {
    pub fn new(key: SecretKey, me: DeviceId, peers: Vec<PeerAddr>) -> Self {
        Peers {
            key,
            me,
            peers,
            state: Mutex::new(BTreeMap::new()),
            timeout: Duration::from_millis(1500),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    fn ordered(&self) -> Vec<PeerAddr> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<PeerAddr> = self
            .peers
            .iter()
            .filter(|p| p.device != self.me)
            .filter(|p| match st.get(&p.addr) {
                // A peer that failed is retried after a minute.
                Some((false, when)) => when.elapsed() > Duration::from_secs(60),
                _ => true,
            })
            .cloned()
            .collect();
        v.sort_by_key(|p| match st.get(&p.addr) {
            Some((true, _)) => 0,
            _ => 1,
        });
        v
    }
    /// Fetch one object from the first peer that has it.
    pub fn get(&self, name: &ObjectName) -> Option<(DeviceId, Vec<u8>)> {
        let path = format!("/p2p/object/{name}");
        for p in self.ordered() {
            let auth = auth_header(&self.key, &self.me, &path);
            let result = http_get(p.addr, &path, &auth, self.timeout);
            if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
                eprintln!(
                    "p2p: {} {} -> {}",
                    p.addr,
                    name,
                    match &result {
                        Ok((s, b)) => format!("HTTP {s}, {} bytes", b.len()),
                        Err(e) => format!("error: {e}"),
                    }
                );
            }
            match result {
                Ok((200, body)) if ObjectName::from_bytes(&crypto::hash(&body)) == *name => {
                    self.state
                        .lock()
                        .unwrap()
                        .insert(p.addr, (true, Instant::now()));
                    return Some((p.device, body));
                }
                Ok((404, _)) | Ok((200, _)) => {
                    self.state
                        .lock()
                        .unwrap()
                        .insert(p.addr, (true, Instant::now()));
                }
                _ => {
                    self.state
                        .lock()
                        .unwrap()
                        .insert(p.addr, (false, Instant::now()));
                }
            }
        }
        None
    }
    /// Which peers answer right now.
    pub fn probe(&self) -> Vec<(PeerAddr, bool)> {
        let path = "/p2p/info";
        self.peers
            .iter()
            .map(|p| {
                let auth = auth_header(&self.key, &self.me, path);
                let ok = matches!(http_get(p.addr, path, &auth, self.timeout), Ok((200, _)));
                (p.clone(), ok)
            })
            .collect()
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
