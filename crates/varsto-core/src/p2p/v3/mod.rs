// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peers and transport of storage format 3 (`docs/spec/format-3-design.md`
//! section 8, work package 9; `alpha-0-format.md` sections 75 and 77.8):
//! the only transport there is. The TCP server (`Server::bind`), the QUIC
//! node (`quic::Node::start_v3`) and the peer table (`Peers::build_v3`)
//! run on what is here; the engine side is `engine/p2p3.rs` and
//! `engine/ledger_heads.rs`.
//!
//! - [`peer`]: peer records as SignedRecords of kind `peer` and the
//!   directory of accepted ones, which maps certificates to devices.
//! - [`token`]: request tokens keyed with the TLS exporter of the
//!   connection; the `p2p-auth` vault key is not used.
//! - [`tls`]: TLS 1.3 over TCP with the pinned certificates (no plain
//!   HTTP).
//! - [`beacon`]: signed LAN beacons with a sequence number.
//! - [`heads`]: head exchange with proofs, batch fetch, the rollback
//!   warning.
//!
//! [`Responder`] answers requests of both transports; [`Client`] makes
//! them.

pub mod beacon;
pub mod heads;
pub mod peer;
pub mod tls;
pub mod token;

#[cfg(test)]
mod tests;

pub use heads::{BatchSource, HeadRef, HeadsAnswer, Pushed, Watch};
pub use peer::{PeerBody, PeerDirectory};

use super::{serve_as, Snapshot, SELF_ANSWER};
use crate::ids::DeviceId;
use crate::p2p::quic::Identity;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// A 16-byte id.
pub type Id16 = crate::record::Id16;

/// ALPN of format 3, on QUIC and on TLS over TCP.
pub const ALPN: &[u8] = b"varsto-p2p/3";
/// The TLS exporter label the tokens are keyed with.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-varsto-p2p-token";

fn id16_of(d: &DeviceId) -> Id16 {
    crate::record::id16(d).unwrap_or_default()
}

fn cert_of_hex(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// What a request's connection says about its client.
#[derive(Clone, Debug, Default)]
pub struct ConnInfo {
    /// SHA-256 of the certificate the other end presented.
    pub cert: Option<[u8; 32]>,
    /// The connection's TLS exporter value.
    pub exporter: Option<[u8; 32]>,
    /// The connection is this device's registration with a relay: requests
    /// on it come from the relay and may name the device they are for.
    pub registration: bool,
}

impl ConnInfo {
    pub(crate) fn of_quic(conn: &quinn::Connection, registration: bool) -> ConnInfo {
        let cert = conn
            .peer_identity()
            .and_then(|i| {
                i.downcast::<Vec<quinn::rustls::pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .and_then(|c| {
                c.first().map(|c| {
                    use sha2::Digest;
                    sha2::Sha256::digest(c.as_ref()).into()
                })
            });
        ConnInfo {
            cert,
            exporter: super::quic::exporter(conn),
            registration,
        }
    }
}

/// A head list heard from a peer on `/p2p/changed` or `/p2p/heads`: the
/// sender is authenticated, the list is its claim (proofs come only as
/// envelopes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub from: DeviceId,
    pub heads: Vec<HeadRef>,
}

const HEARD_MAX: usize = 64;

/// The answering side of format 3, shared by both transports.
pub struct Responder {
    me: DeviceId,
    me16: Id16,
    own_cert: [u8; 32],
    directory: RwLock<Arc<PeerDirectory>>,
    nonces: token::NonceWindow,
    batches: RwLock<Option<Arc<dyn BatchSource>>>,
    heard: Mutex<Vec<Heard>>,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Responder {
    /// `own_cert` is the hex SHA-256 of this device's certificate.
    pub fn new(me: DeviceId, own_cert: &str) -> Arc<Responder> {
        let me16 = id16_of(&me);
        let own = cert_of_hex(own_cert).unwrap_or([0xff; 32]);
        Arc::new(Responder {
            directory: RwLock::new(Arc::new(PeerDirectory::new(me16, own))),
            me,
            me16,
            own_cert: own,
            nonces: token::NonceWindow::default(),
            batches: RwLock::new(None),
            heard: Mutex::new(Vec::new()),
        })
    }

    pub fn me(&self) -> &DeviceId {
        &self.me
    }

    pub fn directory(&self) -> Arc<PeerDirectory> {
        self.directory.read().unwrap().clone()
    }

    /// Replace the directory (after every read of the peer records).
    pub fn set_directory(&self, dir: PeerDirectory) {
        *self.directory.write().unwrap() = Arc::new(dir);
    }

    /// The local ledger, for head lists, proofs and batch fetches.
    pub fn set_batches(&self, source: Arc<dyn BatchSource>) {
        *self.batches.write().unwrap() = Some(source);
    }

    /// Whether the handshake admits a client certificate: named by the
    /// directory, and not this device's own.
    pub fn admits(&self, cert: &[u8; 32]) -> bool {
        cert != &self.own_cert && self.directory().device_for_cert(cert).is_some()
    }

    /// A token from this device for `path` at `responder`, on the
    /// connection with exporter value `exporter` (relays, registrations).
    pub fn token(&self, exporter: &[u8; 32], responder: &DeviceId, path: &str) -> String {
        token::make(
            exporter,
            &self.me16,
            &id16_of(responder),
            path,
            crate::util::now_utc(),
        )
    }

    /// The device that asks: the certificate of the connection must belong
    /// to a device of the directory, and the token must be that device's,
    /// for this device, this connection and this path.
    pub fn authorize(
        &self,
        ci: &ConnInfo,
        auth: &str,
        path: &str,
    ) -> std::result::Result<DeviceId, (u16, Vec<u8>)> {
        let Some(cert) = ci.cert else {
            return Err((403, b"no client certificate".to_vec()));
        };
        if cert == self.own_cert {
            return Err((403, SELF_ANSWER.to_vec()));
        }
        let Some(device) = self.directory().device_for_cert(&cert) else {
            return Err((403, b"certificate not in any accepted peer record".to_vec()));
        };
        let Some(exporter) = ci.exporter else {
            return Err((403, b"no exporter".to_vec()));
        };
        match token::verify(
            auth,
            &exporter,
            &device,
            &self.me16,
            path,
            crate::util::now_utc(),
            &self.nonces,
        ) {
            Ok(d) => Ok(DeviceId::from_bytes(&d)),
            Err(e) => Err((403, format!("forbidden: {e}").into_bytes())),
        }
    }

    /// Answer one request: `(status, body, the device it was for)`.
    pub fn handle(
        &self,
        snap: Option<&Snapshot>,
        ci: &ConnInfo,
        path: &str,
        auth: &str,
        for_device: &str,
    ) -> (u16, Vec<u8>, Option<DeviceId>) {
        let Some(snap) = snap else {
            return (503, b"locked".to_vec(), None);
        };
        let asker = match self.authorize(ci, auth, path) {
            Ok(d) => d,
            Err((s, b)) => return (s, b, None),
        };
        // A removed device is refused at the door, whatever it asks.
        if snap.revoked.contains(&asker) {
            return (403, b"forbidden".to_vec(), None);
        }
        // A relay asks on our registration with it, for another device of
        // the directory; nowhere else may a request speak for another.
        let dev = if for_device.is_empty() {
            asker
        } else {
            let other = DeviceId::from_hex(for_device).ok();
            match other {
                Some(o)
                    if ci.registration
                        && o != self.me
                        && self.directory().contains(&id16_of(&o)) =>
                {
                    o
                }
                _ => {
                    return (
                        403,
                        b"forbidden: not a relay for that device".to_vec(),
                        None,
                    )
                }
            }
        };
        if snap.revoked.contains(&dev) || dev == snap.device_id {
            return serve_as(snap, path, dev);
        }
        if let Some(r) = self.answer_ledger(snap, path, &dev) {
            return (r.0, r.1, Some(dev));
        }
        serve_as(snap, path, dev)
    }

    /// The ledger paths (`/p2p/changed`, `/p2p/heads`, `/p2p/ledger/`), or
    /// `None` for any other path. Batches come from the source set with
    /// `set_batches`, else from the snapshot.
    fn answer_ledger(
        &self,
        snap: &Snapshot,
        path: &str,
        from: &DeviceId,
    ) -> Option<(u16, Vec<u8>)> {
        let changed = heads::list_of_path(path, heads::CHANGED_PREFIX);
        let asked = heads::list_of_path(path, heads::HEADS_PREFIX);
        if let Some(list) = changed.clone().or(asked.clone()) {
            if changed.is_some() {
                super::note_change_heard();
            }
            if !list.is_empty() {
                self.hear(Heard {
                    from: from.clone(),
                    heads: list.clone(),
                });
            }
            let source = self.batches.read().unwrap().clone();
            return Some(match source {
                Some(src) => (200, heads::answer(src.as_ref(), &list).encode()),
                None if snap.ledger_dir.is_some() => (200, heads::answer(snap, &list).encode()),
                None if changed.is_some() => (200, HeadsAnswer::default().encode()),
                None => (404, b"no ledger".to_vec()),
            });
        }
        if let Some((device, seq)) = heads::parse_ledger_path(path) {
            let source = self.batches.read().unwrap().clone();
            let rec = match source {
                Some(s) => s.batch(&device, seq),
                None => snap.batch(&device, seq),
            };
            return Some(match rec {
                Some(rec) => (200, rec),
                None => (404, b"not here".to_vec()),
            });
        }
        None
    }

    fn hear(&self, h: Heard) {
        let mut v = self.heard.lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|o| o.from != h.from);
        if v.len() >= HEARD_MAX {
            v.remove(0);
        }
        v.push(h);
    }

    /// The head lists peers sent since the last call.
    pub fn take_heard(&self) -> Vec<Heard> {
        std::mem::take(&mut *self.heard.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// The asking side of format 3: this device's identity and its kept TLS
/// sessions.
pub struct Client {
    me: DeviceId,
    me16: Id16,
    identity: Identity,
    pool: tls::TlsPool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(me: DeviceId, identity: Identity) -> Arc<Client> {
        Arc::new(Client {
            me16: id16_of(&me),
            me,
            identity,
            pool: tls::TlsPool::default(),
        })
    }

    pub fn me(&self) -> &DeviceId {
        &self.me
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The token of a request for `path` to `responder` on the connection
    /// with exporter value `exporter`.
    pub fn token(&self, exporter: &[u8; 32], responder: &DeviceId, path: &str) -> String {
        token::make(
            exporter,
            &self.me16,
            &id16_of(responder),
            path,
            crate::util::now_utc(),
        )
    }

    /// GET `path` from `responder` at `addr` over TLS, pinning `cert`.
    pub fn tcp_get(
        &self,
        addr: SocketAddr,
        cert: &str,
        responder: &DeviceId,
        path: &str,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        self.pool.get(
            &self.identity,
            addr,
            cert,
            path,
            timeout,
            &|e: &[u8; 32]| self.token(e, responder, path),
        )
    }
}

/// The snapshot answers for the local ledger: its head list, and batches
/// read from the ledger directory (`<device hex>/<seq 16>-0000.rec`).
impl BatchSource for Snapshot {
    fn heads(&self) -> Vec<HeadRef> {
        self.heads.clone()
    }
    fn batch(&self, device: &Id16, seq: u64) -> Option<Vec<u8>> {
        let dir = self.ledger_dir.as_ref()?;
        let p = dir
            .join(hex::encode(device))
            .join(format!("{seq:016}-0000.rec"));
        let meta = std::fs::metadata(&p).ok()?;
        if meta.len() > crate::record::MAX_PART_READ {
            return None;
        }
        std::fs::read(p).ok()
    }
}

/// Tell every peer this device published something, with its head list;
/// the answers (proofs and their lists) come back per peer.
pub fn notify_changed(peers: &super::Peers, mine: &[HeadRef]) -> Vec<(DeviceId, HeadsAnswer)> {
    let path =
        heads::list_path(heads::CHANGED_PREFIX, mine).unwrap_or_else(|| "/p2p/changed".into());
    peers
        .ask_each(&path)
        .into_iter()
        .filter(|(_, s, _)| *s == 200)
        .filter_map(|(d, _, b)| HeadsAnswer::decode(&b).map(|a| (d, a)))
        .collect()
}
