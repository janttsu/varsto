// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peers and transport of storage format 3 as the engine runs them
//! (`docs/spec/format-3-design.md` section 8, `alpha-0-format.md` sections
//! 75 and 77.8): this device's peer record (a SignedRecord of kind `peer`
//! under the registry key), the directory of the accepted records of the
//! other trusted full devices (the pins of both transports), the answering
//! and asking sides (`p2p::v3::Responder`, `p2p::v3::Client`) and the keys
//! that check LAN beacons.

use super::*;
use crate::p2p::v3::{self, peer, HeadRef, PeerBody, PeerDirectory, Pushed, SavedDirectory};
use crate::record::{Acceptor, DeviceSigner, Id16, RecordStore, RecordWriter, RecordsRefused};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The peer directory kept on this device (`alpha-0-format.md` section
/// 77.8, "Offline"): the signed peer records as they were last read, checked again
/// whenever they are loaded.
pub const SAVED_PEERS: &str = "peer-records.json";

/// How one read of the peer records over the storages went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryRead {
    /// Hot metadata storages asked.
    pub storages: usize,
    /// Of them, the ones whose records could be listed.
    pub answered: usize,
}

impl DirectoryRead {
    /// Nothing to ask, or at least one storage answered.
    pub fn ok(&self) -> bool {
        self.storages == 0 || self.answered > 0
    }
}

/// A storage whose identity could not be read is not asked again for this long.
const IDENTITY_RETRY: Duration = Duration::from_secs(300);

type IdentityCache = Mutex<HashMap<String, (Option<String>, Instant)>>;

/// Storage identities by location (`StorageSpec::location_key`): they never
/// change, so building the peer record does not cost a GET per storage
/// each time. A failed read is remembered too, so a dead storage costs one
/// timeout per `IDENTITY_RETRY`.
fn identity_cache() -> &'static IdentityCache {
    static CACHE: OnceLock<IdentityCache> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// The identity of `backend`, cached for every storage but a directory on
/// this device (a removable disk may be another one next time, and reading
/// it costs nothing).
fn cached_storage_identity(spec: &StorageSpec, backend: &dyn Storage) -> Option<String> {
    let key = match spec {
        StorageSpec::LocalDir { .. } => None,
        _ => spec.location_key(),
    };
    let Some(key) = key else {
        return verify::storage_identity(backend).ok();
    };
    if let Some((id, at)) = identity_cache().lock().unwrap().get(&key) {
        if id.is_some() || at.elapsed() < IDENTITY_RETRY {
            return id.clone();
        }
    }
    let id = verify::storage_identity(backend).ok();
    identity_cache()
        .lock()
        .unwrap()
        .insert(key, (id.clone(), Instant::now()));
    id
}

/// The SHA-256 of a certificate as the records carry it.
fn cert_bin(hex_sha: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(hex_sha, &mut out).is_err() {
        return [0u8; 32];
    }
    out
}

impl Engine {
    /// The certificate pin of this device (zero before `p2p enable`).
    fn own_cert3(&self) -> [u8; 32] {
        crate::p2p::quic::Identity::load(&self.home)
            .ok()
            .flatten()
            .map(|id| cert_bin(&id.sha256))
            .unwrap_or([0u8; 32])
    }

    /// The trusted full devices of the vault other than this one: whose
    /// peer records count and whose beacons are heard.
    fn peer_devices(&self) -> Vec<Id16> {
        let me = self.me3();
        self.f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| **d != me && !self.f3.members.revoked.contains(*d))
            .filter(|d| self.trusted(&DeviceId::from_bytes(&d[..])))
            .copied()
            .collect()
    }

    /// The directory as this device saved it after its last good read
    /// (`SAVED_PEERS`), every record checked again against the membership
    /// held here: no storage is asked. A device removed or no longer
    /// trusted since drops out; nothing else changes until a storage
    /// answers. Opening the vault and starting peer-to-peer use this, so
    /// LAN peers work with every storage unreachable.
    pub fn local_peer_directory(&self) -> PeerDirectory {
        self.local_peer_directory_saved().0
    }

    /// `local_peer_directory`, with the saved form it was loaded from.
    fn local_peer_directory_saved(&self) -> (PeerDirectory, SavedDirectory) {
        let me = self.me3();
        let own = self.own_cert3();
        let empty = PeerDirectory::new(me, own);
        if self.vault.member {
            return (empty, SavedDirectory::default());
        }
        let saved: SavedDirectory = match util::read_json_or_default(&self.home.join(SAVED_PEERS)) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("saved peer records not read: {e:#}");
                return (empty, SavedDirectory::default());
            }
        };
        let devices = self.peer_devices();
        if saved.records.is_empty() || devices.is_empty() {
            return (empty, saved);
        }
        let Ok(vault) = members3::bin(&self.vault.vault_id) else {
            return (empty, saved);
        };
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = self.f3.members.trust();
        let acceptor = Acceptor {
            vault,
            keys: &keys,
            trust: &trust,
        };
        let mut refused = RecordsRefused::default();
        let dir = PeerDirectory::from_saved(&saved, &acceptor, &devices, me, own, &mut refused);
        if refused.total() > 0 {
            log::info!("saved peer records refused now: {:?}", refused.by_kind);
        }
        (dir, saved)
    }

    /// The accepted peer records of the other trusted full devices, newest
    /// of each over the directory saved here and every hot metadata
    /// storage. This device, a record carrying this device's certificate
    /// and a certificate two devices claim are left out (`PeerDirectory`).
    /// A storage that does not answer changes nothing: the saved entries
    /// stay until a newer record replaces them.
    pub fn peer_directory(&self) -> Result<PeerDirectory> {
        Ok(self.peer_directory_read().0)
    }

    /// `peer_directory`, and how the listing went. The merged directory is
    /// saved here when at least one storage answered.
    pub fn peer_directory_read(&self) -> (PeerDirectory, DirectoryRead) {
        let (mut dir, saved) = self.local_peer_directory_saved();
        let mut read = DirectoryRead::default();
        if self.vault.member {
            return (dir, read);
        }
        let devices = self.peer_devices();
        if devices.is_empty() {
            return (dir, read);
        }
        let me = self.me3();
        let own = self.own_cert3();
        let Ok(vault) = members3::bin(&self.vault.vault_id) else {
            return (dir, read);
        };
        let storages = match self.record_storages() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("peer records not read: {e:#}");
                // Counted as one storage that did not answer.
                read.storages = 1;
                return (dir, read);
            }
        };
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = self.f3.members.trust();
        let mut refused = RecordsRefused::default();
        for (_, backend) in storages {
            read.storages += 1;
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            match PeerDirectory::read(&store, devices.iter().copied(), me, own, &mut refused) {
                Ok(d) => {
                    read.answered += 1;
                    dir.merge(d);
                }
                Err(e) => log::warn!(storage = backend.name(); "peer records not read: {e:#}"),
            }
        }
        if refused.total() > 0 {
            log::warn!("peer records refused: {:?}", refused.by_kind);
        }
        if read.answered > 0 {
            let now = dir.saved();
            if now != saved {
                if let Err(e) = util::write_json(&self.home.join(SAVED_PEERS), &now) {
                    log::warn!("peer records not saved here: {e:#}");
                }
            }
        }
        (dir, read)
    }

    /// The newest batch this device holds of every full device (its own:
    /// the newest one a storage confirmed), as peer records and head
    /// exchanges carry it.
    pub fn head_list(&self) -> Vec<HeadRef> {
        let me = self.me3();
        let mut out = Vec::new();
        let mut devices: Vec<Id16> = self.f3.members.devices.devices.keys().copied().collect();
        if !devices.contains(&me) {
            devices.push(me);
        }
        for d in devices {
            let head = self.f3.ledger.head(&d);
            let seq = if d == me {
                head.seq.min(self.f3.ledger.pushed_max())
            } else {
                head.seq
            };
            if seq == 0 {
                continue;
            }
            let Ok(Some(hash)) = self.f3.ledger.hash_at(&d, seq) else {
                continue;
            };
            out.push(HeadRef {
                device: d,
                seq,
                hash,
            });
            if out.len() >= v3::heads::MAX_HEADS {
                break;
            }
        }
        out
    }

    /// This device's own newest batch confirmed on each hot metadata
    /// storage, by storage identity.
    fn pushed3(&self) -> Vec<Pushed> {
        let mut out = Vec::new();
        let Ok(storages) = self.record_storages() else {
            return out;
        };
        for (spec, backend) in storages {
            let seq = self.f3.ledger.pushed(spec.name());
            if seq == 0 {
                continue;
            }
            let Some(id) = cached_storage_identity(&spec, backend.as_ref()) else {
                continue;
            };
            let Some(storage) = crate::record::kinds::parse_id16(&id) else {
                continue;
            };
            out.push(Pushed { storage, seq });
            if out.len() >= peer::MAX_PUSHED {
                break;
            }
        }
        out
    }

    /// The peer record this device would publish for `port`, before the
    /// service adds what STUN, the router and the relays told it.
    pub fn peer_body(&self, port: u16) -> PeerBody {
        let mut lan: Vec<std::net::IpAddr> = crate::netif::candidates()
            .into_iter()
            .map(|c| std::net::IpAddr::V4(c.ip))
            .collect();
        if lan.is_empty() {
            lan = crate::p2p::local_ipv4_addrs();
        }
        lan.truncate(peer::MAX_ADDRS);
        let mut name = self.vault.device_name.clone();
        while name.len() > peer::MAX_NAME {
            name.pop();
        }
        let mut public = self.config.p2p.public_addrs.clone();
        public.truncate(peer::MAX_ADDRS);
        PeerBody {
            device: self.me3(),
            seq: 0,
            name,
            port,
            udp_local: lan
                .iter()
                .map(|ip| std::net::SocketAddr::new(*ip, port))
                .collect(),
            lan_addrs: lan,
            reachable: !public.is_empty(),
            public_addrs: public,
            udp_public: Vec::new(),
            mapped_tcp: Vec::new(),
            mapped_udp: Vec::new(),
            cert_sha256: self.own_cert3(),
            nat: crate::p2p::stun::Nat::Unknown,
            relay_via: Vec::new(),
            heads: self.head_list(),
            pushed: self.pushed3(),
        }
    }

    /// Publish `body` as this device's next peer record on every hot
    /// metadata storage (the stream keeps two records). Returns the seq
    /// written last.
    pub fn publish_peer_body(&self, body: &mut PeerBody) -> Result<u64> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device publishes no peer record");
        }
        if body.cert_sha256 == [0u8; 32] {
            bail!("no peer-to-peer certificate yet: enable peer-to-peer first");
        }
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let epoch = vault_keys.newest_epoch();
        let keys = self.keys3(&vault_keys);
        let signer = DeviceSigner {
            device: self.me3(),
            key: &self.keys.signer,
        };
        let writer = RecordWriter {
            vault,
            signer: &signer,
            keys: &keys,
        };
        // Every storage is tried: one that fails does not keep the record
        // from the others. The error (some storage missed it) makes the
        // service try again later.
        let mut last = 0;
        let mut failed = Vec::new();
        let storages = self.record_storages()?;
        let total = storages.len();
        for (_, backend) in storages {
            match peer::publish(backend.as_ref(), &writer, body, epoch) {
                Ok(seq) => last = seq,
                Err(e) => failed.push(format!("{}: {e:#}", backend.name())),
            }
        }
        if !failed.is_empty() {
            bail!(
                "peer record not published on {} of {total} storages ({})",
                failed.len(),
                failed.join("; ")
            );
        }
        Ok(last)
    }

    /// Publish this device's newest peer record again under the newest
    /// registry key (after a removal, so the removed device stops learning
    /// our addresses at once rather than at the next periodic republish).
    pub(super) fn republish_own_peer_record(&self) {
        let me = self.me3();
        let Ok(vault) = members3::bin(&self.vault.vault_id) else {
            return;
        };
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = self.f3.members.trust();
        let Ok(storages) = self.record_storages() else {
            return;
        };
        for (_, backend) in &storages {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            let Ok(listed) = store.list_after(&PeerBody::stream(me), 0) else {
                continue;
            };
            for l in listed.iter().rev() {
                if let Ok(crate::record::Outcome::Accepted(rec)) = store.read::<PeerBody>(l) {
                    let mut body = rec.body;
                    if let Err(e) = self.publish_peer_body(&mut body) {
                        log::warn!("peer record not published again: {e:#}");
                    }
                    return;
                }
            }
        }
    }

    /// The K6 public keys of the trusted full devices: what a signed LAN
    /// beacon and a head proof are checked against.
    pub fn full_device_keys(&self) -> BTreeMap<Id16, crate::crypto::VerifyingKey> {
        let mut out = BTreeMap::new();
        for d in self.peer_devices() {
            if let Some(k) = self.f3.members.devices.signing_key(&d) {
                out.insert(d, k);
            }
        }
        out
    }

    /// The tag LAN beacons of this vault carry.
    pub fn beacon_tag(&self) -> String {
        hex::encode(
            &crypto::keyed_hash(
                &crate::membership3::derive3(self.root_key(), "p2p-tag", &[]),
                self.vault.vault_id.as_str().as_bytes(),
            )[..12],
        )
    }

    /// The signed LAN beacon of this device on `port`.
    pub fn p2p_beacon(&self, port: u16) -> Result<v3::beacon::Beacon> {
        let signer = crypto::SigningKey::from_bytes(&self.keys.signer.to_bytes())?;
        v3::beacon::Beacon::new(self.beacon_tag(), self.me3(), port, Arc::new(signer))
    }

    /// The answering side of both transports for `identity`, with the
    /// directory saved on this device. No storage is asked, so the listener
    /// and the beacons start at once; the service merges the storages'
    /// records in before its first sync.
    pub fn p2p_responder(&self, identity: &crate::p2p::quic::Identity) -> Arc<v3::Responder> {
        let r = v3::Responder::new(self.vault.device_id.clone(), &identity.sha256);
        r.set_directory(self.local_peer_directory());
        r
    }

    /// The asking side for `identity`.
    pub fn p2p_client(&self, identity: crate::p2p::quic::Identity) -> Arc<v3::Client> {
        v3::Client::new(self.vault.device_id.clone(), identity)
    }

    /// A peer table over the directory, TLS over TCP only (command-line
    /// runs; the service adds LAN beacons and the QUIC node). `None`
    /// before `p2p enable` or without peers.
    pub fn p2p_peers_tcp(&self) -> Option<crate::p2p::Peers> {
        let dir = self.peer_directory().ok()?;
        self.p2p_peers_tcp_from(&dir)
    }

    /// `p2p_peers_tcp` over a directory read already.
    pub fn p2p_peers_tcp_from(&self, dir: &PeerDirectory) -> Option<crate::p2p::Peers> {
        let identity = crate::p2p::quic::Identity::load(&self.home)
            .ok()
            .flatten()?;
        if dir.infos().is_empty() {
            return None;
        }
        Some(crate::p2p::Peers::build_v3(
            self.p2p_client(identity),
            dir,
            &[],
            None,
        ))
    }

    /// The peer table a vault opens with: the directory saved on this
    /// device, TLS over TCP, marked so that the first sync reads the
    /// storages' records into it (`refresh_saved_peers`). Opening asks no
    /// storage. `None` before `p2p enable`.
    pub(super) fn p2p_peers_local(&self) -> Option<crate::p2p::Peers> {
        let identity = crate::p2p::quic::Identity::load(&self.home)
            .ok()
            .flatten()?;
        let dir = self.local_peer_directory();
        Some(
            crate::p2p::Peers::build_v3(self.p2p_client(identity), &dir, &[], None)
                .from_saved_directory(),
        )
    }

    /// A table built at open from the saved directory only: read the
    /// storages' records into it now (a command-line sync), keeping the
    /// saved entries when no storage answers. The service hands the engine
    /// its own table before every sync, so this does nothing there.
    pub(super) fn refresh_saved_peers(&mut self) {
        if !self.peers.as_ref().is_some_and(|p| p.is_from_saved()) {
            return;
        }
        let (dir, _) = self.peer_directory_read();
        let fresh = self.p2p_peers_tcp_from(&dir).map(Arc::new);
        if let (Some(new), Some(old)) = (&fresh, &self.peers) {
            new.inherit(old);
        }
        self.peers = fresh;
    }

    /// Where this device's peer-to-peer snapshot finds batches for heads
    /// and `/p2p/ledger/`: its head list and its ledger directory.
    pub(super) fn snapshot_heads(&self) -> (Vec<HeadRef>, Option<PathBuf>) {
        if self.vault.member || self.removal.is_some() {
            return (Vec::new(), None);
        }
        (self.head_list(), Some(self.home.join("ledger")))
    }
}
