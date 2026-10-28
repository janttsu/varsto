// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer records of format 3 (design section 8): SignedRecords of kind
//! `peer` at `vault/peers/<device>/<seq 16>-0000.rec`, sealed under the
//! registry key, newest seq wins; and the directory built from the
//! accepted ones, which says which client certificate belongs to which
//! trusted full device.

use super::heads::{HeadRef, Pushed, MAX_HEADS};
use super::Id16;
use crate::ids::DeviceId;
use crate::p2p::{stun, PeerInfo};
use crate::record::{
    Acceptor, KeyId, Kind, Outcome, Parts, Record, RecordBody, RecordMeta, RecordName, RecordStore,
    RecordWriter, RecordsRefused, StreamRef,
};
use crate::storage::Storage;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};

/// Most addresses in one list of a record.
pub const MAX_ADDRS: usize = 32;
/// Most relays a record names.
pub const MAX_RELAYS: usize = 16;
/// Most storages in `pushed`.
pub const MAX_PUSHED: usize = 64;
/// Longest device name (bytes).
pub const MAX_NAME: usize = 128;

/// The body of a peer record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBody {
    /// Equal to the envelope's device and seq (checked).
    pub device: Id16,
    pub seq: u64,
    pub name: String,
    /// TCP and UDP port (one number for both transports).
    pub port: u16,
    /// Interface addresses, best first as `netif::rank` orders them
    /// (alpha-0-format.md section 68).
    pub lan_addrs: Vec<IpAddr>,
    /// Addresses the user configured (forwarded port, public IP, VPN).
    pub public_addrs: Vec<SocketAddr>,
    /// UDP addresses STUN servers saw, and those of our own interfaces.
    pub udp_public: Vec<SocketAddr>,
    pub udp_local: Vec<SocketAddr>,
    /// Ports the home router forwards to us (section 52).
    pub mapped_tcp: Vec<SocketAddr>,
    pub mapped_udp: Vec<SocketAddr>,
    /// SHA-256 of the device's TLS certificate: the pin of both transports.
    pub cert_sha256: [u8; 32],
    pub nat: stun::Nat,
    /// Reachable devices this one keeps a relay registration with.
    pub relay_via: Vec<Id16>,
    pub reachable: bool,
    /// The newest batch this device holds of every full device.
    pub heads: Vec<HeadRef>,
    /// Its own newest batch confirmed on each metadata storage.
    pub pushed: Vec<Pushed>,
}

impl RecordBody for PeerBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.device {
            return Err("the body names another device".into());
        }
        if self.seq != meta.seq {
            return Err("the body names another seq".into());
        }
        if self.cert_sha256 == [0u8; 32] {
            return Err("no certificate".into());
        }
        if self.name.len() > MAX_NAME {
            return Err("name too long".into());
        }
        let lists = [
            self.lan_addrs.len(),
            self.public_addrs.len(),
            self.udp_public.len(),
            self.udp_local.len(),
            self.mapped_tcp.len(),
            self.mapped_udp.len(),
        ];
        if lists.iter().any(|n| *n > MAX_ADDRS) {
            return Err("too many addresses".into());
        }
        if self.relay_via.len() > MAX_RELAYS
            || self.heads.len() > MAX_HEADS
            || self.pushed.len() > MAX_PUSHED
        {
            return Err("too many entries".into());
        }
        Ok(())
    }
}

fn push_unique(out: &mut Vec<SocketAddr>, a: &SocketAddr) {
    if !out.contains(a) {
        out.push(*a);
    }
}

impl PeerBody {
    /// TCP addresses: LAN first (in rank order), then the router-mapped
    /// ones, then those the user configured.
    pub fn tcp_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for ip in &self.lan_addrs {
            push_unique(&mut out, &SocketAddr::new(*ip, self.port));
        }
        for a in self.mapped_tcp.iter().chain(&self.public_addrs) {
            push_unique(&mut out, a);
        }
        out
    }

    /// UDP (QUIC) addresses: router-mapped, STUN-learned, configured, own.
    pub fn udp_addrs(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        for a in self
            .mapped_udp
            .iter()
            .chain(&self.udp_public)
            .chain(&self.public_addrs)
            .chain(&self.udp_local)
        {
            push_unique(&mut out, a);
        }
        out
    }

    /// What the client side needs to reach the device.
    pub fn info(&self) -> PeerInfo {
        PeerInfo {
            device: DeviceId::from_bytes(&self.device),
            name: self.name.clone(),
            tcp: self.tcp_addrs(),
            udp: self.udp_addrs(),
            cert_sha256: hex::encode(self.cert_sha256),
            relay_via: self
                .relay_via
                .iter()
                .map(|d| DeviceId::from_bytes(d))
                .collect(),
            nat: self.nat,
            reachable: self.reachable,
        }
    }

    /// The stream of `device`'s peer records.
    pub fn stream(device: Id16) -> StreamRef {
        StreamRef::new(Kind::Peer, [0u8; 16], device)
    }

    /// Equal apart from the seq: nothing worth republishing.
    pub fn same_as(&self, other: &PeerBody) -> bool {
        let mut a = self.clone();
        a.seq = other.seq;
        a == *other
    }
}

/// The highest seq of `device`'s peer records on `storage` (0: none).
pub fn highest_seq(storage: &dyn Storage, device: Id16) -> Result<u64> {
    let Some(prefix) = PeerBody::stream(device).prefix() else {
        bail!("peer stream without a prefix");
    };
    Ok(storage
        .list(&prefix)?
        .iter()
        .filter_map(|n| RecordName::parse_as(Kind::Peer, n))
        .map(|n| n.seq)
        .max()
        .unwrap_or(0))
}

/// Publish `body` as the device's next peer record under the registry key
/// of vault epoch `epoch` (put-if-absent at the next free seq), then delete
/// its records older than the one before it, so the stream stays two
/// records long while a reader that listed a moment ago still finds one.
/// Returns the seq written. The seq is above `floor` as well: the highest
/// this device wrote anywhere (another storage, the rendezvous, section
/// 83.9), so a record written here later is never shadowed by an older one.
pub fn publish(
    storage: &dyn Storage,
    writer: &RecordWriter<'_>,
    body: &mut PeerBody,
    epoch: u32,
    floor: u64,
) -> Result<u64> {
    let stream = PeerBody::stream(body.device);
    let first = highest_seq(storage, body.device)?.max(floor) + 1;
    // Another writer of this device's stream may take a seq: try the next.
    for seq in first..first + 4 {
        body.seq = seq;
        let sealed = writer.seal(&stream, seq, seq, &KeyId::Registry(epoch), &*body)?;
        let (name, bytes) = &sealed.parts[0];
        if storage.put_if_absent(name, bytes)? {
            if let Some(prefix) = stream.prefix() {
                for old in storage.list(&prefix)? {
                    if RecordName::parse_as(Kind::Peer, &old).is_some_and(|n| n.seq + 1 < seq) {
                        let _ = storage.delete(&old);
                    }
                }
            }
            return Ok(seq);
        }
    }
    bail!("could not find a free seq for the peer record");
}

/// The peer directory as a device keeps it between runs: the signed
/// records as they were read, each part as (storage name, hex bytes). It
/// is checked again on load, so the file is no source of trust.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedDirectory {
    pub records: Vec<SavedRecord>,
}

/// One saved record: its parts in any order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedRecord {
    pub parts: Vec<(String, String)>,
}

/// Accepted peer records of trusted full devices, newest seq of each.
/// This device and any record carrying this device's certificate are left
/// out (a device never admits or dials its own certificate, section 73).
#[derive(Clone, Debug, Default)]
pub struct PeerDirectory {
    me: Id16,
    own_cert: [u8; 32],
    entries: BTreeMap<Id16, PeerBody>,
    /// The signed parts each entry was accepted from, as they were read:
    /// what is saved on this device (`saved`) and checked again on load.
    raw: BTreeMap<Id16, Parts>,
    by_cert: HashMap<[u8; 32], Id16>,
    /// Certificates two devices claim: admitted for neither.
    contested: Vec<[u8; 32]>,
}

impl PeerDirectory {
    pub fn new(me: Id16, own_cert: [u8; 32]) -> PeerDirectory {
        PeerDirectory {
            me,
            own_cert,
            ..Default::default()
        }
    }

    pub fn me(&self) -> &Id16 {
        &self.me
    }

    pub fn own_cert(&self) -> &[u8; 32] {
        &self.own_cert
    }

    /// Take an accepted record (`record::Acceptor` passed it: the signer is
    /// a trusted device and may write peer records). True when it is now
    /// the device's entry.
    pub fn offer(&mut self, rec: Record<PeerBody>) -> bool {
        self.offer_body(rec.body)
    }

    /// `offer`, keeping the signed parts the record was accepted from so
    /// that the entry can be saved and checked again later.
    pub fn offer_parts(&mut self, rec: Record<PeerBody>, parts: Parts) -> bool {
        let device = rec.body.device;
        let taken = self.offer_body(rec.body);
        if taken {
            self.raw.insert(device, parts);
        }
        taken
    }

    /// Take the entries of a directory read from another storage (or the
    /// one saved on this device): the newest seq of each device wins, and
    /// an entry that is not replaced stays as it was.
    pub fn merge(&mut self, mut other: PeerDirectory) {
        for (device, body) in std::mem::take(&mut other.entries) {
            if self.offer_body(body) {
                if let Some(parts) = other.raw.remove(&device) {
                    self.raw.insert(device, parts);
                }
            }
        }
    }

    /// The signed parts of every entry that has them, as they were read:
    /// what the device saves so that peer-to-peer works before (or
    /// without) any storage answering.
    pub fn saved(&self) -> SavedDirectory {
        SavedDirectory {
            records: self
                .raw
                .iter()
                .filter(|(d, _)| self.entries.contains_key(*d))
                .map(|(_, parts)| SavedRecord {
                    parts: parts
                        .iter()
                        .map(|(name, bytes)| (name.clone(), hex::encode(bytes)))
                        .collect(),
                })
                .collect(),
        }
    }

    /// A directory from records saved earlier, each checked again by
    /// `acceptor` exactly as a record read from a storage is (signature,
    /// signer trusted now, vault, registry key held, body). Records of
    /// devices not in `devices` (removed or no longer trusted since) and
    /// records that do not pass are left out.
    pub fn from_saved(
        saved: &SavedDirectory,
        acceptor: &Acceptor<'_>,
        devices: &[Id16],
        me: Id16,
        own_cert: [u8; 32],
        counter: &mut RecordsRefused,
    ) -> PeerDirectory {
        let mut dir = PeerDirectory::new(me, own_cert);
        for rec in &saved.records {
            let mut parts: Parts = Vec::with_capacity(rec.parts.len());
            for (name, h) in &rec.parts {
                match hex::decode(h) {
                    Ok(b) if b.len() as u64 <= crate::record::MAX_PART_READ => {
                        parts.push((name.clone(), b))
                    }
                    _ => {}
                }
            }
            if parts.is_empty() || parts.len() != rec.parts.len() {
                continue;
            }
            match acceptor.accept::<PeerBody>(&parts) {
                Outcome::Accepted(r) if devices.contains(&r.body.device) => {
                    dir.offer_parts(r, parts);
                }
                Outcome::Accepted(_) | Outcome::Waiting(_) => {}
                Outcome::Refused(r) => {
                    counter.note(&r);
                }
            }
        }
        dir
    }

    fn offer_body(&mut self, body: PeerBody) -> bool {
        if body.device == self.me || body.cert_sha256 == self.own_cert {
            return false;
        }
        if self
            .entries
            .get(&body.device)
            .is_some_and(|old| old.seq >= body.seq)
        {
            return false;
        }
        self.raw.remove(&body.device);
        self.entries.insert(body.device, body);
        self.reindex();
        true
    }

    fn reindex(&mut self) {
        let mut count: HashMap<[u8; 32], usize> = HashMap::new();
        for b in self.entries.values() {
            *count.entry(b.cert_sha256).or_default() += 1;
        }
        self.contested = count
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(c, _)| *c)
            .collect();
        self.by_cert = self
            .entries
            .values()
            .filter(|b| count.get(&b.cert_sha256) == Some(&1))
            .map(|b| (b.cert_sha256, b.device))
            .collect();
    }

    /// The trusted device a client certificate belongs to.
    pub fn device_for_cert(&self, cert: &[u8; 32]) -> Option<Id16> {
        if cert == &self.own_cert {
            return None;
        }
        self.by_cert.get(cert).copied()
    }

    pub fn get(&self, device: &Id16) -> Option<&PeerBody> {
        self.entries.get(device)
    }

    pub fn contains(&self, device: &Id16) -> bool {
        self.entries.contains_key(device)
    }

    pub fn bodies(&self) -> impl Iterator<Item = &PeerBody> {
        self.entries.values()
    }

    /// Every device's entry as the client side uses it; contested
    /// certificates are left out (no route can be pinned to them).
    pub fn infos(&self) -> Vec<PeerInfo> {
        self.entries
            .values()
            .filter(|b| !self.contested.contains(&b.cert_sha256))
            .map(PeerBody::info)
            .collect()
    }

    /// Read the newest acceptable peer record of each of `devices` from
    /// `store`: listed newest first, the first record that passes the
    /// acceptance rule wins; refusals are noted in `counter`.
    pub fn read(
        store: &RecordStore<'_>,
        devices: impl IntoIterator<Item = Id16>,
        me: Id16,
        own_cert: [u8; 32],
        counter: &mut RecordsRefused,
    ) -> Result<PeerDirectory> {
        let mut dir = PeerDirectory::new(me, own_cert);
        for d in devices {
            if d == me {
                continue;
            }
            let listed = store.list_after(&PeerBody::stream(d), 0)?;
            for l in listed.iter().rev() {
                // Fetched and accepted as `RecordStore::read` does, keeping
                // the parts so that the directory can be saved.
                let parts = match store.fetch(l)? {
                    Ok(p) if !p.is_empty() => p,
                    Ok(_) => continue,
                    Err(r) => {
                        counter.note(&r);
                        continue;
                    }
                };
                match store.acceptor.accept::<PeerBody>(&parts) {
                    Outcome::Accepted(rec) => {
                        dir.offer_parts(rec, parts);
                        break;
                    }
                    Outcome::Refused(r) => {
                        counter.note(&r);
                    }
                    Outcome::Waiting(_) => {}
                }
            }
        }
        Ok(dir)
    }
}
