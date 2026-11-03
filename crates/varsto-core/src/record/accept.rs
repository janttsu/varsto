// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `record::accept`: the one acceptance rule for every kind (format 3
//! design, section 5), the refusal reasons, the `records_refused` counter
//! and `RecordStore`, which reads streams through the storage trait.
//!
//! Steps (1) to (4) live here. The engine supplies what they need through
//! `RecordTrust` (device keys and roles, step 2 and 3; announcements, step
//! 5) and `RecordKeys` (step 4); body types add the kind-specific checks of
//! step 6 through `RecordBody::check`. A removed device's cut-off is the
//! engine's: its `announcement` simply stops answering past it.

use super::envelope::{decode_body_limited, record_hash, RecordKeys, SignedRecord, MAX_PART_READ};
use super::kinds::{KeyId, Kind, RecordName, StreamRef};
use super::Id16;
use crate::crypto::VerifyingKey;
use crate::storage::{Storage, TooLarge};
use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// Most records of one stream that may wait for their announcement; more
/// are dropped and fetched again later.
pub const MAX_AHEAD: usize = 64;

/// Why a record is junk: it failed step (1), (2), (3) or (4), or the
/// kind-specific checks of (6). Never applied, counted, reported once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Junk {
    BadMagic,
    Malformed(String),
    WrongFormat(u16),
    UnknownKind(u8),
    WrongVault,
    /// The storage name and the envelope disagree (which field).
    NameMismatch(&'static str),
    KeyIdTooLong,
    BadKeyId,
    /// A key_id of a class the kind does not use (section 5's table).
    KeyNotForKind,
    PartOutOfRange,
    TooManyParts,
    OversizePart,
    BadBodyLength(usize),
    /// The parts of one record disagree on a signed field, or repeat.
    PartsDisagree,
    BadSignature,
    /// No accepted device record (or member record) for the writer.
    UnknownSigner,
    /// The writer's role does not allow this kind in this scope (section 9).
    NotAllowed,
    /// This device does not hold the key the key_id names.
    KeyNotHeld,
    BodyDoesNotOpen,
    /// The body does not decode, or fails its kind's checks.
    BadBody(String),
}

impl std::error::Error for Junk {}

impl fmt::Display for Junk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Junk::BadMagic => f.write_str("not a signed record"),
            Junk::Malformed(e) => write!(f, "the envelope does not parse ({e})"),
            Junk::WrongFormat(v) => write!(f, "storage format {v}, not 3"),
            Junk::UnknownKind(k) => write!(f, "unknown kind {k}"),
            Junk::WrongVault => f.write_str("it belongs to another vault"),
            Junk::NameMismatch(what) => {
                write!(f, "its name and its envelope disagree on the {what}")
            }
            Junk::KeyIdTooLong => f.write_str("its key_id is longer than 64 bytes"),
            Junk::BadKeyId => f.write_str("its key_id is not one Varsto writes"),
            Junk::KeyNotForKind => f.write_str("its key_id does not belong to its kind"),
            Junk::PartOutOfRange => f.write_str("its part number is out of range"),
            Junk::TooManyParts => f.write_str("it claims more than 1024 parts"),
            Junk::OversizePart => f.write_str("a part is larger than 32 MiB"),
            Junk::BadBodyLength(n) => write!(f, "its body length {n} is not a size class"),
            Junk::PartsDisagree => f.write_str("its parts do not belong together"),
            Junk::BadSignature => f.write_str("its signature does not verify"),
            Junk::UnknownSigner => f.write_str("its writer is not a trusted device"),
            Junk::NotAllowed => f.write_str("its writer may not write it"),
            Junk::KeyNotHeld => f.write_str("the key it names is not held here"),
            Junk::BodyDoesNotOpen => f.write_str("its body does not open"),
            Junk::BadBody(e) => write!(f, "its body is invalid ({e})"),
        }
    }
}

/// Why a record is not applied (now).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Junk(Junk),
    /// Fewer parts on the storage than the record has: written half-way,
    /// or a part is gone. Not counted; read again later.
    Incomplete {
        have: u16,
        parts: u16,
    },
    /// Passed (1) to (4) but no accepted batch announces it yet.
    Waiting,
    /// Its batch announced another hash (or its `prev` is not the
    /// announced hash of seq - 1): the writer forked this stream.
    Forked,
}

/// A refused record, with what names it in messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub name: String,
    pub kind: Option<Kind>,
    pub seq: u64,
    pub device: Option<Id16>,
    pub reason: Refusal,
}

impl Refused {
    /// Junk and forks count in `records_refused`; waiting and incomplete
    /// records do not.
    pub fn counts(&self) -> bool {
        matches!(self.reason, Refusal::Junk(_) | Refusal::Forked)
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self.kind.map(Kind::name).unwrap_or("?");
        let device = self.device.map(hex::encode).unwrap_or_else(|| "?".into());
        let seq = self.seq;
        match &self.reason {
            Refusal::Forked => write!(
                f,
                "record {kind} {seq} of {device} does not match what its batch announced"
            ),
            Refusal::Junk(j) => write!(f, "record {kind} {seq} of {device} refused: {j}"),
            Refusal::Waiting => write!(
                f,
                "record {kind} {seq} of {device} waits for the batch that announces it"
            ),
            Refusal::Incomplete { have, parts } => write!(
                f,
                "record {kind} {seq} of {device} is incomplete: {have} of {parts} parts"
            ),
        }
    }
}

impl std::error::Error for Refused {}

/// `records_refused`, by kind name (unknown kinds under `"?"`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordsRefused {
    pub by_kind: BTreeMap<String, u64>,
    /// Names already reported, so each refusal is reported once.
    #[serde(skip)]
    reported: HashSet<String>,
}

impl RecordsRefused {
    /// Count a refusal. True when it should be reported (it counts and
    /// its name was not reported before).
    pub fn note(&mut self, r: &Refused) -> bool {
        if !r.counts() {
            return false;
        }
        if !self.reported.insert(r.name.clone()) {
            return false;
        }
        let k = r.kind.map(Kind::name).unwrap_or("?").to_string();
        *self.by_kind.entry(k).or_insert(0) += 1;
        true
    }

    pub fn get(&self, kind: Kind) -> u64 {
        self.by_kind.get(kind.name()).copied().unwrap_or(0)
    }

    pub fn total(&self) -> u64 {
        self.by_kind.values().sum()
    }
}

/// Everything signed about a record, after acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordMeta {
    pub kind: Kind,
    pub vault: Id16,
    pub scope: Id16,
    pub device: Id16,
    pub seq: u64,
    pub parts: u16,
    pub key_id: KeyId,
    /// `record_hash` of the parts: what a batch announces.
    pub body_hash: [u8; 32],
    /// From the storage name (grants, escrow): not in the envelope, so the
    /// kind's own check compares it with the body.
    pub epoch: Option<u32>,
    pub recipient: Option<Id16>,
    /// Bytes of all part objects.
    pub size: u64,
}

/// A body struct of some kind. The defaults fit kinds without bases,
/// chains or extra checks.
pub trait RecordBody: Serialize + DeserializeOwned {
    /// The seq of the base this record builds on (`== seq` for a base).
    fn base(&self) -> Option<u64> {
        None
    }
    /// `body_hash` of record seq - 1 of the stream (zeros for seq 1).
    fn prev(&self) -> Option<[u8; 32]> {
        None
    }
    /// For `device` records: the K6 public key the record carries, which
    /// signs the record itself; the first 16 bytes of its BLAKE3 must be
    /// the device id.
    fn embedded_signing_key(&self) -> Option<Vec<u8>> {
        None
    }
    /// Step (6): the kind-specific checks (section 28 for manifests,
    /// section 3's limits for maps, the name's epoch for grants, ...).
    fn check(&self, _meta: &RecordMeta) -> Result<(), String> {
        Ok(())
    }
    /// The most bytes the body of this kind decompresses to (a batch, for
    /// example, far less than a manifest base).
    fn max_decoded() -> u64 {
        super::envelope::MAX_DECODED_BODY
    }
    /// Bytes left after the fields this build always understood. Empty for
    /// every kind but a revocation, which grew a sequence cut-off a reader
    /// of an older record does not find (`None` then).
    fn take_tail(&mut self, tail: &[u8]) -> Result<(), String> {
        if tail.is_empty() {
            Ok(())
        } else {
            Err(format!("{} bytes after the body", tail.len()))
        }
    }
}

/// What a batch of the writer announced for one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announced {
    pub parts: u16,
    pub body_hash: [u8; 32],
    pub base: u64,
}

/// What the engine knows about devices, roles and announcements.
pub trait RecordTrust {
    /// Step (2): the K6 public key of `device` from an accepted device
    /// record (or its member device record for `scope`); `None` when the
    /// device is not trusted. Not asked for `device` records.
    fn signer_key(&self, device: &Id16, kind: Kind, scope: &Id16) -> Option<VerifyingKey>;
    /// Step (3): whether the device's role allows `kind` in `scope` at
    /// the epoch `key_id` names (section 9; `super::section9_allows` is the matrix).
    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool;
    /// Step (3), continued: a removed device's `folder`, `grant` and
    /// `escrow` records count only up to the seq its stream had when it
    /// was removed. `epoch` and `recipient` come from the storage name.
    /// The default allows every seq (a trust with no cut-offs).
    fn seq_allowed(
        &self,
        _device: &Id16,
        _kind: Kind,
        _scope: &Id16,
        _seq: u64,
        _epoch: Option<u32>,
        _recipient: Option<Id16>,
    ) -> bool {
        true
    }
    /// Step (5): the `record_published` of an accepted batch of `device`
    /// for (kind, scope, seq), up to the device's cut-off.
    fn announcement(
        &self,
        _device: &Id16,
        _kind: Kind,
        _scope: &Id16,
        _seq: u64,
    ) -> Option<Announced> {
        None
    }
}

/// A record that passed (1) to (4), and after `finish` all steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<T> {
    pub meta: RecordMeta,
    pub body: T,
}

/// A record that passed steps (1) to (3): its envelopes in part order,
/// with the names they were read under.
#[derive(Clone, Debug)]
pub struct Checked {
    pub kind: Kind,
    pub key_id: KeyId,
    pub epoch: Option<u32>,
    pub recipient: Option<Id16>,
    pub size: u64,
    pub names: Vec<String>,
    pub envelopes: Vec<SignedRecord>,
}

/// The result of acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Accepted(Record<T>),
    /// Valid, but its announcement has not arrived: keep it (at most
    /// `MAX_AHEAD` per stream) and `finish` it again later.
    Waiting(Record<T>),
    Refused(Refused),
}

/// Applies the acceptance rule for one vault.
pub struct Acceptor<'a> {
    pub vault: Id16,
    pub keys: &'a dyn RecordKeys,
    pub trust: &'a dyn RecordTrust,
}

fn refused(
    name: &str,
    env: Option<&SignedRecord>,
    parsed: Option<&RecordName>,
    reason: Refusal,
) -> Refused {
    Refused {
        name: name.to_string(),
        kind: env.and_then(SignedRecord::kind).or(parsed.map(|p| p.kind)),
        seq: env.map(|e| e.seq).or(parsed.map(|p| p.seq)).unwrap_or(0),
        device: env.map(|e| e.device).or(parsed.and_then(|p| p.device)),
        reason,
    }
}

impl Acceptor<'_> {
    /// Steps (1) to (3) over the parts of one record (storage name and
    /// bytes, in any order): the name, the envelope, the signature and the
    /// writer, without opening the body. Used alone where no key is held
    /// (a batch kept for later, a proof) and by `open`.
    pub fn check_parts(&self, parts: &[(String, Vec<u8>)]) -> Result<Checked, Refused> {
        if parts.is_empty() {
            return Err(refused(
                "",
                None,
                None,
                Refusal::Incomplete { have: 0, parts: 0 },
            ));
        }
        let mut envs: Vec<(String, RecordName, SignedRecord)> = Vec::with_capacity(parts.len());
        for (name, bytes) in parts {
            let parsed = RecordName::parse(name);
            let env = SignedRecord::decode(bytes)
                .map_err(|j| refused(name, None, parsed.as_ref(), Refusal::Junk(j)))?;
            let junk = |j| refused(name, Some(&env), None, Refusal::Junk(j));
            let kind = env.kind().ok_or(junk(Junk::UnknownKind(env.kind)))?;
            let n = RecordName::parse_as(kind, name).ok_or(junk(Junk::NameMismatch("kind")))?;
            if env.vault != self.vault {
                return Err(junk(Junk::WrongVault));
            }
            if kind.scope_in_name() && n.scope != env.scope {
                return Err(junk(Junk::NameMismatch("scope")));
            }
            if n.device.is_some_and(|d| d != env.device) {
                return Err(junk(Junk::NameMismatch("device")));
            }
            if n.seq != env.seq {
                return Err(junk(Junk::NameMismatch("seq")));
            }
            if n.part != env.part {
                return Err(junk(Junk::NameMismatch("part")));
            }
            if let (Some(r), Some(KeyId::Kem(k))) = (n.recipient, env.key()) {
                if r != k {
                    return Err(junk(Junk::NameMismatch("recipient")));
                }
            }
            envs.push((name.clone(), n, env));
        }
        envs.sort_by_key(|(_, _, e)| e.part);
        let (name0, n0, e0) = &envs[0];
        let junk0 = |j| refused(name0, Some(e0), None, Refusal::Junk(j));
        let repeats = envs.windows(2).any(|w| w[0].2.part == w[1].2.part);
        let differ = envs.iter().any(|(_, n, e)| {
            e.kind != e0.kind
                || e.scope != e0.scope
                || e.device != e0.device
                || e.seq != e0.seq
                || e.parts != e0.parts
                || e.key_id != e0.key_id
                || n.epoch != n0.epoch
                || n.recipient != n0.recipient
        });
        if repeats || differ {
            return Err(junk0(Junk::PartsDisagree));
        }
        if envs.len() != usize::from(e0.parts) {
            return Err(refused(
                name0,
                Some(e0),
                None,
                Refusal::Incomplete {
                    have: envs.len() as u16,
                    parts: e0.parts,
                },
            ));
        }
        let kind = e0.kind().ok_or(junk0(Junk::UnknownKind(e0.kind)))?;
        let key_id = e0.key().ok_or(junk0(Junk::BadKeyId))?;
        // (2) for every kind but `device`, whose key is in its body.
        if kind != Kind::Device {
            let pk = self
                .trust
                .signer_key(&e0.device, kind, &e0.scope)
                .ok_or(junk0(Junk::UnknownSigner))?;
            for (_, _, e) in &envs {
                e.verify(&pk).map_err(junk0)?;
            }
        }
        // (3)
        if !self.trust.may_write(&e0.device, kind, &e0.scope, &key_id)
            || !self
                .trust
                .seq_allowed(&e0.device, kind, &e0.scope, e0.seq, n0.epoch, n0.recipient)
        {
            return Err(junk0(Junk::NotAllowed));
        }
        let size = parts.iter().map(|(_, b)| b.len() as u64).sum();
        let (epoch, recipient) = (n0.epoch, n0.recipient);
        Ok(Checked {
            kind,
            key_id,
            epoch,
            recipient,
            size,
            names: envs.iter().map(|(n, _, _)| n.clone()).collect(),
            envelopes: envs.into_iter().map(|(_, _, e)| e).collect(),
        })
    }

    /// Steps (1) to (4) over the parts of one record (storage name and
    /// bytes, in any order).
    pub fn open<T: RecordBody>(&self, parts: &[(String, Vec<u8>)]) -> Result<Record<T>, Refused> {
        let c = self.check_parts(parts)?;
        let (name0, e0) = (&c.names[0], &c.envelopes[0]);
        let junk0 = |j| refused(name0, Some(e0), None, Refusal::Junk(j));
        // (4)
        let mut compressed = Vec::new();
        for e in &c.envelopes {
            compressed.extend_from_slice(&e.open_part(self.keys).map_err(junk0)?);
        }
        let body: T = decode_body_limited(&compressed, T::max_decoded()).map_err(junk0)?;
        if c.kind == Kind::Device {
            let raw = body
                .embedded_signing_key()
                .ok_or(junk0(Junk::BadBody("no signing key".into())))?;
            if crate::crypto::hash(&raw)[..16] != e0.device {
                return Err(junk0(Junk::BadSignature));
            }
            let pk = VerifyingKey::from_bytes(&raw).map_err(|_| junk0(Junk::BadSignature))?;
            for e in &c.envelopes {
                e.verify(&pk).map_err(junk0)?;
            }
        }
        Ok(Record {
            meta: RecordMeta {
                kind: c.kind,
                vault: e0.vault,
                scope: e0.scope,
                device: e0.device,
                seq: e0.seq,
                parts: e0.parts,
                key_id: c.key_id.clone(),
                body_hash: record_hash(c.envelopes.iter().map(|e| &e.body_hash)),
                epoch: c.epoch,
                recipient: c.recipient,
                size: c.size,
            },
            body,
        })
    }

    /// Steps (5) and (6) for a record that passed (1) to (4).
    pub fn finish<T: RecordBody>(&self, rec: Record<T>) -> Outcome<T> {
        let m = &rec.meta;
        let name = StreamRef {
            kind: m.kind,
            scope: m.scope,
            device: m.device,
            epoch: m.epoch,
            recipient: m.recipient,
        }
        .part_name(m.seq, 0)
        .unwrap_or_default();
        let refuse = |reason| Refused {
            name: name.clone(),
            kind: Some(m.kind),
            seq: m.seq,
            device: Some(m.device),
            reason,
        };
        if m.kind.announced() {
            let Some(a) = self.trust.announcement(&m.device, m.kind, &m.scope, m.seq) else {
                return Outcome::Waiting(rec);
            };
            if a.parts != m.parts || a.body_hash != m.body_hash {
                return Outcome::Refused(refuse(Refusal::Forked));
            }
            let delta = rec.body.base().is_some_and(|b| b != m.seq);
            if let (true, Some(prev)) = (delta, rec.body.prev()) {
                if m.seq <= 1 {
                    return Outcome::Refused(refuse(Refusal::Forked));
                }
                match self
                    .trust
                    .announcement(&m.device, m.kind, &m.scope, m.seq - 1)
                {
                    None => return Outcome::Waiting(rec),
                    Some(p) if p.body_hash != prev => {
                        return Outcome::Refused(refuse(Refusal::Forked))
                    }
                    Some(_) => {}
                }
            }
        }
        if let Err(e) = rec.body.check(m) {
            return Outcome::Refused(refuse(Refusal::Junk(Junk::BadBody(e))));
        }
        Outcome::Accepted(rec)
    }

    /// The whole rule: `open`, then `finish`.
    pub fn accept<T: RecordBody>(&self, parts: &[(String, Vec<u8>)]) -> Outcome<T> {
        match self.open(parts) {
            Ok(rec) => self.finish(rec),
            Err(r) => Outcome::Refused(r),
        }
    }
}

/// The parts of one record: (storage name, bytes).
pub type Parts = Vec<(String, Vec<u8>)>;

/// One record of a stream as listed: its seq and part names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub seq: u64,
    pub names: Vec<String>,
}

/// What one pass over a stream found.
#[derive(Debug)]
pub struct StreamRead<T> {
    /// In seq order.
    pub accepted: Vec<Record<T>>,
    pub waiting: Vec<Record<T>>,
    pub refused: Vec<Refused>,
    /// Records past `MAX_AHEAD` waiting ones, not fetched this time.
    pub dropped_ahead: usize,
}

/// Reads record streams of one storage and checks every record.
pub struct RecordStore<'a> {
    pub storage: &'a dyn Storage,
    pub acceptor: Acceptor<'a>,
}

impl RecordStore<'_> {
    /// The records of `stream` with a seq after `after`, by seq. Names
    /// that are not records of this stream are skipped.
    pub fn list_after(&self, stream: &StreamRef, after: u64) -> Result<Vec<Listed>> {
        let Some(prefix) = stream.prefix() else {
            anyhow::bail!("{} stream without its epoch or recipient", stream.kind);
        };
        let start = format!("{prefix}{after:016}-9999.rec");
        let mut out: Vec<Listed> = Vec::new();
        for name in self.storage.list_after(&prefix, &start)? {
            let Some(n) = RecordName::parse_as(stream.kind, &name) else {
                continue;
            };
            if n.seq <= after || (stream.kind.scope_in_name() && n.scope != stream.scope) {
                continue;
            }
            match out.last_mut() {
                Some(l) if l.seq == n.seq => l.names.push(name),
                _ => out.push(Listed {
                    seq: n.seq,
                    names: vec![name],
                }),
            }
        }
        out.sort_by_key(|l| l.seq);
        Ok(out)
    }

    /// The highest seq of `stream` on this storage (0: none): a writer
    /// starts after it.
    pub fn highest_seq(&self, stream: &StreamRef) -> Result<u64> {
        Ok(self.list_after(stream, 0)?.last().map_or(0, |l| l.seq))
    }

    /// Fetch the parts of one listed record, each at most `MAX_PART_READ`
    /// bytes. A part that is gone is left out (the record is then
    /// incomplete); an oversize part is junk.
    pub fn fetch(&self, listed: &Listed) -> Result<std::result::Result<Parts, Refused>> {
        let mut out = Vec::with_capacity(listed.names.len());
        for name in &listed.names {
            match self.storage.get_bounded(name, MAX_PART_READ) {
                Ok(Some(b)) => out.push((name.clone(), b)),
                Ok(None) => {}
                Err(e) if e.downcast_ref::<TooLarge>().is_some() => {
                    return Ok(Err(refused(
                        name,
                        None,
                        RecordName::parse(name).as_ref(),
                        Refusal::Junk(Junk::OversizePart),
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Ok(out))
    }

    /// Fetch and accept one listed record. `Err` only for storage errors.
    pub fn read<T: RecordBody>(&self, listed: &Listed) -> Result<Outcome<T>> {
        Ok(match self.fetch(listed)? {
            Ok(parts) if parts.is_empty() => Outcome::Refused(Refused {
                name: listed.names.first().cloned().unwrap_or_default(),
                kind: None,
                seq: listed.seq,
                device: None,
                reason: Refusal::Incomplete { have: 0, parts: 0 },
            }),
            Ok(parts) => self.acceptor.accept(&parts),
            Err(r) => Outcome::Refused(r),
        })
    }

    /// Read every record of `stream` after `after`: accepted ones in seq
    /// order, waiting ones (at most `MAX_AHEAD`; the rest are not fetched),
    /// and refusals, which are noted in `counter`.
    pub fn read_after<T: RecordBody>(
        &self,
        stream: &StreamRef,
        after: u64,
        counter: &mut RecordsRefused,
    ) -> Result<StreamRead<T>> {
        let listed = self.list_after(stream, after)?;
        let mut out = StreamRead {
            accepted: Vec::new(),
            waiting: Vec::new(),
            refused: Vec::new(),
            dropped_ahead: 0,
        };
        for (i, l) in listed.iter().enumerate() {
            if out.waiting.len() >= MAX_AHEAD {
                out.dropped_ahead = listed.len() - i;
                break;
            }
            match self.read::<T>(l)? {
                Outcome::Accepted(r) => out.accepted.push(r),
                Outcome::Waiting(r) => out.waiting.push(r),
                Outcome::Refused(r) => {
                    counter.note(&r);
                    out.refused.push(r);
                }
            }
        }
        Ok(out)
    }
}
