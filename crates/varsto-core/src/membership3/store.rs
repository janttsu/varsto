// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Reading and writing membership records on every metadata storage.

use crate::crypto::{SigningKey, VerifyingKey};
use crate::record::{
    record_hash, Acceptor, DeviceSigner, Id16, KeyId, Kind, Outcome, Parts, Record, RecordBody,
    RecordKeys, RecordName, RecordStore, RecordTrust, RecordWriter, RecordsRefused, SignedRecord,
    StreamRef, MAX_PART_READ,
};
use crate::storage::Storage;
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

/// The stream a parsed record name belongs to.
fn stream_of(n: &RecordName) -> StreamRef {
    StreamRef {
        kind: n.kind,
        scope: n.scope,
        // Kinds named without a device (epochs) list one "stream" per
        // number; the device is checked from the envelope.
        device: n.device.unwrap_or([0u8; 16]),
        epoch: n.epoch,
        recipient: n.recipient,
    }
}

/// Every stream of `kind` with a name under `prefix` on one storage, in
/// name order.
pub(crate) fn streams(storage: &dyn Storage, kind: Kind, prefix: &str) -> Result<Vec<StreamRef>> {
    let mut seen = HashSet::new();
    let mut out: Vec<(String, StreamRef)> = Vec::new();
    for name in storage.list(prefix)? {
        let Some(n) = RecordName::parse_as(kind, &name) else {
            continue;
        };
        let s = stream_of(&n);
        if let Some(p) = s.prefix() {
            if seen.insert(p.clone()) {
                out.push((p, s));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out.into_iter().map(|(_, s)| s).collect())
}

/// The accepted records of `kind` under `prefix` on every storage, each
/// record once (by stream, seq and hash). Refusals are counted.
pub(crate) fn read_all<T: RecordBody>(
    storages: &[&dyn Storage],
    vault: Id16,
    kind: Kind,
    prefix: &str,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    counter: &mut RecordsRefused,
) -> Result<Vec<Record<T>>> {
    read_where(
        storages,
        vault,
        kind,
        prefix,
        &|_| true,
        keys,
        trust,
        counter,
    )
}

/// `read_all` over the streams `wanted` picks (grants to this device,
/// say: the others do not open here and are not junk).
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_where<T: RecordBody>(
    storages: &[&dyn Storage],
    vault: Id16,
    kind: Kind,
    prefix: &str,
    wanted: &dyn Fn(&StreamRef) -> bool,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    counter: &mut RecordsRefused,
) -> Result<Vec<Record<T>>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for storage in storages {
        let store = RecordStore {
            storage: *storage,
            acceptor: Acceptor { vault, keys, trust },
        };
        for stream in streams(*storage, kind, prefix)? {
            if !kind.device_in_name() || !wanted(&stream) {
                // Numbered streams (epochs): one record per number, read
                // by `envelopes`, not here.
                continue;
            }
            let read = store.read_after::<T>(&stream, 0, counter)?;
            for r in read.accepted {
                let id = (stream.prefix(), r.meta.seq, r.meta.body_hash);
                if seen.insert(id) {
                    out.push(r);
                }
            }
        }
    }
    Ok(out)
}

/// One record under a number of a numbered stream (vault and folder
/// epochs), as one storage holds it.
pub(crate) struct Numbered {
    pub device: Id16,
    /// `record_hash` of the parts.
    pub hash: [u8; 32],
    pub parts: Parts,
}

/// The records under the numbers of a numbered stream (`prefix` is the
/// stream prefix, e.g. `vault/folder-epochs/<folder>/`) on every storage,
/// envelope only: a record whose envelope does not decode, whose parts do
/// not agree, or whose signature does not verify against `signer` is left
/// out. Several different records under one number are all returned.
pub(crate) fn numbered(
    storages: &[&dyn Storage],
    vault: Id16,
    kind: Kind,
    prefix: &str,
    signer: &dyn Fn(&Id16) -> Option<VerifyingKey>,
) -> Result<BTreeMap<u64, Vec<Numbered>>> {
    let mut out: BTreeMap<u64, Vec<Numbered>> = BTreeMap::new();
    for storage in storages {
        let mut by_seq: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for name in storage.list(prefix)? {
            if let Some(n) = RecordName::parse_as(kind, &name) {
                by_seq.entry(n.seq).or_default().push(name);
            }
        }
        for (seq, names) in by_seq {
            let mut parts = Vec::new();
            for name in &names {
                if let Ok(Some(b)) = storage.get_bounded(name, MAX_PART_READ) {
                    parts.push((name.clone(), b));
                }
            }
            let mut envs = Vec::new();
            for (_, b) in &parts {
                match SignedRecord::decode(b) {
                    Ok(e) if e.vault == vault && e.seq == seq && e.kind == kind.code() => {
                        envs.push(e)
                    }
                    _ => {}
                }
            }
            envs.sort_by_key(|e| e.part);
            let Some(e0) = envs.first() else { continue };
            let complete = envs.len() == usize::from(e0.parts)
                && envs.iter().enumerate().all(|(i, e)| {
                    usize::from(e.part) == i && e.device == e0.device && e.parts == e0.parts
                });
            if !complete {
                continue;
            }
            let Some(pk) = signer(&e0.device) else {
                continue;
            };
            if envs.iter().any(|e| e.verify(&pk).is_err()) {
                continue;
            }
            let hash = record_hash(envs.iter().map(|e| &e.body_hash));
            let device = e0.device;
            let list = out.entry(seq).or_default();
            if !list.iter().any(|n| n.device == device && n.hash == hash) {
                list.push(Numbered {
                    device,
                    hash,
                    parts,
                });
            }
        }
    }
    Ok(out)
}

/// Accept one numbered record with the full rule.
pub(crate) fn accept_numbered<T: RecordBody>(
    vault: Id16,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    n: &Numbered,
    counter: &mut RecordsRefused,
) -> Option<Record<T>> {
    match (Acceptor { vault, keys, trust }).accept::<T>(&n.parts) {
        Outcome::Accepted(r) => Some(r),
        Outcome::Waiting(_) => None,
        Outcome::Refused(r) => {
            counter.note(&r);
            None
        }
    }
}

/// This device's own copy of the membership records. `mirror` holds every
/// record it read or wrote and is read together with the storages; `outbox`
/// holds the records a storage still lacks, until [`flush_outbox`] has put
/// them on every storage.
///
/// `partial`: some storages of the vault are not among the ones written to
/// (down or resting in this run): a record written now stays in the
/// outbox for them even when every storage given took it.
#[derive(Clone, Copy)]
pub struct Local<'a> {
    pub mirror: &'a dyn Storage,
    pub outbox: &'a dyn Storage,
    pub partial: bool,
}

/// A record name that the storage which decides already holds: another
/// device (or another process of this one) wrote that number first.
#[derive(Debug)]
pub struct Taken {
    pub name: String,
    pub on: String,
}

impl std::fmt::Display for Taken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is already on {}: another device wrote it at the same time",
            self.name, self.on
        )
    }
}

impl std::error::Error for Taken {}

/// What putting the parts of one sealed record on one storage gave.
enum Put {
    Written,
    /// The first part is there already (another record under the name).
    Taken,
    Failed(anyhow::Error),
}

fn put_parts(s: &dyn Storage, parts: &[(String, Vec<u8>)]) -> Put {
    for (i, (name, bytes)) in parts.iter().enumerate() {
        match s.put_if_absent(name, bytes) {
            Ok(true) => {}
            Ok(false) if i == 0 => return Put::Taken,
            // A later part left by an earlier try of the same record.
            Ok(false) => {}
            Err(e) => return Put::Failed(e),
        }
    }
    Put::Written
}

/// Seals and writes records of one device.
///
/// A record whose name carries its device (every kind but the vault and
/// folder epochs) belongs to this device alone: with a [`Local`] copy it is
/// kept there first (the local copy decides its seq), then put on every
/// storage that answers; a storage that does not answer gets it later from
/// the outbox. A numbered record (vault and folder epochs) is decided by
/// the first storage that answers, as put-if-absent at its number; with no
/// storage answering it is not written. A storage that is down never fails
/// a write that another storage (or the local copy) took.
pub(crate) struct Writer<'a> {
    pub vault: Id16,
    pub storages: &'a [&'a dyn Storage],
    pub local: Option<Local<'a>>,
    pub device: Id16,
    pub key: &'a SigningKey,
}

impl Writer<'_> {
    /// The next free seq of `stream` over every storage that answers and
    /// the local copy. Fails only when nothing answered.
    pub fn next_seq(&self, stream: &StreamRef) -> Result<u64> {
        let mut top = 0;
        let mut answered = false;
        let mut last_err = None;
        let local = self.local.iter().flat_map(|l| [l.mirror, l.outbox]);
        for s in self.storages.iter().copied().chain(local) {
            let store = RecordStore {
                storage: s,
                acceptor: Acceptor {
                    vault: self.vault,
                    keys: &NoKeys,
                    trust: &NoTrust,
                },
            };
            match store.highest_seq(stream) {
                Ok(h) => {
                    top = top.max(h);
                    answered = true;
                }
                Err(e) => {
                    log::warn!("{} records not listed on {}: {e:#}", stream.kind, s.name());
                    last_err = Some(e);
                }
            }
        }
        if !answered {
            let e = last_err.unwrap_or_else(|| anyhow!("no storage"));
            return Err(e.context(format!(
                "no storage could be read to number the {} record",
                stream.kind
            )));
        }
        Ok(top + 1)
    }

    /// Seal `body` as record `seq` (the next free one when `None`) of
    /// `stream` and write it put-if-absent (see [`Writer`] for who
    /// decides). When the decider holds another record under the name, a
    /// given `seq` fails with [`Taken`]; a free one is tried again with the
    /// next number. Returns the seq.
    pub fn write<T: Serialize>(
        &self,
        keys: &dyn RecordKeys,
        stream: &StreamRef,
        seq: Option<u64>,
        key_id: &KeyId,
        body: &T,
    ) -> Result<u64> {
        if self.storages.is_empty() && self.local.is_none() {
            bail!("no storage to write the {} record to", stream.kind);
        }
        let mut tries = 0;
        loop {
            let at = match seq {
                Some(s) => s,
                None => self.next_seq(stream)?,
            };
            let signer = DeviceSigner {
                device: self.device,
                key: self.key,
            };
            let sealed = RecordWriter {
                vault: self.vault,
                signer: &signer,
                keys,
            }
            .seal(stream, at, at, key_id, body)?;
            let Some(on) = self.place(stream, &sealed.parts)? else {
                return Ok(at);
            };
            tries += 1;
            if seq.is_some() || tries >= 3 {
                let name = sealed
                    .parts
                    .first()
                    .map(|p| p.0.clone())
                    .unwrap_or_default();
                return Err(anyhow::Error::new(Taken { name, on }));
            }
        }
    }

    /// Put one sealed record: `None` once placed, `Some(storage)` when the
    /// decider holds another record under its name (then nothing of it is
    /// kept here).
    fn place(&self, stream: &StreamRef, parts: &[(String, Vec<u8>)]) -> Result<Option<String>> {
        let own = stream.kind.device_in_name();
        let local = self.local.filter(|_| own);
        if let Some(l) = local {
            match put_parts(l.mirror, parts) {
                Put::Written => {}
                Put::Taken => return Ok(Some(l.mirror.name().to_string())),
                Put::Failed(e) => return Err(e.context("keep the record on this device")),
            }
            if let Put::Failed(e) = put_parts(l.outbox, parts) {
                forget(l, parts);
                return Err(e.context("keep the record for the storages on this device"));
            }
        }
        let mut answered = false;
        // No storage to write to (offline), or one of the vault's storages
        // left out of the list: the record waits for them in the outbox.
        let mut missing = self.storages.is_empty() || self.local.is_some_and(|l| l.partial);
        let mut last_err = None;
        for s in self.storages {
            match put_parts(*s, parts) {
                Put::Written => answered = true,
                // The first storage that answers decides.
                Put::Taken if !answered => {
                    if let Some(l) = local {
                        forget(l, parts);
                    }
                    return Ok(Some(s.name().to_string()));
                }
                // A later storage holding something under the name decides
                // nothing (readers see both, as before).
                Put::Taken => {}
                Put::Failed(e) => {
                    log::warn!(
                        "{} record not written to {} (it waits on this device): {e:#}",
                        stream.kind,
                        s.name()
                    );
                    missing = true;
                    last_err = Some(e);
                }
            }
        }
        if !answered && local.is_none() {
            // Nothing holds the record: a numbered one needs a storage that
            // takes its number now.
            let e = last_err.unwrap_or_else(|| anyhow!("no storage"));
            return Err(e.context(format!(
                "no storage took the {} record: it needs a storage that answers now; try again when one is reachable",
                stream.kind
            )));
        }
        match (self.local, own) {
            (Some(l), false) => {
                // A numbered record the decider took: kept here too, and in
                // the outbox for the storages that did not answer.
                if let Put::Failed(e) = put_parts(l.mirror, parts) {
                    log::debug!("{} record not kept locally: {e:#}", stream.kind);
                }
                if missing {
                    if let Put::Failed(e) = put_parts(l.outbox, parts) {
                        log::warn!("{} record not kept for the storages: {e:#}", stream.kind);
                    }
                }
            }
            (Some(l), true) if !missing => {
                // Every storage has it: nothing waits.
                for (name, _) in parts {
                    let _ = l.outbox.delete(name);
                }
            }
            (None, _) if missing => {
                log::warn!(
                    "a {} record is missing on a storage and this device keeps no copy for it",
                    stream.kind
                );
            }
            _ => {}
        }
        Ok(None)
    }
}

/// Take a record that was not placed back out of the local copy.
fn forget(l: Local<'_>, parts: &[(String, Vec<u8>)]) {
    for (name, _) in parts {
        let _ = l.mirror.delete(name);
        let _ = l.outbox.delete(name);
    }
}

/// What [`flush_outbox`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Records every storage holds now (taken out of the outbox).
    pub sent: usize,
    /// Records that still wait for a storage that did not answer.
    pub waiting: usize,
    /// Records a storage holds a different record under the name of: they
    /// cannot reach that storage (taken out of the outbox).
    pub conflicts: usize,
}

/// The records of an outbox: the names of each record's parts, by record.
fn outbox_records(outbox: &dyn Storage) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in outbox.list("vault/")? {
        if RecordName::parse(&name).is_none() {
            continue;
        }
        let record = name
            .rsplit_once('-')
            .map(|(r, _)| r.to_string())
            .unwrap_or_else(|| name.clone());
        out.entry(record).or_default().push(name);
    }
    Ok(out)
}

/// How many records wait in `outbox` for a storage.
pub fn outbox_waiting(outbox: &dyn Storage) -> Result<usize> {
    Ok(outbox_records(outbox)?.len())
}

/// Put one record's parts on a storage: true when it holds them (written
/// now or before), false when it holds another record under the name.
fn send(s: &dyn Storage, parts: &[(String, Vec<u8>)]) -> Result<bool> {
    for (name, bytes) in parts {
        if s.put_if_absent(name, bytes)? {
            continue;
        }
        match s.get_bounded(name, MAX_PART_READ)? {
            Some(have) if have == *bytes => {}
            Some(_) => return Ok(false),
            // Gone between the two calls: try once more.
            None => {
                if !s.put_if_absent(name, bytes)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Put every record of `outbox` on every storage, put-if-absent; a record
/// leaves the outbox once every storage holds it. A storage that fails is
/// left out for the rest of this flush (its records wait for the next one).
/// Nothing here fails because a storage is down; an error is a local one.
pub fn flush_outbox(outbox: &dyn Storage, storages: &[&dyn Storage]) -> Result<Flushed> {
    flush_outbox_to(outbox, storages, false)
}

/// [`flush_outbox`]; with `partial` (some storages of the vault are not in
/// `storages`: down or resting) the records are put where they can be and
/// all stay in the outbox for the others.
pub fn flush_outbox_to(
    outbox: &dyn Storage,
    storages: &[&dyn Storage],
    partial: bool,
) -> Result<Flushed> {
    let records = outbox_records(outbox)?;
    let mut out = Flushed::default();
    if storages.is_empty() {
        out.waiting = records.len();
        return Ok(out);
    }
    let mut down = vec![false; storages.len()];
    for (record, names) in records {
        let mut parts = Vec::with_capacity(names.len());
        for n in &names {
            if let Some(b) = outbox.get(n)? {
                parts.push((n.clone(), b));
            }
        }
        let mut all = !partial;
        let mut conflict = false;
        for (i, s) in storages.iter().enumerate() {
            if down[i] {
                all = false;
                continue;
            }
            match send(*s, &parts) {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!(
                        "{record} cannot be uploaded to {}: it holds another record under that name",
                        s.name()
                    );
                    conflict = true;
                }
                Err(e) => {
                    log::warn!(
                        "{} did not answer; records wait on this device: {e:#}",
                        s.name()
                    );
                    down[i] = true;
                    all = false;
                }
            }
        }
        if !all {
            out.waiting += 1;
            continue;
        }
        for n in &names {
            outbox.delete(n)?;
        }
        if conflict {
            out.conflicts += 1;
        } else {
            out.sent += 1;
        }
    }
    Ok(out)
}

/// No keys (listing only).
pub(crate) struct NoKeys;
impl RecordKeys for NoKeys {
    fn symmetric(&self, _: &KeyId) -> Option<crate::crypto::SecretKey> {
        None
    }
}

/// No trust (listing only).
pub(crate) struct NoTrust;
impl RecordTrust for NoTrust {
    fn signer_key(&self, _: &Id16, _: Kind, _: &Id16) -> Option<VerifyingKey> {
        None
    }
    fn may_write(&self, _: &Id16, _: Kind, _: &Id16, _: &KeyId) -> bool {
        false
    }
}
