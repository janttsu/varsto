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

/// Seals and writes records of one device.
pub(crate) struct Writer<'a> {
    pub vault: Id16,
    pub storages: &'a [&'a dyn Storage],
    pub device: Id16,
    pub key: &'a SigningKey,
}

impl Writer<'_> {
    /// The next free seq of `stream` over every storage.
    pub fn next_seq(&self, stream: &StreamRef) -> Result<u64> {
        let mut top = 0;
        for s in self.storages {
            let store = RecordStore {
                storage: *s,
                acceptor: Acceptor {
                    vault: self.vault,
                    keys: &NoKeys,
                    trust: &NoTrust,
                },
            };
            top = top.max(store.highest_seq(stream)?);
        }
        Ok(top + 1)
    }

    /// Seal `body` as record `seq` (the next free one when `None`) of
    /// `stream` and write it put-if-absent to every storage. The first
    /// storage decides: when the seq is taken there, nothing is written and
    /// the call fails. Returns the seq.
    pub fn write<T: Serialize>(
        &self,
        keys: &dyn RecordKeys,
        stream: &StreamRef,
        seq: Option<u64>,
        key_id: &KeyId,
        body: &T,
    ) -> Result<u64> {
        let Some(first) = self.storages.first() else {
            bail!("no storage to write the {} record to", stream.kind);
        };
        let seq = match seq {
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
        .seal(stream, seq, seq, key_id, body)?;
        for (name, bytes) in &sealed.parts {
            if !first.put_if_absent(name, bytes)? {
                return Err(anyhow!(
                    "{name} is already on {}: another device wrote it at the same time",
                    first.name()
                ));
            }
        }
        for s in &self.storages[1..] {
            for (name, bytes) in &sealed.parts {
                s.put_if_absent(name, bytes)?;
            }
        }
        Ok(seq)
    }
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
