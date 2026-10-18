// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Publishing a device's manifests of one folder as base + delta records
//! (section 7): what changed since the last record, when to write a base,
//! `prev` chaining, sealing through `RecordWriter`.

use super::record::{FileEntry, Header, ManifestBody};
use super::{stream, Hash32, Id16};
use crate::record::{KeyId, RecordWriter, SealedRecord};
use anyhow::{bail, Result};
use std::collections::BTreeMap;

/// When a record is a base (section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseRule {
    /// Records after a base before the size condition may make a base.
    pub min_deltas: u64,
    /// A base when the deltas since the base hold at least
    /// `base bytes / size_divisor`.
    pub size_divisor: u64,
    /// Records after a base at which a base is forced.
    pub max_deltas: u64,
}

impl Default for BaseRule {
    fn default() -> Self {
        BaseRule {
            min_deltas: 64,
            size_divisor: 16,
            max_deltas: 1024,
        }
    }
}

impl BaseRule {
    /// Whether the record `n` places after a base of `base_bytes` is a
    /// base, the `n - 1` deltas before it holding `delta_bytes`.
    pub fn is_base(&self, n: u64, base_bytes: u64, delta_bytes: u64) -> bool {
        n >= self.max_deltas
            || (n >= self.min_deltas && delta_bytes.saturating_mul(self.size_divisor) >= base_bytes)
    }
}

/// The writer side of one manifest stream: what the newest published
/// record says, and the counters of the base rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestWriter {
    pub folder: Id16,
    pub device: Id16,
    /// Seq of the newest published record (0: none yet).
    pub seq: u64,
    /// Seq of the newest base, and its stored bytes.
    pub base_seq: u64,
    pub base_bytes: u64,
    /// Stored bytes of the deltas after the base.
    pub delta_bytes: u64,
    /// `record_hash` of record `seq`.
    pub hash: Hash32,
    /// The next record must be a base (a seq was lost).
    pub force_base: bool,
    pub rule: BaseRule,
    /// The view as the newest record leaves it.
    pub published: BTreeMap<String, FileEntry>,
}

/// A sealed record not yet confirmed: `commit` it once its parts are on
/// every hot metadata storage and its `record_published` is in a batch.
#[derive(Clone, Debug)]
pub struct Pending {
    pub sealed: SealedRecord,
    pub is_base: bool,
    /// Entries in this record (all of them for a base).
    pub files: usize,
    pub removed: usize,
    view: BTreeMap<String, FileEntry>,
}

impl ManifestWriter {
    pub fn new(folder: Id16, device: Id16) -> ManifestWriter {
        ManifestWriter {
            folder,
            device,
            seq: 0,
            base_seq: 0,
            base_bytes: 0,
            delta_bytes: 0,
            hash: [0; 32],
            force_base: false,
            rule: BaseRule::default(),
            published: BTreeMap::new(),
        }
    }

    /// Continue after `seq`, the highest seq found on the storages, from a
    /// view this device holds of its own stream: the next record is a base.
    pub fn resume(&mut self, seq: u64) {
        if seq > self.seq {
            self.seq = seq;
            self.force_base = true;
        }
    }

    /// Seal the next record for `current` (the device's whole view), or
    /// `None` when nothing changed since the last record.
    pub fn seal(
        &self,
        rw: &RecordWriter,
        key: &KeyId,
        current: &BTreeMap<String, FileEntry>,
        lamport: u64,
        created_utc: i64,
    ) -> Result<Option<Pending>> {
        if rw.signer.device() != self.device {
            bail!("a device writes only its own manifests");
        }
        let changed: Vec<&FileEntry> = current
            .iter()
            .filter(|(p, e)| self.published.get(*p) != Some(*e))
            .map(|(_, e)| e)
            .collect();
        let removed: Vec<&str> = self
            .published
            .keys()
            .filter(|p| !current.contains_key(*p))
            .map(String::as_str)
            .collect();
        if self.seq > 0 && !self.force_base && changed.is_empty() && removed.is_empty() {
            return Ok(None);
        }
        let seq = self.seq + 1;
        let is_base = self.seq == 0
            || self.force_base
            || self.base_seq == 0
            || self
                .rule
                .is_base(seq - self.base_seq, self.base_bytes, self.delta_bytes);
        let h = Header {
            folder: self.folder,
            device: self.device,
            seq,
            lamport,
            created_utc,
            base: if is_base { seq } else { self.base_seq },
            prev: if seq == 1 { [0; 32] } else { self.hash },
        };
        let body = if is_base {
            ManifestBody::new(h, current.values(), [])
        } else {
            ManifestBody::new(h, changed.iter().copied(), removed.iter().copied())
        };
        let (files, n_removed) = (body.files.len(), body.removed.len());
        let sealed = rw.seal(&stream(self.folder, self.device), seq, h.base, key, &body)?;
        Ok(Some(Pending {
            sealed,
            is_base,
            files,
            removed: n_removed,
            view: current.clone(),
        }))
    }

    /// The record of `p` is published and announced.
    pub fn commit(&mut self, p: Pending) {
        let pb = &p.sealed.published;
        self.seq = pb.seq;
        self.hash = pb.body_hash;
        if p.is_base {
            self.base_seq = pb.seq;
            self.base_bytes = pb.size;
            self.delta_bytes = 0;
        } else {
            self.delta_bytes += pb.size;
        }
        self.force_base = false;
        self.published = p.view;
    }

    /// The seq of `p` could not be published (taken, or written half-way):
    /// skip it; the next record is a base.
    pub fn abandon(&mut self, p: Pending) {
        self.seq = self.seq.max(p.sealed.published.seq);
        // The base after it names no predecessor it cannot vouch for.
        self.hash = [0; 32];
        self.force_base = true;
    }
}
