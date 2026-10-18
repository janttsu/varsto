// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Publishing a device's trash record of one folder as base + delta records
//! (section 7): what changed since the last record, when to write a base
//! (the manifests' rule: `crate::manifest3::BaseRule`), `prev` chaining,
//! sealing through `RecordWriter`.

use super::record::TrashBody;
use super::state::TrashSnapshot;
use super::{stream, Hash32, Id16};
use crate::manifest3::BaseRule;
use crate::record::{KeyId, RecordWriter, SealedRecord};
use anyhow::{bail, Result};

/// The writer side of one trash stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashWriter {
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
    /// The state as the newest record leaves it.
    pub published: TrashSnapshot,
}

/// A sealed record not yet confirmed: `commit` it once its parts are on
/// every hot metadata storage and its `record_published` is in a batch.
#[derive(Clone, Debug)]
pub struct Pending {
    pub sealed: SealedRecord,
    pub is_base: bool,
    /// Items in this record (all of them for a base).
    pub items: usize,
    state: TrashSnapshot,
}

impl TrashWriter {
    pub fn new(folder: Id16, device: Id16) -> TrashWriter {
        TrashWriter {
            folder,
            device,
            seq: 0,
            base_seq: 0,
            base_bytes: 0,
            delta_bytes: 0,
            hash: [0; 32],
            force_base: false,
            rule: BaseRule::default(),
            published: TrashSnapshot::default(),
        }
    }

    /// Continue after `seq`, the highest seq found on the storages: the
    /// next record is a base.
    pub fn resume(&mut self, seq: u64) {
        if seq > self.seq {
            self.seq = seq;
            self.force_base = true;
        }
    }

    /// Seal the next record for `current` (the device's whole record), or
    /// `None` when nothing changed since the last one.
    pub fn seal(
        &self,
        rw: &RecordWriter,
        key: &KeyId,
        current: &TrashSnapshot,
        lamport: u64,
        created_utc: i64,
    ) -> Result<Option<Pending>> {
        if rw.signer.device() != self.device {
            bail!("a device writes only its own trash records");
        }
        let delta = self.published.diff_to(current);
        if self.seq > 0 && !self.force_base && delta.is_empty() {
            return Ok(None);
        }
        let seq = self.seq + 1;
        let is_base = self.seq == 0
            || self.force_base
            || self.base_seq == 0
            || self
                .rule
                .is_base(seq - self.base_seq, self.base_bytes, self.delta_bytes);
        let base = if is_base { seq } else { self.base_seq };
        let mut body = TrashBody {
            folder: self.folder,
            device: self.device,
            seq,
            lamport,
            created_utc,
            base,
            prev: if seq == 1 { [0; 32] } else { self.hash },
            entries: Vec::new(),
            removals: Vec::new(),
            versions: Vec::new(),
            forget: Vec::new(),
        };
        if is_base {
            body.entries = current.entries.values().cloned().collect();
            body.removals = current.removals.values().cloned().collect();
            body.versions = current.versions.values().cloned().collect();
        } else {
            body.entries = delta.entries;
            body.removals = delta.removals;
            body.versions = delta.versions;
            body.forget = delta.forget;
        }
        let items = body.entries.len() + body.removals.len() + body.versions.len();
        let sealed = rw.seal(&stream(self.folder, self.device), seq, base, key, &body)?;
        Ok(Some(Pending {
            sealed,
            is_base,
            items,
            state: current.clone(),
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
        self.published = p.state;
    }

    /// The seq of `p` could not be published (taken, or written half-way):
    /// skip it; the next record is a base.
    pub fn abandon(&mut self, p: Pending) {
        self.seq = self.seq.max(p.sealed.published.seq);
        self.hash = [0; 32];
        self.force_base = true;
    }
}
