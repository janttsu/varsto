// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Taking snapshots of a backup (section 7): each snapshot is a base (a
//! full listing) or a differential against the current base, never a
//! chain of increments. A new base is taken when the differential would
//! exceed a quarter of the base's stored size, or when 32 snapshots (the
//! base included) name the current base.

use super::record::{SnapHeader, SnapshotBody};
use super::{stream, Id16};
use crate::manifest3::FileEntry;
use crate::record::{KeyId, RecordWriter, SealedRecord};
use anyhow::{bail, Result};
use std::collections::BTreeMap;

/// When a snapshot is a base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapRule {
    /// Snapshots (the base included) that may name one base.
    pub max_on_base: u32,
    /// A differential whose stored size exceeds `base size / divisor` is
    /// taken as a new base instead.
    pub size_divisor: u64,
}

impl Default for SnapRule {
    fn default() -> Self {
        SnapRule {
            max_on_base: 32,
            size_divisor: 4,
        }
    }
}

fn pack(body: &SnapshotBody) -> Result<Vec<u8>> {
    let plain = postcard::to_stdvec(body)?;
    Ok(zstd::bulk::compress(&plain, 3)?)
}

/// The writer side of one snapshot stream (the source device of a backup).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotWriter {
    pub backup: Id16,
    pub device: Id16,
    /// Seq of the newest published snapshot (0: none yet).
    pub seq: u64,
    /// Seq of the current base and its packed bytes (0: none).
    pub base_seq: u64,
    pub base_bytes: u64,
    /// Snapshots naming the current base, the base itself included.
    pub on_base: u32,
    /// The current base's listing.
    pub base_files: BTreeMap<String, FileEntry>,
    /// The next snapshot must be a base (a seq was lost, or the writer
    /// restarted without the base's listing).
    pub force_base: bool,
    pub rule: SnapRule,
}

/// A sealed snapshot not yet confirmed: `commit` it once its parts are on
/// every metadata storage and its `record_published` and `snapshot_taken`
/// are in a batch.
#[derive(Clone, Debug)]
pub struct Pending {
    pub sealed: SealedRecord,
    pub is_base: bool,
    /// Bytes of the body before padding (zstd of postcard).
    pub packed: u64,
    /// Entries in this record (all of them for a base).
    pub files: usize,
    pub removed: usize,
    listing: BTreeMap<String, FileEntry>,
}

impl SnapshotWriter {
    pub fn new(backup: Id16, device: Id16) -> SnapshotWriter {
        SnapshotWriter {
            backup,
            device,
            seq: 0,
            base_seq: 0,
            base_bytes: 0,
            on_base: 0,
            base_files: BTreeMap::new(),
            force_base: false,
            rule: SnapRule::default(),
        }
    }

    /// Continue after `seq`, the highest seq found on the storages: the
    /// next snapshot is a base.
    pub fn resume(&mut self, seq: u64) {
        if seq > self.seq {
            self.seq = seq;
            self.force_base = true;
        }
    }

    /// Seal the next snapshot for `current`, the backup's live files now.
    pub fn seal(
        &self,
        rw: &RecordWriter,
        key: &KeyId,
        current: &BTreeMap<String, FileEntry>,
        lamport: u64,
        taken_utc: i64,
        expires_utc: i64,
    ) -> Result<Pending> {
        if rw.signer.device() != self.device {
            bail!("a device writes only its own snapshots");
        }
        if current.values().any(|f| f.deleted || f.held) {
            bail!("a snapshot lists live files that no device holds");
        }
        let seq = self.seq + 1;
        let s = stream(self.backup, self.device);
        let head = |base| SnapHeader {
            backup: self.backup,
            device: self.device,
            seq,
            lamport,
            taken_utc,
            expires_utc,
            base,
        };
        let need_base =
            self.base_seq == 0 || self.force_base || self.on_base >= self.rule.max_on_base;
        if !need_base {
            let changed: Vec<&FileEntry> = current
                .iter()
                .filter(|(p, e)| self.base_files.get(*p) != Some(*e))
                .map(|(_, e)| e)
                .collect();
            let removed: Vec<&str> = self
                .base_files
                .keys()
                .filter(|p| !current.contains_key(*p))
                .map(String::as_str)
                .collect();
            let body = SnapshotBody::new(
                head(self.base_seq),
                changed.iter().copied(),
                removed.iter().copied(),
            );
            let packed = pack(&body)?;
            // Compared before padding: padding is a multiple of 64 KiB and
            // would make every small snapshot a base.
            if (packed.len() as u64).saturating_mul(self.rule.size_divisor) <= self.base_bytes {
                let sealed = rw.seal_compressed(&s, seq, self.base_seq, key, &packed)?;
                return Ok(Pending {
                    sealed,
                    is_base: false,
                    packed: packed.len() as u64,
                    files: body.files.len(),
                    removed: body.removed.len(),
                    listing: BTreeMap::new(),
                });
            }
        }
        let body = SnapshotBody::new(head(seq), current.values(), []);
        let packed = pack(&body)?;
        let sealed = rw.seal_compressed(&s, seq, seq, key, &packed)?;
        Ok(Pending {
            sealed,
            is_base: true,
            packed: packed.len() as u64,
            files: body.files.len(),
            removed: 0,
            listing: current.clone(),
        })
    }

    /// The snapshot of `p` is published and announced.
    pub fn commit(&mut self, p: Pending) {
        let pb = &p.sealed.published;
        self.seq = pb.seq;
        if p.is_base {
            self.base_seq = pb.seq;
            self.base_bytes = p.packed;
            self.on_base = 1;
            self.base_files = p.listing;
        } else {
            self.on_base += 1;
        }
        self.force_base = false;
    }

    /// The seq of `p` could not be published (taken, or written half-way):
    /// skip it (a sequence number an interrupted attempt wrote is skipped,
    /// section 31). Differentials do not chain, so the next one may still
    /// name the same base.
    pub fn abandon(&mut self, p: Pending) {
        self.seq = self.seq.max(p.sealed.published.seq);
    }
}
