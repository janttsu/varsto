// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The body of a format-3 `trash` record (section 7) and its entries.
//!
//! On the wire (postcard, then zstd, then the record envelope's padding and
//! AEAD, `crate::record::RecordWriter`):
//!
//! ```text
//! TrashBody { folder, device, seq, lamport, created_utc, base, prev,
//!             entries:  Vec<Entry>,     // deletions this device found
//!             removals: Vec<Removal>,   // entries (of any device) it restored or purged
//!             versions: Vec<Entry>,     // versions it replaced (the version history)
//!             forget:   Vec<[u8;16]> }  // delta only: ids it no longer lists
//! Entry   { id, path, size, mtime, content_hash, chunks, deleted_utc, deleted_by, clock, author }
//! Removal { id, utc, restored, deleted_utc, lamport }
//! ```

use super::{Hash32, Id16};
use crate::manifest3::{Chunk3, MAX_CHUNKS_PER_ENTRY, MAX_PATH};
use crate::record::{RecordBody, RecordMeta};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Most items (entries, removals, versions and forgotten ids together) in
/// one record, whatever its number of parts.
pub const MAX_ITEMS: usize = 4_194_304;

/// The largest block of a chunk (`crate::manifest::MAX_CHUNK_SIZE`).
const MAX_CHUNK_SIZE: u64 = crate::manifest::MAX_CHUNK_SIZE;

/// The id of an entry or a version: the first 16 bytes of BLAKE3 over a
/// fixed label, folder, path, the deleting (replacing) device and the
/// Lamport clock of the deletion (replacement).
pub fn entry_id(folder: &Id16, path: &str, device: &Id16, clock: u64) -> Id16 {
    let h = crate::crypto::hash(
        &[
            b"varsto-trash-entry".as_slice(),
            folder,
            &[0],
            path.as_bytes(),
            &[0],
            device,
            &clock.to_le_bytes(),
        ]
        .concat(),
    );
    h[..16].try_into().expect("16 bytes")
}

/// A deleted file version (section 43), or a replaced one (section 50): in
/// a version `deleted_utc` is when it was replaced, `deleted_by` the device
/// that replaced it and `clock` the clock of the new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Id16,
    pub path: String,
    pub size: u64,
    /// Modification time of the version (nanoseconds).
    pub mtime: i64,
    /// Keyed hash of the whole content.
    pub content_hash: Hash32,
    pub chunks: Vec<Chunk3>,
    pub deleted_utc: i64,
    pub deleted_by: Id16,
    pub clock: u64,
    /// The device that wrote the version (shown, not checked).
    pub author: Option<Id16>,
}

impl Entry {
    /// Build an entry with its id computed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        folder: &Id16,
        path: &str,
        size: u64,
        mtime: i64,
        content_hash: Hash32,
        chunks: Vec<Chunk3>,
        deleted_utc: i64,
        deleted_by: Id16,
        clock: u64,
        author: Option<Id16>,
    ) -> Entry {
        Entry {
            id: entry_id(folder, path, &deleted_by, clock),
            path: path.to_string(),
            size,
            mtime,
            content_hash,
            chunks,
            deleted_utc,
            deleted_by,
            clock,
            author,
        }
    }

    /// The object names this entry keeps alive.
    pub fn objects(&self) -> impl Iterator<Item = &Hash32> {
        self.chunks.iter().map(|c| &c.object)
    }

    /// What an honest device could have written: its own deletion, an id
    /// that recomputes, a path inside the folder, sizes that add up
    /// (section 43).
    pub fn validate(&self, folder: &Id16, writer: &Id16) -> Result<(), String> {
        if &self.deleted_by != writer {
            return Err(format!(
                "entry {} is not the deletion of its writer",
                hex::encode(self.id)
            ));
        }
        if self.id != entry_id(folder, &self.path, writer, self.clock) {
            return Err(format!("entry {} does not recompute", hex::encode(self.id)));
        }
        if self.path.len() > MAX_PATH {
            return Err(format!("a path of {} bytes", self.path.len()));
        }
        crate::names::check_synced_path(&self.path).map_err(|e| format!("{e:#}"))?;
        if self.chunks.len() > MAX_CHUNKS_PER_ENTRY {
            return Err(format!("entry with {} chunks", self.chunks.len()));
        }
        let mut total: u64 = 0;
        for c in &self.chunks {
            if c.size == 0 || c.size > MAX_CHUNK_SIZE {
                return Err(format!("a chunk of {} bytes", c.size));
            }
            total = total
                .checked_add(c.size)
                .ok_or_else(|| "entry overflows".to_string())?;
        }
        if total != self.size {
            return Err(format!(
                "entry {:?} says {} bytes but its chunks hold {total}",
                self.path, self.size
            ));
        }
        Ok(())
    }
}

/// A history entry has the shape of a trash entry.
pub type HistoryEntry = Entry;

/// An entry taken out of the trash by restoring or purging it. `lamport`
/// orders concurrent removals of one entry (section 43's merge rule).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removal {
    /// The entry's id.
    pub id: Id16,
    pub utc: i64,
    pub restored: bool,
    /// When the entry was deleted (decides when the removal is forgotten).
    pub deleted_utc: i64,
    pub lamport: u64,
}

/// The body of a `trash` record: a base (`base == seq`, the device's whole
/// record) or a delta (what was added since `seq - 1`, and ids forgotten).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub created_utc: i64,
    /// Seq of the base this record builds on; `== seq` for a base.
    pub base: u64,
    /// `record_hash` of record `seq - 1` of this stream (zeros for seq 1).
    pub prev: Hash32,
    pub entries: Vec<Entry>,
    pub removals: Vec<Removal>,
    pub versions: Vec<Entry>,
    /// Applied before the lists above: the writer no longer lists these ids
    /// (entries, removals and versions alike).
    pub forget: Vec<Id16>,
}

impl TrashBody {
    pub fn is_base(&self) -> bool {
        self.base == self.seq
    }

    /// Every check that does not need the envelope: shape of a base/delta,
    /// limits, unique ids per list, and the entry checks of section 43.
    pub fn validate(&self) -> Result<(), String> {
        if self.seq == 0 {
            return Err("seq 0".into());
        }
        if self.base > self.seq || self.base == 0 {
            return Err(format!("base {} for seq {}", self.base, self.seq));
        }
        if self.seq == 1 && self.prev != [0; 32] {
            return Err("seq 1 names a predecessor".into());
        }
        if self.is_base() && !self.forget.is_empty() {
            return Err("a base forgets ids".into());
        }
        let n = self.entries.len() + self.removals.len() + self.versions.len() + self.forget.len();
        if n > MAX_ITEMS {
            return Err(format!("{n} items, more than {MAX_ITEMS}"));
        }
        let mut seen: HashSet<&Id16> = HashSet::with_capacity(self.entries.len());
        for e in &self.entries {
            e.validate(&self.folder, &self.device)?;
            if !seen.insert(&e.id) {
                return Err("an entry appears twice".into());
            }
        }
        seen.clear();
        for e in &self.versions {
            e.validate(&self.folder, &self.device)?;
            if !seen.insert(&e.id) {
                return Err("a version appears twice".into());
            }
        }
        seen.clear();
        for r in &self.removals {
            if r.lamport > self.lamport {
                return Err("a removal from the future".into());
            }
            if !seen.insert(&r.id) {
                return Err("a removal appears twice".into());
            }
        }
        seen.clear();
        for id in &self.forget {
            if !seen.insert(id) {
                return Err("an id is forgotten twice".into());
            }
        }
        Ok(())
    }
}

impl RecordBody for TrashBody {
    fn base(&self) -> Option<u64> {
        Some(self.base)
    }
    fn prev(&self) -> Option<[u8; 32]> {
        Some(self.prev)
    }
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.folder != meta.scope {
            return Err("its folder is not the record's scope".into());
        }
        if self.device != meta.device {
            return Err("its device is not the record's writer".into());
        }
        if self.seq != meta.seq {
            return Err("its seq is not the record's".into());
        }
        self.validate()
    }
}
