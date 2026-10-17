// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The body of a `block-map` record (section 3, "Body") and its limits.

use serde::{Deserialize, Serialize};

use crate::ledger3::events::class_bytes;
use crate::ledger3::{DeviceBin, FolderBin, Hash32, ObjectBin, PackId, Place};
use crate::record::{RecordBody, RecordMeta};

/// Most entries and marks in one record part, and packs in one record.
/// A record of `p` parts holds at most `p` times the per-part numbers
/// (parts are byte ranges of one compressed body, so the limit is checked
/// over the whole record).
pub const MAX_ENTRIES_PER_PART: usize = 4_194_304;
pub const MAX_MARKS_PER_PART: usize = 1_048_576;
pub const MAX_PACKS: usize = 65_536;

/// `MapEntry::flags` bit 0: the writer's own settled view that the place
/// is dead (kept in bases until the place is collected). Other bits are 0.
pub const FLAG_DEAD: u8 = 1;

/// Shortest member object: a method byte, nonce and tag.
pub const MIN_OBJECT: u32 = 1 + crate::chunk_seal::OBJECT_OVERHEAD as u32;

/// A pack named by a record, referenced by its index in `packs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackRef {
    pub id: PackId,
    /// 0 = 256 KiB, 1 = 1 MiB, 2 = 4, 3 = 16, 4 = 64, 5 = 256 MiB.
    pub class: u8,
}

/// One place of a block: object `object` (chunk `chunk` sealed under
/// `epoch`) is `len` bytes at `offset` in `packs[pack]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MapEntry {
    pub object: ObjectBin,
    pub chunk: [u8; 32],
    pub pack: u32,
    pub offset: u32,
    /// Object length (packed length = `len - 40`).
    pub len: u32,
    /// Plaintext length (the chunk AAD needs both).
    pub plain_len: u32,
    pub epoch: u32,
    pub flags: u8,
}

/// The kind of a mark (`Mark::kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MarkKind {
    Dead = 1,
    Undead = 2,
    Lost = 3,
}

impl MarkKind {
    pub fn from_code(c: u8) -> Option<MarkKind> {
        match c {
            1 => Some(MarkKind::Dead),
            2 => Some(MarkKind::Undead),
            3 => Some(MarkKind::Lost),
            _ => None,
        }
    }
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// A dead, undead or lost mark on a place of any writer of the folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mark {
    pub object: ObjectBin,
    pub pack: PackId,
    pub offset: u32,
    /// 1 dead, 2 undead, 3 lost.
    pub kind: u8,
}

/// `BlockMap` of section 3: per folder, per writer device, sequence
/// numbered; a base lists every live place the writer wrote, a delta the
/// places added since `seq - 1`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMap {
    pub folder: FolderBin,
    pub device: DeviceBin,
    pub seq: u64,
    pub lamport: u64,
    /// The seq of the base this record builds on; `== seq` for a base.
    pub base: u64,
    /// `body_hash` of record `seq - 1` of this stream; zeros for seq 1.
    pub prev: Hash32,
    pub packs: Vec<PackRef>,
    pub entries: Vec<MapEntry>,
    pub marks: Vec<Mark>,
}

impl BlockMap {
    pub fn is_base(&self) -> bool {
        self.base == self.seq
    }

    /// The place of an entry (`None` when its pack index is out of range).
    pub fn place(&self, e: &MapEntry) -> Option<Place> {
        let p = self.packs.get(e.pack as usize)?;
        Some(Place {
            pack: p.id,
            offset: e.offset,
            len: e.len,
        })
    }

    /// Section 3's limits for a record of `parts` parts. Every number comes
    /// from another device: checked before any of it is used.
    pub fn check_limits(&self, parts: u16) -> Result<(), String> {
        let parts = usize::from(parts.max(1));
        if self.seq == 0 || self.base == 0 || self.base > self.seq {
            return Err(format!("base {} of record {}", self.base, self.seq));
        }
        if self.seq == 1 && self.prev != [0; 32] {
            return Err("the first record of a stream names a previous one".into());
        }
        if self.packs.len() > MAX_PACKS {
            return Err(format!("{} packs, more than {MAX_PACKS}", self.packs.len()));
        }
        if self.entries.len() > MAX_ENTRIES_PER_PART * parts {
            return Err(format!(
                "{} entries in {parts} parts, more than {MAX_ENTRIES_PER_PART} per part",
                self.entries.len()
            ));
        }
        if self.marks.len() > MAX_MARKS_PER_PART * parts {
            return Err(format!(
                "{} marks in {parts} parts, more than {MAX_MARKS_PER_PART} per part",
                self.marks.len()
            ));
        }
        for p in &self.packs {
            if class_bytes(p.class).is_none() {
                return Err(format!("pack {} has class {}", hex::encode(p.id), p.class));
            }
        }
        let max_plain = crate::manifest::MAX_CHUNK_SIZE;
        for e in &self.entries {
            let Some(p) = self.packs.get(e.pack as usize) else {
                return Err(format!(
                    "an entry names pack {} of {}",
                    e.pack,
                    self.packs.len()
                ));
            };
            let size = class_bytes(p.class).unwrap_or(0);
            if u64::from(e.offset) + u64::from(e.len) > size {
                return Err(format!(
                    "an entry at {} + {} passes the end of pack {} ({size} bytes)",
                    e.offset,
                    e.len,
                    hex::encode(p.id)
                ));
            }
            if e.len < MIN_OBJECT || u64::from(e.len) > crate::packs::MAX_OBJECT {
                return Err(format!("an entry of {} bytes", e.len));
            }
            if u64::from(e.plain_len) > max_plain {
                return Err(format!("an entry of {} plaintext bytes", e.plain_len));
            }
            if e.flags & !FLAG_DEAD != 0 {
                return Err(format!("entry flags {:#x}", e.flags));
            }
        }
        for m in &self.marks {
            if MarkKind::from_code(m.kind).is_none() {
                return Err(format!("mark kind {}", m.kind));
            }
        }
        Ok(())
    }
}

impl RecordBody for BlockMap {
    fn base(&self) -> Option<u64> {
        Some(self.base)
    }
    fn prev(&self) -> Option<[u8; 32]> {
        Some(self.prev)
    }
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.folder != meta.scope {
            return Err("the body names another folder than its envelope".into());
        }
        if self.device != meta.device {
            return Err("the body names another device than its envelope".into());
        }
        if self.seq != meta.seq {
            return Err("the body names another seq than its envelope".into());
        }
        self.check_limits(meta.parts)
    }
}
