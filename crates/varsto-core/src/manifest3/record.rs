// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The body of a format-3 `manifest` record (section 7) and its entries.
//!
//! On the wire (postcard, then zstd, then the record envelope's padding and
//! AEAD, `crate::record::RecordWriter`):
//!
//! ```text
//! ManifestBody { folder, device, seq, lamport, created_utc, base, prev,
//!                devices: Vec<[16]>,          // interned ids of version vectors and modified_by
//!                files: Vec<WireEntry>,       // base: the whole view; delta: entries changed since seq-1
//!                removed: Vec<path bytes> }   // delta only: paths that left the view
//! WireEntry { path: bytes, version: Vec<(u32 index, u64)>, deleted, size, mtime,
//!             content_hash: Option<[32]>, chunks: Vec<Chunk3>, modified_by: u32 index,
//!             modified_clock, meta: Option<WireMeta>, chunking: u8, held: bool }
//! Chunk3 { chunk: [32], object: [32], size: u64, epoch: u32 }
//! ```

use super::{Hash32, Id16};
use crate::fsmeta::{FileMeta, Owner};
use crate::manifest::{ChunkRef, FileState, MAX_CHUNK_SIZE};
use crate::record::{RecordBody, RecordMeta};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Longest path, in bytes.
pub const MAX_PATH: usize = 4096;
/// Most entries (files plus removed paths) in one record, whatever its
/// number of parts.
pub const MAX_ENTRIES: usize = 4_194_304;
/// Most chunks of one entry (16 TiB of 16 MiB blocks; a 1 TiB file of
/// 1 MiB blocks has 2^20).
pub const MAX_CHUNKS_PER_ENTRY: usize = 1 << 20;
/// Most devices in one record's id table, and in one version vector.
pub const MAX_VV: usize = 65_536;

/// One block of a file version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Chunk3 {
    /// Keyed hash of the plaintext (K11).
    pub chunk: Hash32,
    /// BLAKE3 of the chunk object (the name a block map finds).
    pub object: Hash32,
    /// Plaintext bytes.
    pub size: u64,
    /// Folder key epoch the chunk is sealed under.
    pub epoch: u32,
}

/// One file of a device's view (format 2's `FileState` plus `held`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub version: BTreeMap<Id16, u64>,
    pub deleted: bool,
    pub size: u64,
    /// Nanoseconds since the Unix epoch (change detection only).
    pub mtime: i64,
    /// Keyed hash of the whole content; `None` when deleted.
    pub content_hash: Option<Hash32>,
    pub chunks: Vec<Chunk3>,
    pub modified_by: Id16,
    pub modified_clock: u64,
    /// Section 49's metadata (permissions, link target, xattrs, owner).
    pub meta: Option<FileMeta>,
    /// How the chunks were cut (`FileState::chunking`).
    pub chunking: u8,
    /// This writer holds every block of this version (the file on disk,
    /// or every block in its block cache). Section 4.
    pub held: bool,
}

impl FileEntry {
    /// Same content and metadata (what a merge treats as "the same file").
    pub fn same_as(&self, other: &FileEntry) -> bool {
        self.deleted == other.deleted
            && self.content_hash == other.content_hash
            && self.meta == other.meta
    }

    /// The object names this entry references: none when deleted.
    pub fn objects(&self) -> impl Iterator<Item = &Hash32> {
        self.chunks
            .iter()
            .filter(|_| !self.deleted)
            .map(|c| &c.object)
    }

    /// From a format-2 `FileState` (the engine's folder state), with this
    /// device's `held` flag. Ids and hashes must have the format-3 widths.
    pub fn from_state(f: &FileState, held: bool) -> Result<FileEntry> {
        let id16 = |id: &crate::ids::Id| -> Result<Id16> {
            id.as_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("device id {id} is not 16 bytes"))
        };
        let h32 = |id: &crate::ids::Id| -> Result<Hash32> {
            id.as_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("hash {id} is not 32 bytes"))
        };
        let content_hash = if f.content_hash.is_empty() {
            None
        } else {
            let b = hex::decode(&f.content_hash)?;
            Some(
                b.as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("content hash of {} is not 32 bytes", f.path))?,
            )
        };
        Ok(FileEntry {
            path: f.path.clone(),
            version: f
                .version
                .iter()
                .map(|(d, c)| Ok((id16(d)?, *c)))
                .collect::<Result<_>>()?,
            deleted: f.deleted,
            size: f.size,
            mtime: f.mtime,
            content_hash,
            chunks: f
                .chunks
                .iter()
                .map(|c| {
                    Ok(Chunk3 {
                        chunk: h32(&c.chunk)?,
                        object: h32(&c.object)?,
                        size: c.size,
                        epoch: c.epoch,
                    })
                })
                .collect::<Result<_>>()?,
            modified_by: id16(&f.modified_by)?,
            modified_clock: f.modified_clock,
            meta: f.meta.clone(),
            chunking: f.chunking,
            held,
        })
    }

    /// Back to a format-2 `FileState` (the `held` flag is dropped).
    pub fn to_state(&self) -> FileState {
        let id = crate::ids::Id::from_bytes;
        FileState {
            path: self.path.clone(),
            version: self.version.iter().map(|(d, c)| (id(d), *c)).collect(),
            deleted: self.deleted,
            size: self.size,
            mtime: self.mtime,
            content_hash: self.content_hash.map(hex::encode).unwrap_or_default(),
            chunks: self
                .chunks
                .iter()
                .map(|c| ChunkRef {
                    chunk: id(&c.chunk),
                    object: id(&c.object),
                    size: c.size,
                    epoch: c.epoch,
                })
                .collect(),
            modified_by: id(&self.modified_by),
            modified_clock: self.modified_clock,
            meta: self.meta.clone(),
            chunking: self.chunking,
        }
    }

    /// The checks of `manifest::validate_files` for one entry, plus the
    /// format-3 limits.
    pub fn validate(&self) -> Result<()> {
        let p = &self.path;
        if p.len() > MAX_PATH {
            bail!("a path of {} bytes, more than {MAX_PATH}", p.len());
        }
        crate::names::check_synced_path(p)?;
        if self.version.len() > MAX_VV {
            bail!(
                "entry {p:?} has a version vector of {} devices",
                self.version.len()
            );
        }
        if self.chunks.len() > MAX_CHUNKS_PER_ENTRY {
            bail!("entry {p:?} has {} chunks", self.chunks.len());
        }
        if self.deleted {
            return Ok(());
        }
        if let Some(m) = &self.meta {
            m.validate().map_err(|e| anyhow!("entry {p:?}: {e}"))?;
            if m.symlink.is_some() && (self.size != 0 || !self.chunks.is_empty()) {
                bail!("entry {p:?} is a link with content");
            }
        }
        let mut total: u64 = 0;
        for c in &self.chunks {
            if c.size == 0 || c.size > MAX_CHUNK_SIZE {
                bail!("entry {p:?} has a chunk of {} bytes", c.size);
            }
            total = total
                .checked_add(c.size)
                .ok_or_else(|| anyhow!("entry {p:?} overflows"))?;
        }
        if total != self.size {
            bail!(
                "entry {p:?} says {} bytes but its chunks hold {total}",
                self.size
            );
        }
        Ok(())
    }
}

/// `FileMeta` without format 2's skipped fields (postcard is not
/// self-describing, so every field is always written).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMeta {
    pub v: u8,
    pub mode: Option<u32>,
    pub symlink: Option<String>,
    pub xattrs: Option<Vec<(String, String)>>,
    pub owner: Option<WireOwner>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireOwner {
    pub uid: u32,
    pub gid: u32,
    pub user: Option<String>,
    pub group: Option<String>,
}

impl From<&FileMeta> for WireMeta {
    fn from(m: &FileMeta) -> Self {
        WireMeta {
            v: m.v,
            mode: m.mode,
            symlink: m.symlink.clone(),
            xattrs: m
                .xattrs
                .as_ref()
                .map(|x| x.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            owner: m.owner.as_ref().map(|o| WireOwner {
                uid: o.uid,
                gid: o.gid,
                user: o.user.clone(),
                group: o.group.clone(),
            }),
        }
    }
}

impl WireMeta {
    fn to_meta(&self) -> Result<FileMeta, String> {
        let xattrs = match &self.xattrs {
            None => None,
            Some(list) => {
                let map: BTreeMap<String, String> = list.iter().cloned().collect();
                if map.len() != list.len() {
                    return Err("an extended attribute is named twice".into());
                }
                Some(map)
            }
        };
        Ok(FileMeta {
            v: self.v,
            mode: self.mode,
            symlink: self.symlink.clone(),
            xattrs,
            owner: self.owner.as_ref().map(|o| Owner {
                uid: o.uid,
                gid: o.gid,
                user: o.user.clone(),
                group: o.group.clone(),
            }),
        })
    }
}

/// One entry on the wire: device ids are indexes into the record's table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEntry {
    pub path: Vec<u8>,
    pub version: Vec<(u32, u64)>,
    pub deleted: bool,
    pub size: u64,
    pub mtime: i64,
    pub content_hash: Option<Hash32>,
    pub chunks: Vec<Chunk3>,
    pub modified_by: u32,
    pub modified_clock: u64,
    pub meta: Option<WireMeta>,
    pub chunking: u8,
    pub held: bool,
}

/// The body of a `manifest` record: a base (`base == seq`, the writer's
/// whole view) or a delta (entries changed since `seq - 1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub created_utc: i64,
    /// Seq of the base this record builds on; `== seq` for a base.
    pub base: u64,
    /// `record_hash` of record `seq - 1` of this stream (zeros for seq 1).
    pub prev: Hash32,
    pub devices: Vec<Id16>,
    pub files: Vec<WireEntry>,
    pub removed: Vec<Vec<u8>>,
}

/// Header fields of a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub created_utc: i64,
    pub base: u64,
    pub prev: Hash32,
}

impl ManifestBody {
    /// Encode `files` (and, for a delta, `removed`) with an interned id
    /// table (sorted, so equal views encode equally).
    pub fn new<'a>(
        h: Header,
        files: impl IntoIterator<Item = &'a FileEntry>,
        removed: impl IntoIterator<Item = &'a str>,
    ) -> ManifestBody {
        let files: Vec<&FileEntry> = files.into_iter().collect();
        let mut ids: BTreeSet<Id16> = BTreeSet::new();
        for f in &files {
            ids.extend(f.version.keys().copied());
            ids.insert(f.modified_by);
        }
        let devices: Vec<Id16> = ids.into_iter().collect();
        let idx = |d: &Id16| devices.binary_search(d).expect("interned above") as u32;
        let wire = files
            .iter()
            .map(|f| WireEntry {
                path: f.path.as_bytes().to_vec(),
                version: f.version.iter().map(|(d, c)| (idx(d), *c)).collect(),
                deleted: f.deleted,
                size: f.size,
                mtime: f.mtime,
                content_hash: f.content_hash,
                chunks: f.chunks.clone(),
                modified_by: idx(&f.modified_by),
                modified_clock: f.modified_clock,
                meta: f.meta.as_ref().map(WireMeta::from),
                chunking: f.chunking,
                held: f.held,
            })
            .collect();
        ManifestBody {
            folder: h.folder,
            device: h.device,
            seq: h.seq,
            lamport: h.lamport,
            created_utc: h.created_utc,
            base: h.base,
            prev: h.prev,
            files: wire,
            devices,
            removed: removed.into_iter().map(|p| p.as_bytes().to_vec()).collect(),
        }
    }

    pub fn header(&self) -> Header {
        Header {
            folder: self.folder,
            device: self.device,
            seq: self.seq,
            lamport: self.lamport,
            created_utc: self.created_utc,
            base: self.base,
            prev: self.prev,
        }
    }

    pub fn is_base(&self) -> bool {
        self.base == self.seq
    }

    /// The entries with their ids resolved; fails on anything `check`
    /// refuses about them.
    pub fn entries(&self) -> Result<Vec<FileEntry>, String> {
        let dev = |i: u32| -> Result<Id16, String> {
            self.devices
                .get(i as usize)
                .copied()
                .ok_or_else(|| format!("device index {i} out of range"))
        };
        let mut out = Vec::with_capacity(self.files.len());
        for w in &self.files {
            let path = String::from_utf8(w.path.clone())
                .map_err(|_| "a path that is not UTF-8".to_string())?;
            let mut version = BTreeMap::new();
            for (i, c) in &w.version {
                if version.insert(dev(*i)?, *c).is_some() {
                    return Err(format!("entry {path:?} names a device twice"));
                }
            }
            out.push(FileEntry {
                version,
                deleted: w.deleted,
                size: w.size,
                mtime: w.mtime,
                content_hash: w.content_hash,
                chunks: w.chunks.clone(),
                modified_by: dev(w.modified_by)?,
                modified_clock: w.modified_clock,
                meta: match &w.meta {
                    Some(m) => Some(m.to_meta()?),
                    None => None,
                },
                chunking: w.chunking,
                held: w.held,
                path,
            });
        }
        Ok(out)
    }

    /// The removed paths as text.
    pub fn removed_paths(&self) -> Result<Vec<String>, String> {
        self.removed
            .iter()
            .map(|p| String::from_utf8(p.clone()).map_err(|_| "a path that is not UTF-8".into()))
            .collect()
    }

    /// Every check that does not need the envelope (section 28 for each
    /// entry, the limits, unique paths, a well-formed base/delta).
    pub fn validate(&self) -> Result<(Vec<FileEntry>, Vec<String>), String> {
        if self.seq == 0 {
            return Err("seq 0".into());
        }
        if self.base > self.seq || self.base == 0 {
            return Err(format!("base {} for seq {}", self.base, self.seq));
        }
        if self.seq == 1 && self.prev != [0; 32] {
            return Err("seq 1 names a predecessor".into());
        }
        if self.is_base() && !self.removed.is_empty() {
            return Err("a base removes paths".into());
        }
        if self.files.len() + self.removed.len() > MAX_ENTRIES {
            return Err(format!(
                "{} entries, more than {MAX_ENTRIES}",
                self.files.len() + self.removed.len()
            ));
        }
        if self.devices.len() > MAX_VV {
            return Err(format!("{} devices in the id table", self.devices.len()));
        }
        if self.devices.windows(2).any(|w| w[0] >= w[1]) {
            return Err("the id table is not sorted and unique".into());
        }
        if self.removed.iter().any(|p| p.len() > MAX_PATH) {
            return Err("a removed path is too long".into());
        }
        let entries = self.entries()?;
        let removed = self.removed_paths()?;
        let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len() + removed.len());
        for e in &entries {
            e.validate().map_err(|e| format!("{e:#}"))?;
            if !seen.insert(&e.path) {
                return Err(format!("path {:?} appears twice", e.path));
            }
        }
        for p in &removed {
            if !seen.insert(p) {
                return Err(format!("path {p:?} appears twice"));
            }
        }
        Ok((entries, removed))
    }
}

impl RecordBody for ManifestBody {
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
        self.validate().map(|_| ())
    }
}
