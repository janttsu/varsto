// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The trash record of format 3 (`docs/spec/format-3-design.md` section 7,
//! `trash3`) as the engine's trash keeps it: the engine's entries,
//! removals and versions (`trash::TrashEntry`, `TrashRemoval`) converted to
//! and from the record's (`trash3::Entry`, `Removal`), and the state of
//! this device's own stream and of the others' kept between runs.

use super::trash::{TrashEntry, TrashRemoval};
use super::*;
use crate::manifest3::Chunk3;
use crate::trash3::{DeviceTrash, Entry, Removal, TrashSnapshot, TrashWriter};

/// This device's trash stream as it last published it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Writer3 {
    pub seq: u64,
    pub base_seq: u64,
    pub base_bytes: u64,
    pub delta_bytes: u64,
    pub hash: String,
    pub force_base: bool,
    pub entries: Vec<Entry>,
    pub removals: Vec<Removal>,
    pub versions: Vec<Entry>,
}

/// How far another device's stream was applied.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Applied3 {
    pub seq: u64,
    pub base: u64,
    pub hash: String,
    pub lamport: u64,
    pub created_utc: i64,
    /// Its removals as the record lists them (with their Lamport times).
    #[serde(default)]
    pub removals: Vec<Removal>,
}

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = hex::decode_to_slice(s, &mut out);
    out
}

fn h16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let _ = hex::decode_to_slice(s, &mut out);
    out
}

/// A trash or history entry as the record lists it.
pub(super) fn entry_to3(e: &TrashEntry) -> Result<Entry> {
    Ok(Entry {
        id: h16(&e.id),
        path: e.path.clone(),
        size: e.size,
        mtime: e.mtime,
        content_hash: h32(&e.content_hash),
        chunks: e
            .chunks
            .iter()
            .map(|c| {
                Ok(Chunk3 {
                    chunk: crate::storages3::object_bin(&c.chunk)?,
                    object: crate::storages3::object_bin(&c.object)?,
                    size: c.size,
                    epoch: c.epoch,
                })
            })
            .collect::<Result<_>>()?,
        deleted_utc: e.deleted_utc,
        deleted_by: members3::bin(&e.deleted_by)?,
        clock: e.clock,
        author: e.author.as_ref().map(members3::bin).transpose()?,
    })
}

/// The engine's form of a record's entry.
pub(super) fn entry_from3(e: &Entry) -> TrashEntry {
    let id = crate::ids::Id::from_bytes;
    TrashEntry {
        id: hex::encode(e.id),
        path: e.path.clone(),
        size: e.size,
        mtime: e.mtime,
        content_hash: hex::encode(e.content_hash),
        chunks: e
            .chunks
            .iter()
            .map(|c| ChunkRef {
                chunk: id(&c.chunk),
                object: id(&c.object),
                size: c.size,
                epoch: c.epoch,
            })
            .collect(),
        deleted_utc: e.deleted_utc,
        deleted_by: id(&e.deleted_by),
        clock: e.clock,
        author: e.author.map(|a| id(&a)),
    }
}

pub(super) fn removal_to3(id: &str, r: &TrashRemoval) -> Removal {
    Removal {
        id: h16(id),
        utc: r.utc,
        restored: r.restored,
        deleted_utc: r.deleted_utc,
        lamport: r.lamport,
    }
}

pub(super) fn removal_from3(r: &Removal, by: &DeviceId) -> (String, TrashRemoval) {
    (
        hex::encode(r.id),
        TrashRemoval {
            utc: r.utc,
            by: by.clone(),
            restored: r.restored,
            deleted_utc: r.deleted_utc,
            lamport: r.lamport,
        },
    )
}

/// The snapshot a record of this device lists now.
pub(super) fn snapshot_of(
    own: &[TrashEntry],
    removed: &BTreeMap<String, TrashRemoval>,
    versions: &[TrashEntry],
) -> Result<TrashSnapshot> {
    let mut s = TrashSnapshot::default();
    for e in own {
        let x = entry_to3(e)?;
        s.entries.insert(x.id, x);
    }
    for (id, r) in removed {
        let x = removal_to3(id, r);
        s.removals.insert(x.id, x);
    }
    for e in versions {
        let x = entry_to3(e)?;
        s.versions.insert(x.id, x);
    }
    Ok(s)
}

impl Writer3 {
    pub fn writer(&self, folder: [u8; 16], device: [u8; 16]) -> TrashWriter {
        let mut w = TrashWriter::new(folder, device);
        w.seq = self.seq;
        w.base_seq = self.base_seq;
        w.base_bytes = self.base_bytes;
        w.delta_bytes = self.delta_bytes;
        w.hash = h32(&self.hash);
        w.force_base = self.force_base;
        w.published = TrashSnapshot {
            entries: self.entries.iter().map(|e| (e.id, e.clone())).collect(),
            removals: self.removals.iter().map(|r| (r.id, r.clone())).collect(),
            versions: self.versions.iter().map(|e| (e.id, e.clone())).collect(),
        };
        w
    }

    pub fn of(w: &TrashWriter) -> Writer3 {
        Writer3 {
            seq: w.seq,
            base_seq: w.base_seq,
            base_bytes: w.base_bytes,
            delta_bytes: w.delta_bytes,
            hash: hex::encode(w.hash),
            force_base: w.force_base,
            entries: w.published.entries.values().cloned().collect(),
            removals: w.published.removals.values().cloned().collect(),
            versions: w.published.versions.values().cloned().collect(),
        }
    }
}

impl Applied3 {
    /// The device's trash state as last applied, from the cached lists.
    pub fn device_trash(
        &self,
        device: [u8; 16],
        entries: &[TrashEntry],
        versions: &[TrashEntry],
    ) -> Result<DeviceTrash> {
        let mut d = DeviceTrash::new(device);
        d.seq = self.seq;
        d.base = self.base;
        d.hash = h32(&self.hash);
        d.lamport = self.lamport;
        d.created_utc = self.created_utc;
        for e in entries {
            let x = entry_to3(e)?;
            d.state.entries.insert(x.id, x);
        }
        for e in versions {
            let x = entry_to3(e)?;
            d.state.versions.insert(x.id, x);
        }
        for r in &self.removals {
            d.state.removals.insert(r.id, r.clone());
        }
        Ok(d)
    }

    pub fn of(d: &DeviceTrash) -> Applied3 {
        Applied3 {
            seq: d.seq,
            base: d.base,
            hash: hex::encode(d.hash),
            lamport: d.lamport,
            created_utc: d.created_utc,
            removals: d.state.removals.values().cloned().collect(),
        }
    }
}
