// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Bodies of the format-3 record kinds that had none (format 3 design,
//! section 5's table; work package 12): `policy` (11), `placement` (12),
//! `storage-names` (19), `access` (20), `notes` (21) and `thumbs` (22). None
//! of them is announced: the newest seq of a writer's stream wins, as for
//! `settings` (`trash3::settings`), except `thumbs`, whose records add up
//! (below).
//!
//! - `policy` (`vault/policy/<device>/`, `registry@`): the durability policy
//!   of every folder the writer set one for, each with the time it was set.
//!   Per folder the newest entry of any accepted device wins, by
//!   (`updated_utc`, Lamport time, device); a `None` policy is "cleared by
//!   hand".
//! - `placement` (`vault/placement/<folder>/<device>/`, `registry@`): which
//!   storages a folder's blocks go to, newest of any device by the same
//!   order.
//! - `storage-names` (`vault/storage-names/<device>/`, `registry@`): the
//!   writer's local names of storages and their identities
//!   (`vault/storage-id.json`), so devices that name a storage differently
//!   still count the same copies.
//! - `access` (`access/<folder>/<device>/`, `meta:`): the writer's "last
//!   accessed" times by path.
//! - `notes` (`notes/<folder>/<device>/`, `meta:`): analyses of files.
//! - `thumbs` (`thumbs/<folder>/<device>/`, `meta:`): thumbnails by content
//!   hash. **Interpretation:** a thumbnail is small and one record per
//!   thumbnail would pad each to 64 KiB, so a record carries the
//!   thumbnails its writer made since its previous record, and a reader
//!   takes the union of a writer's records (the first thumbnail of a
//!   content hash wins; every writer makes the same picture of the same
//!   content). Records stay until their folder goes.
//!
//! Every body names its writer and seq, which must be the envelope's
//! (step 6 of the acceptance rule); folder-scoped bodies name the folder.

use crate::record::{Id16, Kind, RecordBody, RecordMeta, RecordStore, RecordsRefused, StreamRef};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Longest path, storage name or identity, tag or model name, in bytes.
pub const MAX_TEXT: usize = 4096;
/// Longest analysis text, in bytes.
pub const MAX_ANALYSIS: usize = 64 << 10;
/// Most items (folders, names, paths, notes, thumbnails) in one record.
pub const MAX_ITEMS: usize = 1 << 20;
/// Largest thumbnail, in bytes.
pub const MAX_THUMB: usize = 1 << 20;

const ZERO: Id16 = [0; 16];

fn check_writer(device: &Id16, seq: u64, meta: &RecordMeta) -> Result<(), String> {
    if *device != meta.device {
        return Err("its device is not the record's writer".into());
    }
    if seq != meta.seq || seq == 0 {
        return Err("its seq is not the record's".into());
    }
    Ok(())
}

fn check_scope(folder: &Id16, meta: &RecordMeta) -> Result<(), String> {
    if *folder != meta.scope || *folder == ZERO {
        return Err("its folder is not the record's scope".into());
    }
    Ok(())
}

fn short(s: &str, what: &str) -> Result<(), String> {
    if s.len() > MAX_TEXT {
        return Err(format!("{what} longer than {MAX_TEXT} bytes"));
    }
    Ok(())
}

fn sorted_unique<K: Ord, V>(items: &[(K, V)], what: &str) -> Result<(), String> {
    if items.len() > MAX_ITEMS {
        return Err(format!("too many {what}"));
    }
    if items.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(format!("{what} are not sorted and unique"));
    }
    Ok(())
}

/// (updated_utc, Lamport time, device): what decides between two entries.
pub type Order = (i64, u64, Id16);

// ----- policy (11) ---------------------------------------------------------

/// A folder's durability policy on the wire (`crate::policy::Policy`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyWire {
    pub min_copies: u32,
    /// (place, copies), sorted by place.
    pub min_per_place: Vec<(String, u32)>,
    pub verified_within_days: Option<u32>,
}

impl From<&crate::policy::Policy> for PolicyWire {
    fn from(p: &crate::policy::Policy) -> Self {
        PolicyWire {
            min_copies: p.min_copies,
            min_per_place: p
                .min_per_place
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            verified_within_days: p.verified_within_days,
        }
    }
}

impl From<&PolicyWire> for crate::policy::Policy {
    fn from(p: &PolicyWire) -> Self {
        crate::policy::Policy {
            min_copies: p.min_copies,
            min_per_place: p.min_per_place.iter().cloned().collect(),
            verified_within_days: p.verified_within_days,
        }
    }
}

/// One folder's policy as a device set it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// `None`: cleared by hand.
    pub policy: Option<PolicyWire>,
    pub updated_utc: i64,
    pub lamport: u64,
}

/// The body of a `policy` record: the writer's policies by folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBody {
    pub device: Id16,
    pub seq: u64,
    /// Sorted by folder.
    pub folders: Vec<(Id16, PolicyEntry)>,
}

impl RecordBody for PolicyBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        if meta.scope != ZERO {
            return Err("policies are vault-wide records".into());
        }
        sorted_unique(&self.folders, "folders")?;
        for (_, e) in &self.folders {
            if let Some(p) = &e.policy {
                sorted_unique(&p.min_per_place, "places")?;
                for (place, _) in &p.min_per_place {
                    short(place, "a place")?;
                }
            }
        }
        Ok(())
    }
}

/// The stream of `device`'s policies.
pub fn policy_stream(device: Id16) -> StreamRef {
    StreamRef::new(Kind::Policy, ZERO, device)
}

/// Per folder, the newest policy entry of `bodies` (one body per device:
/// its newest record), with the device that set it.
pub fn newest_policies<'a>(
    bodies: impl IntoIterator<Item = &'a PolicyBody>,
) -> BTreeMap<Id16, (PolicyEntry, Id16)> {
    let mut out: BTreeMap<Id16, (PolicyEntry, Id16)> = BTreeMap::new();
    for b in bodies {
        for (f, e) in &b.folders {
            let newer = out.get(f).is_none_or(|(o, d)| {
                (e.updated_utc, e.lamport, b.device) > (o.updated_utc, o.lamport, *d)
            });
            if newer {
                out.insert(*f, (e.clone(), b.device));
            }
        }
    }
    out
}

// ----- placement (12) ------------------------------------------------------

/// The body of a `placement` record: where one folder's blocks go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub updated_utc: i64,
    /// Storages by the writer's names; empty with `places` empty: every storage.
    pub storages: Vec<String>,
    /// (name, identity) of the named storages, sorted by name.
    pub storage_ids: Vec<(String, String)>,
    pub places: Vec<String>,
}

impl PlacementBody {
    pub fn order(&self) -> Order {
        (self.updated_utc, self.lamport, self.device)
    }

    pub fn placement(&self) -> crate::placement::Placement {
        crate::placement::Placement {
            storages: self.storages.clone(),
            storage_ids: self.storage_ids.iter().cloned().collect(),
            places: self.places.clone(),
        }
    }
}

impl RecordBody for PlacementBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        check_scope(&self.folder, meta)?;
        sorted_unique(&self.storage_ids, "storage identities")?;
        if self.storages.len() > MAX_ITEMS || self.places.len() > MAX_ITEMS {
            return Err("too many storages or places".into());
        }
        for s in self.storages.iter().chain(&self.places) {
            short(s, "a storage or place")?;
        }
        for (n, i) in &self.storage_ids {
            short(n, "a storage name")?;
            short(i, "a storage identity")?;
        }
        Ok(())
    }
}

/// The stream of `device`'s placements of `folder`.
pub fn placement_stream(folder: Id16, device: Id16) -> StreamRef {
    StreamRef::new(Kind::Placement, folder, device)
}

/// The newest of `bodies` (each device's newest record).
pub fn newest_placement<'a>(
    bodies: impl IntoIterator<Item = &'a PlacementBody>,
) -> Option<&'a PlacementBody> {
    bodies.into_iter().max_by_key(|b| b.order())
}

// ----- storage-names (19) --------------------------------------------------

/// The body of a `storage-names` record: the writer's local names of its
/// storages and their identities, and the shared settings of storages
/// (quota, drain) as the writer knows them. **As built:** the shared
/// settings travel here (format 2 kept them in records of their own); of
/// the entries for one storage the newest `updated_utc` wins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageNamesBody {
    pub device: Id16,
    pub seq: u64,
    pub updated_utc: i64,
    /// (local name, identity), sorted by name.
    pub names: Vec<(String, String)>,
    /// Shared settings by storage key, sorted by key.
    pub settings: Vec<StorageSettingsEntry>,
}

/// The shared settings of one storage (`crate::storage_settings`), keyed
/// by the storage's key: its identity, a pool's identity, or a keyed hash
/// of its name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSettingsEntry {
    pub storage: String,
    /// The device that set them.
    pub by: Id16,
    pub updated_utc: i64,
    /// `StorageSettings` as JSON.
    pub settings_json: Vec<u8>,
}

impl RecordBody for StorageNamesBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        if meta.scope != ZERO {
            return Err("storage names are vault-wide records".into());
        }
        sorted_unique(&self.names, "storage names")?;
        for (n, i) in &self.names {
            short(n, "a storage name")?;
            short(i, "a storage identity")?;
        }
        if self.settings.len() > MAX_ITEMS
            || self
                .settings
                .windows(2)
                .any(|w| w[0].storage >= w[1].storage)
        {
            return Err("storage settings are not sorted and unique".into());
        }
        for e in &self.settings {
            short(&e.storage, "a storage key")?;
            if e.settings_json.len() > MAX_TEXT {
                return Err("storage settings longer than 4096 bytes".into());
            }
        }
        Ok(())
    }
}

/// The stream of `device`'s storage names.
pub fn storage_names_stream(device: Id16) -> StreamRef {
    StreamRef::new(Kind::StorageNames, ZERO, device)
}

// ----- access (20) ---------------------------------------------------------

/// The body of an `access` record: the writer's "last accessed" times.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub updated_utc: i64,
    /// (path, UTC seconds), sorted by path.
    pub accessed: Vec<(String, i64)>,
}

impl RecordBody for AccessBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        check_scope(&self.folder, meta)?;
        sorted_unique(&self.accessed, "paths")?;
        for (p, _) in &self.accessed {
            crate::names::check_synced_path(p).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// The stream of `device`'s access records of `folder`.
pub fn access_stream(folder: Id16, device: Id16) -> StreamRef {
    StreamRef::new(Kind::Access, folder, device)
}

/// The newest access time per path over every device's newest record.
pub fn merged_access<'a>(
    bodies: impl IntoIterator<Item = &'a AccessBody>,
) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    for b in bodies {
        for (p, t) in &b.accessed {
            let e = out.entry(p.clone()).or_insert(*t);
            *e = (*e).max(*t);
        }
    }
    out
}

// ----- notes (21) ----------------------------------------------------------

/// One analysis of a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteWire {
    pub analysis: String,
    pub tags: Vec<String>,
    /// Content hash of the file when it was analysed (hex).
    pub content_hash: String,
    /// The model or tool that wrote it, as it said.
    pub by: Option<String>,
    pub analysed_utc: i64,
}

/// The body of a `notes` record: the writer's analyses by path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotesBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    pub updated_utc: i64,
    /// (path, analysis), sorted by path.
    pub notes: Vec<(String, NoteWire)>,
}

impl RecordBody for NotesBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        check_scope(&self.folder, meta)?;
        sorted_unique(&self.notes, "paths")?;
        for (p, n) in &self.notes {
            crate::names::check_synced_path(p).map_err(|e| e.to_string())?;
            if n.analysis.len() > MAX_ANALYSIS {
                return Err("an analysis longer than 64 KiB".into());
            }
            if n.tags.len() > 64 {
                return Err("more than 64 tags".into());
            }
            for t in &n.tags {
                short(t, "a tag")?;
            }
            short(&n.content_hash, "a content hash")?;
            if let Some(b) = &n.by {
                short(b, "a model name")?;
            }
        }
        Ok(())
    }
}

/// The stream of `device`'s notes of `folder`.
pub fn notes_stream(folder: Id16, device: Id16) -> StreamRef {
    StreamRef::new(Kind::Notes, folder, device)
}

/// Per path, the newest analysis over every device's newest record, with
/// its writer.
pub fn merged_notes<'a>(
    bodies: impl IntoIterator<Item = &'a NotesBody>,
) -> BTreeMap<String, (NoteWire, Id16)> {
    let mut out: BTreeMap<String, (NoteWire, Id16)> = BTreeMap::new();
    for b in bodies {
        for (p, n) in &b.notes {
            let newer = out
                .get(p)
                .is_none_or(|(o, d)| (n.analysed_utc, b.device) > (o.analysed_utc, *d));
            if newer {
                out.insert(p.clone(), (n.clone(), b.device));
            }
        }
    }
    out
}

// ----- thumbs (22) ---------------------------------------------------------

/// The body of a `thumbs` record: thumbnails the writer made since its
/// previous record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbsBody {
    pub folder: Id16,
    pub device: Id16,
    pub seq: u64,
    /// (content hash, JPEG bytes), sorted by content hash.
    pub thumbs: Vec<([u8; 32], Vec<u8>)>,
}

impl RecordBody for ThumbsBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        check_writer(&self.device, self.seq, meta)?;
        check_scope(&self.folder, meta)?;
        sorted_unique(&self.thumbs, "thumbnails")?;
        if self
            .thumbs
            .iter()
            .any(|(_, j)| j.is_empty() || j.len() > MAX_THUMB)
        {
            return Err("a thumbnail that is empty or over 1 MiB".into());
        }
        Ok(())
    }
}

/// The stream of `device`'s thumbnails of `folder`.
pub fn thumbs_stream(folder: Id16, device: Id16) -> StreamRef {
    StreamRef::new(Kind::Thumbs, folder, device)
}

/// Every thumbnail of `bodies` (all records of every writer) by content
/// hash; of two pictures of one hash the one of the smaller (writer, seq)
/// is kept, so every reader keeps the same.
pub fn thumbnails<'a>(
    bodies: impl IntoIterator<Item = &'a ThumbsBody>,
) -> BTreeMap<[u8; 32], &'a [u8]> {
    let mut all: Vec<&ThumbsBody> = bodies.into_iter().collect();
    all.sort_by_key(|b| (b.device, b.seq));
    let mut out: BTreeMap<[u8; 32], &[u8]> = BTreeMap::new();
    for b in all {
        for (h, j) in &b.thumbs {
            out.entry(*h).or_insert(j.as_slice());
        }
    }
    out
}

// ----- reading -------------------------------------------------------------

/// The newest accepted record of each of `streams` on one storage (a
/// refused newest falls back to the one before it, as for settings).
/// Junk is counted in `counter` and left out.
pub fn read_newest<T: RecordBody>(
    store: &RecordStore,
    streams: &[StreamRef],
    counter: &mut RecordsRefused,
) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for s in streams {
        let high = store.highest_seq(s)?;
        if high == 0 {
            continue;
        }
        let read = store.read_after::<T>(s, high.saturating_sub(8), counter)?;
        if let Some(rec) = read.accepted.into_iter().max_by_key(|r| r.meta.seq) {
            out.push(rec.body);
        }
    }
    Ok(out)
}

/// Every accepted record of `stream` on one storage, in seq order (thumbs).
pub fn read_all<T: RecordBody>(
    store: &RecordStore,
    stream: &StreamRef,
    counter: &mut RecordsRefused,
) -> Result<Vec<T>> {
    Ok(store
        .read_after::<T>(stream, 0, counter)?
        .accepted
        .into_iter()
        .map(|r| r.body)
        .collect())
}

#[cfg(test)]
mod tests;
