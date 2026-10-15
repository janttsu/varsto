// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The engine's side of packs (`crate::packs`, format 2): where blocks are,
//! the pack indexes, and garbage collection.
//!
//! - Locations: every `chunk_stored` claim carries the pack, offset and
//!   length of the block on that storage. Whenever the ledger view changes,
//!   the engine hands every location in it to the pack context it shares
//!   with the storages it opens, so reads find blocks without listing
//!   anything but the packs.
//! - Claims: a push (or a repair, a move, an import) writes blocks into
//!   packs and records `chunk_stored` events; before the events are sealed
//!   (or kept for the next batch) each gets the location the storage wrote
//!   it at.
//! - Pack indexes: at the same moment, the packs written since are listed
//!   per storage and folder in `packs/index/<device>/<seq>.enc`, encrypted
//!   under the folder's metadata key (K10).
//! - Garbage collection (`pack_upkeep`): hot packs more than half dead are
//!   rewritten, by a device that holds the key of every folder whose blocks
//!   are in them; cold packs never are.

use super::*;
use crate::packs::{self, IndexEntry, NewPack, PackLoc};

/// What one run of `pack_upkeep` did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackUpkeepReport {
    /// Live blocks moved out of mostly dead packs into new ones.
    pub blocks_moved: u64,
    pub bytes_moved: u64,
    /// Storages that could not be opened or collected (with the error).
    pub skipped: Vec<String>,
}

impl Engine {
    /// A number that changes whenever the view's batches do.
    pub(super) fn pack_generation(view: &LedgerView, context: &str) -> u64 {
        let h = crypto::hash(format!("{}:{}:{context}", view.batches, view.max_lamport).as_bytes());
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
    }

    /// Hand the pack locations of `view` to the storages, when the view
    /// changed since the last time.
    pub(super) fn feed_pack_locator(&self, view: &LedgerView, generation: u64) {
        if self.pack_caches.view_generation() == Some(generation) {
            return;
        }
        let mut map: HashMap<String, Vec<PackLoc>> = HashMap::new();
        let mut claimed: HashSet<(String, String, u64)> = HashSet::new();
        let mut of_object: HashMap<String, String> = HashMap::new();
        for ((folder, _), rec) in &view.chunks {
            if !folder.as_str().is_empty() {
                of_object.insert(rec.object.as_str().to_string(), folder.as_str().to_string());
            }
            for (storage, loc) in &rec.storages {
                if let Some(p) = &loc.pack {
                    let e = map.entry(rec.object.as_str().to_string()).or_default();
                    if !e.contains(p) {
                        e.push(p.clone());
                    }
                    if !loc.claimed_by.is_empty() {
                        claimed.insert((storage.clone(), p.pack.clone(), p.offset));
                    }
                }
            }
        }
        self.pack_caches
            .set_view_locations(generation, map, claimed, of_object);
        // Tombstones of a folder's blocks are listed under its metadata key.
        let mut keys: HashMap<String, Vec<SecretKey>> = HashMap::new();
        for rec in self.keyring.folders.values() {
            if let Ok(fk) = self.folder_keys(rec) {
                let mut all = vec![fk.meta.clone()];
                all.extend(fk.meta_keys().into_iter().filter(|k| k.0 != fk.meta.0));
                keys.insert(rec.folder_id.as_str().to_string(), all);
            }
        }
        self.pack_caches.set_folder_keys(keys);
        // The devices whose tombstone lists count may have changed too.
        self.pack_caches
            .set_tombstone_keys(self.pack_records(), self.pack_tombstone_key());
    }

    /// Give every `chunk_stored` event waiting for the next batch the place
    /// its storage holds the block at.
    pub(super) fn locate_pending(&mut self) {
        for ev in self.pending.iter_mut() {
            if let Event::ChunkStored {
                object,
                storage,
                pack,
                ..
            } = ev
            {
                if pack.is_none() {
                    *pack = self.pack_caches.location_on(storage, object.as_str());
                }
            }
        }
    }

    /// Before the events are sealed or kept: locations into the events,
    /// the new packs into pack indexes, deletions into tombstone lists.
    pub(super) fn settle_packs(&mut self) {
        self.locate_pending();
        let specs: Vec<StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| self.pack_caches.has_work(s.name()))
            .cloned()
            .collect();
        for spec in specs {
            let backend = match self.open_spec(&spec) {
                Ok(b) => b,
                Err(e) => {
                    log::debug!(storage = spec.name(); "packs: not settled: {e:#}");
                    continue;
                }
            };
            let new = backend.take_new_packs();
            // A disk pool holds blocks only: its packs are in the ledger.
            if !new.is_empty() && !spec.is_data_only() {
                if let Err(e) = self.write_pack_indexes(backend.as_ref(), &new) {
                    log::warn!(storage = spec.name(); "pack index not written: {e:#}");
                }
            }
            if let Err(e) = backend.flush_deletions() {
                log::warn!(storage = spec.name(); "pack tombstones not written: {e:#}");
            }
        }
    }

    /// Write the tombstone lists of the pack members deleted so far (the end
    /// of an operation that deletes blocks).
    pub(super) fn flush_pack_deletions(&self) {
        for spec in &self.config.storages {
            if !self.pack_caches.has_work(spec.name()) {
                continue;
            }
            if let Err(e) = self.open_spec(spec).and_then(|b| b.flush_deletions()) {
                log::warn!(storage = spec.name(); "pack tombstones not written: {e:#}");
            }
        }
    }

    /// One pack index per folder for the packs `new` on `backend`: every
    /// block in them whose claim is waiting in this device's next batch.
    fn write_pack_indexes(&mut self, backend: &dyn Storage, new: &[NewPack]) -> Result<()> {
        let mut owner: HashMap<&str, (&FolderId, &ChunkId)> = HashMap::new();
        for ev in &self.pending {
            if let Event::ChunkStored {
                folder,
                chunk,
                object,
                ..
            } = ev
            {
                if !folder.as_str().is_empty() {
                    owner.insert(object.as_str(), (folder, chunk));
                }
            }
        }
        let mut by_folder: BTreeMap<FolderId, Vec<IndexEntry>> = BTreeMap::new();
        for p in new {
            for (object, loc) in &p.members {
                if let Some((folder, chunk)) = owner.get(object.as_str()) {
                    by_folder
                        .entry((*folder).clone())
                        .or_default()
                        .push(IndexEntry {
                            loc: loc.clone(),
                            object: object.clone(),
                            chunk: chunk.as_str().to_string(),
                        });
                }
            }
        }
        let records = self.pack_records();
        for (folder, entries) in by_folder {
            let Some(rec) = self.keyring.folders.get(&folder).cloned() else {
                continue;
            };
            let Ok(fk) = self.folder_keys(&rec) else {
                continue;
            };
            let body = packs::encode_index(&entries)?;
            // The next free number of this device's indexes on the storage.
            let mine = format!("{}{}/", packs::INDEX_PREFIX, self.vault.device_id);
            let mut seq = backend
                .list(&mine)?
                .iter()
                .filter_map(|k| packs::parse_record_key(packs::INDEX_PREFIX, k).map(|(_, s)| s))
                .max()
                .unwrap_or(0);
            loop {
                seq += 1;
                let blob =
                    records.seal(packs::KIND_INDEX, folder.as_str(), seq, &fk.meta, &body)?;
                let key =
                    packs::record_key(packs::INDEX_PREFIX, self.vault.device_id.as_str(), seq);
                if backend.put_if_absent(&key, &blob)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Read the pack indexes on a storage that open with a folder key this
    /// device holds, and learn where their blocks are: what a device needs
    /// when the ledger lost the claims (`ledger rebuild`, `fsck`). Returns
    /// the entries read.
    pub fn load_pack_indexes(&self, storage: &dyn Storage) -> Result<Vec<(FolderId, IndexEntry)>> {
        let records = self.pack_records();
        let mut keys: Vec<(FolderId, Vec<SecretKey>)> = Vec::new();
        for rec in self.keyring.folders.values() {
            if let Ok(fk) = self.folder_keys(rec) {
                keys.push((rec.folder_id.clone(), fk.meta_keys()));
            }
        }
        let mut out = Vec::new();
        for key in storage.list(packs::INDEX_PREFIX)? {
            let Some((device, seq)) = packs::parse_record_key(packs::INDEX_PREFIX, &key) else {
                continue;
            };
            let Ok(writer) = DeviceId::from_hex(device) else {
                continue;
            };
            let Some(blob) = storage.get(&key)? else {
                continue;
            };
            'folders: for (folder, metas) in &keys {
                for k in metas {
                    let Ok(body) =
                        records.open(packs::KIND_INDEX, folder.as_str(), &writer, seq, k, &blob)
                    else {
                        continue;
                    };
                    let Ok(entries) = packs::decode_index(&body) else {
                        break 'folders;
                    };
                    for e in entries {
                        self.pack_caches.learn(&e.object, e.loc.clone());
                        out.push((folder.clone(), e));
                    }
                    break 'folders;
                }
            }
        }
        Ok(out)
    }

    /// On a member of a shared folder, which does not hold the vault ledger
    /// and so not every claim: learn where the folder's blocks are from the
    /// pack indexes on `storages` it has not read yet (each opens only
    /// under the folder's metadata key).
    pub(super) fn learn_folder_pack_indexes(&self, rec: &FolderRecord, storages: &OpenStorages) {
        let Ok(fk) = self.folder_keys(rec) else {
            return;
        };
        let metas = fk.meta_keys();
        let records = self.pack_records();
        for (spec, backend) in storages {
            if spec.is_data_only() {
                continue;
            }
            let Ok(keys) = backend.list(packs::INDEX_PREFIX) else {
                continue;
            };
            for key in keys {
                if !self.pack_caches.index_unread(spec.name(), &key) {
                    continue;
                }
                let Some((device, seq)) = packs::parse_record_key(packs::INDEX_PREFIX, &key) else {
                    self.pack_caches.index_done(spec.name(), &key, true);
                    continue;
                };
                let (Ok(writer), Ok(Some(blob))) = (DeviceId::from_hex(device), backend.get(&key))
                else {
                    continue;
                };
                let body = metas.iter().find_map(|k| {
                    records
                        .open(
                            packs::KIND_INDEX,
                            rec.folder_id.as_str(),
                            &writer,
                            seq,
                            k,
                            &blob,
                        )
                        .ok()
                });
                let Some(body) = body else {
                    self.pack_caches.index_done(spec.name(), &key, false);
                    continue;
                };
                if let Ok(entries) = packs::decode_index(&body) {
                    for e in entries {
                        self.pack_caches.learn(&e.object, e.loc);
                    }
                }
                self.pack_caches.index_done(spec.name(), &key, true);
            }
        }
    }

    /// Rewrite the hot packs that are more than half dead (`crate::packs`):
    /// their live blocks go into new packs, claimed in one batch, and the
    /// old packs go. Only packs whose every block belongs to a folder this
    /// device holds the key of; cold storages never.
    pub fn pack_upkeep(&mut self) -> Result<PackUpkeepReport> {
        let mut report = PackUpkeepReport::default();
        let view = self.view()?;
        let mut owner: HashMap<String, (FolderId, ChunkId)> = HashMap::new();
        for ((folder, chunk), rec) in &view.chunks {
            if !folder.as_str().is_empty() {
                owner.insert(
                    rec.object.as_str().to_string(),
                    (folder.clone(), chunk.clone()),
                );
            }
        }
        let held: BTreeSet<FolderId> = self.keyring.folders.keys().cloned().collect();
        let keep = |object: &str| owner.get(object).is_some_and(|(f, _)| held.contains(f));
        let specs: Vec<StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold())
            .cloned()
            .collect();
        for spec in specs {
            let moved = match self
                .open_spec(&spec)
                .and_then(|b| b.collect_pack_garbage(&keep))
            {
                Ok(m) => m,
                Err(e) => {
                    report.skipped.push(format!("{}: {e:#}", spec.name()));
                    continue;
                }
            };
            for (object, loc) in moved {
                let Some((folder, chunk)) = owner.get(&object) else {
                    continue;
                };
                report.blocks_moved += 1;
                report.bytes_moved += loc.len;
                self.pending.push(Event::ChunkStored {
                    folder: folder.clone(),
                    chunk: chunk.clone(),
                    object: ObjectName::from_hex(&object)?,
                    storage: spec.name().to_string(),
                    size: loc.len,
                    pack: Some(loc),
                });
            }
        }
        self.commit_batch()?;
        Ok(report)
    }

    /// The places of the blocks this device knows on a storage (tests and
    /// tools): object name and pack location.
    #[doc(hidden)]
    pub fn pack_members(&self, storage: &str) -> Result<Vec<(String, PackLoc)>> {
        let _ = self.view()?;
        let backend = self.open_storage(storage)?;
        let mut out = Vec::new();
        for key in backend.list("chunks/")? {
            if let Some(obj) = packs::object_of(&key) {
                if let Some(loc) = backend.pack_location(obj) {
                    out.push((obj.to_string(), loc));
                }
            }
        }
        Ok(out)
    }
}

/// Per pack id on `storage`, the blocks the view places in it (a pool's
/// disks hold packs: what a disk check or a lost pack means for blocks).
pub(super) fn blocks_by_pack(
    view: &LedgerView,
    storage: &str,
) -> HashMap<String, Vec<(FolderId, ChunkId, ObjectName)>> {
    let mut out: HashMap<String, Vec<(FolderId, ChunkId, ObjectName)>> = HashMap::new();
    for ((folder, chunk), rec) in &view.chunks {
        if let Some(p) = rec.storages.get(storage).and_then(|l| l.pack.as_ref()) {
            out.entry(p.pack.clone()).or_default().push((
                folder.clone(),
                chunk.clone(),
                rec.object.clone(),
            ));
        }
    }
    out
}

/// The pack ids on `storage` with any block (or, with `all`, every block)
/// named in `names`, added to `names`: a pool compares the names of what
/// its disks hold, which are pack ids.
pub(super) fn with_pack_ids(
    view: &LedgerView,
    storage: &str,
    names: &mut HashSet<String>,
    all: bool,
) {
    let mut add = Vec::new();
    for (pack, blocks) in blocks_by_pack(view, storage) {
        let mut hits = blocks.iter().map(|(_, _, o)| names.contains(o.as_str()));
        let yes = if all {
            hits.all(|h| h)
        } else {
            hits.any(|h| h)
        };
        if yes {
            add.push(pack);
        }
    }
    names.extend(add);
}

/// The key under which `storage` holds a block, as the view places it:
/// its pack, or the block's own key when no pack is known.
pub(super) fn held_key(rec: &crate::ledger::ChunkRecord, storage: &str) -> String {
    match rec.storages.get(storage).and_then(|l| l.pack.as_ref()) {
        Some(p) => packs::pack_key(&p.pack),
        None => chunk_storage_key(&rec.object),
    }
}
