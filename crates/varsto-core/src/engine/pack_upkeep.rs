// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Garbage collection of storage format 3 in the engine
//! (`docs/spec/format-3-design.md` section 3, "Dead marks, settling and
//! collection", "Garbage collection", "Pruning"; `gc3`).
//!
//! Run by the trash upkeep (and by `trash purge`) on own full devices with
//! the writer role that hold the folder's keys, per attached folder:
//!
//! 1. the folder's map and manifest records are brought up to date, and the
//!    references are gathered: the current files of every writer's newest
//!    manifest, the unexpired trash and history entries;
//! 2. a marking round publishes `dead` marks for places nothing references
//!    (only when every writer's announced reference records were applied)
//!    and `undead` marks for dead-marked places that are referenced again,
//!    in one map record and one batch (`gc3::mark_round`);
//! 3. a collection run drops packs whose every member is collectable
//!    (settled dead marks, nothing references them), rewrites hot packs
//!    more than half collectable and compacts small hot packs
//!    (`gc3::collect`): new packs, one map record, one batch, and only then
//!    the deletes;
//! 4. packs no claim and no map names are deleted 7 days after they were
//!    first seen (`gc3::collect_orphans`, the state in `state/gc3.json`).
//!
//! A mark made by one device settles when every current writer of the
//! folder has acknowledged the batch that carried it; a device that pulls
//! another writer's marks therefore acknowledges them in a batch of its own
//! at its next ledger upkeep (`acks_due3`), even when it has nothing else
//! to seal, so that collection does not wait for its next change.
//!
//! The same module prunes this device's own map and manifest records below
//! its newest base once every reader of the folder acknowledged the batch
//! that announced the base (`gc3::prune_map`, `manifest3::prune_stream`).

use super::fsck3_ops::Sink3;
use super::*;
use crate::blockmap::{MapTable, MapWriter};
use crate::gc3::{
    GcOptions, MapOut, OrphanState, ReferenceSet, Standing, StorageClass, StorageInfo, StorageSet,
};
use crate::ledger3::LedgerView as View3;
use crate::manifest3::{FolderManifests, PruneState};
use crate::record::{Acceptor, DeviceSigner, Id16, Kind, RecordStore, RecordWriter, StreamRef};
use std::sync::Arc;

const GC_STATE_FILE: &str = "state/gc3.json";

/// What garbage collection keeps between runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GcState {
    #[serde(default)]
    orphans: OrphanState,
    /// Folder (hex) -> how far own map records were pruned per storage.
    #[serde(default)]
    maps: BTreeMap<String, PruneState>,
    /// Folder (hex) -> how far own manifest records were pruned per storage.
    #[serde(default)]
    manifests: BTreeMap<String, PruneState>,
    /// Pack copies on cold storage the last run left for later.
    #[serde(default)]
    drops_waiting: u64,
}

/// What one run of `pack_upkeep` did, over every folder.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackUpkeepReport {
    /// Places newly marked dead and undead.
    pub marked_dead: u64,
    pub marked_undead: u64,
    /// Packs dropped whole, rewritten and merged.
    pub packs_dropped: u64,
    pub packs_rewritten: u64,
    pub packs_compacted: u64,
    /// New packs written for rewrites and merges.
    pub packs_written: u64,
    /// Places collected: the members of dropped packs and the dead members
    /// left behind by rewrites and merges.
    pub blocks_dropped: u64,
    /// Live blocks moved out of rewritten or merged packs into new ones.
    pub blocks_moved: u64,
    pub bytes_moved: u64,
    /// Bytes of packs deleted from storages.
    pub bytes_freed: u64,
    /// Pack copies on cold storage that go once the storage's minimum
    /// duration has passed.
    pub drops_waiting: u64,
    /// Unclaimed packs no map lists, deleted after 7 days.
    pub orphans_deleted: u64,
    /// Devices collection waits for (they have not acknowledged a mark).
    pub waiting_for: Vec<String>,
    /// Storages or folders that could not be collected (with the reason).
    pub skipped: Vec<String>,
}

impl PackUpkeepReport {
    fn add(&mut self, r: &crate::gc3::GcReport, collected: u64) {
        self.packs_dropped += r.packs_dropped;
        self.packs_rewritten += r.packs_rewritten;
        self.packs_compacted += r.packs_compacted;
        self.packs_written += r.packs_written;
        self.blocks_moved += r.blocks_moved;
        self.bytes_moved += r.bytes_moved;
        self.bytes_freed += r.bytes_freed;
        self.drops_waiting += r.drops_later.len() as u64;
        self.blocks_dropped += collected;
    }
}

impl Engine {
    fn gc_state_path(&self) -> PathBuf {
        self.home.join(GC_STATE_FILE)
    }

    fn load_gc_state(&self) -> GcState {
        util::read_json_or_default(&self.gc_state_path()).unwrap_or_default()
    }

    fn save_gc_state(&self, st: &GcState) -> Result<()> {
        if !self.home.join("state").is_dir() {
            return Ok(());
        }
        util::write_json(&self.gc_state_path(), st)
    }

    /// The storages garbage collection works on, by class: cold ones keep
    /// their minimum duration, pools and transferrers are never rewritten.
    /// Storages that cannot be opened are left out (and named).
    fn gc_storages3(&self, skipped: &mut Vec<String>) -> StorageSet {
        let mut set = StorageSet::default();
        for spec in &self.config.storages {
            let b: Arc<dyn Storage> = match self.open_spec(spec) {
                Ok(b) => Arc::from(b),
                Err(e) => {
                    skipped.push(format!("{} (cannot open: {e:#})", spec.name()));
                    continue;
                }
            };
            let info = if spec.is_cold() {
                StorageInfo::cold(self.storage_price(spec.name()).as_ref())
            } else if spec.is_data_only() || spec.is_carrier() {
                StorageInfo {
                    class: StorageClass::Pool,
                    minimum_secs: None,
                }
            } else {
                StorageInfo::HOT
            };
            set.add(b, info);
        }
        set
    }

    /// This device's standing in `folder` (`gc3::Standing`).
    pub(super) fn standing3(&self, folder: &Id16) -> Standing {
        Standing {
            device: self.me3(),
            role: self.f3.members.role(&self.me3(), folder),
            member: self.vault.member,
            holds_k10: true,
        }
    }

    /// The folder's current epoch (folder epoch records).
    fn folder_epoch3(&self, folder: &Id16) -> u32 {
        self.f3
            .members
            .registry
            .epochs
            .get(folder)
            .map(|e| e.current())
            .unwrap_or(0)
    }

    /// The current writers of `folder`: whose acknowledgements settle a mark.
    pub(super) fn folder_writers3(&self, folder: &Id16) -> Vec<Id16> {
        crate::gc3::folder_writers(
            &self.f3.members.registry,
            folder,
            self.folder_epoch3(folder),
            &self.f3.members.revoked,
        )
    }

    /// The readers of `folder`: whose acknowledgements let records be pruned.
    fn folder_readers3(&self, folder: &Id16) -> Vec<Id16> {
        crate::gc3::folder_readers(
            &self.f3.members.registry,
            folder,
            self.folder_epoch3(folder),
            &self.f3.members.revoked,
        )
    }

    /// What references blocks of `folder` now: the current files of every
    /// writer's newest manifest and the unexpired trash and history
    /// entries, with how far each writer's manifest and trash streams were
    /// applied (collection waits for a writer whose records are behind).
    fn gc_references3(
        &self,
        rec: &FolderRecord,
        manifests: &FolderManifests,
        now: i64,
    ) -> Result<ReferenceSet> {
        let mut refs = ReferenceSet {
            kinds: [Kind::Manifest, Kind::Trash].into_iter().collect(),
            ..Default::default()
        };
        // Other writers: their newest manifests. This device: its folder
        // state, which is newer than its last manifest when a pull applied
        // changes that no push has published yet (a deletion pulled just
        // now no longer references its blocks here).
        let me = self.me3();
        for (d, v) in &manifests.views {
            refs.applied.insert((Kind::Manifest, *d), v.seq);
            if *d != me {
                refs.objects
                    .extend(v.files.values().flat_map(|f| f.objects()).copied());
            }
        }
        match self.load_state(&rec.folder_id) {
            Ok(state) => {
                for f in state
                    .files
                    .values()
                    .chain(state.pending_remote.values())
                    .filter(|f| !f.deleted)
                {
                    for c in &f.chunks {
                        refs.objects
                            .insert(crate::storages3::object_bin(&c.object)?);
                    }
                }
            }
            Err(_) => {
                if let Some(v) = manifests.views.get(&me) {
                    refs.objects
                        .extend(v.files.values().flat_map(|f| f.objects()).copied());
                }
            }
        }
        let sets = self.trash_sets(&rec.folder_id, now);
        for e in sets.visible.iter().chain(sets.versions.iter()) {
            for c in &e.chunks {
                refs.objects
                    .insert(crate::storages3::object_bin(&c.object)?);
            }
        }
        for (d, seq) in self.trash_applied3(&rec.folder_id) {
            refs.applied.insert((Kind::Trash, d), seq);
        }
        Ok(refs)
    }

    /// The newest own map record on the storages: a record under a seq no
    /// batch announced (a crash before the batch) is skipped by the writer.
    fn own_map_highest3(&self, folder: &Id16, meta: &[&dyn Storage]) -> Result<u64> {
        let Some(first) = meta.first() else {
            return Ok(0);
        };
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = crate::membership3::Trust {
            devices: &self.f3.members.devices,
            revoked: &self.f3.members.revoked,
            folders: None,
            members: None,
        };
        RecordStore {
            storage: *first,
            acceptor: Acceptor {
                vault,
                keys: &keys,
                trust: &trust,
            },
        }
        .highest_seq(&StreamRef::new(Kind::BlockMap, *folder, self.me3()))
    }

    /// Seal and push the events recorded so far now, also inside an action
    /// that would keep them for its one batch.
    pub(super) fn flush_pending3(&mut self) -> Result<()> {
        if self.pending.is_empty() && self.f3.pending.is_empty() {
            return Ok(());
        }
        let cycle = self.cycle.take();
        let out = self.commit_batch();
        self.cycle = cycle;
        out.map(|_| ())
    }

    /// Run `f` with what a marking round, a collection or a repair of
    /// `folder` needs: the map writer of this device, the folder's table,
    /// where map records go and the sink that seals and pushes one batch.
    pub(super) fn with_map_writer3<T>(
        &mut self,
        folder: &Id16,
        epoch: u32,
        view: &View3,
        f: impl FnOnce(&mut MapWriter, &mut MapTable, &MapOut, &mut Sink3) -> Result<T>,
    ) -> Result<T> {
        // Events recorded before (a push's map and manifest announcements,
        // a trash record) are sealed first: the map record this writes
        // follows theirs in seq and in the ledger.
        self.flush_pending3()?;
        let me = self.me3();
        let vault = members3::bin(&self.vault.vault_id)?;
        let table = self.table3(folder)?;
        let (key_id, key) = self.ledger_key3()?;
        let mut lamports = std::collections::VecDeque::new();
        for _ in 0..4 {
            lamports.push_back(self.tick()?);
        }
        let storages = self.record_storages3()?;
        let meta: Vec<&dyn Storage> = storages
            .iter()
            .filter(|(s, _)| !s.is_cold())
            .map(|(_, b)| &**b)
            .collect();
        let highest = self.own_map_highest3(folder, &meta)?;
        let mut writer = MapWriter::from_view(*folder, me, epoch, view, highest);
        let vault_keys = self.vault_keys3();
        let Engine {
            f3, keys, epochs, ..
        } = self;
        let ring = crate::membership3::KeyRing {
            me,
            vault: &vault_keys,
            kem: epochs.kem.as_ref(),
            devices: Some(&f3.members.devices),
            folders: Some(&f3.members.granted),
            recovery: None,
            extra: Vec::new(),
            members: Some(&f3.members.members),
        };
        let signer = DeviceSigner {
            device: me,
            key: &keys.signer,
        };
        let rw = RecordWriter {
            vault,
            signer: &signer,
            keys: &ring,
        };
        let out = MapOut {
            writer: &rw,
            meta: &meta,
        };
        let mut sink = Sink3 {
            ledger: &mut f3.ledger,
            me,
            key,
            key_id,
            signer: &keys.signer,
            storages: &storages,
            last: lamports.back().copied().unwrap_or(0),
            lamports,
        };
        let mut t = table.write().unwrap_or_else(|e| e.into_inner());
        f(&mut writer, &mut t, &out, &mut sink)
    }

    /// One marking round and one collection run of an attached folder.
    fn gc_folder3(
        &mut self,
        rec: &FolderRecord,
        storages: &StorageSet,
        now: i64,
        report: &mut PackUpkeepReport,
    ) -> Result<()> {
        let folder = members3::bin(&rec.folder_id)?;
        let standing = self.standing3(&folder);
        if !standing.may_mark() {
            return Ok(());
        }
        let epoch = self.folder_keys(rec)?.epoch;
        let writers = self.folder_writers3(&folder);
        // 1. Every record up to date, then the references.
        let view = self.view3()?;
        let (manifests, _) = self.pull_folder_records3(&folder, &view)?;
        let refs = self.gc_references3(rec, &manifests, now)?;
        // 2. Marks.
        let marks = self.with_map_writer3(&folder, epoch, &view, |w, t, out, sink| {
            crate::gc3::mark_round(&standing, w, t, &view, out, &refs, &writers, sink)
        })?;
        report.marked_dead += marks.dead;
        report.marked_undead += marks.undead;
        if !marks.behind.is_empty() {
            report.waiting_for.extend(
                marks
                    .behind
                    .iter()
                    .map(|d| self.device_name(&DeviceId::from_bytes(d))),
            );
        }
        if !standing.may_collect() {
            return Ok(());
        }
        // 3. Collection, over the view the marks' batch left.
        let view = self.view3()?;
        let opts = GcOptions {
            now_utc: now,
            ..Default::default()
        };
        let collected = {
            let table = self.table3(&folder)?;
            let t = table.read().unwrap_or_else(|e| e.into_inner());
            let plan = crate::gc3::plan(&t, &view, &writers, &refs, storages, &opts)?;
            for d in plan.waiting.keys() {
                report
                    .waiting_for
                    .push(self.device_name(&DeviceId::from_bytes(d)));
            }
            let mut n = 0u64;
            let gone: BTreeSet<&[u8; 32]> = plan
                .drops
                .iter()
                .map(|(id, _)| id)
                .chain(plan.rewrites.iter())
                .chain(plan.compactions.iter().flatten())
                .collect();
            for id in gone {
                if let Some(p) = plan.packs.get(id) {
                    n += p
                        .members
                        .iter()
                        .filter(|(_, v)| *v == crate::gc3::PlaceVerdict::Collectable)
                        .count() as u64;
                }
            }
            n
        };
        let r = self.with_map_writer3(&folder, epoch, &view, |w, t, out, sink| {
            crate::gc3::collect(
                &standing, w, t, &view, out, storages, &refs, &writers, sink, &opts,
            )
        })?;
        for (id, s) in &r.delete_failed {
            report.skipped.push(format!(
                "pack {} on {s} not deleted yet",
                &hex::encode(id)[..12]
            ));
        }
        report.add(&r, if r.drops > 0 { collected } else { 0 });
        Ok(())
    }

    /// Garbage collection of every attached folder this device may collect
    /// in (see the module documentation). `stale`: folders whose records
    /// could not be brought up to date are left alone.
    pub(super) fn gc_run3(
        &mut self,
        now: i64,
        stale: &BTreeSet<FolderId>,
    ) -> Result<PackUpkeepReport> {
        let mut report = PackUpkeepReport::default();
        if self.vault.member || self.forked_self || self.removal.is_some() {
            return Ok(report);
        }
        self.flush_pending3()?;
        let storages = self.gc_storages3(&mut report.skipped);
        let attached: Vec<FolderRecord> = self
            .config
            .folders
            .iter()
            .filter(|m| !stale.contains(&m.folder_id))
            .filter_map(|m| self.keyring.folders.get(&m.folder_id))
            .filter(|r| !r.is_removed() && !r.is_backup())
            .filter_map(|r| self.with_key(r).ok())
            .collect();
        let mut collecting = None;
        for rec in &attached {
            if let Err(e) = self.gc_folder3(rec, &storages, now, &mut report) {
                report.skipped.push(format!("folder {}: {e:#}", rec.name));
                continue;
            }
            if let Ok(f) = members3::bin(&rec.folder_id) {
                let s = self.standing3(&f);
                if s.may_collect() {
                    collecting = Some(s);
                }
            }
        }
        let mut st = self.load_gc_state();
        st.drops_waiting = report.drops_waiting;
        // 4. Orphans, over the tables of every folder held here.
        if let Some(standing) = collecting {
            let view = self.view3()?;
            self.ensure_tables3();
            let tables: Vec<_> = self
                .f3
                .tables
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .cloned()
                .collect();
            let guards: Vec<_> = tables
                .iter()
                .map(|t| t.read().unwrap_or_else(|e| e.into_inner()))
                .collect();
            let refs: Vec<&MapTable> = guards.iter().map(|g| &**g).collect();
            let names: Vec<String> = self
                .config
                .storages
                .iter()
                .filter(|s| !s.is_carrier() && !s.is_data_only())
                .map(|s| s.name().to_string())
                .collect();
            let opts = GcOptions {
                now_utc: now,
                ..Default::default()
            };
            let o = crate::gc3::collect_orphans(
                &standing,
                &storages,
                &names,
                &view,
                &refs,
                &mut st.orphans,
                &opts,
            )?;
            drop(guards);
            report.orphans_deleted += o.orphans_deleted + o.leftovers_deleted;
            report.skipped.extend(o.skipped);
        }
        self.save_gc_state(&st)?;
        report.waiting_for.sort();
        report.waiting_for.dedup();
        Ok(report)
    }

    /// Pack copies on cold storage the last run left for later (the
    /// storage's minimum duration).
    pub(super) fn gc_drops_waiting3(&self) -> u64 {
        self.load_gc_state().drops_waiting
    }

    /// Garbage collection now (`gc_run3` over every attached folder),
    /// whatever the trash upkeep's schedule.
    pub fn pack_upkeep(&mut self) -> Result<PackUpkeepReport> {
        self.ensure_active()?;
        self.trash_refresh(true)?;
        self.gc_run3(util::now_utc(), &BTreeSet::new())
    }

    /// Whether another writer's marks wait for this device's
    /// acknowledgement: a mark settles only once every current writer of
    /// the folder has signed a batch that names the marker's batch in its
    /// `seen` (design section 3), so a device that pulled one says so at
    /// its next ledger upkeep even when it has nothing else to seal.
    pub(super) fn acks_due3(&self, view: &View3) -> bool {
        let me = self.me3();
        let tables: Vec<_> = self
            .f3
            .tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(f, t)| (*f, t.clone()))
            .collect();
        for (folder, t) in tables {
            if !self.folder_writers3(&folder).contains(&me) {
                continue;
            }
            let t = t.read().unwrap_or_else(|e| e.into_inner());
            for m in t.scan_marks().flatten() {
                if m.marker == me || m.kind != crate::blockmap::MarkKind::Dead {
                    continue;
                }
                let Some(a) = view.announced(Kind::BlockMap.code(), &folder, &m.marker, m.map_seq)
                else {
                    continue;
                };
                if view.acked(&me, &m.marker, Some(&folder)) < a.batch {
                    return true;
                }
            }
        }
        false
    }

    /// Prune this device's own map and manifest records of every folder
    /// below its newest base, once every reader of the folder acknowledged
    /// the batch that announced it (design sections 3 and 7, "Pruning").
    /// Cold storages and storages that do not hold the base are left as
    /// they are.
    pub(super) fn prune_records3(&mut self) -> Result<u64> {
        if self.vault.member || self.forked_self || self.removal.is_some() {
            return Ok(0);
        }
        let view = self.view3()?;
        let me = self.me3();
        let storages = self.metadata_storages(true)?;
        let list: Vec<(&dyn Storage, bool)> = storages
            .iter()
            .filter(|(s, _)| !s.is_carrier())
            .map(|(s, b)| (&**b, s.is_cold()))
            .collect();
        let mut st = self.load_gc_state();
        let mut deleted = 0;
        let folders: Vec<Id16> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed())
            .filter_map(|r| members3::bin(&r.folder_id).ok())
            .collect();
        for folder in folders {
            let readers = self.folder_readers3(&folder);
            let key = hex::encode(folder);
            let maps = st.maps.entry(key.clone()).or_default();
            deleted +=
                crate::gc3::prune_map(&list, &view, &folder, &me, &readers, maps)?.deleted;
            if let Some(floor) = crate::manifest3::prune_floor(&view, &folder, &me, &readers) {
                let m = st.manifests.entry(key).or_default();
                for (s, cold) in &list {
                    deleted += crate::manifest3::prune_stream(*s, *cold, &folder, &me, floor, m)?;
                }
            }
        }
        self.save_gc_state(&st)?;
        Ok(deleted)
    }
}

/// Per pack id on `storage`, the blocks the format-2 view places in it.
/// Format 2: the pools, moves and disk suggestions still call it until
/// their own part of the switch counts packs from the pack-level view
/// (f3-switch: part B, `disk_insert`, `disk_suggest`, `mailbox`, `engine.rs`).
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
/// named in `names`, added to `names`. Format 2, as `blocks_by_pack`.
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

/// The key under which `storage` holds a block, as the format-2 view places
/// it. Format 2, as `blocks_by_pack`.
pub(super) fn held_key(rec: &crate::ledger::ChunkRecord, storage: &str) -> String {
    match rec.storages.get(storage).and_then(|l| l.pack.as_ref()) {
        Some(p) => crate::packs::pack_key(&p.pack),
        None => chunk_storage_key(&rec.object),
    }
}
