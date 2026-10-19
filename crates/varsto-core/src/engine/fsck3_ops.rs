// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `fsck` and repair on the pack-level format (`docs/spec/format-3-design.md`
//! section 3, "Verification and repair"; `fsck3`, `gc3::verify`): every
//! pack the view claims is checked on the storages that hold it (with
//! `--verify` read whole and hashed), every map place and every block of a
//! current file against the packs, every announced record against the
//! storages. A repair copies a pack missing on one storage whole from
//! another (no key needed, the claim is in the ledger already) and writes
//! the good members of a damaged pack into a new pack on that storage
//! (corrupt members from the same place on another storage, the block cache
//! or the file on this device), with `lost` marks where nothing has them,
//! in one map record and one batch before the damaged pack is deleted.

use super::*;
use crate::blockmap::MapRow;
use crate::fsck3::{
    AcceptorProbe, FolderInput, Fsck3Input, Fsck3Options, Fsck3Report, PackVerdict, StorageDesc,
};
use crate::gc3::{Commit, StorageInfo, StorageSet};
use crate::ledger3::events::Event as Event3;
use crate::ledger3::{self, LedgerView as View3};
use crate::record::Id16;
use std::sync::Arc;

/// Seals the events of a garbage collection or repair step as one batch of
/// this device and pushes it before anything is deleted (`gc3::Commit`).
pub(super) struct Sink3<'a> {
    pub ledger: &'a mut ledger3::LedgerStore,
    pub me: Id16,
    pub key: SecretKey,
    pub key_id: String,
    pub signer: &'a crypto::SigningKey,
    pub storages: &'a [(StorageSpec, Box<dyn Storage>)],
    /// Lamport times reserved for this step.
    pub lamports: std::collections::VecDeque<u64>,
    pub last: u64,
}

impl Commit for Sink3<'_> {
    fn tick(&mut self) -> u64 {
        let t = self.lamports.pop_front().unwrap_or(self.last + 1);
        self.last = self.last.max(t);
        t
    }
    fn commit(&mut self, events: Vec<Event3>) -> Result<()> {
        let lamport = self.tick();
        let seen = self.ledger.vault_seen(&self.me);
        let raw = events.iter().map(Event3::to_raw).collect();
        let rec = self.ledger.append_own(
            &self.me,
            raw,
            seen,
            lamport,
            &self.key,
            &self.key_id,
            ledger3::NO_FOLDER,
            self.signer,
        )?;
        for (spec, backend) in self.storages {
            if spec.is_carrier() || spec.is_data_only() {
                continue;
            }
            backend.put_if_absent(
                &ledger3::checkpoint::batch_key(&self.me, rec.seq),
                &rec.encode(),
            )?;
            self.ledger.set_pushed(spec.name(), rec.seq)?;
        }
        Ok(())
    }
}

/// A folder held here: id, name, block map table, every writer's manifests.
type HeldFolder = (
    Id16,
    String,
    Arc<std::sync::RwLock<crate::blockmap::MapTable>>,
    crate::manifest3::FolderManifests,
);

impl Engine {
    /// The folders whose keys this device holds, with their tables and
    /// manifests brought up to date.
    fn fsck_folders(&self, view: &View3) -> Result<Vec<HeldFolder>> {
        let mut out = Vec::new();
        for (rec, _) in self.folders() {
            if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
                continue;
            }
            let id = members3::bin(&rec.folder_id)?;
            let (manifests, _) = self.pull_folder_records(&id, view)?;
            out.push((id, rec.name.clone(), self.table3(&id)?, manifests));
        }
        Ok(out)
    }

    /// `fsck` of format 3 over the hot storages (cold ones are left
    /// unchecked: reading them costs a retrieval).
    pub fn fsck3(&mut self, verify: bool) -> Result<Fsck3Report> {
        let task = activity::start(activity::FSCK, "", 0, activity::Unit::Items);
        task.set_phase("scan");
        self.pull_ledger_once()?;
        let view = self.view3()?;
        let storages = self.open_storages(false)?;
        let descs: Vec<StorageDesc> = storages
            .iter()
            .map(|(spec, b)| StorageDesc {
                name: spec.name().to_string(),
                storage: b.as_ref(),
                cold: spec.is_cold(),
                meta: !spec.is_data_only() && !spec.is_carrier(),
                media: crate::media::Media::Unknown,
            })
            .collect();
        let folders = self.fsck_folders(&view)?;
        let guards: Vec<_> = folders
            .iter()
            .map(|(_, _, t, _)| t.read().unwrap_or_else(|e| e.into_inner()))
            .collect();
        let inputs: Vec<FolderInput> = folders
            .iter()
            .zip(&guards)
            .map(|((id, name, _, m), t)| FolderInput {
                id: *id,
                name: name.clone(),
                map: t,
                manifests: m,
            })
            .collect();
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = members3::EngineTrust {
            inner: self.f3.members.trust(),
            view: &view,
        };
        let probe = AcceptorProbe {
            vault,
            keys: &keys,
            trust: &trust,
        };
        // With `--verify` every claimed pack is read whole: the task counts
        // the blocks the folders' maps place in each (a pack nobody here
        // can open counts as one), and good packs are recorded with
        // `pack_verified` (another device's check of a copy is what counts
        // as independent verification).
        let mut members: HashMap<[u8; 32], u64> = HashMap::new();
        if verify {
            for (_, _, t, _) in &folders {
                let t = t.read().unwrap_or_else(|e| e.into_inner());
                let mut seen: HashSet<([u8; 32], u32)> = HashSet::new();
                for r in t.scan().flatten() {
                    if seen.insert((r.place.pack, r.place.offset)) {
                        *members.entry(r.place.pack).or_default() += 1;
                    }
                }
            }
            let total: u64 = view
                .packs
                .keys()
                .map(|id| {
                    members.get(id).copied().unwrap_or(1) * view.holders(id).len().max(1) as u64
                })
                .sum();
            task.step("verify", total, activity::Unit::Items);
        }
        let verify_one = |c: &crate::fsck3::PackCheck| -> PackVerdict {
            match crate::blockmap::class_of_len(c.class_len)
                .map(|class| crate::gc3::verify_pack(c.backend, &c.pack, class))
            {
                None => PackVerdict::Corrupt(format!("{} bytes is no size class", c.class_len)),
                Some(Ok(v)) => match v.check {
                    crate::gc3::PackCheck::Good => PackVerdict::Ok,
                    crate::gc3::PackCheck::Missing => PackVerdict::Missing,
                    crate::gc3::PackCheck::WrongLength(n) => {
                        PackVerdict::Corrupt(format!("it is {n} bytes long"))
                    }
                    crate::gc3::PackCheck::Mismatch => {
                        PackVerdict::Corrupt("its bytes do not hash to its id".into())
                    }
                },
                Some(Err(e)) => PackVerdict::Unreadable(format!("{e:#}")),
            }
        };
        let verified: std::sync::Mutex<Vec<Event3>> = Default::default();
        let counter = task.counter();
        let verify_pack = |c: &crate::fsck3::PackCheck| -> PackVerdict {
            for _ in 0..members.get(&c.pack).copied().unwrap_or(1) {
                counter.advance(1);
            }
            let verdict = verify_one(c);
            if verdict == PackVerdict::Ok {
                verified
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(Event3::PackVerified(crate::ledger3::events::PackOn {
                        storage: c.storage.to_string(),
                        pack: c.pack,
                    }));
            }
            verdict
        };
        let input = Fsck3Input {
            view: &view,
            storages: &descs,
            folders: &inputs,
            records: Some(&probe),
            refused: Some(&self.f3.members.refused),
            modified_utc: None,
            verify_pack: if verify { Some(&verify_pack) } else { None },
            now_utc: util::now_utc(),
        };
        let out = crate::fsck3::fsck(&input, &Fsck3Options { verify });
        drop(guards);
        let events = verified.into_inner().unwrap_or_else(|e| e.into_inner());
        if !events.is_empty() && !self.vault.member {
            self.f3.pending.extend(events);
            self.commit_batch()?;
        }
        out
    }

    /// The ciphertext of `row`'s block from this device: the block cache,
    /// or a current file on disk cut and sealed again (chunking and sealing
    /// are deterministic).
    fn block_from_here(&self, folder: &FolderId, row: &MapRow) -> Option<Vec<u8>> {
        let object = ObjectName::from_bytes(&row.object);
        if let Some(b) = self.cached_object(&object) {
            return Some(b);
        }
        let (rec, root) = self.resolve_folder(folder.as_str()).ok()?;
        let fk = self.folder_keys(&rec).ok()?;
        let state = self.load_state(&rec.folder_id).ok()?;
        for f in state.files.values().filter(|f| !f.deleted) {
            let Some(index) = f.chunks.iter().position(|c| c.object == object) else {
                continue;
            };
            if !state
                .local_index
                .get(&f.path)
                .is_some_and(|ix| ix.content_hash == f.content_hash)
            {
                continue;
            }
            let disk = self.disk_of(&root, &state, &f.path);
            let handle = fs::File::open(&disk).ok()?;
            let chunker = Chunker::new(
                std::io::BufReader::new(handle),
                self.chunker_for(f.size, &fk),
            )
            .ok()?;
            let plain = chunker.into_iter().nth(index)?.ok()?;
            let c = &f.chunks[index];
            let ct =
                crate::chunk_seal::seal_chunk(&fk, &self.vault.vault_id, &c.chunk, c.epoch, &plain)
                    .ok()?;
            if crypto::hash(&ct) == row.object {
                return Some(ct);
            }
        }
        None
    }

    /// The damaged pack copies an `fsck` found, as repair queue items (one
    /// per pack and storage).
    pub(super) fn fsck3_damage(view: &View3, f: &Fsck3Report, now: i64) -> Vec<Damage> {
        let mut out = Vec::new();
        for (i, kind) in f
            .missing_copies
            .iter()
            .map(|i| (i, DamageKind::Missing))
            .chain(
                f.corrupt_copies
                    .iter()
                    .chain(&f.wrong_length)
                    .map(|i| (i, DamageKind::Corrupt)),
            )
        {
            let pack = hash32(&i.pack);
            out.push(repair::pack_damage(
                view, &pack, &i.storage, kind, "fsck", now,
            ));
        }
        out
    }

    /// One repair run of format 3 over the repair queue (with `scan`, after
    /// an `fsck --verify` that queues what it finds). For each damaged copy
    /// of a pack on a storage of this device: a copy that reads intact by
    /// now leaves the queue; a missing copy is copied whole from another
    /// storage that holds the pack intact (no key needed); otherwise the
    /// pack's members are taken from the damaged copy, the same place on
    /// another storage, the block cache, another pack, this device's file,
    /// a peer, or (with `from_cold`) a cold storage, and written into a new
    /// pack there (`gc3::repair_pack`, which marks members no copy gives
    /// `lost`). A missing pack nothing can be rebuilt from stays queued with
    /// the reason and is tried again a day later. Returns the report and
    /// the queue to keep.
    pub(super) fn run_repair(
        &mut self,
        opts: &RepairOptions,
    ) -> Result<(RepairReport, Vec<Damage>)> {
        let now = util::now_utc();
        let mut report = RepairReport {
            started_utc: now,
            dry_run: opts.dry_run,
            ..Default::default()
        };
        let mut queue = self.load_repair_queue();
        if opts.scan {
            let mut f = self.fsck3(true)?;
            // Transferrers empty themselves on purpose: never repaired.
            let carriers: BTreeSet<String> = self
                .config
                .storages
                .iter()
                .filter(|s| s.is_carrier())
                .map(|s| s.name().to_string())
                .collect();
            f.missing_copies.retain(|i| !carriers.contains(&i.storage));
            f.corrupt_copies.retain(|i| !carriers.contains(&i.storage));
            f.wrong_length.retain(|i| !carriers.contains(&i.storage));
            let view = self.view3()?;
            repair::merge_damage(&mut queue, Self::fsck3_damage(&view, &f, now));
        } else {
            self.pull_ledger_once()?;
        }
        let mut view = self.view3()?;
        let folders = self.fsck_folders(&view)?;
        let specs: BTreeMap<String, StorageSpec> = self
            .config
            .storages
            .iter()
            .map(|s| (s.name().to_string(), s.clone()))
            .collect();
        // Sources: every storage but cold ones (read only when asked).
        let mut readable = StorageSet::default();
        let mut all = StorageSet::default();
        for spec in specs.values() {
            let Ok(b) = self.open_spec(spec) else {
                continue;
            };
            let b: Arc<dyn Storage> = Arc::from(b);
            let info = if spec.is_cold() {
                StorageInfo::cold(self.storage_price(spec.name()).as_ref())
            } else {
                StorageInfo::HOT
            };
            all.add(b.clone(), info);
            if (!spec.is_cold() || opts.from_cold) && !spec.is_carrier() {
                readable.add(b, info);
            }
        }
        let cold_names: BTreeSet<String> = specs
            .values()
            .filter(|s| s.is_cold())
            .map(|s| s.name().to_string())
            .collect();
        let mut keep: Vec<Damage> = Vec::new();
        let (mut packs_done, mut bytes_done) = (0u64, 0u64);
        for mut d in queue {
            if d.retry_utc > now && !opts.retry_all {
                report.left_for_next_run += 1;
                keep.push(d);
                continue;
            }
            let pack: [u8; 32] = match d.object.as_bytes().try_into() {
                Ok(p) => p,
                Err(_) => {
                    report.not_needed += 1;
                    continue;
                }
            };
            // A storage that is gone, a transferrer, or a copy the ledger
            // no longer holds there (dropped on purpose): nothing to do.
            let Some(spec) = specs.get(&d.storage) else {
                report.not_needed += 1;
                continue;
            };
            let class = match view.pack(&pack) {
                Some(p) if !spec.is_carrier() && view.is_held(&pack, &d.storage) => p.class,
                _ => {
                    report.not_needed += 1;
                    continue;
                }
            };
            let size = crate::ledger3::events::class_bytes(class).unwrap_or(0);
            if packs_done >= opts.max_blocks
                || (packs_done > 0 && bytes_done.saturating_add(size) > opts.max_bytes)
            {
                report.left_for_next_run += 1;
                keep.push(d);
                continue;
            }
            packs_done += 1;
            bytes_done += size;
            report.found += 1;
            let Some(target) = all.storages.get(&d.storage).map(|(s, _)| s.clone()) else {
                report.unreachable.push(d.storage.clone());
                d.retry_utc = now + 3600;
                keep.push(d);
                continue;
            };
            let v = match crate::gc3::verify_pack(target.as_ref(), &pack, class) {
                Ok(v) => v,
                Err(e) => {
                    report.unreachable.push(format!("{} ({e:#})", d.storage));
                    d.retry_utc = now + 3600;
                    keep.push(d);
                    continue;
                }
            };
            let (damaged, missing) = match v.check {
                crate::gc3::PackCheck::Good => {
                    report.already_intact += 1;
                    continue;
                }
                crate::gc3::PackCheck::Missing => (Vec::new(), true),
                _ => (v.damaged.unwrap_or_default(), false),
            };
            d.kind = if missing {
                DamageKind::Missing
            } else {
                DamageKind::Corrupt
            };
            let held_folder = view.pack_folder(&pack).and_then(|f| {
                folders
                    .iter()
                    .find(|(id, _, _, _)| *id == f)
                    .map(|(id, n, t, _)| (*id, n.clone(), t.clone()))
            });
            let rows: Vec<MapRow> = held_folder
                .as_ref()
                .map(|(_, _, t)| {
                    let t = t.read().unwrap_or_else(|e| e.into_inner());
                    let mut rows: BTreeMap<u32, MapRow> = BTreeMap::new();
                    for r in t.scan().flatten() {
                        if r.place.pack == pack {
                            rows.entry(r.place.offset).or_insert(r);
                        }
                    }
                    rows.into_values().collect()
                })
                .unwrap_or_default();
            let folder_name = held_folder
                .as_ref()
                .map(|(_, n, _)| n.clone())
                .unwrap_or_default();
            let copy = |object: &[u8; 32], source: String, bytes: u64| RepairedCopy {
                folder: folder_name.clone(),
                storage: d.storage.clone(),
                object: hex::encode(object),
                kind: d.kind,
                source,
                bytes,
            };
            // 1. A missing copy: whole from another storage holding it.
            if missing {
                let mut with_target = readable.clone();
                with_target.add(target.clone(), crate::gc3::Storages::info(&all, &d.storage));
                let src = view
                    .holders(&pack)
                    .into_iter()
                    .filter(|h| *h != d.storage)
                    .find(|h| {
                        with_target.storages.get(*h).is_some_and(|(s, _)| {
                            s.exists(&crate::packs::pack_key(&hex::encode(pack)))
                                .unwrap_or(false)
                        })
                    })
                    .map(str::to_string);
                if let Some(src) = &src {
                    let done = if opts.dry_run {
                        true
                    } else {
                        match crate::gc3::copy_missing_pack(
                            &view,
                            &pack,
                            &d.storage,
                            &with_target,
                            false,
                        )? {
                            Some(ev) => {
                                self.f3.pending.push(ev);
                                report.bytes_written += size;
                                true
                            }
                            None => false,
                        }
                    };
                    if done {
                        if rows.is_empty() {
                            report
                                .repaired
                                .push(copy(&pack, format!("storage {src}"), size));
                        }
                        for r in &rows {
                            report.repaired.push(copy(
                                &r.object,
                                format!("storage {src}"),
                                u64::from(r.place.len),
                            ));
                        }
                        continue;
                    }
                }
            }
            // 2. Member by member: needs the folder's map and the writer role.
            let Some((folder, _, _)) = held_folder.as_ref().filter(|_| !rows.is_empty()) else {
                let reason = if missing {
                    "no storage holds an intact copy of the pack, and no folder this device holds lists its blocks".to_string()
                } else {
                    "no folder this device holds lists the blocks of the pack".to_string()
                };
                self.keep_unrepairable(&mut report, &mut keep, d, &folder_name, reason, now);
                continue;
            };
            let folder = *folder;
            if !self.standing3(&folder).may_repair() {
                let reason =
                    "this device may not write the folder's block map (viewer role)".to_string();
                self.keep_unrepairable(&mut report, &mut keep, d, &folder_name, reason, now);
                continue;
            }
            // Members the damaged copy does not give intact, and where else
            // they are; read before the repair writes anything.
            let fid = FolderId::from_bytes(&folder);
            let mut here: HashMap<[u8; 32], (Vec<u8>, String)> = HashMap::new();
            let mut cold_hint: BTreeSet<String> = BTreeSet::new();
            let mut same_place = 0u64;
            {
                let table = self.table3(&folder)?;
                let t = table.read().unwrap_or_else(|e| e.into_inner());
                let key = crate::packs::pack_key(&hex::encode(pack));
                for r in &rows {
                    let (o, l) = (r.place.offset as usize, r.place.len as usize);
                    if damaged
                        .get(o..o + l)
                        .is_some_and(|b| crypto::hash(b) == r.object)
                    {
                        continue;
                    }
                    let same = view.holders(&pack).into_iter().any(|h| {
                        h != d.storage
                            && readable.storages.get(h).is_some_and(|(s, _)| {
                                s.get_range(&key, o as u64, l as u64)
                                    .ok()
                                    .flatten()
                                    .is_some_and(|b| crypto::hash(&b) == r.object)
                            })
                    });
                    if same {
                        same_place += 1;
                        continue;
                    }
                    let object = ObjectName::from_bytes(&r.object);
                    if let Some(b) = self.cached_object(&object) {
                        here.insert(r.object, (b, "block cache".into()));
                        continue;
                    }
                    let hot = crate::gc3::other_places(&t, &view, &readable, pack);
                    if let Some(b) = hot(r) {
                        let from = t
                            .rows_of(&r.object)
                            .ok()
                            .into_iter()
                            .flatten()
                            .filter(|x| x.place.pack != pack)
                            .flat_map(|x| {
                                view.holders(&x.place.pack)
                                    .into_iter()
                                    .map(str::to_string)
                                    .collect::<Vec<_>>()
                            })
                            .find(|h| readable.storages.contains_key(h))
                            .unwrap_or_default();
                        let label = if cold_names.contains(&from) {
                            format!("cold storage {from}")
                        } else {
                            format!("storage {from}")
                        };
                        here.insert(r.object, (b, label));
                        continue;
                    }
                    if let Some(b) = self.block_from_here(&fid, r) {
                        here.insert(r.object, (b, "local file".into()));
                        continue;
                    }
                    if let Some((dev, b)) = self.peers.as_ref().and_then(|p| p.get(&object)) {
                        if crypto::hash(&b) == r.object {
                            here.insert(r.object, (b, format!("peer {}", dev.short())));
                            continue;
                        }
                    }
                    // Where a copy would be if cold storages were read.
                    for x in t.rows_of(&r.object).ok().into_iter().flatten() {
                        for h in view.holders(&x.place.pack) {
                            if cold_names.contains(h) && h != d.storage {
                                cold_hint.insert(h.to_string());
                            }
                        }
                    }
                }
            }
            if missing && here.is_empty() && same_place == 0 {
                let reason = if !cold_hint.is_empty() && !opts.from_cold {
                    format!(
                        "a copy is on cold storage {}; run `varsto repair --from-cold` to read it (retrieval fees may apply)",
                        cold_hint.into_iter().collect::<Vec<_>>().join(", ")
                    )
                } else {
                    "no storage holds an intact copy, and no device here or nearby has the blocks"
                        .to_string()
                };
                self.keep_unrepairable(&mut report, &mut keep, d, &folder_name, reason, now);
                continue;
            }
            if opts.dry_run {
                for (o, (b, src)) in &here {
                    report.repaired.push(copy(o, src.clone(), b.len() as u64));
                }
                continue;
            }
            let fetched: HashMap<[u8; 32], Vec<u8>> =
                here.iter().map(|(o, (b, _))| (*o, b.clone())).collect();
            let r =
                self.repair_pack3(&folder, &d.storage, &pack, &damaged, &fetched, &all, &view)?;
            // The repair sealed a map record and a batch: the next pack is
            // repaired over the view that has them (a map writer built on
            // the older view writes over this record's rows).
            view = self.view3()?;
            for o in &r.from_same_place {
                report.repaired.push(copy(o, "another storage".into(), 0));
            }
            for o in &r.from_elsewhere {
                let (b, src) = here
                    .get(o)
                    .map(|(b, s)| (b.len() as u64, s.clone()))
                    .unwrap_or_default();
                report.repaired.push(copy(o, src, b));
            }
            report.bytes_written += r.new_packs.len() as u64 * size;
            for o in &r.lost {
                report.unrepairable.push(Unrepairable {
                    folder: folder_name.clone(),
                    storage: d.storage.clone(),
                    object: hex::encode(&o[..6]),
                    kind: d.kind,
                    reason: "no good copy of the block is left anywhere; the file using it is damaged until a device that holds it writes it again".into(),
                });
            }
        }
        report.finished_utc = util::now_utc();
        Ok((report, keep))
    }

    /// Note a copy that could not be repaired: reported, and kept in the
    /// queue for a retry a day later (a peer may come online, a disk may be
    /// attached).
    fn keep_unrepairable(
        &self,
        report: &mut RepairReport,
        keep: &mut Vec<Damage>,
        mut d: Damage,
        folder: &str,
        reason: String,
        now: i64,
    ) {
        report.unrepairable.push(Unrepairable {
            folder: if folder.is_empty() {
                self.folder_label3(&d.folder)
            } else {
                folder.to_string()
            },
            storage: d.storage.clone(),
            object: d.object.short().to_string(),
            kind: d.kind,
            reason: reason.clone(),
        });
        d.reason = Some(reason);
        d.retry_utc = now + 24 * 3600;
        keep.push(d);
    }

    /// `gc3::repair_pack` for one damaged pack of `folder` on `storage`.
    #[allow(clippy::too_many_arguments)]
    fn repair_pack3(
        &mut self,
        folder: &Id16,
        storage: &str,
        pack: &[u8; 32],
        damaged: &[u8],
        here: &HashMap<[u8; 32], Vec<u8>>,
        storages: &StorageSet,
        view: &View3,
    ) -> Result<crate::gc3::RepairReport> {
        let me = self.me3();
        let rec = self
            .keyring
            .folders
            .get(&FolderId::from_bytes(folder))
            .cloned()
            .ok_or_else(|| anyhow!("no folder {}", hex::encode(folder)))?;
        let epoch = self.folder_keys(&rec)?.epoch;
        let standing = self.standing3(folder);
        let _ = me;
        self.with_map_writer(folder, epoch, view, |writer, t, out, sink| {
            let fetch = |row: &MapRow| here.get(&row.object).cloned();
            crate::gc3::repair_pack(
                &standing, writer, t, view, out, storages, storage, pack, damaged, &fetch, sink,
            )
        })
    }
}

fn hash32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = hex::decode_to_slice(s, &mut out);
    out
}
