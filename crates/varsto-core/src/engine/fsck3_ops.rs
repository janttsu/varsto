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
use crate::blockmap::{MapRow, MapWriter};
use crate::fsck3::{
    AcceptorProbe, FixOptions, FolderInput, Fsck3Input, Fsck3Options, Fsck3Report, PackVerdict,
    StorageDesc,
};
use crate::gc3::{Commit, MapOut, Standing, StorageInfo, StorageSet};
use crate::ledger3::events::Event as Event3;
use crate::ledger3::{self, LedgerView as View3};
use crate::record::{DeviceSigner, Id16, RecordWriter};
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
    fn fsck_folders3(&self, view: &View3) -> Result<Vec<HeldFolder>> {
        let mut out = Vec::new();
        for (rec, _) in self.folders() {
            if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
                continue;
            }
            let id = members3::bin(&rec.folder_id)?;
            let (manifests, _) = self.pull_folder_records3(&id, view)?;
            out.push((id, rec.name.clone(), self.table3(&id)?, manifests));
        }
        Ok(out)
    }

    /// `fsck` of format 3 over the hot storages (cold ones are left
    /// unchecked: reading them costs a retrieval).
    pub fn fsck3(&mut self, verify: bool) -> Result<Fsck3Report> {
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
        let folders = self.fsck_folders3(&view)?;
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
        let verify_pack = |c: &crate::fsck3::PackCheck| -> PackVerdict {
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
        crate::fsck3::fsck(&input, &Fsck3Options { verify })
    }

    /// The ciphertext of `row`'s block from this device: the block cache,
    /// or a current file on disk cut and sealed again (chunking and sealing
    /// are deterministic).
    fn block_from_here3(&self, folder: &FolderId, row: &MapRow) -> Option<Vec<u8>> {
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

    /// One repair run of format 3: `fsck` (with `--verify` when scanning),
    /// then whole-pack copies for missing copies and member repairs for
    /// damaged ones. Returns the report and the queue to keep.
    pub(super) fn run_repair3(
        &mut self,
        opts: &RepairOptions,
    ) -> Result<(RepairReport, Vec<Damage>)> {
        let now = util::now_utc();
        let mut report = RepairReport {
            started_utc: now,
            dry_run: opts.dry_run,
            ..Default::default()
        };
        let mut f = self.fsck3(true)?;
        let view = self.view3()?;
        let folders = self.fsck_folders3(&view)?;
        let storages = self.open_storages(opts.from_cold)?;
        // Which folder's table lists a pack's members.
        let folder_of = |pack: &[u8; 32]| -> Option<(Id16, String)> {
            let f = view.pack_folder(pack)?;
            folders
                .iter()
                .find(|(id, _, _, _)| *id == f)
                .map(|(id, n, _, _)| (*id, n.clone()))
        };
        let members_of = |folder: &Id16, pack: &[u8; 32]| -> Vec<MapRow> {
            folders
                .iter()
                .find(|(id, _, _, _)| id == folder)
                .map(|(_, _, t, _)| {
                    let t = t.read().unwrap_or_else(|e| e.into_inner());
                    let mut rows: BTreeMap<u32, MapRow> = BTreeMap::new();
                    for r in t.scan().flatten() {
                        if r.place.pack == *pack {
                            rows.entry(r.place.offset).or_insert(r);
                        }
                    }
                    rows.into_values().collect()
                })
                .unwrap_or_default()
        };
        // 1. Copies missing on a storage: copied whole from another.
        if !opts.dry_run {
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
            let input = Fsck3Input {
                view: &view,
                storages: &descs,
                folders: &[],
                records: None,
                refused: None,
                modified_utc: None,
                verify_pack: None,
                now_utc: now,
            };
            crate::fsck3::fix(&input, &mut f, &FixOptions::default())?;
        } else {
            for i in &f.missing_copies {
                let src = view
                    .holders(&hash32(&i.pack))
                    .into_iter()
                    .find(|h| *h != i.storage)
                    .map(|h| format!("storage {h}"))
                    .unwrap_or_default();
                f.fixed.push(crate::fsck3::FixAction {
                    pack: i.pack.clone(),
                    from: src.strip_prefix("storage ").unwrap_or("").to_string(),
                    to: i.storage.clone(),
                    bytes: 0,
                });
            }
        }
        for a in &f.fixed {
            let pack = hash32(&a.pack);
            let Some((folder, name)) = folder_of(&pack) else {
                continue;
            };
            for r in members_of(&folder, &pack) {
                report.repaired.push(RepairedCopy {
                    folder: name.clone(),
                    storage: a.to.clone(),
                    object: hex::encode(r.object),
                    kind: DamageKind::Missing,
                    source: format!("storage {}", a.from),
                    bytes: u64::from(r.place.len),
                });
            }
        }
        for i in &f.fix_failed {
            report.unrepairable.push(Unrepairable {
                folder: String::new(),
                storage: i.storage.clone(),
                object: i.pack.clone(),
                kind: DamageKind::Missing,
                reason: i.detail.clone(),
            });
        }
        // 2. Damaged copies: the good members into a new pack there.
        let damaged: Vec<crate::fsck3::PackIssue> = f
            .corrupt_copies
            .iter()
            .chain(&f.wrong_length)
            .cloned()
            .collect();
        report.found = (f.fixed.len() + f.fix_failed.len() + damaged.len()) as u64;
        for issue in damaged {
            let pack = hash32(&issue.pack);
            let Some((folder, name)) = folder_of(&pack) else {
                report.unrepairable.push(Unrepairable {
                    folder: String::new(),
                    storage: issue.storage.clone(),
                    object: issue.pack.clone(),
                    kind: DamageKind::Corrupt,
                    reason: "no folder this device holds lists the pack".into(),
                });
                continue;
            };
            let Some((_, backend)) = storages.iter().find(|(s, _)| s.name() == issue.storage)
            else {
                continue;
            };
            let class = view.pack(&pack).map_or(0, |p| p.class);
            let v = crate::gc3::verify_pack(backend.as_ref(), &pack, class)?;
            let Some(bytes) = v.damaged else {
                continue;
            };
            let rows = members_of(&folder, &pack);
            let fid = FolderId::from_bytes(&folder);
            // Members to take from this device, read before the repair.
            let mut here: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
            for r in &rows {
                let (o, l) = (r.place.offset as usize, r.place.len as usize);
                let good = bytes
                    .get(o..o + l)
                    .is_some_and(|b| crypto::hash(b) == r.object);
                if !good {
                    if let Some(ct) = self.block_from_here3(&fid, r) {
                        here.insert(r.object, ct);
                    }
                }
            }
            if opts.dry_run {
                for r in &rows {
                    if here.contains_key(&r.object) {
                        report.repaired.push(RepairedCopy {
                            folder: name.clone(),
                            storage: issue.storage.clone(),
                            object: hex::encode(r.object),
                            kind: DamageKind::Corrupt,
                            source: "local file".into(),
                            bytes: u64::from(r.place.len),
                        });
                    }
                }
                continue;
            }
            let r = self.repair_pack3(
                &folder,
                &issue.storage,
                &pack,
                &bytes,
                &here,
                &storages,
                &view,
            )?;
            for o in &r.from_same_place {
                report.repaired.push(RepairedCopy {
                    folder: name.clone(),
                    storage: issue.storage.clone(),
                    object: hex::encode(o),
                    kind: DamageKind::Corrupt,
                    source: "another storage".into(),
                    bytes: 0,
                });
            }
            for o in &r.from_elsewhere {
                report.repaired.push(RepairedCopy {
                    folder: name.clone(),
                    storage: issue.storage.clone(),
                    object: hex::encode(o),
                    kind: DamageKind::Corrupt,
                    source: "local file".into(),
                    bytes: here.get(o).map_or(0, |b| b.len() as u64),
                });
            }
            for o in &r.lost {
                report.unrepairable.push(Unrepairable {
                    folder: name.clone(),
                    storage: issue.storage.clone(),
                    object: hex::encode(o),
                    kind: DamageKind::Corrupt,
                    reason: "no good copy of the block is left anywhere".into(),
                });
            }
        }
        report.finished_utc = util::now_utc();
        // What could not be repaired stays queued, with its reason, and is
        // tried again a day later (the losses notified once).
        let queue = report
            .unrepairable
            .iter()
            .map(|u| Damage {
                folder: FolderId::default(),
                chunk: ChunkId::from_hex(&u.object).unwrap_or_default(),
                object: ObjectName::from_hex(&u.object).unwrap_or_default(),
                storage: u.storage.clone(),
                kind: u.kind,
                found_by: "fsck".into(),
                found_utc: now,
                retry_utc: now + 24 * 3600,
                reason: Some(u.reason.clone()),
            })
            .collect();
        Ok((report, queue))
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
        storages: &OpenStorages,
        view: &View3,
    ) -> Result<crate::gc3::RepairReport> {
        let me = self.me3();
        let vault = members3::bin(&self.vault.vault_id)?;
        let fid = FolderId::from_bytes(folder);
        let rec = self
            .keyring
            .folders
            .get(&fid)
            .cloned()
            .ok_or_else(|| anyhow!("no folder {}", hex::encode(folder)))?;
        let epoch = self.folder_keys(&rec)?.epoch;
        let table = self.table3(folder)?;
        let (key_id, key) = {
            let keys = self.vault_keys3();
            let e = keys.newest_epoch();
            (
                ledger3::scope::ledger_key_id(e),
                keys.ledger(e).ok_or_else(|| anyhow!("no vault key"))?,
            )
        };
        let mut lamports = std::collections::VecDeque::new();
        for _ in 0..4 {
            lamports.push_back(self.tick()?);
        }
        let set = self.storage_set3(storages)?;
        let standing = Standing {
            device: me,
            role: self.f3.members.role(&me, folder),
            member: false,
            holds_k10: true,
        };
        let meta: Vec<&dyn Storage> = storages
            .iter()
            .filter(|(s, _)| !s.is_carrier() && !s.is_data_only() && !s.is_cold())
            .map(|(_, b)| &**b)
            .collect();
        let vault_keys = self.vault_keys3();
        let mut writer = MapWriter::from_view(*folder, me, epoch, view, 0);
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
            storages,
            last: lamports.back().copied().unwrap_or(0),
            lamports,
        };
        let mut t = table.write().unwrap_or_else(|e| e.into_inner());
        let fetch = |row: &MapRow| here.get(&row.object).cloned();
        crate::gc3::repair_pack(
            &standing,
            &mut writer,
            &mut t,
            view,
            &out,
            &set,
            storage,
            pack,
            damaged,
            &fetch,
            &mut sink,
        )
    }

    /// The opened storages as the set garbage collection and repair use.
    pub(super) fn storage_set3(&self, storages: &OpenStorages) -> Result<StorageSet> {
        let mut set = StorageSet::default();
        for (spec, _) in storages {
            let b: Arc<dyn Storage> = Arc::from(self.open_spec(spec)?);
            let info = if spec.is_cold() {
                StorageInfo::cold(self.storage_price(spec.name()).as_ref())
            } else {
                StorageInfo::HOT
            };
            set.add(b, info);
        }
        Ok(set)
    }
}

fn hash32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = hex::decode_to_slice(s, &mut out);
    out
}
