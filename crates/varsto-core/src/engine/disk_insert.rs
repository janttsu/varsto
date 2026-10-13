// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Filling pool disks and the insert routine (`varsto disk insert`).
//!
//! Filling picks what the pool lacks and places whole files on the disk
//! being filled where it can: a file's blocks are split over disks only
//! when the file cannot fit on any disk of the pool, or at the end of a
//! fill, where the last free space is used by splitting one file rather
//! than left empty. Every object is read back from the disk before it
//! counts (`pool::write_checked`).
//!
//! The insert routine runs on a disk that was just plugged in and mounted:
//! tidy from listings alone, re-hash the copies whose last check is older
//! than the pool's `verify_after_days`, fill, write the disk's index and
//! sync. Unmounting is the caller's (the command line does it on Linux).

use super::*;

/// Progress of one phase of a disk operation, for the caller to show.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiskProgress {
    /// "tidy", "verify" or "fill".
    pub phase: &'static str,
    pub objects_done: u64,
    pub objects_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

/// What one fill wrote.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FillOutcome {
    pub objects: u64,
    pub bytes: u64,
    /// Files whose missing blocks all went to this disk.
    pub files_whole: u64,
    /// Files only part of whose missing blocks went here (the rest waits
    /// for another disk).
    pub files_split: u64,
    /// Objects that were wanted but no source had (they are tried again
    /// at the next fill).
    pub unavailable: u64,
    /// Set when the disk returned wrong bytes twice: the fill stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
}

/// Which phases `disk_insert` runs.
#[derive(Clone, Copy, Debug)]
pub struct InsertOptions {
    pub verify: bool,
    pub fill: bool,
}

impl Default for InsertOptions {
    fn default() -> Self {
        InsertOptions {
            verify: true,
            fill: true,
        }
    }
}

/// What `disk_insert` did.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiskInsertReport {
    pub pool: String,
    pub label: String,
    pub mount: PathBuf,
    pub tidy: pool::TidyOutcome,
    /// Copies re-hashed because their last check was older than
    /// `verify_after_days`, and what that found.
    pub verify_after_days: u32,
    pub verified_objects: u64,
    pub verified_bytes: u64,
    pub bad: Vec<String>,
    pub missing: Vec<String>,
    pub fill: FillOutcome,
    /// The ledger could not be brought up to date first (offline): files
    /// the disk holds that this device does not know were kept, not removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_note: Option<String>,
    pub group_copies: u32,
    pub group_short: u64,
}

/// Blocks a fill may write: one per object.
struct Need {
    folder: FolderId,
    chunk: ChunkId,
    epoch: u32,
    size: u64,
    /// Local paths of files that use the block (to re-encrypt it from).
    files: Vec<PathBuf>,
    /// The pool holds no copy at all (not just too few places).
    first_copy: bool,
    /// Storages claiming a copy, from the ledger.
    copies: usize,
}

/// Ciphertext is a little larger than the chunk.
fn estimate(size: u64) -> u64 {
    size + 64
}

impl Engine {
    /// Fill one attached disk with blocks of current files that the pool
    /// holds on no disk (or, under a disk group rule, in too few places),
    /// within the disk's reserve. Folders whose placement leaves the pool
    /// out are skipped. Blocks come from the pool's other attached disks or
    /// the other hot storages, or are re-encrypted from local files; no
    /// other storage is changed.
    ///
    /// Order: files with blocks the pool lacks entirely before files that
    /// only need further copies; then files whose blocks have the fewest
    /// copies anywhere; then larger files first (first fit decreasing, which
    /// keeps files whole and fills the disk well); then older files. Whole
    /// files that fit go first; a file that fits on no disk of the pool is
    /// split; at the end the remaining space takes parts of the largest
    /// remaining file, so space is not left empty.
    pub(super) fn fill_disk_with(
        &mut self,
        spec: &StorageSpec,
        pool: &PoolStorage,
        disk_id: &str,
        progress: &mut dyn FnMut(&DiskProgress),
    ) -> Result<FillOutcome> {
        let have = pool.objects();
        let view = self.view()?;
        let mut needed: BTreeMap<ObjectName, Need> = BTreeMap::new();
        // (folder, path) -> (mtime, objects the file still needs on the pool).
        let mut files: Vec<(i64, String, Vec<ObjectName>)> = Vec::new();
        let mut folder_keys: BTreeMap<FolderId, FolderKeys> = BTreeMap::new();
        for (rec, mount) in self.folders() {
            let Ok(rec) = self.with_key(&rec) else {
                continue; // a locked Strongroom is skipped
            };
            let targets = self.write_targets(&rec);
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| !f.deleted) {
                let mut objs: Vec<ObjectName> = Vec::new();
                for c in &f.chunks {
                    let key = chunk_storage_key(&c.object);
                    let record = view.locate(&rec.folder_id, &c.chunk);
                    if !pool.wants_copy(disk_id, &key) || !targets.wants(spec.name(), record) {
                        continue;
                    }
                    let n = needed.entry(c.object.clone()).or_insert_with(|| Need {
                        folder: rec.folder_id.clone(),
                        chunk: c.chunk.clone(),
                        epoch: c.epoch,
                        size: c.size,
                        files: Vec::new(),
                        first_copy: !have.contains_key(&key),
                        copies: record.map(|r| r.storages.len()).unwrap_or(0),
                    });
                    if let Some(m) = &mount {
                        n.files.push(m.join(&f.path));
                    }
                    if !objs.contains(&c.object) {
                        objs.push(c.object.clone());
                    }
                }
                if !objs.is_empty() {
                    files.push((f.mtime, format!("{}/{}", rec.folder_id, f.path), objs));
                }
            }
            folder_keys.insert(rec.folder_id.clone(), self.folder_keys(&rec)?);
        }
        let file_bytes =
            |objs: &[ObjectName]| -> u64 { objs.iter().map(|o| estimate(needed[o].size)).sum() };
        files.sort_by_cached_key(|(mtime, path, objs)| {
            let first = objs.iter().any(|o| needed[o].first_copy);
            let copies = objs.iter().map(|o| needed[o].copies).min().unwrap_or(0);
            (
                !first,
                copies,
                std::cmp::Reverse(file_bytes(objs)),
                *mtime,
                path.clone(),
            )
        });
        // Choose what goes to this disk before writing anything.
        let mut left = pool.room(disk_id).unwrap_or(0);
        let largest_disk = pool
            .disks()
            .iter()
            .filter(|d| !d.retired)
            .map(|d| {
                d.capacity_bytes
                    .saturating_sub(pool.reserve(d.capacity_bytes))
            })
            .max()
            .unwrap_or(0);
        let mut chosen: Vec<ObjectName> = Vec::new();
        let mut taken: HashSet<ObjectName> = HashSet::new();
        let (mut whole, mut split) = (0u64, 0u64);
        let mut placed = vec![false; files.len()];
        let remaining = |objs: &[ObjectName], taken: &HashSet<ObjectName>| -> Vec<ObjectName> {
            objs.iter()
                .filter(|o| !taken.contains(*o))
                .cloned()
                .collect()
        };
        // 1. Whole files that fit.
        for (i, (_, _, objs)) in files.iter().enumerate() {
            let rest = remaining(objs, &taken);
            let cost = file_bytes(&rest);
            if cost <= left {
                left -= cost;
                for o in rest {
                    taken.insert(o.clone());
                    chosen.push(o);
                }
                placed[i] = true;
                whole += 1;
            }
        }
        // 2. Files no disk could hold whole, then 3. the last free space:
        // parts of the largest remaining files.
        for pass in [2, 3] {
            for (i, (_, _, objs)) in files.iter().enumerate() {
                if placed[i] || left == 0 {
                    continue;
                }
                let rest = remaining(objs, &taken);
                if pass == 2 && file_bytes(&rest) <= largest_disk {
                    continue;
                }
                let mut any = false;
                for o in rest {
                    let cost = estimate(needed[&o].size);
                    if cost <= left {
                        left -= cost;
                        taken.insert(o.clone());
                        chosen.push(o);
                        any = true;
                    }
                }
                if any {
                    placed[i] = true;
                    split += 1;
                }
            }
        }
        let sources = self.metadata_storages(false)?;
        let mut out = FillOutcome {
            files_whole: whole,
            files_split: split,
            ..Default::default()
        };
        let mut p = DiskProgress {
            phase: "fill",
            objects_total: chosen.len() as u64,
            bytes_total: chosen.iter().map(|o| estimate(needed[o].size)).sum(),
            ..Default::default()
        };
        progress(&p);
        for object in chosen {
            let need = &needed[&object];
            p.objects_done += 1;
            p.bytes_done += estimate(need.size);
            let key = chunk_storage_key(&object);
            // A further copy (disk groups) comes from the disk that has one.
            let mut ct: Option<Vec<u8>> = pool
                .get(&key)
                .ok()
                .flatten()
                .filter(|c| ObjectName::from_bytes(&crypto::hash(c)) == object);
            for (_, backend) in sources.iter().filter(|_| ct.is_none()) {
                if let Ok(Some(c)) = backend.get(&key) {
                    if ObjectName::from_bytes(&crypto::hash(&c)) == object {
                        ct = Some(c);
                        break;
                    }
                }
            }
            if ct.is_none() {
                ct = self.cached_object(&object);
            }
            if ct.is_none() {
                if let Some(fk) = folder_keys.get(&need.folder) {
                    for path in &need.files {
                        if let Ok(c) =
                            self.chunk_ciphertext_from_file(fk, path, &need.chunk, need.epoch)
                        {
                            ct = Some(c);
                            break;
                        }
                    }
                }
            }
            let Some(ct) = ct else {
                out.unavailable += 1;
                progress(&p);
                continue;
            };
            let first_copy = !have.contains_key(&key);
            match pool.add_copy_on_disk(disk_id, &key, &ct) {
                Ok(true) => {
                    out.objects += 1;
                    out.bytes += ct.len() as u64;
                    if first_copy {
                        self.pending.push(Event::ChunkStored {
                            folder: need.folder.clone(),
                            chunk: need.chunk.clone(),
                            object: object.clone(),
                            storage: spec.name().to_string(),
                            size: ct.len() as u64,
                        });
                    }
                }
                Ok(false) => {}
                Err(e) if matches!(pool::pool_error(&e), Some(PoolError::NoRoom { .. })) => {}
                Err(e)
                    if matches!(
                        pool::pool_error(&e),
                        Some(PoolError::WriteNotVerified { .. })
                    ) =>
                {
                    out.failed = Some(format!("{e:#}"));
                    break;
                }
                Err(e) => {
                    self.commit_batch()?;
                    return Err(e);
                }
            }
            progress(&p);
        }
        self.commit_batch()?;
        Ok(out)
    }

    /// `fill_disk_with` without progress; a disk that read back wrong is an error.
    pub(super) fn fill_disk(
        &mut self,
        spec: &StorageSpec,
        pool: &PoolStorage,
        disk_id: &str,
    ) -> Result<(u64, u64)> {
        let out = self.fill_disk_with(spec, pool, disk_id, &mut |_| {})?;
        if let Some(why) = out.failed {
            bail!(why);
        }
        Ok((out.objects, out.bytes))
    }

    /// The insert routine for a disk that was just attached: (1) tidy from
    /// listings alone (queued deletions, leftovers, files nothing references
    /// any more), (2) re-hash every copy whose last check is older than the
    /// pool's `verify_after_days`, (3) fill with what the pool lacks while
    /// the reserve allows, (4) write the disk's index and sync. The ledger
    /// is pulled first when the storages answer, so a file another device
    /// just wrote is not mistaken for an unneeded one; offline, files the
    /// ledger does not know are kept.
    pub fn disk_insert(
        &mut self,
        label: &str,
        opts: InsertOptions,
        progress: &mut dyn FnMut(&DiskProgress),
    ) -> Result<DiskInsertReport> {
        let (spec, pool, disk) = self.find_disk(label)?;
        let mount = pool
            .mount_of(&disk.id)
            .ok_or_else(|| anyhow!("disk {} is not attached", disk.label))?;
        let ledger_note = self
            .pull_ledger()
            .err()
            .map(|e| format!("the ledger could not be brought up to date ({e:#})"));
        let view = self.view()?;
        let mut known: HashSet<String> = HashSet::new();
        for r in view.chunks.values() {
            known.insert(r.object.as_str().to_string());
        }
        progress(&DiskProgress {
            phase: "tidy",
            ..Default::default()
        });
        let offline = ledger_note.is_some();
        let tidy = pool.tidy_disk(&disk.id, &|name: &str| offline || known.contains(name))?;
        let mut report = DiskInsertReport {
            pool: spec.name().to_string(),
            label: disk.label.clone(),
            mount,
            tidy,
            verify_after_days: pool.verify_after_days(),
            ledger_note,
            ..Default::default()
        };
        if opts.verify {
            let cutoff = util::now_utc() - pool.verify_after_days() as i64 * 86_400;
            // A cutoff of now with 0 days: every copy, including ones written a second ago.
            let cutoff = if pool.verify_after_days() == 0 {
                i64::MAX
            } else {
                cutoff
            };
            let stale = pool.stale_on(&disk.id, cutoff);
            let mut p = DiskProgress {
                phase: "verify",
                objects_total: stale.len() as u64,
                bytes_total: stale.iter().map(|(_, s)| s).sum(),
                ..Default::default()
            };
            progress(&p);
            let v = pool.verify_objects(&disk.id, &stale, &mut |n, b| {
                p.objects_done = n;
                p.bytes_done = b;
                progress(&p);
            })?;
            // Re-hashed on the disk: a verification other devices can rely on.
            let mut by_object: BTreeMap<ObjectName, (FolderId, ChunkId)> = BTreeMap::new();
            for ((folder, chunk), r) in view.chunks.iter() {
                by_object.insert(r.object.clone(), (folder.clone(), chunk.clone()));
            }
            for key in &v.verified_keys {
                let Some(object) = key
                    .rsplit('/')
                    .next()
                    .and_then(|n| ObjectName::from_hex(n).ok())
                else {
                    continue;
                };
                if let Some((folder, chunk)) = by_object.get(&object) {
                    self.pending.push(Event::ChunkVerified {
                        folder: folder.clone(),
                        chunk: chunk.clone(),
                        object,
                        storage: spec.name().to_string(),
                    });
                }
            }
            report.verified_objects = v.objects_checked;
            report.verified_bytes = v.bytes_checked;
            report.bad = v.bad;
            report.missing = v.missing;
        }
        if opts.fill && !disk.retired {
            report.fill = self.fill_disk_with(&spec, &pool, &disk.id, progress)?;
        }
        self.commit_batch()?;
        pool.sync_disk(&disk.id)?;
        let disks = pool.disks();
        (report.group_copies, report.group_short) = (pool.copies(), pool.group_shortfall().0);
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(report)
    }

    /// Set after how many days a copy on a disk of the pool is re-hashed at
    /// the next insert (0: every insert re-hashes everything).
    pub fn set_pool_verify_after_days(&mut self, pool_name: &str, days: u32) -> Result<()> {
        if days > 36_500 {
            bail!("verify-after-days must be at most 36500");
        }
        let Some(StorageSpec::Pool {
            verify_after_days, ..
        }) = self
            .config
            .storages
            .iter_mut()
            .find(|s| s.name() == pool_name)
        else {
            bail!("no disk pool named {pool_name}");
        };
        *verify_after_days = days;
        self.config.save(&self.home)
    }

    /// Refuse early what `disk_add` would refuse: an unknown pool or a
    /// label in use (checked before a drive is erased for it).
    pub fn check_new_disk(&self, pool_name: &str, label: &str) -> Result<()> {
        if label.trim().is_empty() {
            bail!("the disk needs a label");
        }
        if !self.pool_specs().iter().any(|s| s.name() == pool_name) {
            bail!("no disk pool named {pool_name}; add one with `varsto storage add-pool {pool_name}`");
        }
        if self.find_disk(label).is_ok() {
            bail!("a disk labelled {label} already exists");
        }
        Ok(())
    }

    /// Like `disk_add_at`, with progress for the fill.
    pub fn disk_add_with(
        &mut self,
        mount: &Path,
        pool_name: &str,
        label: &str,
        place: &str,
        progress: &mut dyn FnMut(&DiskProgress),
    ) -> Result<(DiskAddReport, FillOutcome)> {
        let spec = self
            .pool_specs()
            .into_iter()
            .find(|s| s.name() == pool_name)
            .ok_or_else(|| anyhow!("no disk pool named {pool_name}; add one with `varsto storage add-pool {pool_name}`"))?;
        if self.find_disk(label).is_ok() {
            bail!("a disk labelled {label} already exists");
        }
        let pool = self.open_pool(&spec)?;
        let disk = pool.add_disk_at(mount, label, place)?;
        // A disk no larger than the space the pool keeps free on every disk
        // would silently take nothing: say so.
        let warning = (!pool.has_room(&disk.id, 1)).then(|| {
            format!(
                "{label} has no room above the reserve the pool keeps free on every disk ({} of {}): nothing will be written to it. Use a larger disk, or a pool with a smaller reserve",
                crate::util::human_bytes(pool.reserve(disk.capacity_bytes)),
                crate::util::human_bytes(disk.capacity_bytes)
            )
        });
        let fill = self.fill_disk_with(&spec, &pool, &disk.id, progress)?;
        pool.sync_disk(&disk.id)?;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok((
            DiskAddReport {
                pool: spec.name().to_string(),
                disk,
                objects_added: fill.objects,
                bytes_added: fill.bytes,
                warning,
            },
            fill,
        ))
    }
}
