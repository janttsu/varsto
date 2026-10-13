// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Bit-rot checks (see `crate::scrub`): re-hash, on a rolling schedule,
//!
//! - the objects the ledger places on every storage this device reads
//!   without asking (directories, S3, rclone; cold storages only when the
//!   user opted in), whoever wrote them, single or packed;
//! - every copy on every attached disk of a pool (each disk's own copy);
//! - the synced files in this device's folders whose size and modification
//!   time still match what was recorded (a changed file is the next scan's);
//! - this device's encrypted block cache.
//!
//! A copy that is missing or does not match its name goes to the repair
//! queue (`engine::repair`). A bad copy on a pool disk is deleted from that
//! disk first, as `disk check --full` does. A local file whose content no
//! longer matches its recorded hash is never overwritten: the recorded
//! version is downloaded first, then the file is moved aside as
//! `name.damaged-<YYYYMMDD>.ext` (it may be an edit that kept its time, so
//! nothing is lost) and the recorded version takes its place. A corrupt
//! block cache object is dropped and fetched again.
//!
//! Checks are not recorded in the ledger: a device re-reading its own
//! writes must not look like an independent verification for a policy, and
//! automatic verification already records the checks that count.

use super::*;
use crate::scrub::{
    self, Budget, DamagedFile, Inclusion, Pace, ScrubReport, ScrubSchedule, ScrubState,
    ScrubStatus, TargetReport,
};
use std::io::Read;

const SCRUB_FILE: &str = "state/scrub.json";

/// What one run reads and how.
#[derive(Clone, Debug, Default)]
pub struct ScrubOptions {
    /// Only these storages (local names). None named: every storage, unless
    /// `local` alone was asked for.
    pub storages: Vec<String>,
    /// Local files and the block cache; with no storage named, only those.
    pub local: bool,
    /// Everything selected, from the start, whatever the schedule and the budgets.
    pub full: bool,
    /// Read cold storages in this run (the user confirmed the retrieval).
    pub include_cold: bool,
    /// The service's run: paced over the period (`crate::scrub::Pace`).
    pub scheduled: bool,
}

impl ScrubOptions {
    /// What the background service runs.
    pub fn service() -> Self {
        ScrubOptions {
            scheduled: true,
            ..Default::default()
        }
    }
}

/// What re-hashing one local file found.
enum FileCheck {
    Intact(u64),
    /// Changed since it was recorded (or gone): the next scan's business.
    Changed,
    Damaged(String),
}

fn mtime_of(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Re-hash a file whose size and time match `entry`.
fn check_file(fk: &FolderKeys, disk: &Path, entry: &LocalIndexEntry) -> FileCheck {
    let same = |md: &fs::Metadata| {
        md.file_type().is_file() && md.len() == entry.size && mtime_of(md) == entry.mtime
    };
    match fs::symlink_metadata(disk) {
        Ok(md) if same(&md) => {}
        _ => return FileCheck::Changed,
    }
    let mut hasher = KeyedHasher::new(&fk.hash);
    let mut buf = vec![0u8; 1 << 20];
    let read = (|| -> std::io::Result<u64> {
        let mut f = fs::File::open(disk)?;
        let mut n = 0u64;
        loop {
            let got = f.read(&mut buf)?;
            if got == 0 {
                return Ok(n);
            }
            hasher.update(&buf[..got]);
            n += got as u64;
        }
    })();
    // Written to while it was read: not ours to judge.
    match fs::symlink_metadata(disk) {
        Ok(md) if same(&md) => {}
        _ => return FileCheck::Changed,
    }
    match read {
        Err(e) => FileCheck::Damaged(format!("the file could not be read: {e}")),
        Ok(n) if hex::encode(hasher.finalize()) == entry.content_hash => FileCheck::Intact(n),
        Ok(_) => FileCheck::Damaged(
            "its content no longer matches the recorded hash, while its size and modification time are unchanged".to_string(),
        ),
    }
}

impl Engine {
    fn scrub_path(&self) -> PathBuf {
        self.home.join(SCRUB_FILE)
    }

    fn load_scrub_state(&self) -> ScrubState {
        util::read_json_or_default(&self.scrub_path()).unwrap_or_default()
    }

    pub fn scrub_schedule(&self) -> &ScrubSchedule {
        &self.config.scrub
    }

    /// Change the schedule and budgets (this device only). Cold storages
    /// are added with `set_scrub_cold`, which needs a confirmation.
    pub fn set_scrub_schedule(&mut self, schedule: ScrubSchedule) -> Result<()> {
        if schedule.interval_hours == 0 || schedule.scrub_days == 0 {
            bail!("the interval and the period must be at least one hour and one day");
        }
        if schedule.max_local_bytes == 0 || schedule.max_remote_bytes == 0 {
            bail!("the budgets must allow at least one byte; turn the bit-rot check off instead");
        }
        if let Some(n) = schedule.cold.difference(&self.config.scrub.cold).next() {
            bail!("cold storage {n} is added with its own confirmation (varsto scrub set --cold {n} --confirm-cold-read)");
        }
        self.config.scrub = schedule;
        self.config.save(&self.home)
    }

    /// Include a cold storage in scheduled runs (reads may cost retrieval
    /// fees, so `confirmed` must be true), or leave it out again.
    pub fn set_scrub_cold(&mut self, name: &str, on: bool, confirmed: bool) -> Result<()> {
        if on {
            let spec = self
                .config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .ok_or_else(|| anyhow!("unknown storage {name}"))?;
            if !spec.is_cold() {
                bail!("{name} is not a cold storage; it is scrubbed anyway");
            }
            if !confirmed {
                bail!("reading cold storage {name} starts retrievals your provider may bill; confirm the cold reads to include it");
            }
            self.config.scrub.cold.insert(name.to_string());
        } else {
            self.config.scrub.cold.remove(name);
        }
        self.config.save(&self.home)
    }

    pub fn scrub_status(&self) -> ScrubStatus {
        let st = self.load_scrub_state();
        ScrubStatus {
            schedule: self.config.scrub.clone(),
            last_run_utc: st.last_run_utc,
            next_run_utc: self.config.scrub.next_run_utc(st.last_run_utc),
            last: st.last,
            last_error: st.last_error,
            totals: st.totals,
            targets: st.sweeps,
            unrestored: st
                .unrestored
                .into_values()
                .flat_map(|m| m.into_values())
                .collect(),
        }
    }

    /// Whether the schedule says a run is due now.
    pub fn scrub_due(&self, now_utc: i64) -> bool {
        self.config
            .scrub
            .is_due(self.load_scrub_state().last_run_utc, now_utc)
    }

    /// One run now (see the module documentation).
    pub fn scrub(&mut self, opts: &ScrubOptions) -> Result<ScrubReport> {
        self.scrub_at(opts, util::now_utc())
    }

    /// One run as of `now_utc` (tests look ahead in time).
    pub fn scrub_at(&mut self, opts: &ScrubOptions, now_utc: i64) -> Result<ScrubReport> {
        self.ensure_active()?;
        self.ensure_ledger_writable()?;
        for n in &opts.storages {
            if !self.config.storages.iter().any(|s| s.name() == n) {
                bail!("unknown storage {n}");
            }
        }
        let mut st = self.load_scrub_state();
        let result = self.one_batch(|e| e.run_scrub(opts, now_utc, &mut st));
        // A run of everything is the scheduled one; a narrower run does not
        // move the schedule.
        if opts.storages.is_empty() && !opts.local {
            st.last_run_utc = Some(now_utc);
        }
        match &result {
            Ok(r) => {
                st.totals.objects_checked += r.objects_checked + r.cache_checked;
                st.totals.files_checked += r.files_checked;
                st.totals.problems_found += r.problems();
                st.totals.files_restored +=
                    r.damaged_files.iter().filter(|d| d.restored).count() as u64;
                st.last = Some(r.clone());
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        if self.home.join("state").is_dir() {
            util::write_json(&self.scrub_path(), &st)?;
        }
        result
    }

    fn run_scrub(
        &mut self,
        opts: &ScrubOptions,
        now: i64,
        st: &mut ScrubState,
    ) -> Result<ScrubReport> {
        let schedule = self.config.scrub.clone();
        let pace = if opts.full {
            Pace::Full
        } else if opts.scheduled {
            Pace::Scheduled
        } else {
            Pace::Budget
        };
        let budget = |bytes: u64| {
            if opts.full {
                Budget::unlimited()
            } else {
                Budget::new(bytes)
            }
        };
        let mut local_budget = budget(schedule.max_local_bytes);
        let mut remote_budget = budget(schedule.max_remote_bytes);
        let mut report = ScrubReport {
            started_utc: util::now_utc(),
            full: opts.full,
            ..Default::default()
        };
        let mut damage: Vec<Damage> = Vec::new();
        if let Err(e) = self.pull_ledger_once() {
            report.skipped.push(format!("ledger not refreshed ({e:#})"));
        }
        let want_storages = !opts.storages.is_empty() || !opts.local;
        let want_local = opts.local || opts.storages.is_empty();
        if want_storages {
            self.scrub_storages(
                opts,
                now,
                pace,
                st,
                &mut report,
                &mut local_budget,
                &mut remote_budget,
                &mut damage,
            )?;
        }
        if want_local {
            let mut storages: Option<OpenStorages> = None;
            self.scrub_files(now, pace, st, &mut report, &mut local_budget, &mut storages)?;
            self.scrub_block_cache(now, pace, st, &mut report, &mut local_budget, &mut storages)?;
        }
        // Targets that are gone (a storage removed, a folder detached).
        let storages: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        let folders: BTreeSet<String> = self
            .config
            .folders
            .iter()
            .map(|m| m.folder_id.to_string())
            .collect();
        st.sweeps.retain(|k, _| {
            if let Some(n) = k.strip_prefix("storage:") {
                storages.contains(n)
            } else if let Some(rest) = k.strip_prefix("disk:") {
                rest.rsplit_once('/')
                    .is_some_and(|(pool, _)| storages.contains(pool))
            } else if let Some(f) = k.strip_prefix("files:") {
                folders.contains(f)
            } else {
                true
            }
        });
        st.unrestored
            .retain(|f, m| folders.contains(f) && !m.is_empty());
        report.queued_for_repair = damage.len() as u64;
        self.queue_damage(damage)?;
        report.finished_utc = util::now_utc();
        Ok(report)
    }

    /// Objects on every storage this run reads, and the copies on every
    /// attached disk of a pool.
    #[allow(clippy::too_many_arguments)]
    fn scrub_storages(
        &mut self,
        opts: &ScrubOptions,
        now: i64,
        pace: Pace,
        st: &mut ScrubState,
        report: &mut ScrubReport,
        local_budget: &mut Budget,
        remote_budget: &mut Budget,
        damage: &mut Vec<Damage>,
    ) -> Result<()> {
        let schedule = self.config.scrub.clone();
        let me = self.vault.device_id.clone();
        let mut readable: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        let mut remote: BTreeSet<String> = BTreeSet::new();
        let mut pools: Vec<StorageSpec> = Vec::new();
        for spec in self.config.storages.clone() {
            let name = spec.name().to_string();
            match scrub::inclusion(
                &name,
                spec.is_cold(),
                spec.is_carrier(),
                &schedule,
                &opts.storages,
                opts.include_cold,
            ) {
                Inclusion::NotAsked => continue,
                Inclusion::Transferrer => {
                    report.skipped.push(format!("{name} (transferrer)"));
                    continue;
                }
                Inclusion::Cold => {
                    report.skipped.push(format!(
                        "{name} (cold storage: read only when included, retrieval fees may apply)"
                    ));
                    continue;
                }
                Inclusion::Read => {}
            }
            if spec.is_data_only() {
                pools.push(spec);
                continue;
            }
            if matches!(spec, StorageSpec::S3 { .. } | StorageSpec::Rclone { .. }) {
                remote.insert(name.clone());
            }
            match self.open_spec(&spec) {
                Ok(b) => {
                    readable.insert(name, b);
                }
                Err(e) => report.skipped.push(format!("{name} (cannot open: {e:#})")),
            }
        }
        let view = self.view()?;
        // The objects the ledger places on each storage read here, whoever
        // wrote them: key -> (size, folder, chunk, object).
        type Expected = BTreeMap<String, (u64, FolderId, ChunkId, ObjectName)>;
        let mut expected: BTreeMap<String, Expected> = BTreeMap::new();
        if !readable.is_empty() {
            let names = self.storage_resolver(&readable);
            for ((folder, chunk), rec) in view.chunks.iter() {
                if !self.keyring.folders.contains_key(folder) {
                    continue; // converted into a Strongroom: its old objects are gone
                }
                for (name, loc) in &rec.storages {
                    if loc.claimed_by.is_empty() {
                        continue;
                    }
                    let local = if loc.claimed_by.contains(&me) && readable.contains_key(name) {
                        Some(name.clone())
                    } else {
                        names.resolve(name, &loc.claimed_by)
                    };
                    let Some(local) = local.filter(|l| readable.contains_key(l)) else {
                        continue;
                    };
                    expected
                        .entry(local)
                        .or_default()
                        .entry(chunk_storage_key(&rec.object))
                        .or_insert((rec.size, folder.clone(), chunk.clone(), rec.object.clone()));
                }
            }
        }
        let damaged = |storage: &str,
                       folder: &FolderId,
                       chunk: &ChunkId,
                       object: &ObjectName,
                       kind: DamageKind| {
            Damage {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                storage: storage.to_string(),
                kind,
                found_by: "scrub".to_string(),
                found_utc: now,
                retry_utc: 0,
                reason: None,
            }
        };
        // The pass that began longest ago first.
        let mut order: Vec<String> = readable.keys().cloned().collect();
        order.sort_by_key(|n| {
            st.sweeps
                .get(&format!("storage:{n}"))
                .map(|s| s.pass_started_utc)
                .unwrap_or(0)
        });
        for name in order {
            let budget = if remote.contains(&name) {
                &mut *remote_budget
            } else {
                &mut *local_budget
            };
            let objects = expected.remove(&name).unwrap_or_default();
            let items: Vec<(String, u64)> = objects.iter().map(|(k, v)| (k.clone(), v.0)).collect();
            let metas: Vec<&(u64, FolderId, ChunkId, ObjectName)> = objects.values().collect();
            let target = format!("storage:{name}");
            let sweep = st.sweeps.entry(target.clone()).or_default();
            sweep.label = format!("storage {name}");
            let plan = scrub::plan(&items, sweep, now, &schedule, pace, budget);
            let task = crate::activity::start(
                crate::activity::SCRUB,
                &name,
                plan.picks.iter().map(|&i| items[i].1).sum(),
                crate::activity::Unit::Bytes,
            );
            task.set_phase("storage");
            let mut tr = TargetReport {
                target,
                label: sweep.label.clone(),
                behind: plan.behind,
                ..Default::default()
            };
            let mut done = plan.finishes_pass;
            let mut last: Option<&str> = None;
            for &i in &plan.picks {
                let key = &items[i].0;
                let (_, folder, chunk, object) = metas[i];
                match readable[&name].get(key) {
                    Ok(None) => {
                        report.missing.push(format!("{name}:{}", object.short()));
                        damage.push(damaged(&name, folder, chunk, object, DamageKind::Missing));
                    }
                    Ok(Some(ct)) => {
                        tr.bytes += ct.len() as u64;
                        if ObjectName::from_bytes(&crypto::hash(&ct)) != *object {
                            report.corrupt.push(format!("{name}:{}", object.short()));
                            damage.push(damaged(&name, folder, chunk, object, DamageKind::Corrupt));
                        }
                    }
                    Err(e) => {
                        // Unreachable now: the pass goes on from here next time.
                        report.skipped.push(format!("{name} (read failed: {e:#})"));
                        done = false;
                        break;
                    }
                }
                tr.checked += 1;
                task.advance(items[i].1);
                last = Some(key);
            }
            sweep.advance(now, last, tr.checked, done);
            tr.pass_done = done;
            tr.left_in_pass = plan.remaining - tr.checked;
            report.objects_checked += tr.checked;
            report.object_bytes += tr.bytes;
            report.targets.push(tr);
        }
        // Pools: each attached disk is a target of its own; a disk that is
        // away waits, and one not seen within the period is reported.
        let by_object: HashMap<ObjectName, (FolderId, ChunkId)> = if pools.is_empty() {
            HashMap::new()
        } else {
            view.chunks
                .iter()
                .map(|((f, c), r)| (r.object.clone(), (f.clone(), c.clone())))
                .collect()
        };
        for spec in pools {
            let pool = match self.open_pool(&spec) {
                Ok(p) => p,
                Err(e) => {
                    report
                        .skipped
                        .push(format!("{} (cannot open: {e:#})", spec.name()));
                    continue;
                }
            };
            let pool_name = spec.name().to_string();
            for d in pool.statuses() {
                if !d.attached {
                    if d.objects > 0 {
                        report.offline += d.objects;
                        if d.last_seen_utc < now - schedule.period_secs() {
                            report.disks_away.push(format!(
                                "{} ({}), last seen {}",
                                d.label,
                                d.place,
                                if d.last_seen_utc > 0 {
                                    util::format_date(d.last_seen_utc)
                                } else {
                                    "never".to_string()
                                }
                            ));
                        }
                    }
                    continue;
                }
                let mut items = pool.objects_on(&d.disk_id);
                items.sort();
                let target = format!("disk:{pool_name}/{}", d.disk_id);
                let sweep = st.sweeps.entry(target.clone()).or_default();
                sweep.label = format!("disk {} of pool {pool_name}", d.label);
                let plan = scrub::plan(&items, sweep, now, &schedule, pace, local_budget);
                let task = crate::activity::start(
                    crate::activity::SCRUB,
                    &d.label,
                    plan.picks.iter().map(|&i| items[i].1).sum(),
                    crate::activity::Unit::Bytes,
                );
                task.set_phase("disk");
                let mut tr = TargetReport {
                    target,
                    label: sweep.label.clone(),
                    behind: plan.behind,
                    ..Default::default()
                };
                let mut done = plan.finishes_pass;
                let mut last: Option<&str> = None;
                for &i in &plan.picks {
                    let key = &items[i].0;
                    let name = key.rsplit('/').next().unwrap_or("");
                    let bad = match pool.read_on_disk(&d.disk_id, key) {
                        Ok(None) => {
                            report.missing.push(format!(
                                "{pool_name}/{}:{}",
                                d.label,
                                &name[..name.len().min(12)]
                            ));
                            true
                        }
                        Ok(Some(b)) => {
                            tr.bytes += b.len() as u64;
                            let bad = hex::encode(crypto::hash(&b)) != name;
                            if bad {
                                report.corrupt.push(format!(
                                    "{pool_name}/{}:{}",
                                    d.label,
                                    &name[..name.len().min(12)]
                                ));
                            }
                            bad
                        }
                        Err(e) => {
                            report
                                .skipped
                                .push(format!("disk {} (read failed: {e:#})", d.label));
                            done = false;
                            break;
                        }
                    };
                    tr.checked += 1;
                    task.advance(items[i].1);
                    last = Some(key);
                    if !bad {
                        continue;
                    }
                    // Forget the bad copy; with no copy left on any disk,
                    // repair writes the object again.
                    let left = pool.drop_bad_copy(&d.disk_id, key)?;
                    if left {
                        continue;
                    }
                    if let Ok(o) = ObjectName::from_hex(name) {
                        if let Some((f, c)) = by_object.get(&o) {
                            damage.push(damaged(&pool_name, f, c, &o, DamageKind::Missing));
                        }
                    }
                }
                sweep.advance(now, last, tr.checked, done);
                tr.pass_done = done;
                tr.left_in_pass = plan.remaining - tr.checked;
                report.objects_checked += tr.checked;
                report.object_bytes += tr.bytes;
                report.targets.push(tr);
            }
            pool.flush()?;
            let disks = pool.disks();
            drop(pool);
            self.save_pool_disks(&pool_name, disks)?;
        }
        Ok(())
    }

    /// Synced files on this device's disk whose size and time are unchanged.
    fn scrub_files(
        &mut self,
        now: i64,
        pace: Pace,
        st: &mut ScrubState,
        report: &mut ScrubReport,
        budget: &mut Budget,
        storages: &mut Option<OpenStorages>,
    ) -> Result<()> {
        let schedule = self.config.scrub.clone();
        for (rec, mount) in self.folders() {
            let Some(root) = mount else { continue };
            if self.mount_is_encrypted(&rec.folder_id) || !self.state_path(&rec.folder_id).exists()
            {
                continue; // kept encrypted here: the block cache is checked instead
            }
            let Ok(rec) = self.with_key(&rec) else {
                report
                    .skipped
                    .push(format!("folder {} (Strongroom locked)", rec.name));
                continue;
            };
            let fk = self.folder_keys(&rec)?;
            let mut state = self.load_state(&rec.folder_id)?;
            if state.block_cache {
                continue;
            }
            let fid = rec.folder_id.to_string();
            // Synced files only: the index and the merged view agree.
            let items: Vec<(String, u64)> = state
                .local_index
                .iter()
                .filter(|(p, e)| {
                    state
                        .files
                        .get(*p)
                        .is_some_and(|f| !f.deleted && f.content_hash == e.content_hash)
                })
                .map(|(p, e)| (p.clone(), e.size))
                .collect();
            let target = format!("files:{fid}");
            let sweep = st.sweeps.entry(target.clone()).or_default();
            sweep.label = format!("folder {}", rec.name);
            let plan = scrub::plan(&items, sweep, now, &schedule, pace, budget);
            let task = crate::activity::start(
                crate::activity::SCRUB,
                &rec.name,
                plan.picks.iter().map(|&i| items[i].1).sum(),
                crate::activity::Unit::Bytes,
            );
            task.set_phase("files");
            // Damaged files still waiting for their recorded version first.
            let waiting: Vec<String> = st
                .unrestored
                .get(&fid)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let mut paths: Vec<(String, bool)> = waiting.into_iter().map(|p| (p, false)).collect();
            for &i in &plan.picks {
                paths.push((items[i].0.clone(), true));
            }
            let mut tr = TargetReport {
                target: target.clone(),
                label: format!("folder {}", rec.name),
                behind: plan.behind,
                ..Default::default()
            };
            let mut last: Option<String> = None;
            let mut changed = false;
            for (path, planned) in paths {
                if planned {
                    last = Some(path.clone());
                }
                let entry = match state.local_index.get(&path) {
                    Some(e)
                        if state
                            .files
                            .get(&path)
                            .is_some_and(|f| !f.deleted && f.content_hash == e.content_hash) =>
                    {
                        e.clone()
                    }
                    _ => {
                        if let Some(m) = st.unrestored.get_mut(&fid) {
                            m.remove(&path);
                        }
                        continue;
                    }
                };
                let Ok(disk) = util::safe_join(&root, &path) else {
                    continue;
                };
                let outcome = check_file(&fk, &disk, &entry);
                if planned {
                    tr.checked += 1;
                    task.advance(entry.size);
                }
                match outcome {
                    FileCheck::Intact(n) => {
                        tr.bytes += n;
                        if let Some(m) = st.unrestored.get_mut(&fid) {
                            m.remove(&path);
                        }
                    }
                    FileCheck::Changed => {
                        // Edited or replaced: the next scan records it.
                        if let Some(m) = st.unrestored.get_mut(&fid) {
                            m.remove(&path);
                        }
                    }
                    FileCheck::Damaged(why) => {
                        tr.bytes += entry.size;
                        if storages.is_none() {
                            *storages = Some(self.open_storages(false)?);
                        }
                        let open = storages.as_ref().map(|s| s.as_slice()).unwrap_or(&[]);
                        let found = st
                            .unrestored
                            .get(&fid)
                            .and_then(|m| m.get(&path))
                            .map(|d| d.found_utc)
                            .unwrap_or(now);
                        let mut d = self.restore_damaged(
                            &rec, &fk, &root, &mut state, &path, &entry, now, open,
                        );
                        d.found_utc = found;
                        if !d.restored {
                            d.reason =
                                Some(format!("{why}; {}", d.reason.clone().unwrap_or_default()));
                            st.unrestored
                                .entry(fid.clone())
                                .or_default()
                                .insert(path.clone(), d.clone());
                        } else {
                            changed = true;
                            if let Some(m) = st.unrestored.get_mut(&fid) {
                                m.remove(&path);
                            }
                        }
                        report.damaged_files.push(d);
                    }
                }
            }
            if changed {
                self.save_state(&rec.folder_id, &state)?;
            }
            let sweep = st.sweeps.entry(target).or_default();
            sweep.advance(now, last.as_deref(), tr.checked, plan.finishes_pass);
            tr.pass_done = plan.finishes_pass;
            tr.left_in_pass = plan.remaining - tr.checked;
            report.files_checked += tr.checked;
            report.file_bytes += tr.bytes;
            report.targets.push(tr);
        }
        Ok(())
    }

    /// Download the recorded version of a damaged file next to it, then move
    /// the damaged file aside and put the recorded version in its place.
    /// Nothing is moved when the recorded version cannot be had.
    #[allow(clippy::too_many_arguments)]
    fn restore_damaged(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        root: &Path,
        state: &mut FolderState,
        path: &str,
        entry: &LocalIndexEntry,
        now: i64,
        storages: &[(StorageSpec, Box<dyn Storage>)],
    ) -> DamagedFile {
        let mut out = DamagedFile {
            folder: rec.name.clone(),
            path: path.to_string(),
            moved_to: None,
            restored: false,
            reason: None,
            found_utc: now,
        };
        let (Ok(disk), Some(file)) = (util::safe_join(root, path), state.files.get(path).cloned())
        else {
            out.reason = Some("the path is not usable here".to_string());
            return out;
        };
        let fresh = disk.with_file_name(format!(".varsto-scrub-{:016x}", rand::random::<u64>()));
        let mut pull = PullReport::default();
        if let Err(e) = self.download_to(rec, fk, &fresh, &file, storages, &mut pull) {
            let _ = fs::remove_file(&fresh);
            out.reason = Some(format!("no good copy could be downloaded yet ({e:#})"));
            return out;
        }
        if entry.mtime > 0 {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(entry.mtime as u64);
            if let Ok(f) = fs::File::options().write(true).open(&fresh) {
                let _ = f.set_modified(t);
            }
        }
        let file_name = disk
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let date = util::format_date(now).replace('-', "");
        let mut aside = disk.clone();
        let mut aside_name = String::new();
        for n in 1..1000 {
            aside_name = scrub::damaged_name(&file_name, &date, n);
            aside = disk.with_file_name(&aside_name);
            if fs::symlink_metadata(&aside).is_err() {
                break;
            }
        }
        if let Err(e) = fs::rename(&disk, &aside) {
            let _ = fs::remove_file(&fresh);
            out.reason = Some(format!("the damaged file could not be moved aside ({e})"));
            return out;
        }
        if let Err(e) = fs::rename(&fresh, &disk) {
            let _ = fs::rename(&aside, &disk);
            let _ = fs::remove_file(&fresh);
            out.reason = Some(format!(
                "the recorded version could not be put in place ({e})"
            ));
            return out;
        }
        let rel = match path.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{aside_name}"),
            None => aside_name,
        };
        if let Ok(md) = fs::metadata(&disk) {
            state.local_index.insert(
                path.to_string(),
                LocalIndexEntry {
                    size: md.len(),
                    mtime: mtime_of(&md),
                    content_hash: file.content_hash.clone(),
                },
            );
        }
        out.moved_to = Some(rel);
        out.restored = true;
        out
    }

    /// This device's encrypted block cache: a corrupt object is dropped and
    /// fetched again; when that fails, the files that need it are no longer
    /// counted as cached here (the next sync fetches them).
    fn scrub_block_cache(
        &mut self,
        now: i64,
        pace: Pace,
        st: &mut ScrubState,
        report: &mut ScrubReport,
        budget: &mut Budget,
        storages: &mut Option<OpenStorages>,
    ) -> Result<()> {
        let root = self.block_cache_root();
        let dir = root.join("chunks");
        if !dir.is_dir() {
            return Ok(());
        }
        let schedule = self.config.scrub.clone();
        let mut items: Vec<(String, u64)> = Vec::new();
        for e in walkdir::WalkDir::new(&dir)
            .min_depth(2)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || ObjectName::from_hex(&name).is_err() {
                continue; // a temporary file of a write in progress
            }
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            items.push((name, size));
        }
        items.sort();
        let target = "block-cache".to_string();
        let sweep = st.sweeps.entry(target.clone()).or_default();
        sweep.label = "block cache".to_string();
        let plan = scrub::plan(&items, sweep, now, &schedule, pace, budget);
        let task = crate::activity::start(
            crate::activity::SCRUB,
            "",
            plan.picks.iter().map(|&i| items[i].1).sum(),
            crate::activity::Unit::Bytes,
        );
        task.set_phase("cache");
        let mut tr = TargetReport {
            target,
            label: sweep.label.clone(),
            behind: plan.behind,
            ..Default::default()
        };
        let mut dropped: Vec<ObjectName> = Vec::new();
        let mut last: Option<&str> = None;
        for &i in &plan.picks {
            let name = &items[i].0;
            let Ok(object) = ObjectName::from_hex(name) else {
                continue;
            };
            let path = block_cache::cache_path(&root, &object);
            let good = match fs::read(&path) {
                Ok(b) => {
                    tr.bytes += b.len() as u64;
                    ObjectName::from_bytes(&crypto::hash(&b)) == object
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true, // dropped meanwhile
                Err(_) => false,
            };
            tr.checked += 1;
            task.advance(items[i].1);
            last = Some(name);
            if !good {
                let _ = fs::remove_file(&path);
                dropped.push(object);
            }
        }
        sweep.advance(now, last, tr.checked, plan.finishes_pass);
        tr.pass_done = plan.finishes_pass;
        tr.left_in_pass = plan.remaining - tr.checked;
        report.cache_checked += tr.checked;
        report.object_bytes += tr.bytes;
        report.targets.push(tr);
        if dropped.is_empty() {
            return Ok(());
        }
        report.cache_dropped += dropped.len() as u64;
        report
            .corrupt
            .extend(dropped.iter().map(|o| format!("block cache:{}", o.short())));
        // Fetch each dropped object again; the files of one that cannot be
        // fetched now are no longer cached here.
        if storages.is_none() {
            *storages = Some(self.open_storages(false)?);
        }
        let open = storages.as_ref().map(|s| s.as_slice()).unwrap_or(&[]);
        let mut lost: BTreeSet<ObjectName> = BTreeSet::new();
        for object in dropped {
            // `fetch_object` goes by the object name; the chunk id only
            // names it in an error.
            let cref = ChunkRef {
                chunk: ChunkId::from_bytes(&[0u8; 32]),
                object: object.clone(),
                size: 0,
                epoch: 0,
            };
            match self.fetch_object(&cref, open) {
                Ok((_, ct)) => block_cache::put_cached(&root, &object, &ct)?,
                Err(_) => {
                    lost.insert(object);
                }
            }
        }
        if lost.is_empty() {
            return Ok(());
        }
        for m in self.config.folders.clone() {
            if !m.encrypted || !self.state_path(&m.folder_id).exists() {
                continue;
            }
            let mut state = self.load_state(&m.folder_id)?;
            let gone: Vec<String> = state
                .files
                .values()
                .filter(|f| f.chunks.iter().any(|c| lost.contains(&c.object)))
                .map(|f| f.path.clone())
                .collect();
            let mut changed = false;
            for p in gone {
                changed |= state.local_index.remove(&p).is_some();
            }
            if changed {
                self.save_state(&m.folder_id, &state)?;
            }
        }
        Ok(())
    }
}
