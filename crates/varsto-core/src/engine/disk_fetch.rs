// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Fetching large files from pool disks instead of the network.
//!
//! When the blocks of the files asked for are on pool disks that are away
//! (and maybe also on remote storages), a *plan* compares the two ways:
//! the remote storages (egress and retrieval prices, a cold class, the time
//! at the configured link speed) and the disks (no fee; a fixed time to
//! fetch each disk from the shelf plus the time to read it). Only a large
//! fetch (`threshold_bytes`), one from cold storage, or one whose blocks are
//! only on disks proposes disks; anything else is fetched remotely as
//! before. The disks are chosen to need as few insertions as possible
//! (the disk with the most of the wanted bytes first; disks already
//! attached first of all).
//!
//! Running a plan is a loop over its disks: the user inserts one, Varsto
//! mounts it, copies only the wanted blocks into a staging area in the
//! device directory (`<home>/disk-fetch/<pool>/chunks/..`; each one hashed
//! against its name on the way), writes every file whose blocks are now all
//! here, syncs, unmounts and says the disk can be removed; then the next
//! disk. `download_to` takes staged blocks before asking any storage. The
//! plan itself is kept in `<home>/disk-fetch/plan.json`, so the local API
//! can run it one step per request.

use super::*;

const STAGING_DIR: &str = "disk-fetch";
const PLAN_FILE: &str = "plan.json";

/// When disks are proposed, and how the two ways are timed (`config.json`,
/// `disk_fetch`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskFetchSettings {
    /// Fetches at least this large are worth a trip to the shelf (default 2 GiB).
    pub threshold_bytes: u64,
    /// Time to fetch a disk, plug it in and put it back (default 120 s).
    pub overhead_secs: u64,
    /// Download speed from the remote storages (default 100 Mbit/s).
    pub link_mbit_per_sec: f64,
    /// Read speed of a pool disk in a dock (default 120 MB/s).
    pub disk_mb_per_sec: f64,
}

impl Default for DiskFetchSettings {
    fn default() -> Self {
        DiskFetchSettings {
            threshold_bytes: 2 << 30,
            overhead_secs: 120,
            link_mbit_per_sec: 100.0,
            disk_mb_per_sec: 120.0,
        }
    }
}

impl DiskFetchSettings {
    fn link_secs(&self, bytes: u64) -> f64 {
        bytes as f64 * 8.0 / (self.link_mbit_per_sec.max(0.1) * 1e6)
    }
    pub(super) fn disk_secs(&self, bytes: u64) -> f64 {
        bytes as f64 / (self.disk_mb_per_sec.max(0.1) * 1e6)
    }
}

/// A file of a plan.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PlanFile {
    pub folder: String,
    pub path: String,
    pub size: u64,
    /// Object keys of its blocks.
    pub objects: Vec<String>,
    /// Written to its place.
    #[serde(default)]
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One disk to insert.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DiskStep {
    pub pool: String,
    pub disk_id: String,
    /// The name on the disk's sticker.
    pub label: String,
    pub place: String,
    /// Attached when the plan was made: no insertion, and it stays mounted.
    pub attached: bool,
    /// Object keys to copy from this disk, and their bytes.
    pub objects: Vec<String>,
    pub bytes: u64,
    /// "pending", "done" or "skipped".
    pub state: String,
}

/// The remote way.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RemoteOption {
    /// Every block has a copy on a remote storage.
    pub possible: bool,
    /// Some blocks are only on cold storages (retrieval fees, delays).
    pub cold: bool,
    pub bytes: u64,
    /// Egress plus retrieval at the storages' prices; `None` when a price is unknown.
    pub cost: Option<f64>,
    pub currency: String,
    pub secs: f64,
    pub storages: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FetchPlan {
    pub created_utc: i64,
    pub files: Vec<PlanFile>,
    pub total_bytes: u64,
    /// "disks" or "remote".
    pub recommend: String,
    pub reason: String,
    /// The disks to insert, in order.
    pub steps: Vec<DiskStep>,
    /// What the disk way still fetches remotely (blocks on no chosen disk).
    pub remote_part_bytes: u64,
    pub remote_part_cost: Option<f64>,
    /// Estimated time of the disk way, insertions included.
    pub disks_secs: f64,
    /// Fetching everything remotely instead.
    pub remote: RemoteOption,
}

/// What copying one disk's blocks did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct StepOutcome {
    pub label: String,
    pub objects: u64,
    pub bytes: u64,
    /// Blocks the disk did not have or returned wrong (fetched remotely later).
    pub failed: Vec<String>,
    /// Files written to their place after this disk.
    pub files_done: Vec<String>,
    pub message: String,
}

/// What a whole run did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct FetchPlanReport {
    pub steps: Vec<StepOutcome>,
    pub files_done: Vec<String>,
    /// Files that could not be written: (path, why).
    pub files_failed: Vec<(String, String)>,
    /// The user stopped before the end; the plan is kept.
    pub stopped: bool,
}

/// The user's answer when asked to insert a disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertAnswer {
    Inserted,
    /// Use the remote storages for this disk's blocks.
    Skip,
    Stop,
}

/// The parts of running a plan that talk to the user and the devices.
pub trait PlanDriver {
    /// Ask for the disk of step `k` to be inserted.
    fn ask(&mut self, plan: &FetchPlan, k: usize) -> Result<InsertAnswer>;
    /// Make the inserted disk reachable (mount it). False: it is not there.
    fn attach(&mut self, step: &DiskStep) -> Result<bool>;
    /// The disk's index is written and synced: unmount it and power it off.
    fn release(&mut self, step: &DiskStep, mount: &Path) -> Result<()>;
    fn say(&mut self, message: &str);
}

/// The staged copy of `object`, if any: (path, pool name).
pub(super) fn staged_object(
    roots: &[(PathBuf, String)],
    object: &ObjectName,
) -> Option<(PathBuf, String)> {
    let key = chunk_storage_key(object);
    roots
        .iter()
        .map(|(r, pool)| (r.join(&key), pool.clone()))
        .find(|(p, _)| p.is_file())
}

impl Engine {
    fn staging_dir(&self) -> PathBuf {
        self.home.join(STAGING_DIR)
    }

    /// Staging directories of the pools, when a plan left blocks there.
    pub(super) fn staging_roots(&self) -> Vec<(PathBuf, String)> {
        let dir = self.staging_dir();
        if !dir.is_dir() {
            return Vec::new();
        }
        self.pool_specs()
            .iter()
            .map(|s| (dir.join(s.name()), s.name().to_string()))
            .filter(|(p, _)| p.is_dir())
            .collect()
    }

    pub fn disk_fetch_settings(&self) -> DiskFetchSettings {
        self.config.disk_fetch.clone()
    }

    pub fn set_disk_fetch_settings(&mut self, s: DiskFetchSettings) -> Result<()> {
        self.config.disk_fetch = s;
        self.config.save(&self.home)
    }

    /// Make a plan for fetching `paths` of `folder` (and keep it as the
    /// current plan).
    pub fn fetch_plan(&mut self, folder: &str, paths: &[String]) -> Result<FetchPlan> {
        crate::logged_op_plain!("fetch plan", folder, {
            self.fetch_plan_inner(folder, paths)
        })
    }

    fn fetch_plan_inner(&mut self, folder: &str, paths: &[String]) -> Result<FetchPlan> {
        let settings = self.config.disk_fetch.clone();
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let view = self.view3()?;
        let table = self.folder_table3(&rec)?;
        // The live places of a block, with the storages holding each pack.
        let places_of = |o: &ObjectName| -> Vec<crate::ledger3::view::BlockPlace> {
            let (Some(t), Ok(obj)) = (&table, crate::storages3::object_bin(o)) else {
                return Vec::new();
            };
            let t = t.read().unwrap_or_else(|e| e.into_inner());
            view.block_places(&obj, &*t)
                .into_iter()
                .filter(|p| !p.marked)
                .collect()
        };
        let mut plan = FetchPlan {
            created_utc: util::now_utc(),
            ..Default::default()
        };
        // Object -> (size, chunk) of every distinct block.
        let mut blocks: BTreeMap<ObjectName, (u64, ChunkId)> = BTreeMap::new();
        // The newest file (modification time) that uses each block.
        let mut newest_of: BTreeMap<ObjectName, i64> = BTreeMap::new();
        let mut files: Vec<&crate::manifest::FileState> = Vec::new();
        for path in paths {
            files.push(
                state
                    .files
                    .get(path)
                    .filter(|f| !f.deleted)
                    .ok_or_else(|| anyhow!("unknown file {path}"))?,
            );
        }
        // Files are written newest first.
        files.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
        files.dedup_by(|a, b| a.path == b.path);
        for f in files {
            let path = &f.path;
            let mut objects = Vec::new();
            for c in &f.chunks {
                blocks
                    .entry(c.object.clone())
                    .or_insert((c.size + 64, c.chunk.clone()));
                let n = newest_of.entry(c.object.clone()).or_insert(f.mtime);
                *n = (*n).max(f.mtime);
                let k = chunk_storage_key(&c.object);
                if !objects.contains(&k) {
                    objects.push(k);
                }
            }
            plan.files.push(PlanFile {
                folder: rec.name.clone(),
                path: path.clone(),
                size: f.size,
                objects,
                ..Default::default()
            });
        }
        // Blocks an earlier, interrupted run already copied from a disk.
        let roots = self.staging_roots();
        blocks.retain(|o, _| staged_object(&roots, o).is_none());
        plan.total_bytes = blocks.values().map(|(s, _)| s).sum();
        // Where each block is: remote storages (hot or cold) and pool disks.
        let specs: BTreeMap<String, StorageSpec> = self
            .config
            .storages
            .iter()
            .map(|s| (s.name().to_string(), s.clone()))
            .collect();
        let pools: Vec<(StorageSpec, PoolStorage)> = self
            .pool_specs()
            .into_iter()
            .filter_map(|s| self.open_pool(&s).ok().map(|p| (s, p)))
            .collect();
        let mut remote_cost = Some(0.0f64);
        let mut currency = String::new();
        let mut remote_names: BTreeSet<String> = BTreeSet::new();
        let mut remote_possible = true;
        let mut remote_cold = false;
        // Blocks only on disks, and every block a disk holds: disk id -> objects.
        let mut must: BTreeSet<ObjectName> = BTreeSet::new();
        let mut on_disk: BTreeMap<(String, String), BTreeSet<ObjectName>> = BTreeMap::new();
        let mut disk_info: BTreeMap<(String, String), (String, String, bool)> = BTreeMap::new();
        let mut cost_of: BTreeMap<ObjectName, Option<f64>> = BTreeMap::new();
        for (object, (size, chunk)) in &blocks {
            let _ = chunk;
            let places = places_of(object);
            let claims: BTreeSet<String> = places
                .iter()
                .flat_map(|p| p.storages.iter().cloned())
                .collect();

            // The cheapest remote copy, hot before cold.
            let mut best: Option<(bool, Option<f64>, String)> = None;
            for name in &claims {
                let Some(spec) = specs.get(name) else {
                    continue;
                };
                if spec.is_data_only() || spec.is_carrier() {
                    continue;
                }
                let cost = self
                    .storage_price(name)
                    .map(|p| {
                        if currency.is_empty() {
                            currency = p.currency.clone();
                        }
                        p.read_cost(*size)
                    })
                    .unwrap_or(Some(0.0))
                    .or(if spec.is_cold() { None } else { Some(0.0) });
                let cand = (spec.is_cold(), cost, name.clone());
                let better = match &best {
                    None => true,
                    Some((cold, c, _)) => {
                        (!cand.0 && *cold)
                            || (cand.0 == *cold
                                && cand.1.unwrap_or(f64::MAX) < c.unwrap_or(f64::MAX))
                    }
                };
                if better {
                    best = Some(cand);
                }
            }
            match &best {
                Some((cold, cost, name)) => {
                    remote_cold |= *cold;
                    remote_names.insert(name.clone());
                    remote_cost = remote_cost.zip(*cost).map(|(a, b)| a + b);
                    cost_of.insert(object.clone(), *cost);
                }
                None => {
                    remote_possible = false;
                    cost_of.insert(object.clone(), None);
                }
            }
            let mut on_any = false;
            for (spec, pool) in &pools {
                // The disks hold the block's pack.
                let Some(pack) = places
                    .iter()
                    .find(|p| p.storages.iter().any(|s| s == spec.name()))
                    .map(|p| p.place.pack)
                else {
                    continue;
                };
                let key = crate::packs::pack_key(&hex::encode(pack));
                for l in pool.locate_all(&key) {
                    on_any = true;
                    let id = (spec.name().to_string(), l.disk_id.clone());
                    on_disk
                        .entry(id.clone())
                        .or_default()
                        .insert(object.clone());
                    disk_info.insert(id, (l.label.clone(), l.place.clone(), l.attached));
                }
            }
            if best.is_none() && on_any {
                must.insert(object.clone());
            }
        }
        plan.remote = RemoteOption {
            possible: remote_possible,
            cold: remote_cold,
            bytes: plan.total_bytes,
            cost: remote_cost.filter(|_| remote_possible),
            currency: currency.clone(),
            secs: settings.link_secs(plan.total_bytes),
            storages: remote_names.into_iter().collect(),
        };
        let costly = plan.remote.cost.is_some_and(|c| c > 0.0) || plan.remote.cost.is_none();
        let large = plan.total_bytes >= settings.threshold_bytes;
        if must.is_empty() && !((large || remote_cold) && !on_disk.is_empty()) {
            plan.recommend = "remote".into();
            plan.reason = if on_disk.is_empty() {
                "no pool disk holds these blocks".into()
            } else {
                format!(
                    "{} is below the {} for which fetching disks is worth it",
                    util::human_bytes(plan.total_bytes),
                    util::human_bytes(settings.threshold_bytes)
                )
            };
            plan.disks_secs = plan.remote.secs;
            self.save_fetch_plan(&plan)?;
            return Ok(plan);
        }
        // Choose disks: attached ones first (no insertion), then greedily
        // the disk that holds the most wanted bytes not covered yet. A disk
        // is taken when it holds blocks no remote storage has, or when
        // reading it beats the network on price or time.
        let mut covered: BTreeSet<ObjectName> = BTreeSet::new();
        let mut candidates: Vec<(String, String)> = on_disk.keys().cloned().collect();
        let bytes_of = |set: &BTreeSet<ObjectName>, covered: &BTreeSet<ObjectName>| -> u64 {
            set.iter()
                .filter(|o| !covered.contains(*o))
                .map(|o| blocks[o].0)
                .sum()
        };
        loop {
            candidates.sort_by_key(|id| {
                let attached = disk_info[id].2;
                (
                    !attached,
                    std::cmp::Reverse(bytes_of(&on_disk[id], &covered)),
                    disk_info[id].0.clone(),
                )
            });
            let Some(id) = candidates.first().cloned() else {
                break;
            };
            candidates.remove(0);
            let new: BTreeSet<ObjectName> = on_disk[&id]
                .iter()
                .filter(|o| !covered.contains(*o))
                .cloned()
                .collect();
            if new.is_empty() {
                continue;
            }
            let bytes: u64 = new.iter().map(|o| blocks[o].0).sum();
            let (label, place, attached) = disk_info[&id].clone();
            let needed = new.iter().any(|o| must.contains(o));
            let overhead = if attached {
                0.0
            } else {
                settings.overhead_secs as f64
            };
            let faster = overhead + settings.disk_secs(bytes) < settings.link_secs(bytes);
            let cheaper = new
                .iter()
                .any(|o| cost_of.get(o).copied().flatten().is_none_or(|c| c > 0.0));
            let worth = attached || needed || faster || ((large || remote_cold) && cheaper);
            if !worth {
                continue;
            }
            covered.extend(new.iter().cloned());
            // One disk at a time; on it, the newest files' blocks first.
            let mut objects: Vec<&ObjectName> = new.iter().collect();
            objects.sort_by_key(|o| (std::cmp::Reverse(newest_of.get(*o).copied()), (*o).clone()));
            plan.steps.push(DiskStep {
                pool: id.0.clone(),
                disk_id: id.1.clone(),
                label,
                place,
                attached,
                objects: objects.into_iter().map(chunk_storage_key).collect(),
                bytes,
                state: "pending".into(),
            });
        }
        let rest: Vec<&ObjectName> = blocks.keys().filter(|o| !covered.contains(*o)).collect();
        plan.remote_part_bytes = rest.iter().map(|o| blocks[*o].0).sum();
        plan.remote_part_cost = rest
            .iter()
            .map(|o| cost_of.get(*o).copied().flatten())
            .try_fold(0.0, |a, c| c.map(|c| a + c));
        let insertions = plan.steps.iter().filter(|s| !s.attached).count() as u64;
        plan.disks_secs = (insertions * settings.overhead_secs) as f64
            + settings.disk_secs(plan.total_bytes - plan.remote_part_bytes)
            + settings.link_secs(plan.remote_part_bytes);
        if plan.steps.is_empty() {
            plan.recommend = "remote".into();
            plan.reason = "the network is as cheap and faster".into();
        } else {
            plan.recommend = "disks".into();
            plan.reason = if !must.is_empty() {
                "some blocks are only on pool disks".into()
            } else if remote_cold {
                "the remote copies are in cold storage".into()
            } else if costly && plan.disks_secs < plan.remote.secs {
                "the disks are cheaper and faster than the network".into()
            } else if costly {
                "the disks are cheaper than the network".into()
            } else {
                "the disks are faster than the network".into()
            };
        }
        self.save_fetch_plan(&plan)?;
        Ok(plan)
    }

    pub fn load_fetch_plan(&self) -> Option<FetchPlan> {
        util::read_json(&self.staging_dir().join(PLAN_FILE)).ok()
    }

    fn save_fetch_plan(&self, plan: &FetchPlan) -> Result<()> {
        util::write_json(&self.staging_dir().join(PLAN_FILE), plan)
    }

    /// Forget the plan and every staged block.
    pub fn cancel_fetch_plan(&mut self) -> Result<()> {
        let dir = self.staging_dir();
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Copy the blocks of step `k` from its disk (which must be attached
    /// now) into the staging area, each hashed against its name, then
    /// write every file that is now complete, then write the disk's index
    /// and sync it. Returns the outcome and the disk's mount path.
    pub fn fetch_plan_step(
        &mut self,
        plan: &mut FetchPlan,
        k: usize,
    ) -> Result<(StepOutcome, PathBuf)> {
        let step = plan
            .steps
            .get(k)
            .cloned()
            .ok_or_else(|| anyhow!("the plan has no step {}", k + 1))?;
        let spec = self
            .pool_specs()
            .into_iter()
            .find(|s| s.name() == step.pool)
            .ok_or_else(|| anyhow!("no disk pool named {}", step.pool))?;
        let pool = self.open_pool(&spec)?;
        let mount = pool.mount_of(&step.disk_id).ok_or_else(|| {
            anyhow::Error::new(PoolError::NeedsDisk {
                label: step.label.clone(),
                disk_id: step.disk_id.clone(),
                place: step.place.clone(),
            })
        })?;
        let root = self.staging_dir().join(&step.pool);
        let task = crate::activity::start(
            crate::activity::DISK_FETCH,
            &step.label,
            step.bytes,
            crate::activity::Unit::Bytes,
        );
        task.set_phase("copy");
        let mut out = StepOutcome {
            label: step.label.clone(),
            ..Default::default()
        };
        // The disk holds packs: each block is read from its place in one
        // (the folders' block maps give the places, the view the packs on
        // the pool).
        let view = self.view3()?;
        let mut place: HashMap<String, (crate::ledger3::PackId, u64, u64)> = HashMap::new();
        let folders: BTreeSet<String> = plan.files.iter().map(|f| f.folder.clone()).collect();
        for name in folders {
            let Ok((rec, _)) = self.resolve_folder(&name) else {
                continue;
            };
            let Some(t) = self.folder_table3(&rec)? else {
                continue;
            };
            let t = t.read().unwrap_or_else(|e| e.into_inner());
            for key in &step.objects {
                let Some(o) = key
                    .rsplit('/')
                    .next()
                    .and_then(|n| ObjectName::from_hex(n).ok())
                    .and_then(|o| crate::storages3::object_bin(&o).ok())
                else {
                    continue;
                };
                if let Some(p) = view
                    .block_places(&o, &*t)
                    .into_iter()
                    .find(|p| p.storages.contains(&step.pool))
                {
                    place.insert(
                        key.clone(),
                        (
                            p.place.pack,
                            u64::from(p.place.offset),
                            u64::from(p.place.len),
                        ),
                    );
                }
            }
        }
        for key in &step.objects {
            let dest = root.join(key);
            if dest.is_file() {
                continue;
            }
            let name = key.rsplit('/').next().unwrap_or("");
            let got = match place.get(key) {
                Some((pack, offset, len)) => {
                    pool.get_range(&crate::packs::pack_key(&hex::encode(pack)), *offset, *len)
                }
                None => pool.get(key),
            }
            .ok()
            .flatten()
            .filter(|b| hex::encode(crypto::hash(b)) == name);
            match got {
                Some(b) => {
                    crate::activity::advance_current(b.len() as u64);
                    // Staged in the device directory: stop before its disk
                    // runs short (`freespace`); the step can be run again.
                    crate::freespace::check(
                        &crate::freespace::Place::device(),
                        &root,
                        crate::freespace::DEFAULT,
                        b.len() as u64,
                    )?;
                    util::write_atomic(&dest, &b)?;
                    out.objects += 1;
                    out.bytes += b.len() as u64;
                }
                None => out.failed.push(key.clone()),
            }
        }
        drop(pool);
        if let Some(s) = plan.steps.get_mut(k) {
            s.state = "done".into();
        }
        task.step(
            "write",
            plan.files.iter().filter(|f| !f.done).map(|f| f.size).sum(),
            crate::activity::Unit::Bytes,
        );
        out.files_done = self.fetch_plan_write_ready(plan, false)?;
        drop(task);
        let mount_now = self.disk_eject(&step.label).unwrap_or(mount);
        out.message = format!(
            "Got {} blocks ({}) from {}: you can now remove it",
            out.objects,
            util::human_bytes(out.bytes),
            step.label
        );
        self.save_fetch_plan(plan)?;
        Ok((out, mount_now))
    }

    /// Write the files of the plan whose blocks are all staged (or, with
    /// `remote`, every remaining file, fetching what is missing from the
    /// storages). Returns the paths written.
    pub fn fetch_plan_write_ready(
        &mut self,
        plan: &mut FetchPlan,
        remote: bool,
    ) -> Result<Vec<String>> {
        let roots = self.staging_roots();
        let mut done = Vec::new();
        for i in 0..plan.files.len() {
            if plan.files[i].done {
                continue;
            }
            // Blocks still expected from a disk that is not done yet.
            let waiting = plan.files[i].objects.iter().any(|key| {
                let staged = key
                    .rsplit('/')
                    .next()
                    .and_then(|n| ObjectName::from_hex(n).ok())
                    .is_some_and(|o| staged_object(&roots, &o).is_some());
                !staged
                    && plan
                        .steps
                        .iter()
                        .any(|s| s.state == "pending" && s.objects.contains(key))
            });
            if waiting && !remote {
                continue;
            }
            let (folder, path) = (plan.files[i].folder.clone(), plan.files[i].path.clone());
            match self.fetch_file(&folder, &path) {
                Ok(_) => {
                    plan.files[i].done = true;
                    plan.files[i].error = None;
                    done.push(path);
                }
                Err(e) => plan.files[i].error = Some(format!("{e:#}")),
            }
        }
        if plan.files.iter().all(|f| f.done) {
            self.cancel_fetch_plan()?;
        } else {
            self.save_fetch_plan(plan)?;
        }
        Ok(done)
    }

    /// Mark step `k` skipped: its blocks come from the remote storages.
    pub fn fetch_plan_skip(&mut self, plan: &mut FetchPlan, k: usize) -> Result<()> {
        if let Some(s) = plan.steps.get_mut(k) {
            s.state = "skipped".into();
        }
        self.save_fetch_plan(plan)
    }

    /// Run a plan to the end through `driver`: for every pending disk ask
    /// for it (unless it was attached when the plan was made), copy its
    /// blocks, write the files that are complete, sync, unmount and say it
    /// can be removed; then write what is left from the remote storages.
    pub fn run_fetch_plan(
        &mut self,
        plan: &mut FetchPlan,
        driver: &mut dyn PlanDriver,
    ) -> Result<FetchPlanReport> {
        crate::logged_op!("run fetch plan", "", {
            self.run_fetch_plan_inner(plan, driver)
        })
    }

    fn run_fetch_plan_inner(
        &mut self,
        plan: &mut FetchPlan,
        driver: &mut dyn PlanDriver,
    ) -> Result<FetchPlanReport> {
        let mut report = FetchPlanReport::default();
        for k in 0..plan.steps.len() {
            if plan.steps[k].state != "pending" {
                continue;
            }
            let step = plan.steps[k].clone();
            let attached_now = |e: &Engine| -> bool {
                e.pool_specs()
                    .into_iter()
                    .find(|s| s.name() == step.pool)
                    .and_then(|s| e.open_pool(&s).ok())
                    .is_some_and(|p| p.mount_of(&step.disk_id).is_some())
            };
            if !(step.attached && attached_now(self)) {
                loop {
                    match driver.ask(plan, k)? {
                        InsertAnswer::Stop => {
                            report.stopped = true;
                            self.save_fetch_plan(plan)?;
                            return Ok(report);
                        }
                        InsertAnswer::Skip => {
                            self.fetch_plan_skip(plan, k)?;
                            break;
                        }
                        InsertAnswer::Inserted => {
                            if driver.attach(&step)? && attached_now(self) {
                                break;
                            }
                            driver.say(&format!(
                                "{} is not attached: insert it into the dock and try again",
                                step.label
                            ));
                        }
                    }
                }
                if plan.steps[k].state == "skipped" {
                    continue;
                }
            }
            let (out, mount) = self.fetch_plan_step(plan, k)?;
            report.files_done.extend(out.files_done.iter().cloned());
            if !step.attached {
                driver.release(&step, &mount)?;
                driver.say(&out.message);
            } else {
                driver.say(&format!(
                    "Got {} blocks ({}) from {}",
                    out.objects,
                    util::human_bytes(out.bytes),
                    step.label
                ));
            }
            report.steps.push(out);
        }
        report
            .files_done
            .extend(self.fetch_plan_write_ready(plan, true)?);
        report.files_failed = plan
            .files
            .iter()
            .filter(|f| !f.done)
            .map(|f| (f.path.clone(), f.error.clone().unwrap_or_default()))
            .collect();
        Ok(report)
    }
}
