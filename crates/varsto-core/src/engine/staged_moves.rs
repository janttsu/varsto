// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Staged moves: persistent, resumable move jobs
//! (`docs/spec/alpha-0-format.md`, "Staged moves to disk pools").
//!
//! A job moves a folder's blocks (or those of some paths) from one storage
//! to another over as many runs as it takes. Each run is an ordinary move
//! (`data_moves`): what is left is worked out from the ledger, blocks go to
//! the target in groups, and a source copy is dropped only when the target
//! copy is checked and the policy still holds. Where an ordinary move would
//! leave a block out because the pool has no disk with room, a job run
//! stops and waits: the job stays open, says which disk to attach, and the
//! service runs it again when a disk of the pool comes or its space changes.

use super::data_moves::StagedExtras;
use super::*;
use crate::placement::{MoveReport, MoveRequest};
use crate::staged_move::{self as jobs, JobLock, JobState, MoveJob, MoveWait, Waiting};

/// Groups of 64 blocks the background service moves per run.
pub const SERVICE_RUN_GROUPS: usize = 16;
/// Errors a job file keeps.
const MAX_ERRORS: usize = 20;

/// What to move, and how.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoveJobRequest {
    pub folder: String,
    /// Folder paths (files or directories, relative to the folder or
    /// inside its directory on this device); empty: everything.
    #[serde(default)]
    pub paths: Vec<String>,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub idle_days: Option<i64>,
    /// Copy and check, never drop from `from`.
    #[serde(default)]
    pub keep_source: bool,
    #[serde(default)]
    pub confirm_cold_read: bool,
}

/// How much one run of a job may do.
#[derive(Clone, Debug, Default)]
pub struct JobRunLimits {
    /// Stop after this many groups of 64 blocks.
    pub max_groups: Option<usize>,
}

impl JobRunLimits {
    /// What the background service does per run.
    pub fn service() -> Self {
        JobRunLimits {
            max_groups: Some(SERVICE_RUN_GROUPS),
        }
    }
}

/// The outcome of a job run.
#[derive(Clone, Debug, Serialize)]
pub struct MoveJobRun {
    pub job: MoveJob,
    /// False when the job did not run (paused, finished, or another run
    /// holds it); `note` says why.
    pub ran: bool,
    pub note: Option<String>,
    pub report: MoveReport,
}

impl Engine {
    // ----- creating and listing ------------------------------------------------

    /// What a job would move now, without recording anything.
    pub fn move_job_plan(&mut self, req: &MoveJobRequest) -> Result<MoveReport> {
        let (rec, ex, mreq) = self.job_request(req, true)?;
        self.pull_ledger_once()?;
        let mut plan = self.plan_move(&rec, &mreq, &ex)?;
        plan.report.summary = Self::job_plan_summary(&plan.report, req);
        Ok(plan.report)
    }

    fn job_plan_summary(r: &MoveReport, req: &MoveJobRequest) -> String {
        let mut s = format!(
            "Would move {} block{} ({}) of folder {} from {} to {}{}",
            r.blocks,
            if r.blocks == 1 { "" } else { "s" },
            util::human_bytes(r.bytes),
            r.folder,
            r.from,
            r.to,
            if req.keep_source {
                " and keep them on the source"
            } else {
                ""
            }
        );
        if !req.paths.is_empty() {
            s += &format!(" (only {})", req.paths.join(", "));
        }
        s += ".";
        if r.blocks_kept > 0 {
            s += &format!(
                " {} block{} stay on {}: {}.",
                r.blocks_kept,
                if r.blocks_kept == 1 { "" } else { "s" },
                r.from,
                r.kept.first().map(|(_, w)| w.as_str()).unwrap_or("")
            );
        }
        if !r.remaining_on.is_empty() {
            s += &format!(
                " Afterwards every block has at least {} cop{}, on {}.",
                r.min_copies_after,
                if r.min_copies_after == 1 { "y" } else { "ies" },
                r.remaining_on.join(", ")
            );
        }
        s
    }

    /// Validate a request and work out the folder, the extras and the
    /// move request it stands for.
    fn job_request(
        &self,
        req: &MoveJobRequest,
        dry_run: bool,
    ) -> Result<(FolderRecord, StagedExtras, MoveRequest)> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot move the owner's data");
        }
        let (rec, root) = self.resolve_folder(&req.folder)?;
        let paths = self.job_paths(&rec, &root, &req.paths)?;
        let ex = StagedExtras {
            staged: true,
            paths,
            keep_source: req.keep_source,
            ..Default::default()
        };
        let mreq = MoveRequest {
            folder: rec.folder_id.to_string(),
            from: req.from.clone(),
            to: req.to.clone(),
            idle_days: req.idle_days,
            dry_run,
            confirm_cold_read: req.confirm_cold_read,
        };
        Ok((rec, ex, mreq))
    }

    /// Paths as the folder knows them (forward slashes, relative); each must
    /// hold at least one current file.
    fn job_paths(&self, rec: &FolderRecord, root: &Path, given: &[String]) -> Result<Vec<String>> {
        let state = self.load_state(&rec.folder_id)?;
        let mut out: Vec<String> = Vec::new();
        for p in given {
            let raw = Path::new(p);
            let rel: String = if raw.is_absolute() {
                raw.strip_prefix(root)
                    .map_err(|_| {
                        anyhow!("{p} is not inside folder {} ({})", rec.name, root.display())
                    })?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/")
            } else {
                p.replace('\\', "/")
            };
            let rel = rel.trim_start_matches("./").trim_matches('/').to_string();
            if rel.is_empty() {
                // The folder itself.
                return Ok(Vec::new());
            }
            util::check_rel_path(&rel)?;
            let hit = state.files.values().any(|f| {
                !f.deleted
                    && (f.path == rel
                        || f.path
                            .strip_prefix(rel.as_str())
                            .is_some_and(|r| r.starts_with('/')))
            });
            if !hit {
                bail!("no file of folder {} is at or under {rel}", rec.name);
            }
            if !out.contains(&rel) {
                out.push(rel);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Record a job (or return the open one that is the same move) without
    /// running it. `Ok((job, existing))`.
    pub fn move_job_start(&mut self, req: &MoveJobRequest) -> Result<(MoveJob, bool)> {
        crate::logged_op!("start move job", "", { self.move_job_start_inner(req) })
    }

    fn move_job_start_inner(&mut self, req: &MoveJobRequest) -> Result<(MoveJob, bool)> {
        let (rec, ex, mreq) = self.job_request(req, true)?;
        if let Some(j) = jobs::list_active(&self.home).into_iter().find(|j| {
            j.folder_id == rec.folder_id.to_string()
                && j.from == req.from
                && j.to == req.to
                && j.paths == ex.paths
                && j.keep_source == req.keep_source
                && j.idle_days == req.idle_days
        }) {
            return Ok((j, true));
        }
        self.ensure_ledger_writable()?;
        self.pull_ledger_once()?;
        let plan = self.plan_move(&rec, &mreq, &ex)?;
        let now = util::now_utc();
        let job = MoveJob {
            id: jobs::new_id(),
            folder: rec.name.clone(),
            folder_id: rec.folder_id.to_string(),
            paths: ex.paths.clone(),
            from: req.from.clone(),
            to: req.to.clone(),
            idle_days: req.idle_days,
            keep_source: req.keep_source,
            confirm_cold_read: req.confirm_cold_read,
            policy: rec
                .effective_policy()
                .map(|p| p.describe())
                .unwrap_or_else(|| "no copy rules".to_string()),
            state: JobState::Open,
            bytes_total: plan.items.iter().map(|i| i.size).sum(),
            bytes_remaining: plan.items.iter().map(|i| i.size).sum(),
            blocks_total: plan.items.len() as u64,
            started_utc: now,
            last_progress_utc: now,
            ..Default::default()
        };
        job.save(&self.home)?;
        log::info!(
            id = job.id.as_str(),
            folder = job.folder.as_str(),
            from = job.from.as_str(),
            to = job.to.as_str(),
            bytes = job.bytes_total;
            "move job started"
        );
        Ok((job, false))
    }

    /// Every move job, oldest first.
    pub fn move_jobs(&self) -> Vec<MoveJob> {
        jobs::list(&self.home)
    }

    /// One job by id (or unambiguous prefix).
    pub fn move_job(&self, id: &str) -> Result<MoveJob> {
        jobs::find(&self.home, id)
    }

    /// Pause, resume or cancel a job. Cancelling never deletes anything:
    /// what was moved stays moved, what was copied stays copied.
    pub fn move_job_set_state(&mut self, id: &str, state: JobState) -> Result<MoveJob> {
        let mut job = jobs::find(&self.home, id)?;
        match (job.state, state) {
            (a, b) if a == b => return Ok(job),
            (JobState::Done, _) | (JobState::Cancelled, _) => {
                bail!("move job {} is {}", job.id, job.state.label())
            }
            (JobState::Open, JobState::Paused)
            | (JobState::Paused, JobState::Open)
            | (JobState::Open | JobState::Paused, JobState::Cancelled) => {}
            (a, b) => bail!(
                "move job {} is {}: it cannot become {}",
                job.id,
                a.label(),
                b.label()
            ),
        }
        job.state = state;
        if state == JobState::Cancelled {
            job.finished_utc = util::now_utc();
            job.waiting = None;
        }
        job.save(&self.home)?;
        Ok(job)
    }

    // ----- running -------------------------------------------------------------

    /// Run a job once: move what fits now, then stop. A job that waits for
    /// room stays open.
    pub fn move_job_run(&mut self, id: &str, limits: &JobRunLimits) -> Result<MoveJobRun> {
        crate::logged_op!("run move job", id, { self.move_job_run_inner(id, limits) })
    }

    fn move_job_run_inner(&mut self, id: &str, limits: &JobRunLimits) -> Result<MoveJobRun> {
        let job = jobs::find(&self.home, id)?;
        let skipped = |job: MoveJob, why: String| MoveJobRun {
            job,
            ran: false,
            note: Some(why),
            report: MoveReport::default(),
        };
        if !job.state.is_open() {
            let why = format!("move job {} is {}", job.id, job.state.label());
            return Ok(skipped(job, why));
        }
        let Some(_lock) = JobLock::acquire(&self.home, &job.id) else {
            let why = format!("move job {} is running in another process", job.id);
            return Ok(skipped(job, why));
        };
        match self.job_run_locked(job.clone(), limits) {
            Ok(run) => Ok(run),
            Err(e) => {
                // Keep the reason in the job file; the job stays open.
                let mut j = jobs::find(&self.home, &job.id).unwrap_or(job);
                let msg = format!("{}: {e:#}", util::format_date(util::now_utc()));
                j.errors.push(msg);
                let excess = j.errors.len().saturating_sub(MAX_ERRORS);
                j.errors.drain(..excess);
                let _ = j.save(&self.home);
                Err(e)
            }
        }
    }

    fn job_run_locked(&mut self, job: MoveJob, limits: &JobRunLimits) -> Result<MoveJobRun> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot move the owner's data");
        }
        self.ensure_ledger_writable()?;
        let (rec, _) = self.resolve_folder(&job.folder_id)?;
        self.pull_ledger_once()?;
        let mreq = MoveRequest {
            folder: job.folder_id.clone(),
            from: job.from.clone(),
            to: job.to.clone(),
            idle_days: job.idle_days,
            dry_run: false,
            confirm_cold_read: job.confirm_cold_read,
        };
        let mut ex = StagedExtras {
            staged: true,
            paths: job.paths.clone(),
            keep_source: job.keep_source,
            max_groups: limits.max_groups,
            job_id: Some(job.id.clone()),
            ..Default::default()
        };
        let mut plan = self.plan_move(&rec, &mreq, &ex)?;
        let to_spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == job.to)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {}", job.to))?;
        // Copies already made and checked count as done when nothing is
        // dropped from the source: they need no work.
        let (mut pre_bytes, mut pre_blocks) = (0u64, 0u64);
        if job.keep_source {
            let pool = to_spec
                .is_data_only()
                .then(|| self.open_pool(&to_spec))
                .transpose()?;
            plan.items.retain(|i| {
                let met = i.on_to
                    && pool.as_ref().is_none_or(|p| {
                        p.copies() <= 1
                            || p.places_of(&chunk_storage_key(&i.object)).len() >= p.copies() as usize
                    });
                if met {
                    pre_bytes += i.size;
                    pre_blocks += 1;
                }
                !met
            });
        }
        let todo_bytes: u64 = plan.items.iter().map(|i| i.size).sum();
        let todo_blocks = plan.items.len() as u64;
        let planned_kept = plan.report.blocks_kept;
        let planned_kept_why: Vec<String> = plan.report.kept.iter().map(|(_, w)| w.clone()).collect();
        let done0 = job
            .bytes_done
            .max(job.bytes_total.saturating_sub(todo_bytes))
            .max(pre_bytes);
        let blocks0 = job
            .blocks_done
            .max(job.blocks_total.saturating_sub(todo_blocks))
            .max(pre_blocks);
        ex.base_done = done0;
        ex.base_blocks = blocks0;
        // Totals first, so a crash leaves a consistent file.
        let mut j = jobs::find(&self.home, &job.id)?;
        j.bytes_done = done0;
        j.bytes_total = done0 + todo_bytes;
        j.bytes_remaining = todo_bytes;
        j.blocks_done = blocks0;
        j.blocks_total = blocks0 + todo_blocks;
        j.runs += 1;
        j.kept_blocks = planned_kept;
        j.save(&self.home)?;

        let report = if todo_blocks > 0 || plan.report.already_moved > 0 {
            self.run_move(&rec, &mreq, plan, &ex)?
        } else {
            MoveReport {
                folder: rec.name.clone(),
                from: job.from.clone(),
                to: job.to.clone(),
                ..Default::default()
            }
        };

        // Work out where the job stands.
        let mut j = jobs::find(&self.home, &job.id)?;
        let now = util::now_utc();
        j.bytes_done = done0 + report.bytes_done;
        j.blocks_done = blocks0 + report.blocks_done;
        j.bytes_remaining = todo_bytes.saturating_sub(report.bytes_done);
        j.need_second_place_bytes = report.waiting_place_bytes;
        j.kept_blocks = planned_kept + report.blocks_kept;
        for d in &report.disks_used {
            if !j.disks_used.contains(d) {
                j.disks_used.push(d.clone());
            }
        }
        if report.bytes_done > 0 || report.blocks_copied > 0 {
            j.last_progress_utc = now;
        }
        let before = j.waiting.clone();
        j.waiting = None;
        let finished;
        if report.stopped_early {
            finished = false;
        } else if report.waiting_room_blocks > 0 {
            j.room_needed = report.waiting_min_bytes;
            j.waiting = Some(self.room_waiting(&to_spec, &j, &report));
            j.room_sig = self.room_signature(&to_spec);
            finished = false;
        } else if report.waiting_place_blocks > 0 {
            j.waiting = Some(Waiting {
                kind: "place".to_string(),
                disk: None,
                text: format!(
                    "{} need a copy on a disk kept in another place (disk group of pool {}): attach a disk of another place",
                    util::human_bytes(report.waiting_place_bytes),
                    j.to
                ),
            });
            j.room_sig = self.room_signature(&to_spec);
            finished = false;
        } else {
            finished = true;
        }
        let mut notes: Vec<String> = planned_kept_why;
        notes.extend(report.kept.iter().map(|(_, w)| w.clone()));
        notes.dedup();
        if finished {
            let kept = j.kept_blocks;
            if kept > 0 || j.bytes_remaining > 0 {
                let n = kept.max(todo_blocks.saturating_sub(report.blocks_done));
                j.errors.push(format!(
                    "{}: {} block{} stay on {}{}",
                    util::format_date(now),
                    n,
                    if n == 1 { "" } else { "s" },
                    j.from,
                    notes
                        .first()
                        .map(|w| format!(": {w}"))
                        .unwrap_or_default()
                ));
            }
            j.bytes_remaining = 0;
            // Only a job that left nothing behind makes the target the
            // folder's place for new blocks (as a whole-folder move does).
            if j.paths.is_empty() && j.idle_days.is_none() && !j.keep_source && kept == 0 {
                if let Some(p) = self.placement_without(&rec, &j.from, &j.to) {
                    if let Err(e) = self.set_placement(rec.folder_id.as_str(), Some(p)) {
                        j.errors.push(format!("placement not changed: {e:#}"));
                    }
                }
            }
            j.state = JobState::Done;
            j.finished_utc = now;
        }
        let excess = j.errors.len().saturating_sub(MAX_ERRORS);
        j.errors.drain(..excess);
        // A pause or cancel during the run wins.
        let fresh = jobs::find(&self.home, &job.id)?;
        if fresh.state != JobState::Open {
            j.state = fresh.state;
            j.finished_utc = fresh.finished_utc.max(j.finished_utc);
        }
        j.save(&self.home)?;
        self.publish_job_events(&j, before.as_ref());
        Ok(MoveJobRun {
            job: j,
            ran: true,
            note: None,
            report,
        })
    }

    /// Update the job file after a group of blocks (called by the move).
    pub(super) fn staged_checkpoint(&self, ex: &StagedExtras, report: &MoveReport) {
        let Some(id) = &ex.job_id else { return };
        let Ok(mut j) = jobs::find(&self.home, id) else {
            return;
        };
        j.bytes_done = ex.base_done + report.bytes_done;
        j.blocks_done = ex.base_blocks + report.blocks_done;
        j.bytes_remaining = j.bytes_total.saturating_sub(j.bytes_done);
        j.need_second_place_bytes = report.waiting_place_bytes;
        for d in &report.disks_used {
            if !j.disks_used.contains(d) {
                j.disks_used.push(d.clone());
            }
        }
        j.last_progress_utc = util::now_utc();
        let _ = j.save(&self.home);
        jobs::touch_lock(&self.home, id);
    }

    fn publish_job_events(&self, j: &MoveJob, before: Option<&Waiting>) {
        match (&j.state, &j.waiting) {
            (JobState::Done, _) => {
                crate::events::publish(
                    "move.done",
                    serde_json::json!({
                        "id": j.id,
                        "folder": j.folder,
                        "from": j.from,
                        "to": j.to,
                        "bytes": j.bytes_done,
                        "disks": j.disks_used,
                    }),
                );
            }
            (JobState::Open, Some(w)) if before != Some(w) => {
                crate::events::publish(
                    "move.waiting",
                    serde_json::json!({
                        "id": j.id,
                        "folder": j.folder,
                        "to": j.to,
                        "kind": w.kind,
                        "disk": w.disk,
                        "bytes_left": j.bytes_remaining,
                        "need_second_place_bytes": j.need_second_place_bytes,
                        "text": w.text,
                    }),
                );
            }
            _ => {}
        }
    }

    // ----- waiting for room ----------------------------------------------------

    /// Free room (within its reserve) of a known pool disk, from the last
    /// measurement for one that is away.
    fn disk_room(pool: &PoolStorage, d: &PoolDisk) -> u64 {
        if pool.mount_of(&d.id).is_some() {
            pool.room(&d.id).unwrap_or(0)
        } else {
            d.free_bytes.saturating_sub(pool.reserve(d.capacity_bytes))
        }
    }

    /// The sentence for a job that waits for room on its target.
    fn room_waiting(&self, to: &StorageSpec, j: &MoveJob, report: &MoveReport) -> Waiting {
        let left = util::human_bytes(j.bytes_remaining);
        if !to.is_data_only() {
            return Waiting {
                kind: "room".to_string(),
                disk: None,
                text: report
                    .waiting_note
                    .clone()
                    .map(|n| format!("{n}; {left} left"))
                    .unwrap_or_else(|| format!("storage {} has no room; {left} left", j.to)),
            };
        }
        let next = self
            .open_pool(to)
            .ok()
            .and_then(|pool| Self::next_known_disk(&pool, j.room_needed));
        match next {
            Some((label, room)) => Waiting {
                kind: "disk".to_string(),
                disk: Some(label.clone()),
                text: format!(
                    "attach disk «{label}» ({} free) to continue the move: {left} left",
                    util::human_bytes(room)
                ),
            },
            None => Waiting {
                kind: "disk".to_string(),
                disk: None,
                text: format!(
                    "attach a new disk of pool {} to continue the move: {left} left (`varsto disk init <device> --pool {} --label <name>` or `varsto disk add <mount> --pool {} --label <name>`)",
                    j.to, j.to, j.to
                ),
            },
        }
    }

    /// The known disk of a pool that is away and has the most room.
    fn next_known_disk(pool: &PoolStorage, needed: u64) -> Option<(String, u64)> {
        pool.disks()
            .into_iter()
            .filter(|d| !d.retired && pool.mount_of(&d.id).is_none())
            .map(|d| (Self::disk_room(pool, &d), d))
            .filter(|(room, d)| *room >= needed.max(1) && d.write_failed_utc == 0)
            .max_by_key(|(room, _)| *room)
            .map(|(room, d)| (d.label, room))
    }

    /// Which attached disks of a pool have room, and how much: a job that
    /// waited for room runs again when this changes.
    fn room_signature(&self, to: &StorageSpec) -> String {
        if !to.is_data_only() {
            return String::new();
        }
        let Ok(pool) = self.open_pool(to) else {
            return String::new();
        };
        let mut parts: Vec<String> = pool
            .disks()
            .into_iter()
            .filter(|d| !d.retired && pool.mount_of(&d.id).is_some())
            .map(|d| format!("{}:{}", d.id, Self::disk_room(&pool, &d)))
            .collect();
        parts.sort();
        parts.join(",")
    }

    /// Open jobs that wait for room on a pool, for the disk suggestion.
    pub fn move_waits(&self) -> Vec<MoveWait> {
        jobs::list_active(&self.home)
            .into_iter()
            .filter(|j| j.state.is_open() && j.bytes_remaining > 0)
            .filter(|j| {
                self.config
                    .storages
                    .iter()
                    .any(|s| s.name() == j.to && s.is_data_only())
            })
            .map(|j| MoveWait {
                id: j.id,
                folder: j.folder,
                pool: j.to,
                bytes_left: j.bytes_remaining,
                need_second_place_bytes: j.need_second_place_bytes,
                room_needed: j.room_needed,
            })
            .collect()
    }

    // ----- the service ---------------------------------------------------------

    /// Open jobs worth running now. A job to a pool runs when an attached
    /// disk has room and the attached disks or their room differ from when
    /// the job last waited (a disk came, or a disk's space changed); a job
    /// to another storage runs after every sync (`after_sync`).
    pub fn move_jobs_ready(&self, after_sync: bool) -> Vec<String> {
        jobs::list_active(&self.home)
            .into_iter()
            .filter(|j| j.state.is_open())
            .filter(|j| {
                let Some(to) = self.config.storages.iter().find(|s| s.name() == j.to) else {
                    return false;
                };
                if !to.is_data_only() {
                    return after_sync;
                }
                let sig = self.room_signature(to);
                // Something has room, and it is not what the job last saw.
                let has_room = sig
                    .split(',')
                    .filter_map(|p| p.rsplit(':').next()?.parse::<u64>().ok())
                    .any(|room| room >= j.room_needed.max(1));
                has_room && (j.waiting.is_none() || sig != j.room_sig)
            })
            .map(|j| j.id)
            .collect()
    }

    /// Run the open jobs that are ready (the service calls this after a
    /// sync and when pool disks come, go or change). Errors go to the log
    /// and the job file.
    pub fn move_jobs_run_ready(
        &mut self,
        after_sync: bool,
        limits: &JobRunLimits,
    ) -> Vec<MoveJobRun> {
        let mut out = Vec::new();
        for id in self.move_jobs_ready(after_sync) {
            match self.move_job_run(&id, limits) {
                Ok(r) if r.ran => out.push(r),
                Ok(_) => {}
                Err(e) => log::warn!("move job {id} failed: {e:#}"),
            }
        }
        out
    }
}
