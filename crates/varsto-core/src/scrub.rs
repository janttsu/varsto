// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Bit-rot checks ("scrub"): every copy this device can read is re-hashed
//! on a rolling schedule, whoever wrote it, and so is every synced file on
//! this device's disk and its encrypted block cache.
//!
//! Automatic verification (`crate::autoverify`) checks copies *other*
//! devices wrote, for the policies; nothing re-read what a device wrote
//! itself, and nothing re-read a local file whose size and modification
//! time had not changed. A scrub does, without counting for any policy: its
//! checks are not recorded in the ledger.
//!
//! What is read is split into targets: one per storage, one per attached
//! disk of a pool, one per attached folder and the block cache. Each target
//! is swept in order of its keys (object names, paths) with a cursor kept in
//! `state/scrub.json`: the items after the cursor are the ones checked
//! longest ago (or never), so taking them in order is "oldest first", and the
//! state stays a few lines per target however many objects there are. A pass
//! over a target should end within `scrub_days`; a scheduled run takes the
//! share of what is left that the time since its last run stands for, within
//! the run's byte budgets (one for this device's disks, one for remote
//! storages), so the reads spread evenly over the period instead of reading
//! everything at once and nothing for weeks.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Schedule and budgets, per device (`config.json`, `scrub`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScrubSchedule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hours between runs.
    #[serde(default = "default_interval_hours")]
    pub interval_hours: u32,
    /// Every copy and file is re-hashed at least once in this many days.
    #[serde(default = "default_scrub_days")]
    pub scrub_days: u32,
    /// Most bytes read per run from this device's disks: local files, the
    /// block cache, directory storages and attached pool disks.
    #[serde(default = "default_max_local_bytes")]
    pub max_local_bytes: u64,
    /// Most bytes downloaded per run from S3 and rclone storages.
    #[serde(default = "default_max_remote_bytes")]
    pub max_remote_bytes: u64,
    /// Cold storages the user agreed to have scrubbed (retrieval fees).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub cold: BTreeSet<String>,
}

fn default_true() -> bool {
    true
}
fn default_interval_hours() -> u32 {
    24
}
fn default_scrub_days() -> u32 {
    90
}
fn default_max_local_bytes() -> u64 {
    2 << 30
}
fn default_max_remote_bytes() -> u64 {
    1 << 30
}

impl Default for ScrubSchedule {
    fn default() -> Self {
        ScrubSchedule {
            enabled: true,
            interval_hours: default_interval_hours(),
            scrub_days: default_scrub_days(),
            max_local_bytes: default_max_local_bytes(),
            max_remote_bytes: default_max_remote_bytes(),
            cold: BTreeSet::new(),
        }
    }
}

impl ScrubSchedule {
    /// When the next run is due, given the last one.
    pub fn next_run_utc(&self, last_run_utc: Option<i64>) -> Option<i64> {
        if !self.enabled {
            return None;
        }
        Some(last_run_utc.map_or(0, |t| t + self.interval_hours.max(1) as i64 * 3600))
    }
    pub fn is_due(&self, last_run_utc: Option<i64>, now_utc: i64) -> bool {
        self.next_run_utc(last_run_utc)
            .is_some_and(|next| now_utc >= next)
    }
    pub fn period_secs(&self) -> i64 {
        self.scrub_days.max(1) as i64 * 86_400
    }
    pub fn interval_secs(&self) -> i64 {
        self.interval_hours.max(1) as i64 * 3600
    }
}

/// Where one target's sweep is.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Sweep {
    /// What the target is, for people: "storage box", "disk shelf-1 of pool
    /// shelf", "folder docs", "block cache".
    #[serde(default)]
    pub label: String,
    /// Last key checked in the current pass; none: the pass starts at the
    /// first key.
    #[serde(default)]
    pub cursor: Option<String>,
    /// When the current pass began (0: no pass yet).
    #[serde(default)]
    pub pass_started_utc: i64,
    /// When a run last read this target.
    #[serde(default)]
    pub last_run_utc: i64,
    /// When a pass last went through every item.
    #[serde(default)]
    pub last_pass_done_utc: Option<i64>,
    /// Items checked in the current pass.
    #[serde(default)]
    pub checked_in_pass: u64,
}

/// The bytes a run may still read, for one class of targets.
#[derive(Clone, Debug)]
pub struct Budget {
    pub left: u64,
    /// Something was read under this budget in this run.
    pub used: bool,
}

impl Budget {
    pub fn new(bytes: u64) -> Self {
        Budget {
            left: bytes,
            used: false,
        }
    }
    pub fn unlimited() -> Self {
        Budget::new(u64::MAX)
    }
    /// Take `size` bytes; the first item of a run is always allowed, so a
    /// large object cannot stall the sweep.
    fn take(&mut self, size: u64) -> bool {
        if size <= self.left || !self.used {
            self.left = self.left.saturating_sub(size);
            self.used = true;
            true
        } else {
            false
        }
    }
    pub fn spent(&self) -> bool {
        self.used && self.left == 0
    }
}

/// What to read of one target now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepPlan {
    /// Indices into the item list, in order.
    pub picks: Vec<usize>,
    /// The picks reach the last item: the pass ends with them.
    pub finishes_pass: bool,
    /// Items after the cursor before this run.
    pub remaining: u64,
    /// The pass should have ended by now and items remain after this run.
    pub behind: bool,
}

/// How a run takes items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pace {
    /// The service: the share of what is left that the time since the last
    /// run stands for, so a pass ends within the period.
    Scheduled,
    /// A run asked for: as much as the budget allows.
    Budget,
    /// Everything, from the first item, whatever the budget.
    Full,
}

/// The items of one target to check now. `items` are (key, size) sorted by
/// key; the ones after the sweep's cursor have waited longest and come first.
pub fn plan(
    items: &[(String, u64)],
    sweep: &Sweep,
    now_utc: i64,
    schedule: &ScrubSchedule,
    pace: Pace,
    budget: &mut Budget,
) -> SweepPlan {
    let start = match (pace, &sweep.cursor) {
        (Pace::Full, _) | (_, None) => 0,
        (_, Some(c)) => items.partition_point(|(k, _)| k.as_str() <= c.as_str()),
    };
    let ahead = &items[start..];
    let remaining = ahead.len() as u64;
    let pass_started = if sweep.pass_started_utc > 0 {
        sweep.pass_started_utc
    } else {
        now_utc
    };
    let deadline = pass_started + schedule.period_secs();
    let quota: u64 = match pace {
        Pace::Full | Pace::Budget => u64::MAX,
        Pace::Scheduled => {
            let prev = if sweep.last_run_utc > 0 {
                sweep.last_run_utc
            } else {
                now_utc - schedule.interval_secs()
            };
            let left_bytes: u64 = ahead.iter().map(|(_, s)| (*s).max(1)).sum();
            if now_utc >= deadline || deadline <= prev {
                left_bytes
            } else {
                let share = (now_utc - prev).max(0) as f64 / (deadline - prev) as f64;
                ((left_bytes as f64 * share.min(1.0)).ceil() as u64).max(1)
            }
        }
    };
    let mut picks = Vec::new();
    let mut taken = 0u64;
    for (i, (_, size)) in ahead.iter().enumerate() {
        if taken >= quota {
            break;
        }
        let size = (*size).max(1);
        if pace != Pace::Full && !budget.take(size) {
            break;
        }
        taken = taken.saturating_add(size);
        picks.push(start + i);
    }
    let finishes_pass = picks.len() as u64 == remaining;
    SweepPlan {
        behind: !finishes_pass && now_utc >= deadline,
        finishes_pass,
        remaining,
        picks,
    }
}

impl Sweep {
    /// Record a run that checked items up to `last_key` (none: nothing).
    pub fn advance(&mut self, now_utc: i64, last_key: Option<&str>, checked: u64, done: bool) {
        if self.pass_started_utc == 0 {
            self.pass_started_utc = now_utc;
        }
        // A run that read nothing here (the budget went to other targets)
        // leaves the pace as it was: the next run's share is larger.
        if checked > 0 || done {
            self.last_run_utc = now_utc;
        }
        self.checked_in_pass += checked;
        if done {
            self.cursor = None;
            self.last_pass_done_utc = Some(now_utc);
            self.pass_started_utc = now_utc;
            self.checked_in_pass = 0;
        } else if let Some(k) = last_key {
            self.cursor = Some(k.to_string());
        }
    }
}

/// The name a damaged local file is moved to: `photo.jpg` becomes
/// `photo.damaged-20261013.jpg` (`-2`, `-3`, ... when that is taken).
pub fn damaged_name(file_name: &str, date_yyyymmdd: &str, n: u32) -> String {
    let tag = if n <= 1 {
        format!("damaged-{date_yyyymmdd}")
    } else {
        format!("damaged-{date_yyyymmdd}-{n}")
    };
    match file_name.rfind('.') {
        Some(dot) if dot > 0 => format!("{}.{tag}{}", &file_name[..dot], &file_name[dot..]),
        _ => format!("{file_name}.{tag}"),
    }
}

/// A local file whose content no longer matched its recorded hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DamagedFile {
    pub folder: String,
    pub path: String,
    /// Where the damaged file was moved (relative to the folder); none while
    /// the recorded version could not be restored (the file is left as is).
    pub moved_to: Option<String>,
    pub restored: bool,
    /// Why it could not be restored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub found_utc: i64,
}

/// How far one target is.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct TargetReport {
    pub target: String,
    pub label: String,
    pub checked: u64,
    pub bytes: u64,
    /// Items left in the current pass.
    pub left_in_pass: u64,
    /// A pass ended in this run.
    pub pass_done: bool,
    /// The pass is overdue: the budget is too small for the period.
    pub behind: bool,
}

/// What one run did.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct ScrubReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub full: bool,
    /// Storage objects (and pool disk copies) re-hashed.
    pub objects_checked: u64,
    pub object_bytes: u64,
    /// Local files re-hashed.
    pub files_checked: u64,
    pub file_bytes: u64,
    /// Block cache objects re-hashed.
    pub cache_checked: u64,
    /// "storage:object" (or "pool/disk:object") whose bytes do not match the name.
    pub corrupt: Vec<String>,
    /// "storage:object" the ledger places there that the storage does not have.
    pub missing: Vec<String>,
    /// Damaged or missing copies put in the repair queue.
    pub queued_for_repair: u64,
    /// Local files whose content changed under an unchanged size and time.
    pub damaged_files: Vec<DamagedFile>,
    /// Corrupt objects dropped from the block cache.
    pub cache_dropped: u64,
    /// Copies on pool disks that are not attached (not read).
    pub offline: u64,
    /// Pool disks not seen within the scrub period: "label (place), last seen <date>".
    pub disks_away: Vec<String>,
    /// Targets not read, with the reason.
    pub skipped: Vec<String>,
    pub targets: Vec<TargetReport>,
}

impl ScrubReport {
    /// Problems found in this run.
    pub fn problems(&self) -> u64 {
        (self.corrupt.len() + self.missing.len() + self.damaged_files.len()) as u64
            + self.cache_dropped
    }
}

/// Every run so far.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ScrubTotals {
    pub objects_checked: u64,
    pub files_checked: u64,
    pub problems_found: u64,
    pub files_restored: u64,
}

/// Kept in `state/scrub.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ScrubState {
    #[serde(default)]
    pub sweeps: BTreeMap<String, Sweep>,
    #[serde(default)]
    pub last_run_utc: Option<i64>,
    #[serde(default)]
    pub last: Option<ScrubReport>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub totals: ScrubTotals,
    /// Damaged local files whose recorded version could not be restored
    /// yet, by folder id and path: tried again on every run.
    #[serde(default)]
    pub unrestored: BTreeMap<String, BTreeMap<String, DamagedFile>>,
}

/// Schedule, last run and progress, for the API, the CLI and the interface.
#[derive(Clone, Debug, Serialize)]
pub struct ScrubStatus {
    pub schedule: ScrubSchedule,
    pub last_run_utc: Option<i64>,
    pub next_run_utc: Option<i64>,
    pub last: Option<ScrubReport>,
    pub last_error: Option<String>,
    pub totals: ScrubTotals,
    /// Every target with its pass.
    pub targets: BTreeMap<String, Sweep>,
    /// Damaged files still waiting for their recorded version.
    pub unrestored: Vec<DamagedFile>,
}

impl ScrubStatus {
    /// "bit-rot check every 24 h, every copy and file within 90 days; last run ...".
    pub fn describe(&self) -> String {
        let s = &self.schedule;
        let mut out = if !s.enabled {
            "bit-rot check is off".to_string()
        } else {
            format!(
                "bit-rot check every {} h, everything within {} days, up to {} MiB local and {} MiB remote per run",
                s.interval_hours,
                s.scrub_days,
                s.max_local_bytes >> 20,
                s.max_remote_bytes >> 20
            )
        };
        if !s.cold.is_empty() {
            out += &format!(
                "; cold storages included: {}",
                s.cold.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        match (&self.last, self.last_run_utc) {
            (Some(r), Some(t)) => {
                out += &format!(
                    "; last run {}: {} objects and {} files checked, {} problems found",
                    crate::util::format_date(t),
                    r.objects_checked + r.cache_checked,
                    r.files_checked,
                    r.problems()
                );
            }
            _ => out += "; not run yet",
        }
        if self.totals.problems_found > 0 {
            out += &format!(
                " ({} problems and {} files restored in all)",
                self.totals.problems_found, self.totals.files_restored
            );
        }
        if !self.unrestored.is_empty() {
            out += &format!(
                "; {} damaged file(s) waiting for a good copy",
                self.unrestored.len()
            );
        }
        if let Some(e) = &self.last_error {
            out += &format!("; last error: {e}");
        }
        if let Some(n) = self.next_run_utc {
            if self.last_run_utc.is_some() {
                out += &format!("; next run {}", crate::util::format_date(n));
            } else {
                out += "; next run at the next sync";
            }
        }
        out
    }
}

/// Which storages a run reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inclusion {
    Read,
    /// A transferrer: emptied on purpose, never scrubbed.
    Transferrer,
    /// A cold storage the user did not opt in for.
    Cold,
    /// Not among the storages asked for.
    NotAsked,
}

/// Whether a run reads a storage: never a transferrer; a cold storage only
/// when the user opted it in or confirmed a cold read for this run.
pub fn inclusion(
    name: &str,
    cold: bool,
    carrier: bool,
    schedule: &ScrubSchedule,
    asked: &[String],
    include_cold: bool,
) -> Inclusion {
    if !asked.is_empty() && !asked.iter().any(|a| a == name) {
        return Inclusion::NotAsked;
    }
    if carrier {
        return Inclusion::Transferrer;
    }
    if cold && !include_cold && !schedule.cold.contains(name) {
        return Inclusion::Cold;
    }
    Inclusion::Read
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(n: usize, size: u64) -> Vec<(String, u64)> {
        (0..n).map(|i| (format!("k{i:03}"), size)).collect()
    }

    #[test]
    fn plan_takes_the_items_after_the_cursor_first() {
        let s = ScrubSchedule::default();
        let it = items(10, 10);
        let sweep = Sweep {
            cursor: Some("k005".into()),
            pass_started_utc: 1,
            ..Default::default()
        };
        let mut b = Budget::unlimited();
        let p = plan(&it, &sweep, 100, &s, Pace::Budget, &mut b);
        // The oldest: k006..k009, then the pass ends (no wrap in one run).
        assert_eq!(p.picks, vec![6, 7, 8, 9]);
        assert!(p.finishes_pass);
        assert_eq!(p.remaining, 4);
        // A cursor between keys (that item went away) starts after it.
        let sweep = Sweep {
            cursor: Some("k0055".into()),
            ..sweep
        };
        let p = plan(&it, &sweep, 100, &s, Pace::Budget, &mut Budget::unlimited());
        assert_eq!(p.picks[0], 6);
        // Full: everything from the start, whatever the budget.
        let mut tiny = Budget::new(1);
        let p = plan(&it, &sweep, 100, &s, Pace::Full, &mut tiny);
        assert_eq!(p.picks.len(), 10);
        assert!(p.finishes_pass);
    }

    #[test]
    fn plan_respects_the_budget_across_targets() {
        let s = ScrubSchedule::default();
        let it = items(10, 100);
        let mut b = Budget::new(350);
        let p = plan(&it, &Sweep::default(), 1_000, &s, Pace::Budget, &mut b);
        assert_eq!(p.picks, vec![0, 1, 2]);
        assert!(!p.finishes_pass);
        // The next target of the same class gets nothing more this run.
        let p = plan(&it, &Sweep::default(), 1_000, &s, Pace::Budget, &mut b);
        assert!(p.picks.is_empty());
        // A first item larger than the whole budget is still read.
        let big = vec![("a".to_string(), 10_000)];
        let mut b = Budget::new(10);
        let p = plan(&big, &Sweep::default(), 0, &s, Pace::Budget, &mut b);
        assert_eq!(p.picks, vec![0]);
    }

    #[test]
    fn scheduled_runs_spread_a_pass_over_the_period() {
        let s = ScrubSchedule {
            scrub_days: 10,
            interval_hours: 24,
            ..Default::default()
        };
        let it = items(100, 1);
        let day = 86_400;
        let mut sweep = Sweep::default();
        let mut now = 1_000 * day;
        let mut runs = 0;
        // Daily runs read about a tenth each and end the pass in ten days.
        loop {
            let mut b = Budget::unlimited();
            let p = plan(&it, &sweep, now, &s, Pace::Scheduled, &mut b);
            assert!(!p.behind);
            runs += 1;
            assert!(p.picks.len() <= 12, "run {runs} took {}", p.picks.len());
            let last = p.picks.last().map(|i| it[*i].0.clone());
            sweep.advance(now, last.as_deref(), p.picks.len() as u64, p.finishes_pass);
            if p.finishes_pass {
                break;
            }
            now += day;
        }
        assert!((9..=11).contains(&runs), "{runs} runs");
        assert_eq!(sweep.cursor, None);
        assert_eq!(sweep.last_pass_done_utc, Some(now));
        // A pass that is overdue (the device was off) takes all that is left,
        // within the budget, and says it is behind when the budget stops it.
        let late = Sweep {
            cursor: Some("k049".into()),
            pass_started_utc: now - 20 * day,
            last_run_utc: now - 15 * day,
            ..Default::default()
        };
        let mut b = Budget::unlimited();
        let p = plan(&it, &late, now, &s, Pace::Scheduled, &mut b);
        assert_eq!(p.picks.len(), 50);
        let mut b = Budget::new(10);
        let p = plan(&it, &late, now, &s, Pace::Scheduled, &mut b);
        assert_eq!(p.picks.len(), 10);
        assert!(p.behind);
    }

    #[test]
    fn cold_storages_and_transferrers_are_left_out_unless_asked() {
        let mut s = ScrubSchedule::default();
        assert_eq!(
            inclusion("box", false, false, &s, &[], false),
            Inclusion::Read
        );
        assert_eq!(
            inclusion("deep", true, false, &s, &[], false),
            Inclusion::Cold
        );
        assert_eq!(
            inclusion("deep", true, false, &s, &[], true),
            Inclusion::Read
        );
        assert_eq!(
            inclusion("usb", false, true, &s, &[], true),
            Inclusion::Transferrer
        );
        assert_eq!(
            inclusion("box", false, false, &s, &["other".into()], false),
            Inclusion::NotAsked
        );
        s.cold.insert("deep".into());
        assert_eq!(
            inclusion("deep", true, false, &s, &[], false),
            Inclusion::Read
        );
    }

    #[test]
    fn damaged_names_keep_the_extension() {
        assert_eq!(
            damaged_name("photo.jpg", "20261013", 1),
            "photo.damaged-20261013.jpg"
        );
        assert_eq!(
            damaged_name("photo.jpg", "20261013", 2),
            "photo.damaged-20261013-2.jpg"
        );
        assert_eq!(
            damaged_name("README", "20261013", 1),
            "README.damaged-20261013"
        );
        assert_eq!(
            damaged_name(".bashrc", "20261013", 1),
            ".bashrc.damaged-20261013"
        );
        assert_eq!(
            damaged_name("a.tar.gz", "20261013", 1),
            "a.tar.damaged-20261013.gz"
        );
    }

    #[test]
    fn schedule_defaults_and_due() {
        let parsed: ScrubSchedule = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, ScrubSchedule::default());
        assert_eq!(parsed.scrub_days, 90);
        assert_eq!(parsed.max_local_bytes, 2 << 30);
        assert_eq!(parsed.max_remote_bytes, 1 << 30);
        assert!(parsed.is_due(None, 0));
        assert!(!parsed.is_due(Some(1_000), 1_000 + 3_600));
        assert!(parsed.is_due(Some(1_000), 1_000 + 24 * 3_600));
        let off = ScrubSchedule {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(off.next_run_utc(None), None);
    }
}
