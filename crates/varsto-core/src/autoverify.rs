// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic verification (F-032): the background service re-reads, within
//! a budget, blocks that *other* devices wrote, checks their content hash and
//! records the check in the ledger exactly as `fsck --verify` does. A
//! policy's "verified by another device within N days" then stays true
//! without anyone running fsck by hand.
//!
//! What is picked: copies on storages this device can read without asking
//! (no cold storage, no transferrer, no replica), written by another device,
//! whose last independent verification is due. Oldest first: never verified,
//! then the copy whose policy deadline comes first. A copy in a folder with a
//! `verified_within_days` window is due at half the window, so it is checked
//! long before the policy turns "at risk" at three quarters; other copies are
//! due after `reverify_days`.

use serde::{Deserialize, Serialize};

/// Schedule and budget, per device (`config.json`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifySchedule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hours between runs.
    #[serde(default = "default_interval_hours")]
    pub interval_hours: u32,
    /// Most bytes downloaded per run.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Most blocks checked per run.
    #[serde(default = "default_max_blocks")]
    pub max_blocks: u64,
    /// Copies in folders without a verification window are checked again
    /// after this many days.
    #[serde(default = "default_reverify_days")]
    pub reverify_days: u32,
}

fn default_true() -> bool {
    true
}
fn default_interval_hours() -> u32 {
    24
}
fn default_max_bytes() -> u64 {
    256 * 1024 * 1024
}
fn default_max_blocks() -> u64 {
    2000
}
fn default_reverify_days() -> u32 {
    30
}

impl Default for VerifySchedule {
    fn default() -> Self {
        VerifySchedule {
            enabled: true,
            interval_hours: default_interval_hours(),
            max_bytes: default_max_bytes(),
            max_blocks: default_max_blocks(),
            reverify_days: default_reverify_days(),
        }
    }
}

impl VerifySchedule {
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
}

/// What one run did.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct VerifyRunReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    /// Copies that were due (before the budget was applied).
    pub due: u64,
    pub blocks_checked: u64,
    pub blocks_verified: u64,
    pub bytes_downloaded: u64,
    /// "storage:object" whose content did not match its name.
    pub corrupt: Vec<String>,
    /// "storage:object" the ledger claims but the storage does not have.
    pub missing: Vec<String>,
    /// Copies left for the next run because the budget ran out.
    pub left_for_next_run: u64,
    /// Storages not read: cold storages and transferrers.
    pub storages_skipped: Vec<String>,
    /// Copies on pool disks that are not attached.
    #[serde(default)]
    pub offline: u64,
}

/// Kept in `state/auto-verify.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct VerifyState {
    pub last_run_utc: Option<i64>,
    pub last: Option<VerifyRunReport>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Blocks verified by every run so far.
    #[serde(default)]
    pub total_verified: u64,
}

/// Schedule, last run and next run, for the API, the CLI and the interface.
#[derive(Clone, Debug, Serialize)]
pub struct VerifyStatus {
    pub schedule: VerifySchedule,
    pub last_run_utc: Option<i64>,
    pub next_run_utc: Option<i64>,
    pub last: Option<VerifyRunReport>,
    pub last_error: Option<String>,
    pub total_verified: u64,
}

impl VerifyStatus {
    /// "last run 2026-10-09, 120 blocks verified, next run 2026-10-10".
    pub fn describe(&self) -> String {
        let mut s = if !self.schedule.enabled {
            "automatic verification is off".to_string()
        } else {
            format!(
                "automatic verification every {} h, up to {} blocks or {} MiB per run",
                self.schedule.interval_hours,
                self.schedule.max_blocks,
                self.schedule.max_bytes / (1024 * 1024)
            )
        };
        match (&self.last, self.last_run_utc) {
            (Some(r), Some(t)) => {
                s += &format!(
                    "; last run {}: {} blocks verified, {} checked, {} left for the next run",
                    crate::util::format_date(t),
                    r.blocks_verified,
                    r.blocks_checked,
                    r.left_for_next_run
                );
                if !r.corrupt.is_empty() {
                    s += &format!(", {} CORRUPT", r.corrupt.len());
                }
                if !r.missing.is_empty() {
                    s += &format!(", {} MISSING", r.missing.len());
                }
            }
            _ => s += "; not run yet",
        }
        if let Some(e) = &self.last_error {
            s += &format!("; last error: {e}");
        }
        if let Some(n) = self.next_run_utc {
            if self.last_run_utc.is_some() {
                s += &format!("; next run {}", crate::util::format_date(n));
            } else {
                s += "; next run at the next sync";
            }
        }
        s
    }
}

/// One copy that could be verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// When the copy is due (UTC seconds); 0 for a copy never verified by another device.
    pub due_utc: i64,
    /// The folder has a verification window (checked first on ties).
    pub has_window: bool,
    pub size: u64,
    /// Opaque index into the caller's list.
    pub index: usize,
}

/// When a copy is due: half the policy window after its last independent
/// verification, or `reverify_days` without a window. `last_verified_utc` is
/// 0 for a copy never verified by another device.
pub fn due_utc(last_verified_utc: i64, window_days: Option<u32>, reverify_days: u32) -> i64 {
    if last_verified_utc <= 0 {
        return 0;
    }
    let secs = match window_days {
        Some(d) => d as i64 * 86_400 / 2,
        None => reverify_days as i64 * 86_400,
    };
    last_verified_utc + secs
}

/// The copies to check now, in order, within the budget: every copy due by
/// `now_utc`, oldest deadline first (windowed folders first on ties), until
/// `max_blocks` copies or `max_bytes` bytes. The first copy is always taken
/// even when it alone exceeds the byte budget, so a large block cannot stall
/// the queue. Returns the chosen indices and how many due copies were left.
pub fn plan(
    mut candidates: Vec<Candidate>,
    now_utc: i64,
    max_blocks: u64,
    max_bytes: u64,
) -> (Vec<usize>, u64, u64) {
    candidates.retain(|c| c.due_utc <= now_utc);
    candidates.sort_by_key(|c| (c.due_utc, !c.has_window, c.index));
    let due = candidates.len() as u64;
    let mut chosen = Vec::new();
    let mut bytes = 0u64;
    for c in &candidates {
        if chosen.len() as u64 >= max_blocks {
            break;
        }
        if !chosen.is_empty() && bytes + c.size > max_bytes {
            break;
        }
        bytes += c.size;
        chosen.push(c.index);
    }
    let left = due - chosen.len() as u64;
    (chosen, due, left)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(due_utc: i64, has_window: bool, size: u64, index: usize) -> Candidate {
        Candidate {
            due_utc,
            has_window,
            size,
            index,
        }
    }

    #[test]
    fn plan_orders_by_deadline_and_respects_the_budget() {
        let now = 1_000_000;
        let cands = vec![
            c(500, false, 10, 0),
            c(0, false, 10, 1),
            c(0, true, 10, 2),
            c(2_000_000, true, 10, 3), // not due yet
            c(900_000, true, 10, 4),
        ];
        let (order, due, left) = plan(cands.clone(), now, 10, 1_000);
        assert_eq!(order, vec![2, 1, 0, 4]);
        assert_eq!((due, left), (4, 0));
        let (order, _, left) = plan(cands.clone(), now, 2, 1_000);
        assert_eq!(order, vec![2, 1]);
        assert_eq!(left, 2);
        let (order, _, left) = plan(cands.clone(), now, 10, 25);
        assert_eq!(order, vec![2, 1]);
        assert_eq!(left, 2);
        // A first block larger than the byte budget is still checked.
        let (order, _, _) = plan(vec![c(0, false, 500, 7)], now, 10, 100);
        assert_eq!(order, vec![7]);
    }

    #[test]
    fn due_dates_and_schedule() {
        assert_eq!(due_utc(0, Some(30), 30), 0);
        assert_eq!(due_utc(1_000, Some(30), 90), 1_000 + 15 * 86_400);
        assert_eq!(due_utc(1_000, None, 7), 1_000 + 7 * 86_400);
        let s = VerifySchedule::default();
        assert!(s.is_due(None, 0));
        assert!(!s.is_due(Some(1_000), 1_000 + 3_600));
        assert!(s.is_due(Some(1_000), 1_000 + 24 * 3_600));
        let off = VerifySchedule {
            enabled: false,
            ..Default::default()
        };
        assert!(!off.is_due(None, 0));
        assert_eq!(off.next_run_utc(Some(5)), None);
        // Older configuration files without the section get the defaults.
        let parsed: VerifySchedule = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, VerifySchedule::default());
    }
}
