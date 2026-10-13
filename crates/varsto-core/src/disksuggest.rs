// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Which pool disk to dock next (`varsto disk suggest`, the Storages page).
//!
//! Works on the per-disk bookkeeping of `pool::DiskStatus` alone: no disk is
//! read, so the service can recompute it after every sync. Each disk gets a
//! score, the sum of simple factors, each with the reason it adds:
//!
//! | factor | points |
//! |---|---|
//! | overdue checks | `100 × share × (1 + min(late / verify_after_days, 1))`, 0–200 |
//! | only copy | `80 × (only-copy copies overdue / copies)`, plus 10 when the disk holds any object no other disk or storage has |
//! | fetch plan | 70 when a pending step of the fetch plan reads from it |
//! | repair | 50 when a queued repair needs an object it holds |
//! | fill | `40 × fill potential / bytes the pool lacks` (the share of the shortfall it can take) |
//! | reclaimable | `30 × min(reclaimable / (capacity / 3), 1)`: a third of the disk to free counts fully |
//! | file system | 25 when its last forced check corrected errors, plus `10 × min(age / 365 days, 1)` |
//! | unseen | `20 × min(days since last seen / 365, 1)` |
//!
//! `share` is the share of the disk's bytes whose last check is older than
//! the pool's `verify_after_days` (never-checked copies included) and `late`
//! how far the oldest check is past that limit. Overdue checks weigh most:
//! X bytes overdue give at least `100 × X / used` points, X bytes to free at
//! most `90 × X / capacity`, so at equal sizes the check always wins. Disks that
//! are away are ranked (score down, then the one seen longest ago, then by
//! label); the top one is suggested when it scores at least `MIN_SCORE`.
//! Attached disks are scored the same way but listed apart (they need no
//! docking: check them). Retired disks and failing ones (a file system
//! check that left errors or failed, or a write that read back wrong
//! twice) are never suggested; they are listed with a warning.

use crate::blockdev::FsckVerdict;
use crate::pool::DiskStatus;
use crate::util;
use serde::{Deserialize, Serialize};

/// Below this score nothing is suggested ("no disk needs docking").
pub const MIN_SCORE: f64 = 5.0;

pub const W_OVERDUE: f64 = 100.0;
pub const W_ONLY_OVERDUE: f64 = 80.0;
pub const W_ONLY_ANY: f64 = 10.0;
pub const W_FETCH: f64 = 70.0;
pub const W_REPAIR: f64 = 50.0;
pub const W_FILL: f64 = 40.0;
pub const W_RECLAIM: f64 = 30.0;
pub const W_FSCK_CORRECTED: f64 = 25.0;
pub const W_FSCK_AGE: f64 = 10.0;
pub const W_UNSEEN: f64 = 20.0;

const DAY: i64 = 86_400;

/// The service's reminder (`config.json`, `disk_suggest`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SuggestSettings {
    /// A desktop notification, at most once a week, when a disk that is
    /// away has copies past the pool's `verify_after_days`.
    pub notify_overdue: bool,
}

impl Default for SuggestSettings {
    fn default() -> Self {
        SuggestSettings {
            notify_overdue: true,
        }
    }
}

/// The overdue reminder is shown at most this often.
pub const REMIND_EVERY_SECS: i64 = 7 * DAY;

/// One reason a disk scores: which factor, its points and the sentence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SuggestReason {
    /// "overdue", "only_copy", "fetch", "repair", "fill", "reclaimable",
    /// "fsck" or "unseen".
    pub kind: String,
    pub points: f64,
    pub text: String,
}

/// A scored disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DiskSuggestion {
    pub pool: String,
    pub label: String,
    pub disk_id: String,
    pub place: String,
    pub attached: bool,
    /// Sum of the reasons' points, rounded to one decimal.
    pub score: f64,
    pub reasons: Vec<SuggestReason>,
    pub last_seen_utc: i64,
    /// "«Blue 4TB»: 62 % of its copies ...; 41 GB can be freed".
    pub summary: String,
    /// What to run: `varsto disk insert "<label>"`.
    pub command: String,
}

/// A disk that is never suggested, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DiskWarning {
    pub pool: String,
    pub label: String,
    pub disk_id: String,
    pub place: String,
    pub attached: bool,
    pub retired: bool,
    pub failing: bool,
    pub warning: String,
}

/// The ranking of every disk.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DiskSuggestions {
    pub computed_utc: i64,
    /// The disk to dock next, if any scores at least `MIN_SCORE`.
    pub top: Option<DiskSuggestion>,
    /// Disks that are away, best first.
    pub ranked: Vec<DiskSuggestion>,
    /// Attached disks, scored the same way (best first): no docking needed.
    pub attached: Vec<DiskSuggestion>,
    /// Retired and failing disks.
    pub excluded: Vec<DiskWarning>,
    /// Labels of the disks that are away with copies past `verify_after_days`.
    pub overdue: Vec<String>,
}

/// `varsto disk insert "<label>"`, quoted for a shell.
pub fn insert_command(label: &str) -> String {
    format!(
        "varsto disk insert \"{}\"",
        label
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('`', "\\`")
    )
}

/// "today", "5 days ago", "3 weeks ago", "4 months ago", "2 years ago".
pub fn ago(now: i64, t: i64) -> String {
    let days = (now - t).max(0) / DAY;
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        2..=13 => format!("{days} days ago"),
        14..=59 => format!("{} weeks ago", days / 7),
        60..=729 => format!("{} months ago", days / 30),
        _ => format!("{} years ago", days / 365),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The reasons (and points) of one disk at `now`.
pub fn reasons(d: &DiskStatus, now: i64) -> Vec<SuggestReason> {
    let mut out = Vec::new();
    let mut add = |kind: &str, points: f64, text: String| {
        if points >= 0.05 {
            out.push(SuggestReason {
                kind: kind.to_string(),
                points,
                text,
            });
        }
    };
    let days = d.verify_after_days;
    // Overdue checks.
    if d.copies_overdue > 0 && d.objects > 0 {
        let share = if d.used_bytes > 0 {
            (d.bytes_overdue as f64 / d.used_bytes as f64).clamp(0.0, 1.0)
        } else {
            d.overdue_share.clamp(0.0, 1.0)
        };
        let oldest = d.oldest_check_utc.unwrap_or(0);
        let factor = if days == 0 {
            1.0
        } else {
            let limit = now - days as i64 * DAY;
            let late = (limit - oldest).max(0) as f64;
            1.0 + (late / (days as f64 * DAY as f64)).min(1.0)
        };
        let pct = (d.overdue_share * 100.0).round() as u64;
        let size = util::human_bytes(d.bytes_overdue);
        let pct = if pct == 0 {
            "under 1".to_string()
        } else {
            pct.to_string()
        };
        let oldest_text = if oldest > 0 {
            format!("oldest {}", util::format_date(oldest))
        } else {
            "some never".to_string()
        };
        let text = if days == 0 {
            format!("{pct} % of its copies ({size}) are due for a check (verify-after-days is 0; {oldest_text})")
        } else {
            format!("{pct} % of its copies ({size}) were last checked over {days} days ago ({oldest_text})")
        };
        add("overdue", W_OVERDUE * share * factor, text);
    }
    // Data that exists only here.
    if let (Some(only), Some(bytes)) = (d.only_copy_objects, d.only_copy_bytes) {
        if only > 0 {
            let overdue = d.only_copy_overdue.unwrap_or(0);
            let points = W_ONLY_ANY
                + if d.objects > 0 {
                    W_ONLY_OVERDUE * overdue as f64 / d.objects as f64
                } else {
                    0.0
                };
            let mut text = format!(
                "{} ({}) exist on no other disk or storage",
                plural(only, "object", "objects"),
                util::human_bytes(bytes)
            );
            if overdue > 0 {
                text += &format!(", {overdue} of them not checked for over {days} days");
            }
            add("only_copy", points, text);
        }
    }
    // A fetch plan waiting for it.
    if let Some(n) = d.fetch_objects.filter(|n| *n > 0) {
        add(
            "fetch",
            W_FETCH,
            format!(
                "the fetch plan waits for it ({}, {})",
                plural(n, "block", "blocks"),
                util::human_bytes(d.fetch_bytes.unwrap_or(0))
            ),
        );
    }
    // A repair needing it.
    if let Some(n) = d.repair_objects.filter(|n| *n > 0) {
        add(
            "repair",
            W_REPAIR,
            format!(
                "a queued repair needs {} it holds",
                plural(n, "object", "objects")
            ),
        );
    }
    // What the pool lacks.
    if let (Some(lacking), Some(fill)) = (d.lacking_bytes, d.fill_potential_bytes) {
        if lacking > 0 && fill > 0 {
            add(
                "fill",
                W_FILL * fill as f64 / lacking as f64,
                if fill >= lacking {
                    format!(
                        "it can take all {} the pool lacks",
                        util::human_bytes(lacking)
                    )
                } else {
                    format!(
                        "it can take {} of the {} the pool lacks",
                        util::human_bytes(fill),
                        util::human_bytes(lacking)
                    )
                },
            );
        }
    }
    // Space to free.
    if d.reclaimable_bytes > 0 {
        let third = d.capacity_bytes.max(d.used_bytes) / 3;
        let share = if third == 0 {
            1.0
        } else {
            (d.reclaimable_bytes as f64 / third as f64).min(1.0)
        };
        add(
            "reclaimable",
            W_RECLAIM * share,
            format!("{} can be freed", util::human_bytes(d.reclaimable_bytes)),
        );
    }
    // The file system check.
    if let Some(c) = &d.fsck {
        let age_days = (now - c.checked_utc).max(0) as f64 / DAY as f64;
        let mut points = W_FSCK_AGE * (age_days / 365.0).min(1.0);
        let text = if c.verdict == FsckVerdict::Corrected {
            points += W_FSCK_CORRECTED;
            format!(
                "its last file system check ({}) corrected errors",
                util::format_date(c.checked_utc)
            )
        } else {
            format!(
                "its file system was last checked {}",
                ago(now, c.checked_utc)
            )
        };
        add("fsck", points, text);
    }
    // Long unseen.
    if !d.attached {
        if d.last_seen_utc > 0 {
            let days_unseen = (now - d.last_seen_utc).max(0) as f64 / DAY as f64;
            add(
                "unseen",
                W_UNSEEN * (days_unseen / 365.0).min(1.0),
                format!("last seen {}", ago(now, d.last_seen_utc)),
            );
        } else {
            add("unseen", W_UNSEEN, "never seen by this device".to_string());
        }
    }
    out.sort_by(|a, b| b.points.total_cmp(&a.points));
    out
}

/// Score one disk.
pub fn suggest(d: &DiskStatus, now: i64) -> DiskSuggestion {
    let reasons = reasons(d, now);
    let score: f64 = reasons.iter().map(|r| r.points).sum();
    let summary = if reasons.is_empty() {
        format!("«{}»: nothing due", d.label)
    } else {
        format!(
            "«{}»: {}",
            d.label,
            reasons
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )
    };
    DiskSuggestion {
        pool: d.pool.clone(),
        label: d.label.clone(),
        disk_id: d.disk_id.clone(),
        place: d.place.clone(),
        attached: d.attached,
        score: (score * 10.0).round() / 10.0,
        reasons,
        last_seen_utc: d.last_seen_utc,
        summary,
        command: insert_command(&d.label),
    }
}

/// Rank every disk (see the module documentation).
pub fn rank(disks: &[DiskStatus], now: i64) -> DiskSuggestions {
    let mut out = DiskSuggestions {
        computed_utc: now,
        ..Default::default()
    };
    for d in disks {
        if d.retired || d.failing {
            let mut why = Vec::new();
            if d.failing {
                why.push(
                    d.failing_reason
                        .clone()
                        .unwrap_or_else(|| "the disk may be failing".to_string()),
                );
            }
            if d.retired {
                why.push("retired: nothing new goes to it".to_string());
            }
            if let Some(n) = d.only_copy_objects.filter(|n| *n > 0) {
                why.push(format!(
                    "{} exist only on it: copy them elsewhere before the disk goes",
                    plural(n, "object", "objects")
                ));
            }
            out.excluded.push(DiskWarning {
                pool: d.pool.clone(),
                label: d.label.clone(),
                disk_id: d.disk_id.clone(),
                place: d.place.clone(),
                attached: d.attached,
                retired: d.retired,
                failing: d.failing,
                warning: why.join("; "),
            });
            continue;
        }
        let s = suggest(d, now);
        if d.attached {
            out.attached.push(s);
        } else {
            if d.copies_overdue > 0 {
                out.overdue.push(d.label.clone());
            }
            out.ranked.push(s);
        }
    }
    let order = |a: &DiskSuggestion, b: &DiskSuggestion| {
        b.score
            .total_cmp(&a.score)
            .then(a.last_seen_utc.cmp(&b.last_seen_utc))
            .then(a.label.cmp(&b.label))
    };
    out.ranked.sort_by(order);
    out.attached.sort_by(order);
    out.top = out.ranked.first().filter(|s| s.score >= MIN_SCORE).cloned();
    out
}

/// Columns `disk list --sort` takes, each with its natural direction:
/// name A-Z, free most first, used most first, checked oldest first,
/// reclaimable most first, seen longest ago first.
pub const SORT_KEYS: &[&str] = &["name", "free", "used", "checked", "reclaimable", "seen"];

/// Sort disk rows by one of `SORT_KEYS` (`reverse` flips the direction);
/// ties go by label. Unknown values (free space never measured, a disk
/// holding nothing) sort last.
pub fn sort_disks(rows: &mut [DiskStatus], key: &str, reverse: bool) -> anyhow::Result<()> {
    use std::cmp::Ordering;
    // Larger first, unknown last.
    fn desc(a: Option<u64>, b: Option<u64>) -> Ordering {
        match (a, b) {
            (Some(a), Some(b)) => b.cmp(&a),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
    }
    let by_name = |a: &DiskStatus, b: &DiskStatus| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then(a.label.cmp(&b.label))
            .then(a.pool.cmp(&b.pool))
    };
    type Cmp = fn(&DiskStatus, &DiskStatus) -> Ordering;
    let cmp: Cmp = match key {
        "name" | "label" => |_, _| Ordering::Equal,
        "free" => |a, b| desc(a.free_bytes, b.free_bytes),
        "used" => |a, b| b.used_bytes.cmp(&a.used_bytes),
        // Oldest check first; a disk holding nothing last.
        "checked" => |a, b| match (a.oldest_check_utc, b.oldest_check_utc) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        "reclaimable" => |a, b| b.reclaimable_bytes.cmp(&a.reclaimable_bytes),
        "seen" => |a, b| a.last_seen_utc.cmp(&b.last_seen_utc),
        other => anyhow::bail!(
            "unknown sort column {other}: use one of {}",
            SORT_KEYS.join(", ")
        ),
    };
    rows.sort_by(|a, b| {
        let o = cmp(a, b);
        let o = if reverse { o.reverse() } else { o };
        let n = by_name(a, b);
        o.then(if reverse && key == "name" {
            n.reverse()
        } else {
            n
        })
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_791_849_600; // 2026-10-13
    const GB: u64 = 1_000_000_000;

    fn disk(label: &str) -> DiskStatus {
        DiskStatus {
            pool: "shelf".into(),
            place: "home".into(),
            label: label.into(),
            disk_id: format!("id-{label}"),
            attached: false,
            mount: None,
            free_bytes: Some(500 * GB),
            capacity_bytes: 1000 * GB,
            used_bytes: 400 * GB,
            objects: 1000,
            last_seen_utc: NOW - 10 * DAY,
            last_verified_utc: NOW - 10 * DAY,
            pending_deletes: 0,
            retired: false,
            reserve_bytes: 50 * GB,
            space_measured_utc: NOW - 10 * DAY,
            pending_delete_bytes: 0,
            reclaimable_bytes: 0,
            verify_after_days: 180,
            oldest_check_utc: Some(NOW - 10 * DAY),
            copies_overdue: 0,
            bytes_overdue: 0,
            overdue_share: 0.0,
            write_failed_utc: 0,
            failing: false,
            failing_reason: None,
            fsck: None,
            unneeded_objects: Some(0),
            unneeded_bytes: Some(0),
            only_copy_objects: Some(0),
            only_copy_bytes: Some(0),
            only_copy_overdue: Some(0),
            lacking_bytes: Some(0),
            fill_potential_bytes: Some(0),
            repair_objects: Some(0),
            fetch_objects: Some(0),
            fetch_bytes: Some(0),
        }
    }

    fn overdue(mut d: DiskStatus, share: f64, oldest_days: i64) -> DiskStatus {
        d.copies_overdue = (d.objects as f64 * share) as u64;
        d.bytes_overdue = (d.used_bytes as f64 * share) as u64;
        d.overdue_share = share;
        d.oldest_check_utc = Some(NOW - oldest_days * DAY);
        d
    }

    #[test]
    fn overdue_checks_beat_reclaimable_space_of_the_same_size() {
        // 40 GB overdue on one disk, 40 GB to free on the other.
        let a = overdue(disk("Blue 4TB"), 0.1, 200);
        let mut b = disk("Red 4TB");
        b.reclaimable_bytes = 40 * GB;
        let r = rank(&[b, a], NOW);
        assert_eq!(r.top.as_ref().unwrap().label, "Blue 4TB");
        assert_eq!(r.ranked[1].label, "Red 4TB");
        assert!(r.ranked[0].score > r.ranked[1].score);
        assert_eq!(r.overdue, vec!["Blue 4TB".to_string()]);
        let top = r.top.unwrap();
        assert_eq!(top.reasons[0].kind, "overdue");
        assert!(top.summary.starts_with(
            "«Blue 4TB»: 10 % of its copies (40.0 GB) were last checked over 180 days ago (oldest 2026-03-27)"
        ));
        assert_eq!(top.command, "varsto disk insert \"Blue 4TB\"");
    }

    #[test]
    fn later_checks_and_larger_shares_weigh_more() {
        let a = overdue(disk("a"), 0.5, 190);
        let b = overdue(disk("b"), 0.5, 400);
        let c = overdue(disk("c"), 0.8, 190);
        let r = rank(&[a, b, c], NOW);
        let order: Vec<&str> = r.ranked.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(order, ["b", "c", "a"]);
        // At most twice the share: 0.5 × 100 × 2, plus 10 days unseen.
        assert_eq!(r.ranked[0].score, 100.5);
    }

    #[test]
    fn only_copy_risk_raises_a_disk() {
        let a = overdue(disk("a"), 0.3, 200);
        let mut b = overdue(disk("b"), 0.3, 200);
        b.only_copy_objects = Some(300);
        b.only_copy_bytes = Some(120 * GB);
        b.only_copy_overdue = Some(300);
        let r = rank(&[a, b], NOW);
        assert_eq!(r.top.as_ref().unwrap().label, "b");
        let only = r.ranked[0]
            .reasons
            .iter()
            .find(|x| x.kind == "only_copy")
            .unwrap();
        assert_eq!(only.points, 10.0 + 80.0 * 0.3);
        assert!(only.text.contains("300 objects (120.0 GB) exist on no other disk or storage, 300 of them not checked for over 180 days"), "{}", only.text);
    }

    #[test]
    fn retired_and_failing_disks_are_listed_apart_never_suggested() {
        let mut a = overdue(disk("old"), 1.0, 900);
        a.retired = true;
        a.only_copy_objects = Some(2);
        let mut b = overdue(disk("flaky"), 1.0, 900);
        b.failing = true;
        b.failing_reason = Some("its file system has errors".into());
        let c = disk("fine");
        let r = rank(&[a, b, c], NOW);
        assert_eq!(r.ranked.len(), 1);
        assert!(r.top.is_none(), "nothing due on the fine disk");
        assert_eq!(r.excluded.len(), 2);
        assert!(r.excluded[0].retired);
        assert!(r.excluded[0].warning.contains("2 objects exist only on it"));
        assert!(r.excluded[1].failing);
        assert_eq!(r.excluded[1].warning, "its file system has errors");
        assert!(r.overdue.is_empty());
    }

    #[test]
    fn ties_go_to_the_disk_seen_longest_ago_and_attached_disks_stand_apart() {
        let mut a = disk("a");
        let mut b = disk("b");
        let mut c = disk("c");
        for d in [&mut a, &mut b, &mut c] {
            d.repair_objects = Some(1);
        }
        // Equal unseen points (both a year or more) and equal repair points.
        a.last_seen_utc = NOW - 400 * DAY;
        b.last_seen_utc = NOW - 500 * DAY;
        c.attached = true;
        let r = rank(&[a, b, c], NOW);
        assert_eq!(r.ranked[0].score, r.ranked[1].score);
        assert_eq!(r.ranked[0].label, "b");
        assert_eq!(r.attached.len(), 1);
        assert_eq!(r.attached[0].label, "c");
        assert!(r.attached[0].reasons.iter().all(|x| x.kind != "unseen"));
        assert!(r.ranked[0].summary.contains("last seen 16 months ago"));
    }

    #[test]
    fn fill_fetch_and_fsck_reasons() {
        let mut a = disk("a");
        a.lacking_bytes = Some(100 * GB);
        a.fill_potential_bytes = Some(50 * GB);
        a.fetch_objects = Some(812);
        a.fetch_bytes = Some(3_400_000_000);
        a.fsck = Some(crate::blockdev::FsckOutcome {
            partition: "/dev/sdx1".into(),
            code: 1,
            verdict: FsckVerdict::Corrected,
            summary: String::new(),
            stderr: String::new(),
            checked_utc: NOW - 30 * DAY,
        });
        let s = suggest(&a, NOW);
        let kinds: Vec<&str> = s.reasons.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["fetch", "fsck", "fill", "unseen"]);
        assert_eq!(s.reasons[2].points, 20.0);
        assert_eq!(
            s.reasons[2].text,
            "it can take 50.0 GB of the 100.0 GB the pool lacks"
        );
        assert_eq!(
            s.reasons[0].text,
            "the fetch plan waits for it (812 blocks, 3.4 GB)"
        );
        assert!(s.reasons[1].text.contains("corrected errors"));
    }

    #[test]
    fn disk_rows_sort_by_every_column() {
        let mut a = disk("alpha");
        let mut b = disk("Bravo");
        let mut c = disk("charlie");
        a.free_bytes = Some(10 * GB);
        b.free_bytes = None; // never measured
        c.free_bytes = Some(90 * GB);
        a.used_bytes = 5 * GB;
        c.used_bytes = 700 * GB;
        a.oldest_check_utc = Some(NOW - 400 * DAY);
        b.oldest_check_utc = None; // holds nothing
        c.oldest_check_utc = Some(0); // a copy never checked
        b.reclaimable_bytes = 7 * GB;
        a.last_seen_utc = NOW - DAY;
        c.last_seen_utc = NOW - 90 * DAY;
        let mut rows = vec![a, b, c];
        let order =
            |rows: &[DiskStatus]| -> Vec<String> { rows.iter().map(|d| d.label.clone()).collect() };
        for (key, want) in [
            ("name", ["alpha", "Bravo", "charlie"]),
            ("free", ["charlie", "alpha", "Bravo"]),
            ("used", ["charlie", "Bravo", "alpha"]),
            ("checked", ["charlie", "alpha", "Bravo"]),
            ("reclaimable", ["Bravo", "alpha", "charlie"]),
            ("seen", ["charlie", "Bravo", "alpha"]),
        ] {
            sort_disks(&mut rows, key, false).unwrap();
            assert_eq!(order(&rows), want, "{key}");
        }
        sort_disks(&mut rows, "name", true).unwrap();
        assert_eq!(order(&rows), ["charlie", "Bravo", "alpha"]);
        sort_disks(&mut rows, "free", true).unwrap();
        assert_eq!(order(&rows), ["Bravo", "alpha", "charlie"]);
        assert!(sort_disks(&mut rows, "colour", false).is_err());
    }

    #[test]
    fn commands_are_quoted_and_ages_read_well() {
        assert_eq!(
            insert_command("My \"big\" $disk"),
            "varsto disk insert \"My \\\"big\\\" \\$disk\""
        );
        assert_eq!(ago(NOW, NOW - 3600), "today");
        assert_eq!(ago(NOW, NOW - 5 * DAY), "5 days ago");
        assert_eq!(ago(NOW, NOW - 21 * DAY), "3 weeks ago");
        assert_eq!(ago(NOW, NOW - 95 * DAY), "3 months ago");
        assert_eq!(ago(NOW, NOW - 800 * DAY), "2 years ago");
    }
}
