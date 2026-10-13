// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Change history of a folder's files (`docs/spec/alpha-0-format.md`,
//! section "Change history of files"): which version of a path appeared
//! when, made by which device, with its size and content hash.
//!
//! The events come from manifests only (this device's own as it publishes
//! them, the others' as a pull opens them), never from a local event log:
//! every version a manifest names is a fact signed into the vault (manifests
//! are announced with their hash in signed ledger batches). A version is
//! identified by `(path, modified_by, modified_clock)`; the first manifest
//! that names it gives its time. A path deleted and another created with
//! the same content by the same device in one manifest is a rename.
//!
//! Per folder, `state/changes/<folder>.jsonl` holds the events (one JSON
//! object per line, appended) and `state/changes/<folder>.json` the index:
//! the versions seen per path, so a version is recorded once. Both are
//! bounded by [`ChangeLimits`]: the newest `per_file` versions of a path
//! and the newest `per_folder` events of the folder are kept.

use crate::ids::DeviceId;
use crate::manifest::FileState;
use crate::util;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// How much history a device keeps (`config.json` `changes`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeLimits {
    /// Versions kept per path.
    #[serde(default = "default_per_file")]
    pub per_file: usize,
    /// Events kept per folder.
    #[serde(default = "default_per_folder")]
    pub per_folder: usize,
}

fn default_per_file() -> usize {
    100
}
fn default_per_folder() -> usize {
    20_000
}

impl Default for ChangeLimits {
    fn default() -> Self {
        ChangeLimits {
            per_file: default_per_file(),
            per_folder: default_per_folder(),
        }
    }
}

impl ChangeLimits {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// What a version did to its path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// A path that did not exist (or was deleted and comes back with content
    /// it never had).
    Created,
    /// New content at an existing path.
    Modified,
    /// The path was deleted.
    Deleted,
    /// A deleted path came back with content it had before.
    Restored,
    /// Moved: on the new path `from` names the old one; on the old path
    /// (deleted by the move) `to` names the new one.
    Renamed,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Created => "created",
            Action::Modified => "modified",
            Action::Deleted => "deleted",
            Action::Restored => "restored",
            Action::Renamed => "renamed",
        }
    }
}

/// One version of one path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeEvent {
    pub path: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The device that made the change (`modified_by`).
    pub device: DeviceId,
    /// Its Lamport clock (`modified_clock`).
    pub clock: u64,
    /// When the change was first published: the creation time of the
    /// first manifest this device saw naming it (UTC seconds).
    pub time_utc: i64,
    pub size: u64,
    /// The first 16 hex digits of the keyed content hash (empty when deleted).
    #[serde(default)]
    pub hash: String,
    /// The device whose manifest carried it.
    pub source: DeviceId,
    /// That manifest matched the hash a signed ledger batch announced for
    /// it (always true for this device's own).
    #[serde(default)]
    pub verified: bool,
    /// Recorded when the history began on this device, from the versions
    /// it already held: `time_utc` is then the file's modification time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub backfilled: bool,
}

impl ChangeEvent {
    fn key(&self) -> (i64, u64, &str) {
        (self.time_utc, self.clock, self.path.as_str())
    }
}

/// A version recorded for a path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seen {
    pub device: DeviceId,
    pub clock: u64,
    pub deleted: bool,
    #[serde(default)]
    pub hash: String,
}

/// `state/changes/<folder>.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Index {
    /// Versions recorded per path, oldest first (by clock).
    #[serde(default)]
    pub seen: BTreeMap<String, Vec<Seen>>,
    /// The history was started from the versions held then.
    #[serde(default)]
    pub backfilled: bool,
    /// Lines in the events file.
    #[serde(default)]
    pub lines: usize,
}

/// A version offered to the history, with where it came from.
pub struct Candidate<'a> {
    pub state: &'a FileState,
    pub source: &'a DeviceId,
    pub time_utc: i64,
    pub verified: bool,
    pub backfilled: bool,
}

pub fn short_hash(h: &str) -> String {
    h.chars().take(16).collect()
}

/// The change history files of one folder.
pub struct ChangeLog {
    index_path: PathBuf,
    events_path: PathBuf,
    limits: ChangeLimits,
    pub index: Index,
    /// The index changed since it was read.
    dirty: bool,
}

impl ChangeLog {
    pub fn open(home: &Path, folder: &str, limits: ChangeLimits) -> ChangeLog {
        let dir = home.join("state").join("changes");
        let index_path = dir.join(format!("{folder}.json"));
        let events_path = dir.join(format!("{folder}.jsonl"));
        let index = util::read_json_or_default(&index_path).unwrap_or_default();
        ChangeLog {
            index_path,
            events_path,
            limits,
            index,
            dirty: false,
        }
    }

    /// Record the versions not seen before; returns the new events.
    pub fn record(&mut self, mut cands: Vec<Candidate>) -> Result<Vec<ChangeEvent>> {
        cands.sort_by_key(|c| (c.state.modified_clock, c.state.path.clone()));
        let mut out: Vec<ChangeEvent> = Vec::new();
        for c in cands {
            let f = c.state;
            let list = self.index.seen.entry(f.path.clone()).or_default();
            if list
                .iter()
                .any(|s| s.device == f.modified_by && s.clock == f.modified_clock)
            {
                continue;
            }
            // Older than everything kept for a full path: dropped long ago.
            if list.len() >= self.limits.per_file
                && list.first().is_some_and(|s| f.modified_clock < s.clock)
            {
                continue;
            }
            let prev = list
                .iter()
                .rev()
                .find(|s| s.clock < f.modified_clock)
                .cloned();
            let action = if f.deleted {
                Action::Deleted
            } else {
                match &prev {
                    None => Action::Created,
                    Some(p) if p.deleted => {
                        if list.iter().any(|s| {
                            !s.deleted && s.hash == f.content_hash && s.clock < f.modified_clock
                        }) {
                            Action::Restored
                        } else {
                            Action::Created
                        }
                    }
                    Some(_) => Action::Modified,
                }
            };
            let pos = list
                .iter()
                .position(|s| s.clock > f.modified_clock)
                .unwrap_or(list.len());
            list.insert(
                pos,
                Seen {
                    device: f.modified_by.clone(),
                    clock: f.modified_clock,
                    deleted: f.deleted,
                    hash: f.content_hash.clone(),
                },
            );
            let excess = list.len().saturating_sub(self.limits.per_file);
            list.drain(..excess);
            out.push(ChangeEvent {
                path: f.path.clone(),
                action,
                from: None,
                to: None,
                device: f.modified_by.clone(),
                clock: f.modified_clock,
                time_utc: c.time_utc,
                size: if f.deleted { 0 } else { f.size },
                // A deletion names the content that was there.
                hash: short_hash(if f.deleted {
                    prev.as_ref().map(|p| p.hash.as_str()).unwrap_or("")
                } else {
                    &f.content_hash
                }),
                source: c.source.clone(),
                verified: c.verified,
                backfilled: c.backfilled,
            });
        }
        pair_renames(&mut out);
        self.dirty |= !out.is_empty();
        self.append(&out)?;
        Ok(out)
    }

    fn append(&mut self, events: &[ChangeEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.events_path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)?;
        let mut buf = Vec::new();
        for e in events {
            serde_json::to_writer(&mut buf, e)?;
            buf.push(b'\n');
        }
        f.write_all(&buf)?;
        self.index.lines += events.len();
        if self.index.lines > self.limits.per_folder + self.limits.per_folder / 4 + 16 {
            self.compact()?;
        }
        Ok(())
    }

    /// Every event kept, oldest first.
    pub fn events(&self) -> Vec<ChangeEvent> {
        let Ok(text) = fs::read_to_string(&self.events_path) else {
            return Vec::new();
        };
        let mut out: Vec<ChangeEvent> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        out.sort_by(|a, b| a.key().cmp(&b.key()));
        out
    }

    /// Keep the newest `per_file` versions of each path and the newest
    /// `per_folder` events, rewriting the file.
    pub fn compact(&mut self) -> Result<()> {
        let all = self.events();
        let mut per_path: BTreeMap<&str, usize> = BTreeMap::new();
        let mut kept: Vec<&ChangeEvent> = Vec::new();
        for e in all.iter().rev() {
            let n = per_path.entry(e.path.as_str()).or_insert(0);
            if *n >= self.limits.per_file || kept.len() >= self.limits.per_folder {
                continue;
            }
            *n += 1;
            kept.push(e);
        }
        kept.reverse();
        let mut buf = Vec::new();
        for e in &kept {
            serde_json::to_writer(&mut buf, e)?;
            buf.push(b'\n');
        }
        util::write_atomic(&self.events_path, &buf)?;
        self.index.lines = kept.len();
        Ok(())
    }

    /// Mark the history as started from what the device held.
    pub fn set_backfilled(&mut self) {
        if !self.index.backfilled {
            self.index.backfilled = true;
            self.dirty = true;
        }
    }

    /// Write the index if it changed.
    pub fn save(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.dirty = false;
        if let Some(dir) = self.index_path.parent() {
            fs::create_dir_all(dir)?;
        }
        util::write_json(&self.index_path, &self.index)
    }

    /// Remove both files (the folder left this device).
    pub fn remove(home: &Path, folder: &str) {
        let dir = home.join("state").join("changes");
        let _ = fs::remove_file(dir.join(format!("{folder}.json")));
        let _ = fs::remove_file(dir.join(format!("{folder}.jsonl")));
    }
}

/// In one batch of new events, a deletion and a creation of the same
/// content by the same device are a rename (each pair used once).
fn pair_renames(events: &mut [ChangeEvent]) {
    let mut used: BTreeSet<usize> = BTreeSet::new();
    for i in 0..events.len() {
        if events[i].action != Action::Deleted || events[i].hash.is_empty() || used.contains(&i) {
            continue;
        }
        let Some(j) = (0..events.len()).find(|j| {
            !used.contains(j)
                && *j != i
                && matches!(events[*j].action, Action::Created | Action::Restored)
                && events[*j].hash == events[i].hash
                && events[*j].device == events[i].device
        }) else {
            continue;
        };
        used.insert(i);
        used.insert(j);
        let (old, new) = (events[i].path.clone(), events[j].path.clone());
        events[i].action = Action::Renamed;
        events[i].to = Some(new);
        events[j].action = Action::Renamed;
        events[j].from = Some(old);
    }
}

/// `2026-10-13`, `2026-10-13T08:30[:00]` (UTC), seconds since 1970, or an
/// age such as `7d`, `12h`, `30m`.
pub fn parse_since(s: &str, now_utc: i64) -> Result<i64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now_utc - n * 86_400);
    }
    if let Some(n) = s.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now_utc - n * 3600);
    }
    if let Some(n) = s.strip_suffix('m').and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now_utc - n * 60);
    }
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    let (date, time) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let d: Vec<i64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let [y, mo, da] = d.as_slice() else {
        bail!("give the date as YYYY-MM-DD[THH:MM], seconds since 1970, or an age such as 7d");
    };
    if !(1..=12).contains(mo) || !(1..=31).contains(da) {
        bail!("{s} is not a date");
    }
    let mut secs = days_from_civil(*y, *mo, *da) * 86_400;
    if let Some(t) = time {
        let t: Vec<i64> = t
            .trim_end_matches('Z')
            .split(':')
            .filter_map(|x| x.parse().ok())
            .collect();
        secs += t.first().copied().unwrap_or(0) * 3600
            + t.get(1).copied().unwrap_or(0) * 60
            + t.get(2).copied().unwrap_or(0);
    }
    Ok(secs)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::VersionVector;

    fn fs_state(path: &str, dev: &DeviceId, clock: u64, hash: &str, deleted: bool) -> FileState {
        FileState {
            path: path.into(),
            version: VersionVector::default(),
            deleted,
            size: if deleted { 0 } else { 3 },
            mtime: 0,
            content_hash: if deleted { String::new() } else { hash.into() },
            chunks: vec![],
            modified_by: dev.clone(),
            modified_clock: clock,
        }
    }

    #[test]
    fn versions_are_recorded_once_with_their_action() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DeviceId::random();
        let mut h = ChangeLog::open(tmp.path(), "f", ChangeLimits::default());
        let a1 = fs_state("a.txt", &d, 1, "aa", false);
        let a2 = fs_state("a.txt", &d, 5, "bb", false);
        let cand = |s| Candidate {
            state: s,
            source: &d,
            time_utc: 100,
            verified: true,
            backfilled: false,
        };
        let ev = h.record(vec![cand(&a1)]).unwrap();
        assert_eq!(ev[0].action, Action::Created);
        assert!(h.record(vec![cand(&a1)]).unwrap().is_empty());
        let ev = h.record(vec![cand(&a2)]).unwrap();
        assert_eq!(ev[0].action, Action::Modified);
        // Moved: deleted at a.txt, created at b.txt with the same content.
        let gone = fs_state("a.txt", &d, 7, "", true);
        let moved = fs_state("b.txt", &d, 6, "bb", false);
        let ev = h.record(vec![cand(&gone), cand(&moved)]).unwrap();
        assert!(ev.iter().all(|e| e.action == Action::Renamed), "{ev:?}");
        assert!(ev.iter().any(|e| e.to.as_deref() == Some("b.txt")));
        assert!(ev.iter().any(|e| e.from.as_deref() == Some("a.txt")));
        // Back at a.txt with content it had: restored.
        let back = fs_state("a.txt", &d, 9, "aa", false);
        assert_eq!(
            h.record(vec![cand(&back)]).unwrap()[0].action,
            Action::Restored
        );
        h.save().unwrap();
        let again = ChangeLog::open(tmp.path(), "f", ChangeLimits::default());
        assert_eq!(again.events().len(), 5);
        assert_eq!(again.index.seen["a.txt"].len(), 4);
    }

    #[test]
    fn limits_bound_the_history() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DeviceId::random();
        let limits = ChangeLimits {
            per_file: 3,
            per_folder: 10,
        };
        let mut h = ChangeLog::open(tmp.path(), "f", limits);
        for i in 1..=40u64 {
            let s = fs_state(&format!("f{}.txt", i % 4), &d, i, &format!("{i:02}"), false);
            h.record(vec![Candidate {
                state: &s,
                source: &d,
                time_utc: i as i64,
                verified: true,
                backfilled: false,
            }])
            .unwrap();
        }
        h.compact().unwrap();
        let ev = h.events();
        assert!(ev.len() <= 10);
        assert_eq!(ev.last().unwrap().clock, 40);
        assert!(h.index.seen.values().all(|v| v.len() <= 3));
    }

    #[test]
    fn since_accepts_dates_seconds_and_ages() {
        assert_eq!(parse_since("1970-01-02", 0).unwrap(), 86_400);
        assert_eq!(parse_since("2026-10-13", 0).unwrap(), 1_791_849_600);
        assert_eq!(
            parse_since("2026-10-13T01:02:03Z", 0).unwrap(),
            1_791_853_323
        );
        assert_eq!(
            parse_since("7d", 1_000_000).unwrap(),
            1_000_000 - 7 * 86_400
        );
        assert_eq!(parse_since("12345", 0).unwrap(), 12_345);
        assert!(parse_since("yesterday", 0).is_err());
    }
}
