// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The snapshots of one backup as a device reads them: which announced
//! records a pull loads, rebuilding any snapshot from its base + itself,
//! expiry (which records may go, which bases stay), and the references
//! garbage collection starts from.
//!
//! Snapshot records are never pruned: a snapshot goes only when it expires
//! (`snapshot_expired` in the ledger, or `expires_utc` of its signed body
//! reached), and a base goes only after the last unexpired differential
//! built on it.

use super::record::SnapshotBody;
use super::{stream, Hash32, Id16};
use crate::ledger3::events::SnapshotExpired;
use crate::ledger3::LedgerView;
use crate::manifest3::FileEntry;
use crate::record::{
    Kind, Listed, Outcome, RecordName, RecordStore, RecordsRefused, Refusal, Refused,
};
use crate::storage::Storage;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// One announced snapshot record a pull should load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WantSnap {
    pub device: Id16,
    pub seq: u64,
    pub parts: u16,
    /// The base the announcement names (`== seq` for a base).
    pub base: u64,
}

/// What one pull did.
#[derive(Clone, Debug, Default)]
pub struct PullReport {
    /// Snapshots loaded.
    pub loaded: u64,
    /// Records that wait for the batch that announces them.
    pub waiting: usize,
    /// Differentials whose base is not loaded (yet).
    pub missing_base: usize,
    pub refused: Vec<Refused>,
}

/// A snapshot as listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub device: Id16,
    pub seq: u64,
    pub taken_utc: i64,
    pub expires_utc: i64,
    /// The base it is a differential against (`== seq` for a base).
    pub base: u64,
    /// Files and bytes `snapshot_taken` said (0 when the ledger has none).
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug)]
struct Loaded {
    base: u64,
    taken_utc: i64,
    expires_utc: i64,
    /// A base: every file. A differential: the entries that differ.
    files: BTreeMap<String, FileEntry>,
    removed: BTreeSet<String>,
}

/// Whether a snapshot is expired: marked so in the ledger, or past its
/// expiry time (`expires_utc` from the signed body when loaded, else from
/// `snapshot_taken`). Unknown to the ledger: not expired.
fn expired_in(
    view: &LedgerView,
    backup: &Id16,
    device: &Id16,
    seq: u64,
    body_expires: Option<i64>,
    now: i64,
) -> bool {
    let rec = view.snapshots.get(&(*backup, *device, seq));
    if rec.is_some_and(|r| r.expired) {
        return true;
    }
    if let Some(t) = body_expires {
        return now >= t;
    }
    rec.is_some_and(|r| r.taken && now >= r.expires_utc)
}

/// The announced snapshot records of `(backup, device)` in the ledger view:
/// seq -> base.
fn announced(view: &LedgerView, backup: &Id16, device: &Id16) -> BTreeMap<u64, u64> {
    view.stream(Kind::Snapshot.code(), backup, device)
        .map(|s| s.records.iter().map(|(q, a)| (*q, a.base)).collect())
        .unwrap_or_default()
}

/// Records of `device` that may be deleted from the storages at `now`:
/// expired ones that no unexpired differential names as its base. Decided
/// from the ledger alone (a writer knows every record it announced).
pub fn deletable(view: &LedgerView, backup: &Id16, device: &Id16, now: i64) -> Vec<u64> {
    let records = announced(view, backup, device);
    let expired = |seq| expired_in(view, backup, device, seq, None, now);
    let named: BTreeSet<u64> = records
        .iter()
        .filter(|(seq, base)| **base != **seq && !expired(**seq))
        .map(|(_, base)| *base)
        .collect();
    records
        .keys()
        .copied()
        .filter(|seq| expired(*seq) && !named.contains(seq))
        .collect()
}

/// The `snapshot_expired` events `me` owes the ledger: its own snapshots
/// past their expiry time that the ledger does not show as expired.
pub fn expiry_due(view: &LedgerView, backup: &Id16, me: &Id16, now: i64) -> Vec<SnapshotExpired> {
    view.snapshots
        .range((*backup, *me, 0)..=(*backup, *me, u64::MAX))
        .filter(|(_, r)| r.taken && !r.expired && now >= r.expires_utc)
        .map(|((b, d, seq), _)| SnapshotExpired {
            backup: *b,
            device: *d,
            seq: *seq,
        })
        .collect()
}

/// Delete `device`'s snapshot records `seqs` (as `deletable` returned them)
/// from one storage. Returns the number of objects deleted. The caller
/// keeps a cold storage's minimum storage duration.
pub fn delete_records(
    storage: &dyn Storage,
    backup: &Id16,
    device: &Id16,
    seqs: &[u64],
) -> Result<u64> {
    let s = stream(*backup, *device);
    let Some(prefix) = s.prefix() else {
        return Ok(0);
    };
    let want: HashSet<u64> = seqs.iter().copied().collect();
    let mut deleted = 0;
    for name in storage.list(&prefix)? {
        let Some(n) = RecordName::parse_as(Kind::Snapshot, &name) else {
            continue;
        };
        if want.contains(&n.seq) && n.scope == *backup && n.device == Some(*device) {
            storage.delete(&name)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// The loaded snapshots of one backup.
#[derive(Clone, Debug, Default)]
pub struct BackupSnapshots {
    pub backup: Id16,
    loaded: BTreeMap<(Id16, u64), Loaded>,
}

impl BackupSnapshots {
    pub fn new(backup: Id16) -> BackupSnapshots {
        BackupSnapshots {
            backup,
            loaded: BTreeMap::new(),
        }
    }

    pub fn is_loaded(&self, device: &Id16, seq: u64) -> bool {
        self.loaded.contains_key(&(*device, seq))
    }

    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    fn expired(&self, view: &LedgerView, device: &Id16, seq: u64, now: i64) -> bool {
        let t = self.loaded.get(&(*device, seq)).map(|l| l.expires_utc);
        expired_in(view, &self.backup, device, seq, t, now)
    }

    /// The announced records a pull should load: unexpired snapshots not
    /// loaded yet, and the bases the unexpired differentials name (even an
    /// expired base: it is kept while they live). Bases come before the
    /// differentials built on them.
    pub fn wanted(&self, view: &LedgerView, now: i64) -> Vec<WantSnap> {
        let mut out = Vec::new();
        for ((k, scope, device), s) in &view.streams {
            if *k != Kind::Snapshot.code() || scope != &self.backup || view.forked.contains(device)
            {
                continue;
            }
            let key = (*k, *scope, *device);
            let live: Vec<(u64, u64)> = s
                .records
                .iter()
                .filter(|(seq, _)| !view.forked_streams.contains(&(key, **seq)))
                .filter(|(seq, _)| !self.expired(view, device, **seq, now))
                .map(|(seq, a)| (*seq, a.base))
                .collect();
            let mut need: BTreeSet<u64> = live.iter().map(|(seq, _)| *seq).collect();
            need.extend(live.iter().filter(|(q, b)| b != q).map(|(_, b)| *b));
            for seq in need {
                let Some(a) = s.records.get(&seq) else {
                    continue;
                };
                if self.is_loaded(device, seq) || view.forked_streams.contains(&(key, seq)) {
                    continue;
                }
                out.push(WantSnap {
                    device: *device,
                    seq,
                    parts: a.parts,
                    base: a.base,
                });
            }
        }
        out
    }

    /// Load everything `wanted` lists from one storage and keep what is
    /// accepted. `Err` only for storage errors.
    pub fn pull(
        &mut self,
        store: &RecordStore,
        view: &LedgerView,
        now: i64,
        counter: &mut RecordsRefused,
    ) -> Result<PullReport> {
        let mut report = PullReport::default();
        for w in self.wanted(view, now) {
            let s = stream(self.backup, w.device);
            let names: Vec<String> = (0..w.parts).filter_map(|p| s.part_name(w.seq, p)).collect();
            let listed = Listed { seq: w.seq, names };
            match store.read::<SnapshotBody>(&listed)? {
                Outcome::Accepted(rec) => {
                    if rec.body.base != w.base {
                        let r = Refused {
                            name: String::new(),
                            kind: Some(Kind::Snapshot),
                            seq: w.seq,
                            device: Some(w.device),
                            reason: Refusal::Forked,
                        };
                        counter.note(&r);
                        report.refused.push(r);
                        continue;
                    }
                    match self.add(&rec.body) {
                        Ok(()) => report.loaded += 1,
                        Err(AddError::MissingBase) => report.missing_base += 1,
                        Err(AddError::Bad(e)) => {
                            let r = Refused {
                                name: String::new(),
                                kind: Some(Kind::Snapshot),
                                seq: w.seq,
                                device: Some(w.device),
                                reason: Refusal::Junk(crate::record::Junk::BadBody(e)),
                            };
                            counter.note(&r);
                            report.refused.push(r);
                        }
                    }
                }
                Outcome::Waiting(_) => report.waiting += 1,
                Outcome::Refused(r) => {
                    counter.note(&r);
                    report.refused.push(r);
                }
            }
        }
        Ok(report)
    }

    /// Keep an accepted snapshot. A differential needs its base loaded
    /// first, and that base must be a base.
    pub fn add(&mut self, body: &SnapshotBody) -> Result<(), AddError> {
        if body.backup != self.backup {
            return Err(AddError::Bad("a snapshot of another backup".into()));
        }
        let (files, removed) = body.validate().map_err(AddError::Bad)?;
        if !body.is_base() {
            match self.loaded.get(&(body.device, body.base)) {
                None => return Err(AddError::MissingBase),
                Some(b) if b.base != body.base => {
                    return Err(AddError::Bad(format!(
                        "snapshot {} names {} as its base, which is not one",
                        body.seq, body.base
                    )))
                }
                Some(_) => {}
            }
        }
        self.loaded.insert(
            (body.device, body.seq),
            Loaded {
                base: body.base,
                taken_utc: body.taken_utc,
                expires_utc: body.expires_utc,
                files,
                removed: removed.into_iter().collect(),
            },
        );
        Ok(())
    }

    /// Put in a snapshot this device took itself (its writer's listing).
    pub fn add_own(&mut self, body: &SnapshotBody) -> Result<(), AddError> {
        self.add(body)
    }

    /// The unexpired snapshots loaded, newest first.
    pub fn list(&self, view: &LedgerView, now: i64) -> Vec<SnapshotInfo> {
        let mut out: Vec<SnapshotInfo> = self
            .loaded
            .iter()
            .filter(|((d, q), _)| !self.expired(view, d, *q, now))
            .map(|((d, q), l)| {
                let r = view.snapshots.get(&(self.backup, *d, *q));
                SnapshotInfo {
                    device: *d,
                    seq: *q,
                    taken_utc: l.taken_utc,
                    expires_utc: l.expires_utc,
                    base: l.base,
                    files: r.map_or(0, |r| r.files),
                    bytes: r.map_or(0, |r| r.bytes),
                }
            })
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse((a.taken_utc, a.seq, a.device)));
        out
    }

    /// Rebuild a snapshot's listing from its base + itself: what a restore
    /// reads. It reads this snapshot and, for a differential, its base,
    /// never another snapshot.
    pub fn reconstruct(
        &self,
        device: &Id16,
        seq: u64,
    ) -> Result<BTreeMap<String, FileEntry>, String> {
        let me = self
            .loaded
            .get(&(*device, seq))
            .ok_or_else(|| format!("snapshot {seq} is not loaded"))?;
        if me.base == seq {
            return Ok(me.files.clone());
        }
        let base = self
            .loaded
            .get(&(*device, me.base))
            .filter(|b| b.base == me.base)
            .ok_or_else(|| format!("the base {} of snapshot {seq} is not loaded", me.base))?;
        let mut out = base.files.clone();
        for p in &me.removed {
            out.remove(p);
        }
        for (p, e) in &me.files {
            out.insert(p.clone(), e.clone());
        }
        Ok(out)
    }

    /// Expired bases that stay because an unexpired differential is built
    /// on them: hidden from listings, bodies retained.
    pub fn retained_bases(&self, view: &LedgerView, now: i64) -> Vec<(Id16, u64)> {
        let named: BTreeSet<(Id16, u64)> = self
            .loaded
            .iter()
            .filter(|((d, q), l)| l.base != *q && !self.expired(view, d, *q, now))
            .map(|((d, _), l)| (*d, l.base))
            .collect();
        named
            .into_iter()
            .filter(|(d, b)| self.expired(view, d, *b, now))
            .collect()
    }

    /// Forget loaded bodies that expired and that no unexpired
    /// differential needs (their records may be deleted from the storages).
    /// Returns how many were forgotten.
    pub fn forget_expired(&mut self, view: &LedgerView, now: i64) -> usize {
        let needed: BTreeSet<(Id16, u64)> = self
            .loaded
            .iter()
            .filter(|((d, q), _)| !self.expired(view, d, *q, now))
            .flat_map(|((d, q), l)| [(*d, *q), (*d, l.base)])
            .collect();
        let before = self.loaded.len();
        self.loaded.retain(|k, _| needed.contains(k));
        before - self.loaded.len()
    }

    /// Object names the unexpired snapshots keep alive (what garbage
    /// collection must not collect): each snapshot's reconstructed listing,
    /// computed without rebuilding it per snapshot. Repeats are possible.
    /// Call after a pull: an unexpired snapshot not loaded is not counted.
    pub fn references(&self, view: &LedgerView, now: i64) -> Vec<Hash32> {
        let mut out: Vec<Hash32> = Vec::new();
        // Per base: its unexpired differentials.
        let mut diffs: BTreeMap<(Id16, u64), Vec<&Loaded>> = BTreeMap::new();
        for ((d, q), l) in &self.loaded {
            if self.expired(view, d, *q, now) {
                continue;
            }
            out.extend(l.files.values().flat_map(|e| e.objects().copied()));
            if l.base != *q {
                diffs.entry((*d, l.base)).or_default().push(l);
            }
        }
        for ((d, b), ds) in diffs {
            let Some(base) = self.loaded.get(&(d, b)) else {
                continue;
            };
            if !self.expired(view, &d, b, now) {
                continue; // a live base already counted every entry
            }
            // A base entry is kept by a differential that does not
            // override it (replace or remove it).
            let mut overridden: HashMap<&str, usize> = HashMap::new();
            for l in &ds {
                for p in l.files.keys().chain(l.removed.iter()) {
                    *overridden.entry(p.as_str()).or_default() += 1;
                }
            }
            for (p, e) in &base.files {
                if overridden.get(p.as_str()).copied().unwrap_or(0) < ds.len() {
                    out.extend(e.objects().copied());
                }
            }
        }
        out
    }

    /// `references` as a set.
    pub fn reference_set(&self, view: &LedgerView, now: i64) -> HashSet<Hash32> {
        self.references(view, now).into_iter().collect()
    }
}

/// Why a snapshot could not be kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddError {
    /// A differential whose base is not loaded yet.
    MissingBase,
    Bad(String),
}
