// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Section 7's merge rules, unchanged, as pure functions over format-3
//! entries and views:
//!
//! - a version that dominates another (version vector) wins;
//! - concurrent versions with identical content need no conflict copy (only
//!   metadata may differ: the later change wins);
//! - a deletion never wins against a concurrent modification;
//! - otherwise the later change (modified clock, then device) wins and the
//!   other becomes a conflict copy; the winner carries the element-wise
//!   maximum of the version vectors.
//!
//! [`merge_entry`] is the pairwise decision of `manifest::merge` (what the
//! engine applies to one remote state against its own). [`resolve`] applies
//! the same rules to any set of states of one path at once: it depends only
//! on the set, so merging views is commutative, associative and idempotent
//! (a winner dominates every state it was chosen from). [`merge_views`]
//! merges the writer's own view with every other writer's reconstructed
//! view; [`Merged::refresh`] recomputes only the paths a delta changed and
//! gives the same result as merging the full views again.

use super::record::{FileEntry, WireMeta};
use super::Id16;
use crate::manifest::Order;
use std::collections::{BTreeMap, BTreeSet};

/// Order of two version vectors (as `manifest::compare`).
pub fn compare(local: &BTreeMap<Id16, u64>, remote: &BTreeMap<Id16, u64>) -> Order {
    let le = |a: &BTreeMap<Id16, u64>, b: &BTreeMap<Id16, u64>| {
        a.iter().all(|(k, v)| b.get(k).copied().unwrap_or(0) >= *v)
    };
    match (le(local, remote), le(remote, local)) {
        (true, true) => Order::Equal,
        (true, false) => Order::RemoteNewer,
        (false, true) => Order::LocalNewer,
        (false, false) => Order::Concurrent,
    }
}

/// Element-wise maximum.
pub fn vv_max(a: &BTreeMap<Id16, u64>, b: &BTreeMap<Id16, u64>) -> BTreeMap<Id16, u64> {
    let mut out = a.clone();
    for (k, v) in b {
        let e = out.entry(*k).or_insert(0);
        *e = (*e).max(*v);
    }
    out
}

/// The pairwise decision (`manifest::Merge`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Merge3 {
    KeepLocal,
    TakeRemote,
    /// Both sides changed: `winner` becomes the file; `loser` is kept as a
    /// conflict copy (None when the loser is a deletion or the same content).
    Conflict {
        winner: FileEntry,
        loser: Option<FileEntry>,
    },
}

fn later(a: &FileEntry, b: &FileEntry) -> bool {
    (a.modified_clock, &a.modified_by) > (b.modified_clock, &b.modified_by)
}

/// Port of `manifest::merge`: how a remote state combines with the local
/// state of the same path.
pub fn merge_entry(local: Option<&FileEntry>, remote: &FileEntry) -> Merge3 {
    let Some(local) = local else {
        return Merge3::TakeRemote;
    };
    match compare(&local.version, &remote.version) {
        Order::Equal | Order::LocalNewer => Merge3::KeepLocal,
        Order::RemoteNewer => Merge3::TakeRemote,
        Order::Concurrent => {
            let merged = vv_max(&local.version, &remote.version);
            let same_content =
                local.deleted == remote.deleted && local.content_hash == remote.content_hash;
            if same_content {
                let local_wins = local.meta == remote.meta || later(local, remote);
                let mut w = if local_wins { local } else { remote }.clone();
                w.version = merged;
                return Merge3::Conflict {
                    winner: w,
                    loser: None,
                };
            }
            if local.deleted != remote.deleted {
                let mut w = if local.deleted { remote } else { local }.clone();
                w.version = merged;
                return Merge3::Conflict {
                    winner: w,
                    loser: None,
                };
            }
            let (w, l) = if later(local, remote) {
                (local, remote)
            } else {
                (remote, local)
            };
            let mut w = w.clone();
            w.version = merged;
            Merge3::Conflict {
                winner: w,
                loser: Some(l.clone()),
            }
        }
    }
}

/// A total order on states for deterministic choices: the later change
/// first, then every other field. `held` is not part of it.
fn rank(e: &FileEntry) -> (u64, Id16, Vec<u8>) {
    (e.modified_clock, e.modified_by, canonical(e))
}

/// Every field but `held`, encoded.
fn canonical(e: &FileEntry) -> Vec<u8> {
    let vv: Vec<(&Id16, &u64)> = e.version.iter().collect();
    postcard::to_stdvec(&(
        vv,
        &e.path,
        e.deleted,
        e.size,
        e.mtime,
        e.content_hash,
        &e.chunks,
        e.modified_by,
        e.modified_clock,
        e.meta.as_ref().map(WireMeta::from),
        e.chunking,
    ))
    .expect("in-memory encoding")
}

/// The result of resolving the states of one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// `held` is false: whether a device holds it is that device's to say.
    pub winner: FileEntry,
    /// States kept as conflict copies (each distinct content once), in
    /// order of their copy paths.
    pub losers: Vec<FileEntry>,
}

/// Section 7's rules over every state of one path at once. None for no
/// states.
pub fn resolve<'a>(states: impl IntoIterator<Item = &'a FileEntry>) -> Option<Resolved> {
    let mut uniq: BTreeMap<Vec<u8>, &FileEntry> = BTreeMap::new();
    for s in states {
        uniq.entry(canonical(s)).or_insert(s);
    }
    let all: Vec<&FileEntry> = uniq.into_values().collect();
    // Maximal states: not dominated by another.
    let maxima: Vec<&FileEntry> = all
        .iter()
        .copied()
        .filter(|s| {
            !all.iter()
                .any(|o| compare(&s.version, &o.version) == Order::RemoteNewer)
        })
        .collect();
    let mut out = match maxima.as_slice() {
        [] => return None,
        [one] => Resolved {
            winner: (*one).clone(),
            losers: Vec::new(),
        },
        many => {
            let merged = many
                .iter()
                .fold(BTreeMap::new(), |acc, s| vv_max(&acc, &s.version));
            // A deletion never wins against a concurrent modification.
            let live: Vec<&FileEntry> = many.iter().copied().filter(|s| !s.deleted).collect();
            let cands = if live.is_empty() { many.to_vec() } else { live };
            let winner = *cands.iter().max_by_key(|s| rank(s)).expect("not empty");
            // One loser per other content, the latest state of it.
            let mut by_content: BTreeMap<(bool, Option<[u8; 32]>), &FileEntry> = BTreeMap::new();
            for s in &cands {
                let k = (s.deleted, s.content_hash);
                if k == (winner.deleted, winner.content_hash) {
                    continue;
                }
                let e = by_content.entry(k).or_insert(s);
                if rank(s) > rank(e) {
                    *e = s;
                }
            }
            let mut losers: Vec<FileEntry> = by_content.into_values().cloned().collect();
            losers.sort_by_cached_key(|l| (conflict_path(&l.path, l), rank(l)));
            let mut w = winner.clone();
            w.version = merged;
            Resolved { winner: w, losers }
        }
    };
    out.winner.held = false;
    for l in &mut out.losers {
        l.held = false;
    }
    Some(out)
}

/// Name of a conflict copy: `report.txt` -> `report.conflict-<device>-<clock>.txt`
/// (as `manifest::conflict_path`, device shown by its first 8 hex digits).
pub fn conflict_path(path: &str, loser: &FileEntry) -> String {
    let (dir, name) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let dev = hex::encode(loser.modified_by);
    let tag = format!("conflict-{}-{}", &dev[..8], loser.modified_clock);
    let new_name = match name.rfind('.') {
        Some(i) if i > 0 => format!("{}.{}{}", &name[..i], tag, &name[i..]),
        _ => format!("{name}.{tag}"),
    };
    format!("{dir}{new_name}")
}

/// A conflict copy the engine is to make (with its own new version).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub path: String,
    pub copy_path: String,
    pub loser: FileEntry,
}

/// The merged view of a folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Merged {
    pub files: BTreeMap<String, FileEntry>,
    /// Per path, its conflict copies.
    pub conflicts: BTreeMap<String, Vec<Conflict>>,
}

fn held_here(own: Option<&FileEntry>, w: &FileEntry) -> bool {
    own.is_some_and(|o| {
        o.held
            && !o.deleted
            && !w.deleted
            && o.content_hash == w.content_hash
            && o.chunks == w.chunks
    })
}

impl Merged {
    /// Recompute `paths` from the views as they are now. Equal to
    /// `merge_views` over the same views when `paths` covers every path
    /// that changed since the last merge.
    pub fn refresh<'a>(
        &mut self,
        own: &BTreeMap<String, FileEntry>,
        others: &[&BTreeMap<String, FileEntry>],
        paths: impl IntoIterator<Item = &'a str>,
    ) {
        for p in paths {
            let mine = own.get(p);
            let states = mine
                .into_iter()
                .chain(others.iter().filter_map(|v| v.get(p)));
            match resolve(states) {
                None => {
                    self.files.remove(p);
                    self.conflicts.remove(p);
                }
                Some(r) => {
                    let mut w = r.winner;
                    w.held = held_here(mine, &w);
                    self.files.insert(p.to_string(), w);
                    if r.losers.is_empty() {
                        self.conflicts.remove(p);
                    } else {
                        let c = r
                            .losers
                            .into_iter()
                            .map(|l| Conflict {
                                path: p.to_string(),
                                copy_path: conflict_path(p, &l),
                                loser: l,
                            })
                            .collect();
                        self.conflicts.insert(p.to_string(), c);
                    }
                }
            }
        }
    }
}

/// Merge the writer's own view with every other writer's view. The
/// winner's `held` is the own entry's when the own entry has the winner's
/// content and blocks.
pub fn merge_views(
    own: &BTreeMap<String, FileEntry>,
    others: &[&BTreeMap<String, FileEntry>],
) -> Merged {
    let mut paths: BTreeSet<&str> = own.keys().map(String::as_str).collect();
    for v in others {
        paths.extend(v.keys().map(String::as_str));
    }
    let mut m = Merged::default();
    m.refresh(own, others, paths);
    m
}
