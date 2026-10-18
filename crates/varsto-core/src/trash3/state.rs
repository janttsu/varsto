// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One device's trash record of a folder, reconstructed from its newest
//! announced base and the deltas after it, in order (section 7), and the
//! difference of two such records (what a delta carries).

use super::record::{Entry, Removal, TrashBody};
use super::{Hash32, Id16};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Why a record does not apply to a state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// Not newer than what the state holds: nothing to do.
    Stale { have: u64, got: u64 },
    /// A delta that does not follow the state's seq: read again from the
    /// newest base.
    Gap { have: u64, got: u64 },
    /// A delta that names another base or predecessor than the records this
    /// state applied: the writer forked its stream.
    Forked { seq: u64 },
    /// The body fails its checks (already refused by acceptance normally).
    Bad(String),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Stale { have, got } => write!(f, "trash {got} is not newer than {have}"),
            ApplyError::Gap { have, got } => write!(f, "trash delta {got} does not follow {have}"),
            ApplyError::Forked { seq } => {
                write!(f, "trash {seq} does not continue the records before it")
            }
            ApplyError::Bad(e) => write!(f, "trash record refused: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

/// What a device's whole trash record lists: the content of a base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrashSnapshot {
    pub entries: BTreeMap<Id16, Entry>,
    pub removals: BTreeMap<Id16, Removal>,
    pub versions: BTreeMap<Id16, Entry>,
}

impl TrashSnapshot {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.removals.is_empty() && self.versions.is_empty()
    }

    /// The state a base lists.
    pub fn from_base(body: &TrashBody) -> TrashSnapshot {
        TrashSnapshot {
            entries: body.entries.iter().map(|e| (e.id, e.clone())).collect(),
            removals: body.removals.iter().map(|r| (r.id, r.clone())).collect(),
            versions: body.versions.iter().map(|e| (e.id, e.clone())).collect(),
        }
    }

    /// Apply a delta: forgotten ids go first, then the lists are put in.
    /// Returns the ids that changed.
    pub fn apply_delta(&mut self, body: &TrashBody) -> BTreeSet<Id16> {
        let mut changed = BTreeSet::new();
        for id in &body.forget {
            let a = self.entries.remove(id).is_some();
            let b = self.removals.remove(id).is_some();
            let c = self.versions.remove(id).is_some();
            if a || b || c {
                changed.insert(*id);
            }
        }
        for e in &body.entries {
            if self.entries.get(&e.id) != Some(e) {
                self.entries.insert(e.id, e.clone());
                changed.insert(e.id);
            }
        }
        for r in &body.removals {
            if self.removals.get(&r.id) != Some(r) {
                self.removals.insert(r.id, r.clone());
                changed.insert(r.id);
            }
        }
        for e in &body.versions {
            if self.versions.get(&e.id) != Some(e) {
                self.versions.insert(e.id, e.clone());
                changed.insert(e.id);
            }
        }
        changed
    }

    /// What a delta from `self` to `cur` carries: changed or new items, and
    /// the ids `cur` no longer lists in some list. An id forgotten in one
    /// list but still listed in another is listed again in the same delta
    /// (forgetting is applied first).
    pub fn diff_to(&self, cur: &TrashSnapshot) -> Delta {
        fn changed<'a, T: PartialEq>(
            old: &BTreeMap<Id16, T>,
            new: &'a BTreeMap<Id16, T>,
            force: &BTreeSet<Id16>,
        ) -> Vec<&'a T> {
            new.iter()
                .filter(|(id, v)| old.get(*id) != Some(*v) || force.contains(*id))
                .map(|(_, v)| v)
                .collect()
        }
        let mut forget: BTreeSet<Id16> = BTreeSet::new();
        forget.extend(
            self.entries
                .keys()
                .filter(|i| !cur.entries.contains_key(*i)),
        );
        forget.extend(
            self.removals
                .keys()
                .filter(|i| !cur.removals.contains_key(*i)),
        );
        forget.extend(
            self.versions
                .keys()
                .filter(|i| !cur.versions.contains_key(*i)),
        );
        Delta {
            entries: changed(&self.entries, &cur.entries, &forget)
                .into_iter()
                .cloned()
                .collect(),
            removals: changed(&self.removals, &cur.removals, &forget)
                .into_iter()
                .cloned()
                .collect(),
            versions: changed(&self.versions, &cur.versions, &forget)
                .into_iter()
                .cloned()
                .collect(),
            forget: forget.into_iter().collect(),
        }
    }
}

/// The lists of a delta record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delta {
    pub entries: Vec<Entry>,
    pub removals: Vec<Removal>,
    pub versions: Vec<Entry>,
    pub forget: Vec<Id16>,
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.removals.is_empty()
            && self.versions.is_empty()
            && self.forget.is_empty()
    }
}

/// A device's trash record as of record `seq` of its stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceTrash {
    pub device: Id16,
    /// Seq of the newest applied record (0: none).
    pub seq: u64,
    /// Seq of the base the state was built from.
    pub base: u64,
    /// `record_hash` of record `seq` (what the next delta's `prev` names).
    pub hash: Hash32,
    pub lamport: u64,
    pub created_utc: i64,
    pub state: TrashSnapshot,
}

impl DeviceTrash {
    pub fn new(device: Id16) -> DeviceTrash {
        DeviceTrash {
            device,
            ..Default::default()
        }
    }

    /// Apply accepted record `body` whose announced hash is `hash`. A base
    /// replaces the state; a delta must follow it (`seq + 1`, same base,
    /// `prev` = the state's hash). Returns the ids that changed.
    pub fn apply(&mut self, body: &TrashBody, hash: Hash32) -> Result<BTreeSet<Id16>, ApplyError> {
        if body.device != self.device {
            return Err(ApplyError::Bad("a record of another writer".into()));
        }
        if body.seq <= self.seq {
            return Err(ApplyError::Stale {
                have: self.seq,
                got: body.seq,
            });
        }
        body.validate().map_err(ApplyError::Bad)?;
        let changed = if body.is_base() {
            let new = TrashSnapshot::from_base(body);
            let mut changed = BTreeSet::new();
            for (id, e) in &self.state.entries {
                if new.entries.get(id) != Some(e) {
                    changed.insert(*id);
                }
            }
            for (id, e) in &self.state.versions {
                if new.versions.get(id) != Some(e) {
                    changed.insert(*id);
                }
            }
            for (id, r) in &self.state.removals {
                if new.removals.get(id) != Some(r) {
                    changed.insert(*id);
                }
            }
            for (id, e) in &new.entries {
                if self.state.entries.get(id) != Some(e) {
                    changed.insert(*id);
                }
            }
            for (id, e) in &new.versions {
                if self.state.versions.get(id) != Some(e) {
                    changed.insert(*id);
                }
            }
            for (id, r) in &new.removals {
                if self.state.removals.get(id) != Some(r) {
                    changed.insert(*id);
                }
            }
            self.state = new;
            self.base = body.seq;
            changed
        } else {
            if self.seq == 0 || body.seq != self.seq + 1 {
                return Err(ApplyError::Gap {
                    have: self.seq,
                    got: body.seq,
                });
            }
            if body.base != self.base || body.prev != self.hash {
                return Err(ApplyError::Forked { seq: body.seq });
            }
            self.state.apply_delta(body)
        };
        self.seq = body.seq;
        self.hash = hash;
        self.lamport = self.lamport.max(body.lamport);
        self.created_utc = body.created_utc;
        Ok(changed)
    }
}
