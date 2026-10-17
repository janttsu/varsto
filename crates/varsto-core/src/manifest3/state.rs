// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One writer's view of a folder, reconstructed from its newest announced
//! base and the deltas after it, in order (section 7).

use super::record::{FileEntry, ManifestBody};
use super::{Hash32, Id16};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Why a record does not apply to a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// Not newer than what the view holds: nothing to do.
    Stale { have: u64, got: u64 },
    /// A delta that does not follow the view's seq (a record in between is
    /// missing): read again from the newest base.
    Gap { have: u64, got: u64 },
    /// A delta that names another base or another predecessor than the
    /// records this view applied: the writer forked its stream.
    Forked { seq: u64 },
    /// The body fails its checks (already refused by acceptance normally).
    Bad(String),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Stale { have, got } => write!(f, "manifest {got} is not newer than {have}"),
            ApplyError::Gap { have, got } => {
                write!(f, "manifest delta {got} does not follow {have}")
            }
            ApplyError::Forked { seq } => {
                write!(f, "manifest {seq} does not continue the records before it")
            }
            ApplyError::Bad(e) => write!(f, "manifest refused: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

/// A writer's view: what a full manifest of `seq` would have listed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriterView {
    pub device: Id16,
    /// Seq of the newest applied record (0: none).
    pub seq: u64,
    /// Seq of the base the view was built from.
    pub base: u64,
    /// `record_hash` of record `seq` (what the next delta's `prev` names).
    pub hash: Hash32,
    pub lamport: u64,
    pub created_utc: i64,
    pub files: BTreeMap<String, FileEntry>,
}

impl WriterView {
    pub fn new(device: Id16) -> WriterView {
        WriterView {
            device,
            ..Default::default()
        }
    }

    /// Apply accepted record `body` whose announced hash is `hash`. A base
    /// replaces the view; a delta must follow it (`seq + 1`, same base,
    /// `prev` = the view's hash). Returns the paths that changed.
    pub fn apply(
        &mut self,
        body: &ManifestBody,
        hash: Hash32,
    ) -> Result<BTreeSet<String>, ApplyError> {
        if body.device != self.device {
            return Err(ApplyError::Bad("a record of another writer".into()));
        }
        if body.seq <= self.seq {
            return Err(ApplyError::Stale {
                have: self.seq,
                got: body.seq,
            });
        }
        let (entries, removed) = body.validate().map_err(ApplyError::Bad)?;
        let mut changed = BTreeSet::new();
        if body.is_base() {
            let files: BTreeMap<String, FileEntry> =
                entries.into_iter().map(|e| (e.path.clone(), e)).collect();
            for (p, old) in &self.files {
                if files.get(p) != Some(old) {
                    changed.insert(p.clone());
                }
            }
            for (p, new) in &files {
                if self.files.get(p) != Some(new) {
                    changed.insert(p.clone());
                }
            }
            self.files = files;
            self.base = body.seq;
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
            for e in entries {
                if self.files.get(&e.path) != Some(&e) {
                    changed.insert(e.path.clone());
                    self.files.insert(e.path.clone(), e);
                }
            }
            for p in removed {
                if self.files.remove(&p).is_some() {
                    changed.insert(p);
                }
            }
        }
        self.seq = body.seq;
        self.hash = hash;
        self.lamport = self.lamport.max(body.lamport);
        self.created_utc = body.created_utc;
        Ok(changed)
    }

    /// Entries that name a file (not deleted).
    pub fn current(&self) -> impl Iterator<Item = &FileEntry> {
        self.files.values().filter(|f| !f.deleted)
    }
}
