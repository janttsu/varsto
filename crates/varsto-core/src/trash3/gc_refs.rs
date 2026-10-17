// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What garbage collection must not collect (design section 3, "Dead
//! marks"): an object is live while it is referenced by a current file in
//! any accepted writer's newest manifest, an unexpired trash or history
//! entry, or an unexpired snapshot of the folder.
//!
//! [`all`] is the union of the three readers' references as one predicate.
//! Pass `None` for a part the folder has none of (a backup has snapshots
//! and no manifests; an ordinary folder has no snapshots). Build it after
//! the pulls of this round: an announced record not pulled yet is not
//! counted, so garbage collection waits for the pulls (section 3's race
//! argument is about exactly that order).

use super::reader::{FolderTrash, Trust};
use super::settings::Settings;
use super::Hash32;
use crate::ledger3::LedgerView;
use crate::manifest3::FolderManifests;
use crate::snapshot3::BackupSnapshots;
use std::collections::HashSet;

/// The inputs of one folder's references at one time.
pub struct Refs<'a> {
    pub manifests: Option<&'a FolderManifests>,
    pub trash: Option<(&'a FolderTrash, &'a Settings, &'a Trust)>,
    pub snapshots: Option<(&'a BackupSnapshots, &'a LedgerView)>,
    pub now: i64,
}

impl Refs<'_> {
    /// Every referenced object name, once.
    pub fn set(&self) -> HashSet<Hash32> {
        let mut out: HashSet<Hash32> = HashSet::new();
        if let Some(m) = self.manifests {
            out.extend(m.references().copied());
        }
        if let Some((t, settings, trust)) = self.trash {
            out.extend(t.references(self.now, settings, trust));
        }
        if let Some((s, view)) = self.snapshots {
            out.extend(s.references(view, self.now));
        }
        out
    }
}

/// `references::all(folder)`: a predicate that says whether an object is
/// referenced by the folder's manifests, unexpired trash and history, or
/// unexpired snapshots. The set is computed once.
pub fn all(refs: &Refs) -> impl Fn(&Hash32) -> bool {
    let set = refs.set();
    move |o| set.contains(o)
}
