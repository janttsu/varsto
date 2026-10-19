// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Keeping folder manifests cheap as they accumulate
//! (`docs/spec/alpha-0-format.md` section 24; format 3: section 77).
//!
//! **Listing.** A manifest is a base plus deltas in a stream
//! `manifests/<folder>/<device>/`. Every record is announced in the ledger
//! (`record_published`), which a pull reads first, so a pull reads exactly
//! the records announced past what it applied (`manifest3` reader) and
//! lists nothing else: with nothing new, nothing is listed or read.
//!
//! **Pruning.** A reader rebuilds a writer's view from the newest base and
//! the deltas after it, so records below that base are dead weight. After a
//! sync a full device deletes its own records of a folder below its newest
//! base, once every reader of the folder (the participants holding its
//! keys, own devices and members) has acknowledged the batch that announced
//! the base (`manifest3::prune_floor`). Every reader therefore knows of the
//! base or newer before anything older goes, and a revocation cut-off taken
//! by any reader still finds its records. Cold storages are never pruned.

use super::*;

/// Whether superseded own manifest records are deleted from the storages.
#[derive(Clone, Copy, Debug)]
pub struct ManifestPolicy {
    /// Delete own records below the newest base that every reader has
    /// seen past.
    pub prune: bool,
}

impl Default for ManifestPolicy {
    fn default() -> Self {
        ManifestPolicy { prune: true }
    }
}

impl Engine {
    /// Use another manifest policy (tests and measurements).
    pub fn set_manifest_policy(&mut self, policy: ManifestPolicy) {
        self.manifest_policy = policy;
    }

    /// After a sync: delete own manifest and map records below the newest
    /// base every reader of the folder has acknowledged, from the hot
    /// storages (`prune_records3`). Anything left undone is retried after
    /// the next sync.
    pub fn manifest_upkeep(&mut self) -> Result<()> {
        if !self.manifest_policy.prune || !self.pending.is_empty() || !self.f3.pending.is_empty() {
            return Ok(());
        }
        crate::logged_op_plain!("manifest upkeep", "", { self.prune_records3().map(|_| ()) })
    }
}
