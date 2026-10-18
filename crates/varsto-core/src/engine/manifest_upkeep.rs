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
    /// Unused since format 3: a pull reads the records the ledger
    /// announced and never lists a folder's manifests in full (kept so that
    /// callers of the format-2 policy compile).
    pub sweep_secs: i64,
    /// Delete own records below the newest base that every reader has
    /// seen past.
    pub prune: bool,
}

impl Default for ManifestPolicy {
    fn default() -> Self {
        ManifestPolicy {
            sweep_secs: 6 * 3600,
            prune: true,
        }
    }
}

const UPKEEP_FILE: &str = "state/manifests.json";

/// Kept in `state/manifests.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ManifestUpkeep {
    #[serde(default)]
    folders: BTreeMap<FolderId, FolderUpkeep>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FolderUpkeep {
    /// Per storage: own manifest records below this seq are gone there.
    #[serde(default)]
    pruned_below: BTreeMap<String, u64>,
}

/// (device, seq) of a key under `manifests/<folder>/` in format 2 (the
/// format-2 ledger rebuild in `ledger_recovery` still reads it; it goes
/// with that code).
pub(super) fn parse_key(folder_prefix: &str, key: &str) -> Option<(DeviceId, u64)> {
    let rest = key.strip_prefix(folder_prefix)?;
    let (dev, file) = rest.split_once('/')?;
    let seq = file.strip_suffix(".enc")?.parse::<u64>().ok()?;
    Some((DeviceId::from_hex(dev).ok()?, seq))
}

impl Engine {
    /// Use another manifest policy (tests and measurements).
    pub fn set_manifest_policy(&mut self, policy: ManifestPolicy) {
        self.manifest_policy = policy;
    }


    fn manifest_upkeep_path(&self) -> PathBuf {
        self.home.join(UPKEEP_FILE)
    }

    fn load_manifest_upkeep(&self) -> ManifestUpkeep {
        util::read_json_or_default(&self.manifest_upkeep_path()).unwrap_or_default()
    }

    fn save_manifest_upkeep(&self, up: &ManifestUpkeep) -> Result<()> {
        // Never recreate a state directory that was removed (reset, wipe).
        if !self.home.join("state").is_dir() {
            return Ok(());
        }
        util::write_json(&self.manifest_upkeep_path(), up)
    }

    /// After a sync: delete own manifest records below the newest base
    /// every reader of the folder has acknowledged, from the hot
    /// storages. Anything left undone is retried after the next sync.
    pub fn manifest_upkeep(&mut self) -> Result<()> {
        if !self.manifest_policy.prune || !self.pending.is_empty() {
            return Ok(());
        }
        crate::logged_op_plain!("manifest upkeep", "", {
            self.prune_records3().map(|_| ())
        })
    }

}
