// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Keeping folder manifests cheap as they accumulate
//! (`docs/spec/alpha-0-format.md` section 23).
//!
//! **Listing.** A pull used to list `manifests/<folder>/` in full on every
//! storage, so its cost grew with every manifest any device ever published.
//! Every manifest is announced in the ledger (`manifest_published`), which a
//! pull reads first, so the pull now lists only the devices whose newest
//! announced manifest of the folder is newer than the one this device has
//! applied, and for each of them only the keys after that one (`list_after`).
//! With nothing new, nothing is listed. A full listing still runs once per
//! `ManifestPolicy::sweep_secs` per folder (and on the first pull of a folder
//! here), which also finds manifests whose announcement this device cannot
//! read yet; members of shared folders, which do not read the vault ledger,
//! always list in full (pruning keeps that listing short).
//!
//! **Pruning.** A reader only ever applies the newest manifest of a device
//! (or, for a revoked device, the newest one its accepted batches announced),
//! so older manifests are dead weight. After a sync a full device deletes
//! its own manifests of a folder below `m`, where `m` is the newest manifest
//! it announced in a batch that every reader (the trusted full devices, the
//! same set that acknowledges ledger checkpoints) has acknowledged holding.
//! Every reader therefore knows of `m` or newer before anything older goes,
//! and a revocation cut-off taken by any reader still finds its manifest.
//! Cold storages are never pruned.

use super::*;

/// When a pull lists a folder's manifests in full, and whether superseded
/// own manifests are deleted from the storages.
#[derive(Clone, Copy, Debug)]
pub struct ManifestPolicy {
    /// Seconds between full listings of one folder's manifests.
    pub sweep_secs: i64,
    /// Delete own manifests that every reader has seen past.
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
    /// Last full listing of the folder's manifests (UTC seconds).
    #[serde(default)]
    swept_utc: i64,
    /// Own manifest seq -> own batch seq by which it was announced.
    #[serde(default)]
    announced: BTreeMap<u64, u64>,
    /// Per storage: own manifests below this seq are gone there.
    #[serde(default)]
    pruned_below: BTreeMap<String, u64>,
}

/// (device, seq) of a key under `manifests/<folder>/`.
fn parse_key(folder_prefix: &str, key: &str) -> Option<(DeviceId, u64)> {
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

    /// The newest manifest of every other device that may be newer than the
    /// one applied here (`last_seen`), with the index of a storage that has
    /// it. Lists only what the ledger announced since, unless a full listing
    /// is due (see the module documentation).
    pub(super) fn newest_manifests(
        &self,
        folder: &FolderId,
        last_seen: &BTreeMap<DeviceId, u64>,
        storages: &OpenStorages,
    ) -> Result<BTreeMap<DeviceId, (u64, usize)>> {
        let me = &self.vault.device_id;
        let now = util::now_utc();
        let mut up = self.load_manifest_upkeep();
        let swept = up.folders.get(folder).map(|f| f.swept_utc).unwrap_or(0);
        let full = self.vault.member
            || swept == 0
            || now < swept
            || now - swept >= self.manifest_policy.sweep_secs;
        // Devices whose announced manifests are newer than what was applied.
        let mut wanted: BTreeMap<DeviceId, u64> = BTreeMap::new();
        if !full {
            for ((f, dev), seq) in &self.view()?.manifests {
                let seen = last_seen.get(dev).copied().unwrap_or(0);
                if f == folder && dev != me && *seq > seen {
                    wanted.insert(dev.clone(), seen);
                }
            }
        }
        let folder_prefix = format!("manifests/{folder}/");
        let mut newest: BTreeMap<DeviceId, (u64, usize)> = BTreeMap::new();
        for (idx, (_, backend)) in storages
            .iter()
            .enumerate()
            .filter(|(_, (s, _))| !s.is_data_only())
        {
            let mut keys = Vec::new();
            if full {
                keys = backend.list(&folder_prefix)?;
            } else {
                for (dev, seen) in &wanted {
                    let start = if *seen == 0 {
                        String::new()
                    } else {
                        Manifest::storage_key(folder, dev, *seen)
                    };
                    keys.extend(
                        backend.list_after(&Manifest::storage_prefix(folder, dev), &start)?,
                    );
                }
            }
            for key in keys {
                let Some((dev, seq)) = parse_key(&folder_prefix, &key) else {
                    continue;
                };
                if &dev == me {
                    continue;
                }
                let e = newest.entry(dev).or_insert((0, idx));
                if seq > e.0 {
                    *e = (seq, idx);
                }
            }
        }
        if full {
            up.folders.entry(folder.clone()).or_default().swept_utc = now;
            self.save_manifest_upkeep(&up)?;
        }
        Ok(newest)
    }

    /// After a sync: note which batch announced each folder's newest own
    /// manifest, and delete own manifests every reader has seen past from
    /// the hot storages. Anything left undone is retried after the next sync.
    pub fn manifest_upkeep(&mut self) -> Result<()> {
        if self.vault.member
            || self.forked_self
            || self.removal.is_some()
            || !self.manifest_policy.prune
            || !self.pending.is_empty()
        {
            return Ok(());
        }
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me).seq;
        let view = self.view()?;
        // The newest own batch every reader has said it holds.
        let acked = self
            .ledger_readers()
            .iter()
            .map(|r| {
                view.acks
                    .get(r)
                    .and_then(|a| a.get(&me))
                    .copied()
                    .unwrap_or(0)
            })
            .min()
            .unwrap_or(head);
        let mut up = self.load_manifest_upkeep();
        let mut changed = false;
        let mut storages: Option<OpenStorages> = None;
        for rec in self.keyring.folders.values().cloned().collect::<Vec<_>>() {
            let state_file = self.state_path(&rec.folder_id);
            if !state_file.exists() {
                continue;
            }
            let published = self.load_state(&rec.folder_id)?.published_seq;
            if published == 0 {
                continue;
            }
            let fu = up.folders.entry(rec.folder_id.clone()).or_default();
            // Sealed by now (nothing is pending), so batch `head` or an
            // earlier one announced it.
            if let std::collections::btree_map::Entry::Vacant(e) = fu.announced.entry(published) {
                e.insert(head);
                changed = true;
            }
            let Some(keep_from) = fu
                .announced
                .iter()
                .filter(|(_, b)| **b <= acked)
                .map(|(m, _)| *m)
                .max()
            else {
                continue;
            };
            if storages.is_none() {
                storages = Some(self.metadata_storages(false)?);
            }
            let prefix = Manifest::storage_prefix(&rec.folder_id, &me);
            for (spec, backend) in storages.as_ref().expect("opened above") {
                let below = fu.pruned_below.get(spec.name()).copied().unwrap_or(1);
                if below >= keep_from
                    || !backend.exists(&Manifest::storage_key(&rec.folder_id, &me, keep_from))?
                {
                    continue;
                }
                let start = if below <= 1 {
                    String::new()
                } else {
                    Manifest::storage_key(&rec.folder_id, &me, below - 1)
                };
                for key in backend.list_after(&prefix, &start)? {
                    let seq = key
                        .strip_prefix(&prefix)
                        .and_then(|f| f.strip_suffix(".enc"))
                        .and_then(|s| s.parse::<u64>().ok());
                    if seq.is_some_and(|s| s < keep_from) {
                        backend.delete(&key)?;
                    }
                }
                fu.pruned_below.insert(spec.name().to_string(), keep_from);
                changed = true;
            }
            let before = fu.announced.len();
            fu.announced.retain(|m, _| *m >= keep_from);
            changed |= fu.announced.len() != before;
        }
        if changed {
            self.save_manifest_upkeep(&up)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse() {
        let f = FolderId::random();
        let d = DeviceId::random();
        let prefix = format!("manifests/{f}/");
        assert_eq!(
            parse_key(&prefix, &Manifest::storage_key(&f, &d, 42)),
            Some((d.clone(), 42))
        );
        assert_eq!(parse_key(&prefix, &format!("{prefix}{d}/x.enc")), None);
        assert_eq!(
            parse_key("manifests/other/", &Manifest::storage_key(&f, &d, 1)),
            None
        );
    }
}
