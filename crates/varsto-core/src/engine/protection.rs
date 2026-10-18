// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! How well a folder is protected, from the ledger view alone: the share of
//! the bytes of its current files that has a copy in external storage (S3 and
//! rclone targets), on the user's own disks (directories and disk pools), or
//! only on devices (this device's files, other devices, untrusted replicas).
//! Shown as a colour-coded indicator in the interface; spec section 63.

use super::*;

/// Where a copy is kept, as the safety indicator groups it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Cloud,
    Disk,
    Device,
}

/// What share of a folder one class of places holds.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ClassCoverage {
    /// Bytes of the folder's current files that have a copy in the class
    /// (counted once per block, whatever the number of copies).
    pub bytes: u64,
    /// `bytes` as a percentage of the folder (rounded down, so 100 means all).
    pub pct: f64,
    pub blocks: u64,
    /// Bytes of those that a device other than the writer has verified.
    pub verified_bytes: u64,
    pub verified_pct: f64,
}

/// See `FolderStatus::protection`.
#[derive(Clone, Debug, Serialize)]
pub struct Protection {
    /// "empty", "cloud" (all in external storage), "disks" (all on own disks,
    /// not all in the cloud), "mixed" (all external, but split between cloud
    /// and disks), "partial" (some bytes have no external copy), "device"
    /// (no external copy at all).
    pub state: String,
    /// The percentage the state is about: bytes with an external copy.
    pub pct: f64,
    pub total_bytes: u64,
    pub total_blocks: u64,
    /// External storage: S3 and rclone targets.
    pub cloud: ClassCoverage,
    /// Own disks: directories and disk pools (a disk that is away counts).
    pub disks: ClassCoverage,
    /// Devices: this device's files, other devices' files and replicas.
    pub devices: ClassCoverage,
    /// Bytes with a copy in the cloud or on own disks.
    pub external_bytes: u64,
    /// Bytes and blocks with no copy in external storage or on own disks.
    pub unprotected_bytes: u64,
    pub unprotected_blocks: u64,
    /// Of those, bytes that exist nowhere this ledger knows of.
    pub missing_bytes: u64,
    /// The folder's durability policy state ("ok", "at_risk", "violated",
    /// "unknown"), when it has a policy.
    pub policy_state: Option<String>,
}

impl Protection {
    pub(crate) fn empty() -> Protection {
        Protection {
            state: "empty".to_string(),
            pct: 0.0,
            total_bytes: 0,
            total_blocks: 0,
            cloud: ClassCoverage::default(),
            disks: ClassCoverage::default(),
            devices: ClassCoverage::default(),
            external_bytes: 0,
            unprotected_bytes: 0,
            unprotected_blocks: 0,
            missing_bytes: 0,
            policy_state: None,
        }
    }
}

fn pct(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else if part >= total {
        100.0
    } else {
        // Never rounds up to 100: only "all" is 100.
        ((part as u128 * 1000 / total as u128) as f64 / 10.0).min(99.9)
    }
}

fn coverage(bytes: u64, blocks: u64, verified: u64, total: u64) -> ClassCoverage {
    ClassCoverage {
        bytes,
        pct: pct(bytes, total),
        blocks,
        verified_bytes: verified,
        verified_pct: pct(verified, total),
    }
}

impl Engine {
    fn storage_classes(&self) -> BTreeMap<String, Class> {
        self.config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| {
                let class = match s {
                    StorageSpec::S3 { .. } | StorageSpec::Rclone { .. } => Class::Cloud,
                    StorageSpec::LocalDir { .. } | StorageSpec::Pool { .. } => Class::Disk,
                };
                (s.name().to_string(), class)
            })
            .collect()
    }

    /// The protection of every folder, by folder id, with each folder's
    /// durability policy state. One pass over the ledger view.
    pub fn protection(&self) -> Result<BTreeMap<String, Protection>> {
        let view = self.view()?;
        let reports = self
            .policy_reports(&view, util::now_utc(), |id| {
                self.load_state(id).map(std::borrow::Cow::Owned)
            })
            .ok();
        self.protection_with(&view, reports.as_deref(), |id| {
            self.load_state(id).map(std::borrow::Cow::Owned)
        })
    }

    /// [`Engine::protection`] from a view, policy reports and folder states
    /// the caller already has (`status` reads each of them once).
    pub(super) fn protection_with<'s, F>(
        &self,
        _view: &LedgerView,
        reports: Option<&[PolicyReport]>,
        state_of: F,
    ) -> Result<BTreeMap<String, Protection>>
    where
        F: Fn(&FolderId) -> Result<std::borrow::Cow<'s, FolderState>>,
    {
        // Format 3: copies of a block are the storages holding a live
        // place of it (`storages3::block_copy_details`); "another device
        // holds it" is the `held` flag of that device's manifest.
        let view = self.view3()?;
        let policy_states: BTreeMap<String, String> = reports
            .unwrap_or_default()
            .iter()
            .map(|r| {
                let s = serde_json::to_value(r.state)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                (r.folder.clone(), s)
            })
            .collect();
        let classes = self.storage_classes();
        let carriers: HashSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name())
            .collect();
        let mut out = BTreeMap::new();
        for (rec, mount) in self.folders() {
            let state = state_of(&rec.folder_id)?;
            let Ok(folder) = members3::bin(&rec.folder_id) else {
                continue;
            };
            let has_keys = !rec.key_hex.is_empty() || !rec.epoch_keys.is_empty();
            let table = if has_keys {
                Some(self.table3(&folder)?)
            } else {
                None
            };
            let held = self.load_manifests3(&folder).held_index();
            let mut chunks: BTreeMap<&ObjectName, u64> = BTreeMap::new();
            for f in state.files.values().filter(|f| !f.deleted) {
                for c in &f.chunks {
                    chunks.entry(&c.object).or_insert(c.size);
                }
            }
            let here: HashSet<&ObjectName> = match &mount {
                Some(_) => state
                    .files
                    .values()
                    .filter(|f| !f.deleted && state.local_index.contains_key(&f.path))
                    .flat_map(|f| f.chunks.iter().map(|c| &c.object))
                    .collect(),
                None => HashSet::new(),
            };
            let me = self.me3();
            let mut p = Protection::empty();
            p.policy_state = policy_states.get(&rec.name).cloned();
            // (bytes, blocks, verified bytes) per class
            let mut acc = [(0u64, 0u64, 0u64); 3];
            for (object, manifest_size) in chunks {
                // Plaintext bytes, as the folder's own size counts them.
                let size = manifest_size;
                p.total_bytes += size;
                p.total_blocks += 1;
                // (has a copy, has a verified copy) per class
                let mut has = [(false, false); 3];
                let obj = crate::storages3::object_bin(object)?;
                if let Some(t) = &table {
                    let t = t.read().unwrap_or_else(|e| e.into_inner());
                    for c in crate::storages3::block_copy_details(&view, &*t, &obj) {
                        if carriers.contains(c.storage.as_str()) {
                            continue;
                        }
                        let class = if c.storage.starts_with("replica:") {
                            Class::Device
                        } else {
                            // A storage only other devices know of: not
                            // counted as external, the safe reading.
                            classes.get(&c.storage).copied().unwrap_or(Class::Device)
                        };
                        let e = &mut has[class as usize];
                        e.0 = true;
                        e.1 |= c.independently_verified;
                    }
                }
                if held.held_elsewhere(&obj, &me) {
                    has[Class::Device as usize].0 = true;
                }
                if here.contains(object) {
                    has[Class::Device as usize].0 = true;
                }
                for (i, (any, checked)) in has.iter().enumerate() {
                    if *any {
                        acc[i].0 += size;
                        acc[i].1 += 1;
                        if *checked {
                            acc[i].2 += size;
                        }
                    }
                }
                if has[Class::Cloud as usize].0 || has[Class::Disk as usize].0 {
                    p.external_bytes += size;
                } else {
                    p.unprotected_bytes += size;
                    p.unprotected_blocks += 1;
                    if !has[Class::Device as usize].0 {
                        p.missing_bytes += size;
                    }
                }
            }
            let t = p.total_bytes;
            p.cloud = coverage(acc[0].0, acc[0].1, acc[0].2, t);
            p.disks = coverage(acc[1].0, acc[1].1, acc[1].2, t);
            p.devices = coverage(acc[2].0, acc[2].1, acc[2].2, t);
            p.pct = pct(p.external_bytes, t);
            p.state = if t == 0 {
                "empty"
            } else if p.cloud.bytes == t {
                "cloud"
            } else if p.disks.bytes == t {
                "disks"
            } else if p.external_bytes == t {
                "mixed"
            } else if p.external_bytes > 0 {
                "partial"
            } else {
                "device"
            }
            .to_string();
            out.insert(rec.folder_id.to_string(), p);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::pct;

    #[test]
    fn only_everything_is_a_hundred_percent() {
        assert_eq!(pct(0, 0), 0.0);
        assert_eq!(pct(0, 10), 0.0);
        assert_eq!(pct(10, 10), 100.0);
        assert_eq!(pct(9_999_999, 10_000_000), 99.9);
        assert_eq!(pct(1, 3), 33.3);
    }
}
