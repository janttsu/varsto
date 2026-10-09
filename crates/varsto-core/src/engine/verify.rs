// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic verification by another device (see `crate::autoverify`): pick
//! copies that other devices wrote, download them within the budget, check
//! the content hash and record `ChunkVerified` in the ledger, the same event
//! `fsck --verify` records.
//!
//! The ledger names a storage by the writer's local name, and two devices may
//! name the same bucket or directory differently ("box" here, "primary"
//! there). Every storage therefore carries a random identity object
//! (`vault/storage-id.json`), and every device publishes, sealed under the
//! registry key, which of its storage names has which identity
//! (`vault/storage-names/<device>/<time>.enc`). A copy the writer calls "box"
//! is read from whichever local storage has the same identity, and the check
//! is recorded under the writer's name so that it meets the writer's claim.

use super::{chunk_storage_key, Engine};
use crate::autoverify::{
    self, Candidate, VerifyRunReport, VerifySchedule, VerifyState, VerifyStatus,
};
use crate::crypto;
use crate::ids::DeviceId;
use crate::ids::{ChunkId, FolderId, ObjectName};
use crate::ledger::Event;
use crate::pool::{self, PoolError};
use crate::storage::Storage;
use crate::util;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const STORAGE_ID_KEY: &str = "vault/storage-id.json";
const NAMES_PREFIX: &str = "vault/storage-names/";

#[derive(Serialize, Deserialize)]
struct StorageIdentity {
    storage_id: String,
}

/// One device's storage names and the identity of each storage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct StorageNames {
    device: DeviceId,
    updated_utc: i64,
    /// Local storage name -> storage identity.
    names: BTreeMap<String, String>,
}

fn names_aad(vault: &crate::ids::VaultId, device: &DeviceId) -> Vec<u8> {
    crypto::aad(
        "storage-names",
        &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
    )
}

/// The identity of a storage, created by the first device that asks.
fn storage_identity(backend: &dyn Storage) -> Result<String> {
    if let Some(raw) = backend.get(STORAGE_ID_KEY)? {
        return Ok(serde_json::from_slice::<StorageIdentity>(&raw)?.storage_id);
    }
    let fresh = StorageIdentity {
        storage_id: hex::encode(&crypto::hash(crypto::SecretKey::random().as_bytes())[..16]),
    };
    backend.put_if_absent(STORAGE_ID_KEY, &serde_json::to_vec(&fresh)?)?;
    // Another device may have won the race: its identity is the one.
    match backend.get(STORAGE_ID_KEY)? {
        Some(raw) => Ok(serde_json::from_slice::<StorageIdentity>(&raw)?.storage_id),
        None => Ok(fresh.storage_id),
    }
}

impl Engine {
    fn verify_state_path(&self) -> PathBuf {
        self.home.join("state").join("auto-verify.json")
    }

    fn load_verify_state(&self) -> VerifyState {
        util::read_json_or_default(&self.verify_state_path()).unwrap_or_default()
    }

    pub fn verify_schedule(&self) -> &VerifySchedule {
        &self.config.verify
    }

    /// Change the schedule and budget of automatic verification (this device only).
    pub fn set_verify_schedule(&mut self, schedule: VerifySchedule) -> Result<()> {
        if schedule.interval_hours == 0 {
            bail!("the interval must be at least one hour");
        }
        if schedule.max_blocks == 0 || schedule.max_bytes == 0 {
            bail!(
                "the budget must allow at least one block; turn automatic verification off instead"
            );
        }
        self.config.verify = schedule;
        self.config.save(&self.home)
    }

    pub fn verify_status(&self) -> VerifyStatus {
        let st = self.load_verify_state();
        VerifyStatus {
            schedule: self.config.verify.clone(),
            last_run_utc: st.last_run_utc,
            next_run_utc: self.config.verify.next_run_utc(st.last_run_utc),
            last: st.last,
            last_error: st.last_error,
            total_verified: st.total_verified,
        }
    }

    /// Whether the schedule says a run is due now.
    pub fn auto_verify_due(&self, now_utc: i64) -> bool {
        self.config
            .verify
            .is_due(self.load_verify_state().last_run_utc, now_utc)
    }

    /// One run of automatic verification now, whatever the schedule says.
    pub fn auto_verify(&mut self) -> Result<VerifyRunReport> {
        self.auto_verify_at(util::now_utc())
    }

    /// One run, deciding what is due as of `now_utc` (tests look ahead in time).
    pub fn auto_verify_at(&mut self, now_utc: i64) -> Result<VerifyRunReport> {
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let result = self.run_auto_verify(now_utc);
        let mut st = self.load_verify_state();
        st.last_run_utc = Some(now_utc);
        match &result {
            Ok(r) => {
                st.total_verified += r.blocks_verified;
                st.last = Some(r.clone());
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        util::write_json(&self.verify_state_path(), &st)?;
        result
    }

    /// Publish this device's storage names with their identities (when they
    /// changed) and read every other device's newest list.
    fn exchange_storage_names(
        &self,
        mine: &BTreeMap<String, String>,
        backends: &BTreeMap<String, Box<dyn Storage>>,
    ) -> BTreeMap<DeviceId, BTreeMap<String, String>> {
        let key = self.registry_key_now();
        let reg_keys: Vec<crate::crypto::SecretKey> =
            self.registry_keys().into_iter().map(|(_, k)| k).collect();
        let vault = &self.vault.vault_id;
        let me = &self.vault.device_id;
        let mut out: BTreeMap<DeviceId, (i64, BTreeMap<String, String>)> = BTreeMap::new();
        let metadata: Vec<&String> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_data_only())
            .map(|s| s.name())
            .filter_map(|n| backends.get_key_value(n).map(|(k, _)| k))
            .collect();
        for name in metadata {
            let backend = &backends[name];
            let Ok(keys) = backend.list(NAMES_PREFIX) else {
                continue;
            };
            // Newest object per device (keys sort by time within a device).
            let mut newest: BTreeMap<&str, &String> = BTreeMap::new();
            for k in &keys {
                if let Some((dev, _)) = k[NAMES_PREFIX.len()..].split_once('/') {
                    newest.insert(dev, k);
                }
            }
            let mut mine_published = false;
            for (dev, k) in newest {
                let Ok(dev) = DeviceId::from_hex(dev) else {
                    continue;
                };
                let rec = backend
                    .get(k)
                    .ok()
                    .flatten()
                    .and_then(|blob| {
                        reg_keys
                            .iter()
                            .find_map(|k| crypto::decrypt(k, &names_aad(vault, &dev), &blob).ok())
                    })
                    .and_then(|plain| serde_json::from_slice::<StorageNames>(&plain).ok())
                    .filter(|r| r.device == dev);
                let Some(rec) = rec else { continue };
                if &dev == me {
                    mine_published = rec.names == *mine;
                    continue;
                }
                if out.get(&dev).is_none_or(|(t, _)| *t < rec.updated_utc) {
                    out.insert(dev, (rec.updated_utc, rec.names));
                }
            }
            if !mine_published && !self.vault.member && !mine.is_empty() {
                let rec = StorageNames {
                    device: me.clone(),
                    updated_utc: util::now_utc(),
                    names: mine.clone(),
                };
                let sealed = serde_json::to_vec(&rec)
                    .ok()
                    .and_then(|plain| crypto::encrypt(&key, &names_aad(vault, me), &plain).ok());
                if let Some(blob) = sealed {
                    let k = format!("{NAMES_PREFIX}{me}/{:020}.enc", rec.updated_utc);
                    let _ = backend.put_if_absent(&k, &blob);
                }
            }
        }
        out.into_iter().map(|(d, (_, n))| (d, n)).collect()
    }

    fn run_auto_verify(&mut self, now_utc: i64) -> Result<VerifyRunReport> {
        let _ = self.pull_ledger()?;
        let view = self.view()?;
        let me = self.vault.device_id.clone();
        let schedule = self.config.verify.clone();
        let mut report = VerifyRunReport {
            started_utc: util::now_utc(),
            ..Default::default()
        };
        // Storages this device reads without asking: never a cold storage
        // (F-043) and never a transferrer (pruned on purpose).
        let mut readable: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for spec in self.config.storages.clone() {
            if spec.is_cold() || spec.is_carrier() {
                report.storages_skipped.push(spec.name().to_string());
                continue;
            }
            match self.open_spec(&spec) {
                Ok(b) => {
                    readable.insert(spec.name().to_string(), b);
                }
                Err(e) => report
                    .storages_skipped
                    .push(format!("{} (cannot open: {e:#})", spec.name())),
            }
        }
        // Storage identities: ours, and the other devices' names for them.
        let mut mine: BTreeMap<String, String> = BTreeMap::new();
        let mut local_by_id: BTreeMap<String, String> = BTreeMap::new();
        for spec in &self.config.storages {
            if spec.is_data_only() {
                continue; // a pool's identity is derived from its name
            }
            if let Some(b) = readable.get(spec.name()) {
                if let Ok(id) = storage_identity(b.as_ref()) {
                    mine.insert(spec.name().to_string(), id.clone());
                    local_by_id.insert(id, spec.name().to_string());
                }
            }
        }
        let theirs = self.exchange_storage_names(&mine, &readable);
        // The local storage that holds a copy the claimers call `name`: by
        // identity when a claimer published its names, else by equal name.
        let resolve =
            |name: &str, claimers: &std::collections::BTreeSet<DeviceId>| -> Option<String> {
                let mut known = false;
                for d in claimers {
                    if let Some(id) = theirs.get(d).and_then(|n| n.get(name)) {
                        known = true;
                        if let Some(local) = local_by_id.get(id) {
                            return Some(local.clone());
                        }
                    }
                }
                (!known && readable.contains_key(name)).then(|| name.to_string())
            };
        // Verification window of every folder this device holds a key record for.
        let windows: BTreeMap<FolderId, Option<u32>> = self
            .keyring
            .folders
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.policy.as_ref().and_then(|p| p.verified_within_days),
                )
            })
            .collect();
        // (folder, chunk, object, storage name in the ledger, local storage to read).
        let mut items: Vec<(FolderId, ChunkId, ObjectName, String, String)> = Vec::new();
        let mut candidates = Vec::new();
        for ((folder, chunk), rec) in &view.chunks {
            let Some(window) = windows.get(folder) else {
                continue;
            };
            for (storage, loc) in &rec.storages {
                // Only copies another device wrote: our own check of our own
                // write does not count for a policy.
                if loc.claimed_by.is_empty() || loc.claimed_by.contains(&me) {
                    continue;
                }
                let Some(local) = resolve(storage, &loc.claimed_by) else {
                    continue;
                };
                let last = if loc.independently_verified(storage) {
                    loc.verified_utc
                } else {
                    0
                };
                candidates.push(Candidate {
                    due_utc: autoverify::due_utc(last, *window, schedule.reverify_days),
                    has_window: window.is_some(),
                    size: rec.size,
                    index: items.len(),
                });
                items.push((
                    folder.clone(),
                    chunk.clone(),
                    rec.object.clone(),
                    storage.clone(),
                    local,
                ));
            }
        }
        let (order, due, left) =
            autoverify::plan(candidates, now_utc, schedule.max_blocks, schedule.max_bytes);
        report.due = due;
        report.left_for_next_run = left;
        for i in order {
            let (folder, chunk, object, storage, local) = &items[i];
            let key = chunk_storage_key(object);
            let ct = match readable[local].get(&key) {
                Ok(ct) => ct,
                Err(e) if matches!(pool::pool_error(&e), Some(PoolError::NeedsDisk { .. })) => {
                    report.offline += 1;
                    continue;
                }
                Err(e) => {
                    // Keep what was checked so far.
                    self.commit_batch()?;
                    return Err(e);
                }
            };
            report.blocks_checked += 1;
            let Some(ct) = ct else {
                report.missing.push(format!("{storage}:{}", object.short()));
                continue;
            };
            report.bytes_downloaded += ct.len() as u64;
            if ObjectName::from_bytes(&crypto::hash(&ct)) == *object {
                report.blocks_verified += 1;
                self.pending.push(Event::ChunkVerified {
                    folder: folder.clone(),
                    chunk: chunk.clone(),
                    object: object.clone(),
                    storage: storage.clone(),
                });
            } else {
                report.corrupt.push(format!("{storage}:{}", object.short()));
            }
        }
        self.commit_batch()?;
        report.finished_utc = util::now_utc();
        Ok(report)
    }
}
