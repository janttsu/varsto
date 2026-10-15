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

use super::{Damage, DamageKind, Engine};
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
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub(super) const STORAGE_ID_KEY: &str = "vault/storage-id.json";
const NAMES_PREFIX: &str = "vault/storage-names/";

#[derive(Serialize, Deserialize)]
pub(super) struct StorageIdentity {
    pub(super) storage_id: String,
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
pub(super) fn storage_identity(backend: &dyn Storage) -> Result<String> {
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

/// Which local storage holds a copy that the ledger names after its
/// writers' storage names (see the module documentation).
pub(super) struct NameResolver {
    /// Other devices' storage names -> storage identity.
    theirs: BTreeMap<DeviceId, BTreeMap<String, String>>,
    /// Storage identity -> local name.
    local_by_id: BTreeMap<String, String>,
    /// Local storages that were opened.
    readable: BTreeSet<String>,
}

impl NameResolver {
    /// The local storage that holds a copy the claimers call `name`: by
    /// identity when a claimer published its names, else by equal name.
    pub(super) fn resolve(&self, name: &str, claimers: &BTreeSet<DeviceId>) -> Option<String> {
        let mut known = false;
        for d in claimers {
            if let Some(id) = self.theirs.get(d).and_then(|n| n.get(name)) {
                known = true;
                if let Some(local) = self.local_by_id.get(id) {
                    return Some(local.clone());
                }
            }
        }
        (!known && self.readable.contains(name)).then(|| name.to_string())
    }

    /// Other devices' names for storages, with the identity of each.
    pub(super) fn others(&self) -> &BTreeMap<DeviceId, BTreeMap<String, String>> {
        &self.theirs
    }

    /// Local storage name -> identity.
    pub(super) fn local_ids(&self) -> BTreeMap<String, String> {
        self.local_by_id
            .iter()
            .map(|(id, n)| (n.clone(), id.clone()))
            .collect()
    }

    /// Other devices' storage names that match a storage here by
    /// identity: device -> (their name -> local name).
    pub(super) fn aliases(&self) -> BTreeMap<DeviceId, BTreeMap<String, String>> {
        self.theirs
            .iter()
            .map(|(d, names)| {
                (
                    d.clone(),
                    names
                        .iter()
                        .filter_map(|(n, id)| {
                            self.local_by_id.get(id).map(|l| (n.clone(), l.clone()))
                        })
                        .collect::<BTreeMap<_, _>>(),
                )
            })
            .filter(|(_, m)| !m.is_empty())
            .collect()
    }

    /// Like `resolve`, with every configured storage (`configured`) as a
    /// candidate for an equal name, readable now or not; replicas are
    /// their own storages.
    pub(super) fn resolve_any(
        &self,
        name: &str,
        claimers: &BTreeSet<DeviceId>,
        configured: &BTreeSet<String>,
    ) -> Option<String> {
        if name.starts_with("replica:") {
            return Some(name.to_string());
        }
        let mut known = false;
        for d in claimers {
            if let Some(id) = self.theirs.get(d).and_then(|n| n.get(name)) {
                known = true;
                if let Some(local) = self.local_by_id.get(id) {
                    return Some(local.clone());
                }
            }
        }
        (!known && configured.contains(name)).then(|| name.to_string())
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
        crate::logged_op!("auto verify at", "", { self.auto_verify_at_inner(now_utc) })
    }

    fn auto_verify_at_inner(&mut self, now_utc: i64) -> Result<VerifyRunReport> {
        self.ensure_ledger_writable()?;
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
            let mut mine_newest = 0i64;
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
                    mine_newest = rec.updated_utc;
                    continue;
                }
                if out.get(&dev).is_none_or(|(t, _)| *t < rec.updated_utc) {
                    out.insert(dev, (rec.updated_utc, rec.names));
                }
            }
            if !mine_published && !self.vault.member && !mine.is_empty() {
                // Newer than the list it replaces, even within the same second.
                let rec = StorageNames {
                    device: me.clone(),
                    updated_utc: util::now_utc().max(mine_newest + 1),
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

    /// Storage identities: ours (published when they changed), and the
    /// other devices' names for them, read from the storages in `readable`.
    pub(super) fn storage_resolver(
        &self,
        readable: &BTreeMap<String, Box<dyn Storage>>,
    ) -> NameResolver {
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
        NameResolver {
            theirs: self.exchange_storage_names(&mine, readable),
            local_by_id,
            readable: readable.keys().cloned().collect(),
        }
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
        let mut lanes: BTreeMap<String, crate::parverify::LanePlan> = BTreeMap::new();
        for spec in self.config.storages.clone() {
            if spec.is_cold() || spec.is_carrier() {
                report.storages_skipped.push(spec.name().to_string());
                continue;
            }
            match self.open_spec(&spec) {
                Ok(b) => {
                    lanes.insert(spec.name().to_string(), self.storage_lane(&spec));
                    readable.insert(spec.name().to_string(), b);
                }
                Err(e) => report
                    .storages_skipped
                    .push(format!("{} (cannot open: {e:#})", spec.name())),
            }
        }
        let names = self.storage_resolver(&readable);
        // Verification window of every folder this device holds a key record for.
        let windows: BTreeMap<FolderId, Option<u32>> = self
            .keyring
            .folders
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.effective_policy().and_then(|p| p.verified_within_days),
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
                let Some(local) = names.resolve(storage, &loc.claimed_by) else {
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
        let mut damage: Vec<Damage> = Vec::new();
        let damaged = |i: usize, kind: DamageKind| {
            let (folder, chunk, object, _, local) = &items[i];
            Damage {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                storage: local.clone(),
                kind,
                found_by: "verify".to_string(),
                found_utc: now_utc,
                retry_utc: 0,
                reason: None,
            }
        };
        let task = crate::activity::start(
            crate::activity::VERIFY,
            "",
            order.len() as u64,
            crate::activity::Unit::Items,
        );
        // One lane per local storage, read ahead in parallel where its
        // medium allows; the results come back here in the planned order.
        // The blocks due in one pack are read together, with one request
        // (`packs::read_members`).
        let lane_names: Vec<String> = lanes.keys().cloned().collect();
        let plans: Vec<crate::parverify::LanePlan> = lanes.values().copied().collect();
        let groups = crate::packs::group_by_pack(order.into_iter().map(|i| {
            let local = items[i].4.clone();
            let loc = readable[&local].pack_location(items[i].2.as_str());
            (i, local, items[i].2.as_str().to_string(), loc)
        }));
        let jobs: Vec<crate::parverify::Job<usize>> = groups
            .iter()
            .enumerate()
            .map(|(g, (local, members))| crate::parverify::Job {
                item: g,
                lane: lane_names.iter().position(|n| n == local).unwrap_or(0),
                size: members
                    .iter()
                    .map(|(i, _, _)| {
                        view.locate(&items[*i].0, &items[*i].1)
                            .map_or(0, |r| r.size)
                    })
                    .sum(),
            })
            .collect();
        let mut failed: Option<anyhow::Error> = None;
        let (groups_ref, readable_ref) = (&groups, &readable);
        crate::parverify::run_ordered(
            &jobs,
            &plans,
            |&g| {
                let (local, members) = &groups_ref[g];
                let wanted: Vec<(String, Option<crate::packs::PackLoc>)> = members
                    .iter()
                    .map(|(_, o, l)| (o.clone(), l.clone()))
                    .collect();
                crate::storage::guarded(local, || {
                    crate::packs::read_members(readable_ref[local].as_ref(), &wanted)
                })
            },
            |_, got| {
                got.map(|all| {
                    all.into_iter()
                        .map(|ct| ct.map(|ct| (ct.len() as u64, crypto::hash(&ct))))
                        .collect::<Vec<_>>()
                })
            },
            |_, &g, got| {
                let members = &groups[g].1;
                let got = match got {
                    Ok(got) => got,
                    Err(e) if matches!(pool::pool_error(&e), Some(PoolError::NeedsDisk { .. })) => {
                        report.offline += members.len() as u64;
                        task.advance(members.len() as u64);
                        return true;
                    }
                    Err(e) => {
                        failed = Some(e);
                        return false;
                    }
                };
                for ((i, _, _), got) in members.iter().zip(got) {
                    let i = *i;
                    task.advance(1);
                    let (folder, chunk, object, storage, _) = &items[i];
                    report.blocks_checked += 1;
                    let Some((len, hash)) = got else {
                        report.missing.push(format!("{storage}:{}", object.short()));
                        damage.push(damaged(i, DamageKind::Missing));
                        continue;
                    };
                    report.bytes_downloaded += len;
                    if ObjectName::from_bytes(&hash) == *object {
                        report.blocks_verified += 1;
                        self.pending.push(Event::ChunkVerified {
                            folder: folder.clone(),
                            chunk: chunk.clone(),
                            object: object.clone(),
                            storage: storage.clone(),
                        });
                    } else {
                        report.corrupt.push(format!("{storage}:{}", object.short()));
                        damage.push(damaged(i, DamageKind::Corrupt));
                    }
                }
                true
            },
        );
        if let Some(e) = failed {
            // Keep what was checked so far.
            self.commit_batch()?;
            return Err(e);
        }
        report.queued_for_repair = damage.len() as u64;
        self.queue_damage(damage)?;
        self.commit_batch()?;
        report.finished_utc = util::now_utc();
        Ok(report)
    }
}
