// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage quotas and the vault-wide settings of storages
//! (`crate::storage_settings`, `docs/spec/alpha-0-format.md` section 44).
//!
//! A quota is the most bytes (and optionally objects) Varsto keeps on one
//! storage. Usage is counted from the ledger: the blocks claimed on the
//! storage and not dropped, plus an estimate of the records, ledger batches
//! and manifests there (the size of this device's ledger, or what the last
//! `storage quota --measure` found). Writers keep 1 % of the quota free
//! and skip a storage that would go over it; the block then goes to the
//! folder's other storages, or waits on this device until there is room.

use super::*;
use crate::ids::Id;
use crate::storage_settings::{
    self, SettingsEntry, StorageSettings, StorageSettingsRecord, QUOTA_WARN_PERCENT,
};
use std::sync::Mutex;

/// Local cache of storage keys by storage name.
const KEYS_FILE: &str = "storage-keys.json";
/// What `storage quota --measure` found, by storage name.
const MEASURED_FILE: &str = "storage-measured.json";
/// Other devices' names for this device's storages (see `refresh_aliases`).
const ALIASES_FILE: &str = "storage-aliases.json";

/// A storage's use against its quota.
#[derive(Clone, Debug, Serialize, Default, PartialEq)]
pub struct QuotaStatus {
    pub storage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_objects: Option<u64>,
    /// Bytes in use: blocks from the ledger plus the records estimate.
    pub used_bytes: u64,
    pub used_objects: u64,
    /// Of `used_bytes`: the records, ledger batches and manifests.
    pub metadata_bytes: u64,
    /// When the records were last measured (`--measure`), if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_utc: Option<i64>,
    /// Share of the quota in use (the larger of bytes and objects).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u32>,
    /// "none" (no quota), "ok", "warning" (90 % or more) or "full".
    pub state: String,
    /// The sentence to show for "warning" and "full".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The storage is being drained or is drained (no new blocks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Measured {
    measured_utc: i64,
    metadata_bytes: u64,
    metadata_objects: u64,
    objects: u64,
}

/// Blocks per storage (bytes, objects) from the ledger, and the size of
/// this device's ledger (bytes, files).
pub(super) struct Usage {
    blocks: BTreeMap<String, (u64, u64)>,
    ledger: (u64, u64),
}

/// Bytes and objects left on a storage, `None` where unlimited.
type Room = (Option<i128>, Option<i128>);

/// Room left on the storages with a quota, taken as writes are planned.
#[derive(Default)]
pub(super) struct QuotaGate {
    /// Storage -> (bytes left, objects left), `None` where unlimited.
    left: Mutex<BTreeMap<String, Room>>,
    /// The sentence for a full storage, by name.
    messages: BTreeMap<String, String>,
    refused: Mutex<BTreeSet<String>>,
}

impl QuotaGate {
    /// Take room for one object of `bytes` on `storage`; false (and nothing
    /// taken) when it does not fit.
    pub(super) fn take(&self, storage: &str, bytes: u64) -> bool {
        let mut left = self.left.lock().unwrap_or_else(|e| e.into_inner());
        let Some((b, o)) = left.get_mut(storage) else {
            return true;
        };
        let fits = b.is_none_or(|b| b >= bytes as i128) && o.is_none_or(|o| o >= 1);
        if fits {
            if let Some(b) = b {
                *b -= bytes as i128;
            }
            if let Some(o) = o {
                *o -= 1;
            }
        } else {
            self.refused
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(storage.to_string());
        }
        fits
    }

    /// Whether `bytes` more would fit, without taking them.
    pub(super) fn fits(&self, storage: &str, bytes: u64) -> bool {
        let left = self.left.lock().unwrap_or_else(|e| e.into_inner());
        left.get(storage)
            .is_none_or(|(b, o)| b.is_none_or(|b| b >= bytes as i128) && o.is_none_or(|o| o >= 1))
    }

    /// Give back room taken for a write that did not happen.
    pub(super) fn give_back(&self, storage: &str, bytes: u64) {
        let mut left = self.left.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((b, o)) = left.get_mut(storage) {
            if let Some(b) = b {
                *b += bytes as i128;
            }
            if let Some(o) = o {
                *o += 1;
            }
        }
    }

    /// The sentences for the storages that refused a write.
    pub(super) fn refusals(&self) -> Vec<String> {
        self.refused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|n| self.message(n))
            .collect()
    }

    pub(super) fn message(&self, storage: &str) -> String {
        self.messages
            .get(storage)
            .cloned()
            .unwrap_or_else(|| format!("storage {storage} is at its quota"))
    }
}

fn full_message(storage: &str, used: u64, quota: u64) -> String {
    format!(
        "storage {storage} is at its quota ({} of {})",
        super::placement::fmt_size(used),
        super::placement::fmt_size(quota)
    )
}

impl Engine {
    // ----- storage keys --------------------------------------------------------

    /// The key every device uses for a storage in shared settings: its
    /// identity, a pool's identity, or a keyed hash of its name.
    fn storage_keys(&self) -> BTreeMap<String, Id> {
        let path = self.home.join("state").join(KEYS_FILE);
        let mut cached: BTreeMap<String, Id> =
            util::read_json_or_default(&path).unwrap_or_default();
        let before = cached.clone();
        cached.retain(|n, _| self.config.storages.iter().any(|s| s.name() == n));
        let mut out = BTreeMap::new();
        for spec in &self.config.storages {
            let name = spec.name().to_string();
            if let Some(k) = cached.get(&name) {
                out.insert(name, k.clone());
                continue;
            }
            let key = match spec {
                StorageSpec::Pool { .. } => {
                    Id::from_hex(&self.pool_identity(spec.name()).pool_id).ok()
                }
                _ => self
                    .open_spec(spec)
                    .ok()
                    .and_then(|b| super::verify::storage_identity(b.as_ref()).ok())
                    .and_then(|id| Id::from_hex(&id).ok()),
            };
            match key {
                Some(k) => {
                    cached.insert(name.clone(), k.clone());
                    out.insert(name, k);
                }
                // Unreadable now (a cold class, offline): by name, not cached.
                None => {
                    let k = self.root_key().derive("storage-settings", &[]);
                    let h = crypto::keyed_hash(&k, format!("name:{name}").as_bytes());
                    out.insert(name, Id::from_bytes(&h[..16]));
                }
            }
        }
        if cached != before {
            let _ = util::write_json(&path, &cached);
        }
        out
    }

    // ----- shared settings ------------------------------------------------------

    /// The vault-wide settings of a storage as this device knows them.
    pub fn storage_settings(&self, name: &str) -> StorageSettings {
        self.config
            .storage_settings
            .get(name)
            .map(|e| e.settings.clone())
            .unwrap_or_default()
    }

    /// Storages that take no new blocks: being drained, or drained.
    pub(super) fn closed_storages(&self) -> BTreeSet<String> {
        self.config
            .storage_settings
            .iter()
            .filter(|(_, e)| e.settings.closed())
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Storages emptied by a drain: not used for records any more either.
    pub(super) fn drained_storages(&self) -> BTreeSet<String> {
        self.config
            .storage_settings
            .iter()
            .filter(|(_, e)| e.settings.drained())
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Change a storage's settings here and publish them to every device.
    pub(super) fn publish_storage_settings(
        &mut self,
        name: &str,
        settings: StorageSettings,
    ) -> Result<()> {
        let Some(key) = self.storage_keys().get(name).cloned() else {
            bail!("unknown storage {name}");
        };
        let prev = self
            .config
            .storage_settings
            .get(name)
            .map(|e| e.updated_utc)
            .unwrap_or(0);
        let now = util::now_utc().max(prev + 1);
        let rec = StorageSettingsRecord {
            storage: key,
            name: name.to_string(),
            device: self.vault.device_id.clone(),
            updated_utc: now,
            settings: settings.clone(),
        };
        let (fr_id, fr_key) = self.folder_record_key_id_now();
        let blob = rec.seal_signed(&self.vault.vault_id, &fr_id, &fr_key, &self.keys.signer)?;
        // Every storage that holds records, drained ones too: they say so.
        let mut written = 0;
        let mut last_err = None;
        for spec in self.config.storages.clone() {
            if spec.is_data_only() || spec.is_carrier() {
                continue;
            }
            match self
                .open_spec(&spec)
                .and_then(|b| b.put_if_absent(&rec.storage_key(), &blob))
            {
                Ok(_) => written += 1,
                Err(e) => last_err = Some(e),
            }
        }
        if written == 0 {
            if let Some(e) = last_err {
                return Err(e.context("the storage settings could not be published"));
            }
        }
        // Kept with its time even when empty, so an older record does not
        // come back.
        self.config.storage_settings.insert(
            name.to_string(),
            SettingsEntry {
                settings,
                updated_utc: now,
            },
        );
        self.config.save(&self.home)?;
        self.refresh_aliases();
        Ok(())
    }

    /// Adopt the newest settings record of every storage this device has.
    /// Returns whether anything changed.
    pub(super) fn pull_storage_settings(&mut self) -> Result<bool> {
        if self.vault.member {
            return Ok(false);
        }
        let keys = self.storage_keys();
        let by_key: BTreeMap<&Id, &String> = keys.iter().map(|(n, k)| (k, n)).collect();
        let mut newest: BTreeMap<String, StorageSettingsRecord> = BTreeMap::new();
        for (_, backend) in self.metadata_storages(false)? {
            let Ok(list) = backend.list(storage_settings::PREFIX) else {
                continue;
            };
            for key in list {
                let mut parts = key[storage_settings::PREFIX.len()..].split('/');
                let (Some(sk), Some(dev), Some(stamp)) = (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };
                let (Ok(sk), Ok(dev)) = (Id::from_hex(sk), DeviceId::from_hex(dev)) else {
                    continue;
                };
                let Some(name) = by_key.get(&sk).map(|n| n.to_string()) else {
                    continue;
                };
                let stamp: i64 = stamp
                    .strip_suffix(".enc")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let known = self
                    .config
                    .storage_settings
                    .get(&name)
                    .map(|e| e.updated_utc)
                    .unwrap_or(0)
                    .max(newest.get(&name).map(|r| r.updated_utc).unwrap_or(0));
                if stamp <= known {
                    continue;
                }
                let Ok(Some(blob)) = backend.get(&key) else {
                    continue;
                };
                let verify = |d: &DeviceId| self.device_key(d);
                let key_for = |id: &str| self.folder_record_key_for(id);
                let Ok(rec) = StorageSettingsRecord::open_any(
                    &blob,
                    &self.vault.vault_id,
                    &sk,
                    &dev,
                    &key_for,
                    &verify,
                ) else {
                    continue;
                };
                if rec.updated_utc != stamp || !self.trusted(&rec.device) {
                    continue;
                }
                let allowed = match &self.org {
                    Some(o) => o.is_admin(&rec.device) || o.policy().members_may_add_storages,
                    None => true,
                };
                if allowed {
                    newest.insert(name, rec);
                }
            }
        }
        let changed = !newest.is_empty();
        for (name, rec) in newest {
            self.config.storage_settings.insert(
                name,
                SettingsEntry {
                    settings: rec.settings,
                    updated_utc: rec.updated_utc,
                },
            );
        }
        if changed {
            self.config.save(&self.home)?;
        }
        self.refresh_aliases();
        Ok(changed)
    }

    /// While any storage has a quota or a drain: publish this device's
    /// names for its storages (the ledger names a storage by its writer's
    /// name) and keep the other devices' names for them, so that usage
    /// and drains count every device's copies.
    fn refresh_aliases(&self) {
        if self
            .config
            .storage_settings
            .values()
            .all(|e| e.settings.is_empty())
        {
            return;
        }
        let aliases = self.drain_resolver().aliases();
        let _ = util::write_json(&self.home.join("state").join(ALIASES_FILE), &aliases);
    }

    // ----- quotas ----------------------------------------------------------------

    /// Set or clear a storage's quota (`None` leaves a figure as it is,
    /// `Some(None)` clears it) and publish it to every device.
    pub fn set_storage_quota(
        &mut self,
        name: &str,
        bytes: Option<Option<u64>>,
        objects: Option<Option<u64>>,
    ) -> Result<QuotaStatus> {
        self.org_allows(|p| p.members_may_add_storages, "change storage quotas")?;
        let Some(spec) = self.config.storages.iter().find(|s| s.name() == name) else {
            bail!("unknown storage {name}");
        };
        if spec.is_data_only() && (bytes.flatten().is_some() || objects.flatten().is_some()) {
            bail!("{name} is a disk pool: each disk keeps space free instead (reserve percent); quotas are for storages such as S3 buckets");
        }
        if spec.is_carrier() && (bytes.flatten().is_some() || objects.flatten().is_some()) {
            bail!("{name} is a transferrer: it empties itself as devices receive what it carries");
        }
        if bytes.flatten() == Some(0) || objects.flatten() == Some(0) {
            bail!("a quota must be more than zero; clear it instead");
        }
        let mut s = self.storage_settings(name);
        if let Some(b) = bytes {
            s.quota_bytes = b;
        }
        if let Some(o) = objects {
            s.quota_objects = o;
        }
        self.publish_storage_settings(name, s)?;
        self.quota_status(name)
    }

    /// Bytes and objects on each storage according to the ledger: the
    /// blocks claimed there and not dropped (each object once).
    fn block_usage(&self, view: &LedgerView) -> Usage {
        // Other devices' claims count under this device's name for the storage.
        let aliases: BTreeMap<DeviceId, BTreeMap<String, String>> =
            util::read_json_or_default(&self.home.join("state").join(ALIASES_FILE))
                .unwrap_or_default();
        let mut seen: BTreeMap<String, HashSet<&ObjectName>> = BTreeMap::new();
        let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for rec in view.chunks.values() {
            for (name, loc) in &rec.storages {
                if loc.claimed_by.is_empty() {
                    continue;
                }
                let local = loc
                    .claimed_by
                    .iter()
                    .find_map(|d| aliases.get(d).and_then(|m| m.get(name)))
                    .unwrap_or(name);
                if seen.entry(local.clone()).or_default().insert(&rec.object) {
                    let e = out.entry(local.clone()).or_default();
                    e.0 += rec.size;
                    e.1 += 1;
                }
            }
        }
        // This device's ledger: every batch is on every storage with records.
        let (mut bytes, mut objects) = (0u64, 0u64);
        for e in walkdir::WalkDir::new(self.home.join("ledger"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            objects += 1;
        }
        Usage {
            blocks: out,
            ledger: (bytes, objects),
        }
    }

    /// The records estimate for a storage: what `--measure` found, else
    /// this device's ledger (every batch is on every storage that holds
    /// records) with a small allowance for the other records.
    fn metadata_estimate(&self, spec: &StorageSpec, usage: &Usage) -> (u64, u64, Option<i64>) {
        if spec.is_data_only() {
            return (0, 0, None);
        }
        let measured: BTreeMap<String, Measured> =
            util::read_json_or_default(&self.home.join("state").join(MEASURED_FILE))
                .unwrap_or_default();
        if let Some(m) = measured.get(spec.name()) {
            return (m.metadata_bytes, m.metadata_objects, Some(m.measured_utc));
        }
        let (bytes, objects) = usage.ledger;
        // Device and folder records, manifests and thumbnails: a guess.
        let folders = self.keyring.folders.len() as u64;
        (
            bytes + 64 * 1024 * (folders + 1),
            objects + 8 * (folders + 1),
            None,
        )
    }

    fn quota_status_from(&self, spec: &StorageSpec, usage: &Usage) -> QuotaStatus {
        let name = spec.name();
        let settings = self.storage_settings(name);
        let (blocks_b, blocks_o) = usage.blocks.get(name).copied().unwrap_or_default();
        let (meta_b, meta_o, measured) = self.metadata_estimate(spec, usage);
        let used_bytes = blocks_b + meta_b;
        let used_objects = blocks_o + meta_o;
        let pct = |used: u64, q: u64| ((used as f64 / q as f64) * 100.0).floor() as u32;
        let percent = [
            settings.quota_bytes.map(|q| pct(used_bytes, q)),
            settings.quota_objects.map(|q| pct(used_objects, q)),
        ]
        .into_iter()
        .flatten()
        .max();
        let full = settings
            .quota_bytes
            .is_some_and(|q| used_bytes >= storage_settings::usable(q))
            || settings
                .quota_objects
                .is_some_and(|q| used_objects >= storage_settings::usable(q));
        let (state, message) = match (settings.quota_bytes, settings.quota_objects, percent) {
            (None, None, _) => ("none", None),
            _ if full => (
                "full",
                Some(match settings.quota_bytes {
                    Some(q) if used_bytes >= storage_settings::usable(q) => {
                        full_message(name, used_bytes, q)
                    }
                    _ => format!(
                        "storage {name} is at its quota ({used_objects} of {} objects)",
                        settings.quota_objects.unwrap_or(0)
                    ),
                }),
            ),
            (_, _, Some(p)) if p as u64 >= QUOTA_WARN_PERCENT => (
                "warning",
                Some(format!(
                    "storage {name} is nearly full: {} of {} ({p} %)",
                    super::placement::fmt_size(used_bytes),
                    settings
                        .quota_bytes
                        .map(super::placement::fmt_size)
                        .unwrap_or_else(|| format!(
                            "{} objects",
                            settings.quota_objects.unwrap_or(0)
                        ))
                )),
            ),
            _ => ("ok", None),
        };
        QuotaStatus {
            storage: name.to_string(),
            quota_bytes: settings.quota_bytes,
            quota_objects: settings.quota_objects,
            used_bytes,
            used_objects,
            metadata_bytes: meta_b,
            measured_utc: measured,
            percent,
            state: state.to_string(),
            message,
            drain: settings.drain.as_ref().map(|d| {
                match d.phase {
                    storage_settings::DrainPhase::Draining => "draining",
                    storage_settings::DrainPhase::Drained => "drained",
                }
                .to_string()
            }),
        }
    }

    /// One storage's use against its quota.
    pub fn quota_status(&self, name: &str) -> Result<QuotaStatus> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let view = self.view()?;
        Ok(self.quota_status_from(spec, &self.block_usage(&view)))
    }

    /// Every storage's use against its quota, in configuration order.
    pub fn quota_statuses(&self) -> Result<Vec<QuotaStatus>> {
        let view = self.view()?;
        let usage = self.block_usage(&view);
        Ok(self
            .config
            .storages
            .iter()
            .map(|s| self.quota_status_from(s, &usage))
            .collect())
    }

    /// List a storage to count its objects and measure its records (each
    /// record is read once; blocks are counted from the ledger), and use
    /// the result for the records estimate from now on.
    pub fn measure_storage(&mut self, name: &str) -> Result<QuotaStatus> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        if spec.is_cold() {
            bail!("{name} is cold storage: its records cannot be read without a restore; the estimate stays");
        }
        let backend = self.open_spec(&spec)?;
        let keys = backend.list("")?;
        let mut m = Measured {
            measured_utc: util::now_utc(),
            objects: keys.len() as u64,
            ..Default::default()
        };
        for k in keys
            .iter()
            .filter(|k| !k.starts_with("chunks/") && !k.starts_with(crate::packs::PREFIX))
        {
            if let Some(b) = backend.get(k)? {
                m.metadata_bytes += b.len() as u64;
                m.metadata_objects += 1;
            }
        }
        let path = self.home.join("state").join(MEASURED_FILE);
        let mut all: BTreeMap<String, Measured> =
            util::read_json_or_default(&path).unwrap_or_default();
        all.insert(name.to_string(), m);
        util::write_json(&path, &all)?;
        self.quota_status(name)
    }

    /// Sentences on storages that keep blocks out: at their quota, or
    /// being drained (for policy reports).
    pub(super) fn storage_notes(&self, view: &LedgerView) -> Vec<String> {
        let mut out = Vec::new();
        let any = self
            .config
            .storage_settings
            .values()
            .any(|e| !e.settings.is_empty());
        if !any {
            return out;
        }
        let usage = self.block_usage(view);
        for spec in &self.config.storages {
            let st = self.quota_status_from(spec, &usage);
            if st.state == "full" {
                if let Some(m) = st.message {
                    out.push(format!("{m}: new blocks cannot go there"));
                }
            }
            if st.drain.as_deref() == Some("draining") {
                out.push(format!(
                    "storage {} is being drained: it takes no new blocks",
                    spec.name()
                ));
            }
        }
        out
    }

    /// Room left on every storage with a quota, from the ledger as of `view`.
    pub(super) fn quota_gate(&self, view: &LedgerView) -> QuotaGate {
        let limited: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| {
                let st = self.storage_settings(s.name());
                st.quota_bytes.is_some() || st.quota_objects.is_some()
            })
            .collect();
        if limited.is_empty() {
            return QuotaGate::default();
        }
        let usage = self.block_usage(view);
        let mut gate = QuotaGate::default();
        let mut left = BTreeMap::new();
        for spec in limited {
            let st = self.quota_status_from(spec, &usage);
            let b = st
                .quota_bytes
                .map(|q| storage_settings::usable(q) as i128 - st.used_bytes as i128);
            let o = st
                .quota_objects
                .map(|q| storage_settings::usable(q) as i128 - st.used_objects as i128);
            left.insert(spec.name().to_string(), (b, o));
            let msg = match st.quota_bytes {
                Some(q) => full_message(spec.name(), st.used_bytes, q),
                None => format!(
                    "storage {} is at its quota ({} of {} objects)",
                    spec.name(),
                    st.used_objects,
                    st.quota_objects.unwrap_or(0)
                ),
            };
            gate.messages.insert(spec.name().to_string(), msg);
        }
        gate.left = Mutex::new(left);
        gate
    }
}
