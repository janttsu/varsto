// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The storages of the vault as every device sees them (spec section 20):
//! the ones configured here, and the ones other devices publish
//! (`vault/storage-names`) that are not configured here ("known, not
//! configured here": credentials are per device and never shared). It also
//! recognises the same bucket or remote added twice, by identity
//! (`vault/storage-id.json`) or, where that is not readable, by location.

use super::verify::{StorageIdentity, STORAGE_ID_KEY};
use super::*;

/// One storage of the vault.
#[derive(Clone, Debug, Default, Serialize)]
pub struct KnownStorage {
    /// The name here when configured here, else the name other devices use.
    pub name: String,
    pub configured: bool,
    /// "directory", "s3", "rclone", "pool", or "unknown" when not configured here.
    pub kind: String,
    /// Storage identity, where it could be read or another device published it.
    pub identity: Option<String>,
    /// Other devices that have this storage configured.
    pub devices: Vec<String>,
    /// The names those devices give it, when they differ from `name`.
    pub other_names: Vec<String>,
    /// Other entries here that are the same storage (a mistake to fix).
    pub same_as: Vec<String>,
    /// A sentence for listings.
    pub state: String,
}

impl Engine {
    /// Publish this device's storage names with their identities, so the
    /// other devices list the storages added here. Best effort.
    pub(super) fn publish_storage_names(&self) {
        let _ = self.drain_resolver();
    }

    /// Every storage of the vault: configured here, then known only from
    /// other devices (merged by identity, whatever each device calls it).
    pub fn storage_directory(&self) -> Result<Vec<KnownStorage>> {
        let names = self.drain_resolver();
        let ids = names.local_ids();
        let from_ledger = self.view().map(|v| v.devices).unwrap_or_default();
        let device_name = |d: &DeviceId| {
            self.devices
                .devices
                .get(d)
                .map(|r| r.name.clone())
                .or_else(|| from_ledger.get(d).cloned())
                .unwrap_or_else(|| d.short().to_string())
        };
        let mut out: Vec<KnownStorage> = Vec::new();
        for spec in &self.config.storages {
            let id = ids.get(spec.name()).cloned();
            let mut k = KnownStorage {
                name: spec.name().to_string(),
                configured: true,
                kind: match spec.kind() {
                    "local-dir" => "directory",
                    other => other,
                }
                .to_string(),
                identity: id.clone(),
                state: "configured here".to_string(),
                ..Default::default()
            };
            if let Some(id) = &id {
                for (dev, theirs) in names.others() {
                    for (n, i) in theirs {
                        if i == id {
                            k.devices.push(device_name(dev));
                            if n != spec.name() && !k.other_names.contains(n) {
                                k.other_names.push(n.clone());
                            }
                        }
                    }
                }
                k.devices.sort();
                k.devices.dedup();
            }
            out.push(k);
        }
        // The same place twice: same identity, or the same location.
        let keys: Vec<Option<String>> = self
            .config
            .storages
            .iter()
            .map(|s| self.location_key_resolved(s))
            .collect();
        for i in 0..out.len() {
            for j in 0..out.len() {
                if i == j {
                    continue;
                }
                let same_id = out[i].identity.is_some() && out[i].identity == out[j].identity;
                let same_loc = keys[i].is_some() && keys[i] == keys[j];
                if same_id || same_loc {
                    let n = out[j].name.clone();
                    out[i].same_as.push(n);
                }
            }
            if !out[i].same_as.is_empty() {
                out[i].state = format!(
                    "configured here, and the same storage as {}: keep one of them",
                    out[i].same_as.join(", ")
                );
            }
        }
        // Storages only other devices have.
        let mut unknown: BTreeMap<String, KnownStorage> = BTreeMap::new();
        for (dev, theirs) in names.others() {
            for (n, id) in theirs {
                if ids.values().any(|i| i == id) {
                    continue;
                }
                let e = unknown.entry(id.clone()).or_insert_with(|| KnownStorage {
                    name: n.clone(),
                    kind: "unknown".to_string(),
                    identity: Some(id.clone()),
                    state:
                        "known from another device, not configured here: add its credentials here"
                            .to_string(),
                    ..Default::default()
                });
                let dn = device_name(dev);
                if !e.devices.contains(&dn) {
                    e.devices.push(dn);
                }
                if *n != e.name && !e.other_names.contains(n) {
                    e.other_names.push(n.clone());
                }
            }
        }
        out.extend(unknown.into_values().map(|mut k| {
            k.devices.sort();
            k
        }));
        Ok(out)
    }

    /// `StorageSpec::location_key`, with rclone aliases followed.
    fn location_key_resolved(&self, spec: &StorageSpec) -> Option<String> {
        match spec {
            StorageSpec::Rclone {
                name,
                remote,
                cold,
                place,
            } => StorageSpec::Rclone {
                name: name.clone(),
                remote: crate::rclone::resolve_alias(remote),
                cold: *cold,
                place: place.clone(),
            }
            .location_key(),
            other => other.location_key(),
        }
    }

    /// Before `spec` becomes a storage of this device: refuse it when it is
    /// the same place as a storage already configured here, or (by identity)
    /// as one another device has under a different name. `backend` is the
    /// opened new storage. A storage another device has, added here under
    /// that device's name, is how its credentials are given: allowed.
    pub(super) fn refuse_duplicate_storage(
        &self,
        spec: &StorageSpec,
        backend: &dyn Storage,
    ) -> Result<()> {
        let key = self.location_key_resolved(spec);
        for s in &self.config.storages {
            if key.is_some() && self.location_key_resolved(s) == key {
                bail!(
                    "this is the same {} as '{}', already configured here: use that storage instead of adding it twice",
                    place_word(spec),
                    s.name()
                );
            }
        }
        let Some(raw) = backend.get(STORAGE_ID_KEY).ok().flatten() else {
            return Ok(());
        };
        let Ok(id) = serde_json::from_slice::<StorageIdentity>(&raw).map(|i| i.storage_id) else {
            return Ok(());
        };
        let names = self.drain_resolver();
        if let Some((local, _)) = names.local_ids().into_iter().find(|(_, i)| *i == id) {
            bail!(
                "this is the same {} as '{local}', already configured here: use that storage instead of adding it twice",
                place_word(spec)
            );
        }
        for theirs in names.others().values() {
            for (n, i) in theirs {
                if *i == id && n != spec.name() {
                    bail!(
                        "this is the same {} as '{n}', already in your vault (added on another device): use that one, or add its credentials here under the same name '{n}'",
                        place_word(spec)
                    );
                }
            }
        }
        Ok(())
    }
}

fn place_word(spec: &StorageSpec) -> &'static str {
    match spec {
        StorageSpec::S3 { .. } => "bucket",
        StorageSpec::Rclone { .. } => "rclone destination",
        _ => "storage",
    }
}
