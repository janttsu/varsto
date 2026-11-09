// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Publishing and reading the storage-key reminder (`crate::credentials`).
//!
//! The signed record is written after a removal, with the key that is still
//! stored, so the revocation is already on the storages. Status reads only
//! the local cache and the secret stored on this device: it does not list
//! the bucket. A failed publish is retried on the next read of the
//! membership and does not undo the removal or block a sync.

use super::members3;
use super::*;
use crate::credentials::{self, Baseline, CloudNote, CredentialBody, Current, DeviceStatement};
use crate::media::{storage_media, Media};
use crate::record::{RecordBody, RecordsRefused};
use crate::records3::read_newest;
use crate::vault::VaultMeta;
use std::collections::BTreeMap;

const FILE: &str = "credential-reminder.json";

/// Hashes and labels only. The secret stays in `secrets.enc`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ReminderCache {
    #[serde(default)]
    baselines: Vec<Baseline>,
    #[serde(default)]
    current: Vec<Current>,
    /// Other devices' statements, keyed by the hex device id.
    #[serde(default)]
    others: BTreeMap<String, Vec<Current>>,
}

impl Engine {
    fn reminder_path(&self) -> PathBuf {
        self.home.join("state").join(FILE)
    }

    fn load_reminder(&self) -> ReminderCache {
        let path = self.reminder_path();
        if !path.is_file() {
            return ReminderCache::default();
        }
        match util::read_json::<ReminderCache>(&path) {
            Ok(mut cache) => {
                scrub_reminder(&mut cache);
                cache
            }
            Err(e) => {
                log::warn!("storage-key reminder file ignored: {e:#}");
                ReminderCache::default()
            }
        }
    }

    fn save_reminder(&self, cache: &ReminderCache) -> Result<()> {
        let path = self.reminder_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        util::write_json(&path, cache)
    }

    /// Device id to the name shown for it. Removed devices are left out:
    /// they cannot write a credential record, and their old key is the
    /// reason for the reminder rather than a device that still has to change it.
    fn remaining_names(&self) -> BTreeMap<crate::record::Id16, String> {
        let mut out = BTreeMap::new();
        for d in self.devices_list() {
            if d.revoked {
                continue;
            }
            let Ok(id) = crate::ids::DeviceId::from_hex(&d.device_id) else {
                continue;
            };
            let Ok(bin) = members3::bin(&id) else {
                continue;
            };
            out.insert(bin, d.name);
        }
        let me = self.me3();
        out.entry(me)
            .or_insert_with(|| self.vault.device_name.clone());
        out
    }

    fn s3_secret(&self, spec: &StorageSpec) -> Option<String> {
        let StorageSpec::S3 {
            name, secret_ref, ..
        } = spec
        else {
            return None;
        };
        let reference = if secret_ref.is_empty() {
            name
        } else {
            secret_ref
        };
        if let Some(secret) = self
            .secret_store()
            .ok()
            .and_then(|store| store.secrets.get(reference).cloned())
        {
            return Some(secret);
        }
        let env_name = format!(
            "VARSTO_S3_SECRET_{}",
            name.to_uppercase()
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        );
        let Ok(value) = std::env::var(&env_name) else {
            return None;
        };
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        crate::logging::register_secret(value);
        Some(value.to_string())
    }

    fn live_secrets(&self) -> Vec<credentials::LiveSecret> {
        let mut out = Vec::new();
        for spec in &self.config.storages {
            let Some(id) = spec.location_key() else {
                continue;
            };
            let storage_id = credentials::clip(&id, 1024);
            match spec {
                StorageSpec::S3 { .. } => {
                    let secret_hash = self
                        .s3_secret(spec)
                        .map(|secret| credentials::secret_hash(&storage_id, &secret));
                    out.push(credentials::LiveSecret {
                        storage_id,
                        has_storage: true,
                        secret_hash,
                    });
                }
                StorageSpec::Rclone { .. } => out.push(credentials::LiveSecret {
                    storage_id,
                    has_storage: true,
                    secret_hash: None,
                }),
                _ => {}
            }
        }
        out
    }

    /// Bring `current` in line with the secret stored here. A new secret
    /// clears the confirmation. An rclone entry is created only once a
    /// removal has named that remote, because Varsto has no hash to publish
    /// before that.
    fn overlay_live(&self, cache: &mut ReminderCache) {
        for spec in &self.config.storages {
            let Some(id) = spec.location_key() else {
                continue;
            };
            let storage_id = credentials::clip(&id, 1024);
            match spec {
                StorageSpec::S3 { name, bucket, .. } => {
                    let Some(secret) = self.s3_secret(spec) else {
                        continue;
                    };
                    let hash = credentials::secret_hash(&storage_id, &secret);
                    touch_current(
                        cache,
                        &storage_id,
                        credentials::KIND_S3,
                        name,
                        bucket,
                        hash,
                        false,
                    );
                }
                StorageSpec::Rclone { name, remote, .. } => {
                    let known = cache.baselines.iter().any(|b| b.storage_id == storage_id)
                        || cache.current.iter().any(|c| c.storage_id == storage_id);
                    if !known {
                        continue;
                    }
                    if let Some(entry) = cache
                        .current
                        .iter_mut()
                        .find(|c| c.storage_id == storage_id)
                    {
                        entry.kind = credentials::KIND_RCLONE;
                        entry.name = credentials::clip(name, 256);
                        entry.detail = credentials::clip(remote, 1024);
                        entry.secret_hash = [0; 32];
                    } else {
                        cache.current.push(Current {
                            storage_id: storage_id.clone(),
                            kind: credentials::KIND_RCLONE,
                            name: credentials::clip(name, 256),
                            detail: credentials::clip(remote, 1024),
                            secret_hash: [0; 32],
                            retired: false,
                        });
                    }
                }
                _ => {}
            }
        }
        canon_reminder(cache);
    }

    fn read_credential_records(&self) -> Result<BTreeMap<crate::record::Id16, CredentialBody>> {
        let names = self.remaining_names();
        let streams: Vec<_> = names
            .keys()
            .copied()
            .map(credentials::credential_stream)
            .collect();
        let mut best: BTreeMap<crate::record::Id16, CredentialBody> = BTreeMap::new();
        if streams.is_empty() {
            return Ok(best);
        }
        let mut refused = RecordsRefused::default();
        self.with_records(|store| {
            for body in read_newest::<CredentialBody>(store, &streams, &mut refused)? {
                match best.get(&body.device) {
                    Some(old) if old.seq >= body.seq => {}
                    _ => {
                        best.insert(body.device, body);
                    }
                }
            }
            Ok(())
        })?;
        if refused.total() > 0 {
            log::debug!("{} credential record(s) refused", refused.total());
        }
        Ok(best)
    }

    fn publish_reminder(&self, cache: &ReminderCache) -> Result<()> {
        if cache.baselines.is_empty() && cache.current.is_empty() {
            return Ok(());
        }
        let me = self.me3();
        let epoch = self.key_epoch();
        let baselines = cache.baselines.clone();
        let current = cache.current.clone();
        if let Some(prev) = self.read_credential_records()?.remove(&me) {
            if prev.baselines == baselines && prev.current == current && prev.epoch == epoch {
                return Ok(());
            }
        }
        self.publish_newest(&credentials::credential_stream(me), |seq| CredentialBody {
            device: me,
            seq,
            epoch,
            baselines: baselines.clone(),
            current: current.clone(),
        })
    }

    /// Read every remaining device's statement into the cache and publish
    /// this device's when it would say something new. Errors are the
    /// caller's to log: a sync still finishes.
    pub(crate) fn refresh_credentials(&mut self) -> Result<()> {
        if self.vault.member || self.removal.is_some() {
            return Ok(());
        }
        let me = self.me3();
        let records = self.read_credential_records()?;
        let mut cache = self.load_reminder();
        let mut bases = std::mem::take(&mut cache.baselines);
        for body in records.values() {
            bases.extend(body.baselines.iter().cloned());
        }
        cache.baselines = credentials::merge_baselines(bases);
        cache.others.clear();
        for (id, body) in &records {
            if *id != me {
                cache.others.insert(hex::encode(id), body.current.clone());
            }
        }
        self.overlay_live(&mut cache);
        self.save_reminder(&cache)?;
        self.publish_reminder(&cache)?;
        Ok(())
    }

    /// The lines for a removal that just succeeded. The revocation is
    /// already stored. Publishing the reminder is best-effort.
    pub(super) fn credential_after_revoke(&mut self, epoch: u32) -> Result<Vec<String>> {
        let specs = self.config.storages.clone();
        let mut cache = self.load_reminder();
        let mut cloud = Vec::new();
        let mut network = Vec::new();
        let mut fresh = Vec::new();
        for spec in &specs {
            match spec {
                StorageSpec::S3 { name, bucket, .. } => {
                    let Some(id) = spec.location_key() else {
                        continue;
                    };
                    let storage_id = credentials::clip(&id, 1024);
                    let secret = self.s3_secret(spec);
                    let hash = match &secret {
                        Some(s) => credentials::secret_hash(&storage_id, s),
                        None => [0; 32],
                    };
                    fresh.push(baseline_of(
                        &storage_id,
                        credentials::KIND_S3,
                        name,
                        bucket,
                        hash,
                        epoch,
                    ));
                    touch_current(
                        &mut cache,
                        &storage_id,
                        credentials::KIND_S3,
                        name,
                        bucket,
                        hash,
                        true,
                    );
                    cloud.push(CloudNote {
                        kind: credentials::KIND_S3,
                        name: name.clone(),
                        detail: bucket.clone(),
                        has_secret: secret.is_some(),
                    });
                }
                StorageSpec::Rclone { name, remote, .. } => {
                    let Some(id) = spec.location_key() else {
                        continue;
                    };
                    let storage_id = credentials::clip(&id, 1024);
                    fresh.push(baseline_of(
                        &storage_id,
                        credentials::KIND_RCLONE,
                        name,
                        remote,
                        [0; 32],
                        epoch,
                    ));
                    touch_current(
                        &mut cache,
                        &storage_id,
                        credentials::KIND_RCLONE,
                        name,
                        remote,
                        [0; 32],
                        true,
                    );
                    cloud.push(CloudNote {
                        kind: credentials::KIND_RCLONE,
                        name: name.clone(),
                        detail: remote.clone(),
                        has_secret: false,
                    });
                }
                StorageSpec::LocalDir { path, .. } => {
                    if storage_media(path) == Media::Network {
                        network.push(path.display().to_string());
                    }
                }
                StorageSpec::Pool { .. } => {}
            }
        }
        cache.baselines = credentials::merge_baselines(cache.baselines.into_iter().chain(fresh));
        canon_reminder(&mut cache);
        self.save_reminder(&cache)?;
        if let Err(e) = self.publish_reminder(&cache) {
            log::warn!(
                "the removal is stored, but the storage-key reminder was not published: {e:#}"
            );
        }
        Ok(credentials::removal_notes(&cloud, &network))
    }

    /// What status and the overview show. No network.
    pub fn credential_warnings(&self) -> Result<Vec<credentials::CredentialWarning>> {
        if self.removal.is_some() {
            return Ok(Vec::new());
        }
        let cache = self.load_reminder();
        let names = self.remaining_names();
        let me = self.me3();
        let devices = names
            .iter()
            .map(|(id, name)| DeviceStatement {
                device: *id,
                name: name.clone(),
                current: if *id == me {
                    cache.current.clone()
                } else {
                    cache
                        .others
                        .get(&hex::encode(id))
                        .cloned()
                        .unwrap_or_default()
                },
            })
            .collect::<Vec<_>>();
        Ok(credentials::warnings(
            &cache.baselines,
            &devices,
            &me,
            &self.live_secrets(),
        ))
    }

    /// Replace the S3 secret stored on this device. The new secret is kept
    /// only when the storage accepts a request signed with it; otherwise the
    /// previous secret is put back. Other devices learn the new hash when a
    /// storage can be reached.
    pub fn replace_storage_secret(&mut self, name: &str, secret: &str) -> Result<()> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let StorageSpec::S3 { secret_ref, .. } = &spec else {
            bail!(
                "{name} is not an S3 storage; an rclone remote's credential stays in rclone's configuration"
            );
        };
        let secret = secret.trim();
        if secret.is_empty() {
            bail!("the secret is empty");
        }
        crate::logging::register_secret(secret);
        let reference = if secret_ref.is_empty() {
            spec.name().to_string()
        } else {
            secret_ref.clone()
        };
        let mut store = self.secret_store()?;
        let previous = store.secrets.get(&reference).cloned();
        store.secrets.insert(reference.clone(), secret.to_string());
        store.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.forget_storages();
        if let Err(e) = self.probe_storage(&spec) {
            let mut store = self.secret_store()?;
            match &previous {
                Some(old) => {
                    store.secrets.insert(reference, old.clone());
                }
                None => {
                    store.secrets.remove(&reference);
                }
            }
            let _ = store.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            );
            self.forget_storages();
            return Err(e).context("the new key was not kept");
        }
        let mut cache = self.load_reminder();
        self.overlay_live(&mut cache);
        self.save_reminder(&cache)?;
        if let Err(e) = self.publish_reminder(&cache) {
            log::warn!(
                "the new key is stored on this device; other devices were not told yet: {e:#}"
            );
        }
        Ok(())
    }

    /// One request with the new key. A missing vault object is fine (the
    /// key was accepted); a refusal or a storage that cannot be reached is not.
    fn probe_storage(&self, spec: &StorageSpec) -> Result<()> {
        let backend = self.open_spec(spec)?;
        backend
            .get(VaultMeta::STORAGE_KEY)
            .context("the storage did not accept the new key")?;
        Ok(())
    }

    /// Record that the old key is disabled at the provider. The flag is kept
    /// only when the signed record was published, so another device can see it.
    pub fn confirm_storage_key_disabled(&mut self, name: &str) -> Result<()> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let (kind, detail) = match &spec {
            StorageSpec::S3 { bucket, .. } => (credentials::KIND_S3, bucket.clone()),
            StorageSpec::Rclone { remote, .. } => (credentials::KIND_RCLONE, remote.clone()),
            _ => bail!("{name} has no provider key to disable"),
        };
        let storage_id = spec.location_key().ok_or_else(|| {
            anyhow!("{name} has no stable place (an rclone remote needs a colon)")
        })?;
        let storage_id = credentials::clip(&storage_id, 1024);
        if self.record_storages()?.is_empty() {
            bail!("no storage to publish the confirmation to, so other devices would not see it");
        }
        let mut cache = self.load_reminder();
        self.overlay_live(&mut cache);
        if !cache.baselines.iter().any(|b| b.storage_id == storage_id) {
            bail!("{name} has no key waiting to be disabled");
        }
        let previous = cache.clone();
        let hash = cache
            .current
            .iter()
            .find(|c| c.storage_id == storage_id)
            .map(|c| c.secret_hash)
            .unwrap_or(if kind == credentials::KIND_RCLONE {
                [0; 32]
            } else {
                self.s3_secret(&spec)
                    .map(|s| credentials::secret_hash(&storage_id, &s))
                    .unwrap_or([0; 32])
            });
        touch_current(&mut cache, &storage_id, kind, name, &detail, hash, false);
        let Some(entry) = cache
            .current
            .iter_mut()
            .find(|c| c.storage_id == storage_id)
        else {
            bail!("{name} has no key waiting to be disabled");
        };
        entry.retired = true;
        canon_reminder(&mut cache);
        self.save_reminder(&cache)?;
        if let Err(e) = self.publish_reminder(&cache) {
            let _ = self.save_reminder(&previous);
            return Err(e).context("the confirmation was not published, so it was not kept");
        }
        Ok(())
    }
}

/// `force_hash` replaces the stored hash and clears the confirmation, which
/// a removal does: the key in use now is the one the removed device has.
fn touch_current(
    cache: &mut ReminderCache,
    storage_id: &str,
    kind: u8,
    name: &str,
    detail: &str,
    hash: [u8; 32],
    force_hash: bool,
) {
    let hash = if kind == credentials::KIND_RCLONE {
        [0; 32]
    } else {
        hash
    };
    if let Some(entry) = cache
        .current
        .iter_mut()
        .find(|c| c.storage_id == storage_id)
    {
        entry.kind = kind;
        entry.name = credentials::clip(name, 256);
        entry.detail = credentials::clip(detail, 1024);
        // A removal starts the reminder over, even when the secret did not change.
        // A different secret does the same. An unchanged secret leaves the confirmation.
        if force_hash || entry.secret_hash != hash {
            entry.secret_hash = hash;
            entry.retired = false;
        }
        return;
    }
    // A secret on a storage nobody has removed yet is not a statement.
    if !force_hash && !cache.baselines.iter().any(|b| b.storage_id == storage_id) {
        return;
    }
    cache.current.push(Current {
        storage_id: storage_id.to_string(),
        kind,
        name: credentials::clip(name, 256),
        detail: credentials::clip(detail, 1024),
        secret_hash: hash,
        retired: false,
    });
}

fn baseline_of(
    storage_id: &str,
    kind: u8,
    name: &str,
    detail: &str,
    hash: [u8; 32],
    epoch: u32,
) -> Baseline {
    Baseline {
        storage_id: storage_id.to_string(),
        kind,
        name: credentials::clip(name, 256),
        detail: credentials::clip(detail, 1024),
        old_hash: if kind == credentials::KIND_RCLONE {
            [0; 32]
        } else {
            hash
        },
        epoch,
    }
}

fn canon_reminder(cache: &mut ReminderCache) {
    cache.baselines = credentials::merge_baselines(std::mem::take(&mut cache.baselines));
    cache.current = credentials::normalize_current(std::mem::take(&mut cache.current));
}

fn scrub_reminder(cache: &mut ReminderCache) {
    cache.baselines.retain(baseline_ok);
    cache.current.retain(current_ok);
    cache.others.retain(|_, rows| {
        rows.retain(current_ok);
        !rows.is_empty()
    });
    canon_reminder(cache);
}

fn baseline_ok(b: &Baseline) -> bool {
    one_ok(
        &b.storage_id,
        b.kind,
        &b.name,
        &b.detail,
        &b.old_hash,
        false,
    )
}

fn current_ok(c: &Current) -> bool {
    one_ok(
        &c.storage_id,
        c.kind,
        &c.name,
        &c.detail,
        &c.secret_hash,
        c.retired,
    )
}

/// The record's own check, one row at a time, so one bad cache entry does
/// not throw away the rest.
fn one_ok(
    storage_id: &str,
    kind: u8,
    name: &str,
    detail: &str,
    hash: &[u8; 32],
    retired: bool,
) -> bool {
    let device = [1; 16];
    let body = CredentialBody {
        device,
        seq: 1,
        epoch: 0,
        baselines: vec![Baseline {
            storage_id: storage_id.to_string(),
            kind,
            name: name.to_string(),
            detail: detail.to_string(),
            old_hash: *hash,
            epoch: 0,
        }],
        current: vec![Current {
            storage_id: storage_id.to_string(),
            kind,
            name: name.to_string(),
            detail: detail.to_string(),
            secret_hash: *hash,
            retired,
        }],
    };
    let meta = crate::record::RecordMeta {
        kind: crate::record::Kind::Credential,
        vault: [0; 16],
        scope: [0; 16],
        device,
        seq: 1,
        parts: 1,
        key_id: crate::record::KeyId::Registry(0),
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    body.check(&meta).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::Media;

    const PASS: &str = "correct horse battery staple";

    fn local_lab() -> (tempfile::TempDir, StorageSpec, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let storage = StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        };
        (tmp, storage, root)
    }

    #[test]
    fn a_local_directory_removal_has_no_key_warning_and_sync_still_works() {
        let (_tmp, storage, root) = local_lab();
        let (mut a, key) = Engine::init(&root.join("a"), "dev0", PASS).unwrap();
        a.add_storage(storage.clone()).unwrap();
        let mut b = Engine::join(&root.join("b"), "dev1", PASS, &key, storage.clone()).unwrap();
        a.refresh_members().unwrap();
        b.refresh_members().unwrap();
        let report = a.revoke_device("dev1", false).unwrap();
        let network = storage_media(&root.join("storage")) == Media::Network;
        if network {
            assert!(report
                .credential_notes
                .iter()
                .any(|n| n.contains("network share")));
        } else {
            assert!(
                report.credential_notes.is_empty(),
                "{:?}",
                report.credential_notes
            );
        }
        assert!(a.credential_warnings().unwrap().is_empty());
        a.sync(None).unwrap();
        assert!(a.credential_warnings().unwrap().is_empty());
    }

    #[test]
    fn a_signed_reminder_is_seen_by_the_other_device_and_clears_when_confirmed() {
        let (_tmp, storage, root) = local_lab();
        let (mut a, key) = Engine::init(&root.join("a"), "dev0", PASS).unwrap();
        a.add_storage(storage.clone()).unwrap();
        let mut b = Engine::join(&root.join("b"), "dev1", PASS, &key, storage).unwrap();
        a.refresh_members().unwrap();
        b.refresh_members().unwrap();
        let id = "s3:example.invalid|bucket|".to_string();
        let mut cache = a.load_reminder();
        cache.baselines.push(Baseline {
            storage_id: id.clone(),
            kind: credentials::KIND_S3,
            name: "photos".into(),
            detail: "bucket".into(),
            old_hash: [7; 32],
            epoch: 1,
        });
        cache.current.push(Current {
            storage_id: id.clone(),
            kind: credentials::KIND_S3,
            name: "photos".into(),
            detail: "bucket".into(),
            secret_hash: [7; 32],
            retired: false,
        });
        canon_reminder(&mut cache);
        a.save_reminder(&cache).unwrap();
        a.publish_reminder(&cache).unwrap();

        b.refresh_credentials().unwrap();
        let w = b.credential_warnings().unwrap();
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0].devices_old, vec!["dev0".to_string()]);
        assert!(w[0].needs_confirm);
        assert!(!w[0].needs_secret);

        cache.current[0].secret_hash = [8; 32];
        cache.current[0].retired = true;
        canon_reminder(&mut cache);
        a.save_reminder(&cache).unwrap();
        a.publish_reminder(&cache).unwrap();
        b.refresh_credentials().unwrap();
        assert!(b.credential_warnings().unwrap().is_empty());
    }
}
