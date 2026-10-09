// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Last-accessed times across devices (`docs/spec/alpha-0-format.md`
//! section 13).
//!
//! Each device records when it last used a file (fetch, open, read, the
//! access time seen at scan) in its folder state. To make "idle for 90
//! days" mean idle on every device, each device publishes that map as one
//! *access record* per folder, replaced as a whole:
//! `vault/access/<folder>/<device>/<written utc, 20 digits>.enc`, zstd JSON
//! sealed with XChaCha20-Poly1305 under a key derived from the folder's
//! current metadata key (associated data: vault, folder, device, time). A
//! device writes a new record only when its map changed, at most once per
//! [`ACCESS_INTERVAL_SECS`] from the background sync, and deletes its older
//! ones; readers keep the newest record per device. The merged time of a
//! file is the newest over this device and every other device that is not
//! removed.
//!
//! Why not ledger events: access times change with every use, and the
//! ledger is append-only and replicated to every device forever (checkpoints
//! bound it, they do not erase it). One replaceable object per device and
//! folder costs O(files) bytes regardless of how often files are used, and
//! needs no ledger format change. The ledger keeps facts about data; this is
//! a hint for advice.

use super::*;

/// Least time between two access exchanges started by a sync.
pub const ACCESS_INTERVAL_SECS: i64 = 3600;
const PREFIX: &str = "vault/access/";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct AccessBody {
    device: DeviceId,
    folder: FolderId,
    written_utc: i64,
    accessed: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RemoteAccess {
    written_utc: i64,
    accessed: BTreeMap<String, i64>,
}

/// `state/access/<folder>.json`: what this device published last and the
/// newest record of every other device.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct AccessCache {
    #[serde(default)]
    published_utc: i64,
    #[serde(default)]
    published_hash: String,
    #[serde(default)]
    remote: BTreeMap<DeviceId, RemoteAccess>,
}

/// What one exchange did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct AccessExchangeReport {
    /// Folders whose record this device published now.
    pub published: usize,
    /// Records of other devices read now.
    pub received: usize,
}

fn record_key(meta: &SecretKey, folder: &FolderId) -> SecretKey {
    meta.derive("access-record", &[folder.as_str().as_bytes()])
}

fn aad(vault: &VaultId, folder: &FolderId, device: &DeviceId, written: i64) -> Vec<u8> {
    crypto::aad(
        "access-record",
        &[
            vault.as_str().as_bytes(),
            folder.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &written.to_le_bytes(),
        ],
    )
}

fn storage_key(folder: &FolderId, device: &DeviceId, written: i64) -> String {
    format!("{PREFIX}{folder}/{device}/{written:020}.enc")
}

impl Engine {
    fn access_cache_path(&self, folder: &FolderId) -> PathBuf {
        self.home
            .join("state")
            .join("access")
            .join(format!("{folder}.json"))
    }

    fn load_access_cache(&self, folder: &FolderId) -> AccessCache {
        util::read_json_or_default(&self.access_cache_path(folder)).unwrap_or_default()
    }

    /// Last use of every file of a folder on any device: this device's own
    /// record merged with the newest record of every other device that
    /// still belongs to the folder (newest time wins per path).
    pub(super) fn merged_access(
        &self,
        folder: &FolderId,
        state: &FolderState,
    ) -> BTreeMap<String, i64> {
        let mut out = state.accessed.clone();
        for (dev, r) in self.load_access_cache(folder).remote {
            if self.is_revoked(&dev) {
                continue;
            }
            for (path, t) in r.accessed {
                let e = out.entry(path).or_insert(0);
                *e = (*e).max(t);
            }
        }
        out
    }

    /// Publish this device's access records and read the other devices'
    /// ones for every attached folder whose key is at hand, when the last
    /// exchange is older than [`ACCESS_INTERVAL_SECS`] (or always with
    /// `force`). Called after every sync.
    pub(super) fn access_upkeep(&mut self, force: bool) -> Result<AccessExchangeReport> {
        let mut report = AccessExchangeReport::default();
        if self.removal.is_some() {
            return Ok(report);
        }
        let marker = self.home.join("state").join("access").join("last.json");
        let last: i64 = util::read_json_or_default(&marker).unwrap_or(0);
        let now = util::now_utc();
        if !force && now - last < ACCESS_INTERVAL_SECS {
            return Ok(report);
        }
        let storages = self.metadata_storages(false)?;
        if storages.is_empty() {
            return Ok(report);
        }
        let mounted: Vec<FolderId> = self
            .config
            .folders
            .iter()
            .map(|m| m.folder_id.clone())
            .collect();
        for fid in mounted {
            let Some(rec) = self.keyring.folders.get(&fid).filter(|r| !r.is_removed()) else {
                continue;
            };
            // A locked Strongroom is left alone.
            let Ok(rec) = self.with_key(rec) else {
                continue;
            };
            let fk = self.folder_keys(&rec)?;
            let state = self.load_state(&fid)?;
            let mut cache = self.load_access_cache(&fid);
            if self.publish_access(&storages, &fk, &state, &mut cache, now)? {
                report.published += 1;
            }
            report.received += self.read_access(&storages, &fk, &mut cache)?;
            let path = self.access_cache_path(&fid);
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            util::write_json(&path, &cache)?;
        }
        util::write_json(&marker, &now)?;
        Ok(report)
    }

    /// Exchange access records now, whatever the schedule says.
    pub fn exchange_access_records(&mut self) -> Result<AccessExchangeReport> {
        self.access_upkeep(true)
    }

    fn publish_access(
        &self,
        storages: &OpenStorages,
        fk: &FolderKeys,
        state: &FolderState,
        cache: &mut AccessCache,
        now: i64,
    ) -> Result<bool> {
        if state.accessed.is_empty() {
            return Ok(false);
        }
        let json = serde_json::to_vec(&state.accessed)?;
        let hash = hex::encode(crypto::hash(&json));
        if hash == cache.published_hash {
            return Ok(false);
        }
        let me = &self.vault.device_id;
        let written = now.max(cache.published_utc + 1);
        let body = AccessBody {
            device: me.clone(),
            folder: fk.folder.clone(),
            written_utc: written,
            accessed: state.accessed.clone(),
        };
        let packed = zstd::bulk::compress(&serde_json::to_vec(&body)?, 3)?;
        let blob = crypto::encrypt(
            &record_key(&fk.meta, &fk.folder),
            &aad(&self.vault.vault_id, &fk.folder, me, written),
            &packed,
        )?;
        let key = storage_key(&fk.folder, me, written);
        let own = format!("{PREFIX}{}/{me}/", fk.folder);
        for (_, b) in storages {
            b.put_if_absent(&key, &blob)?;
            // Only the newest record of a device is ever read.
            for old in b.list(&own)? {
                if old != key {
                    b.delete(&old)?;
                }
            }
        }
        cache.published_utc = written;
        cache.published_hash = hash;
        Ok(true)
    }

    fn read_access(
        &self,
        storages: &OpenStorages,
        fk: &FolderKeys,
        cache: &mut AccessCache,
    ) -> Result<usize> {
        let prefix = format!("{PREFIX}{}/", fk.folder);
        let mut newest: BTreeMap<DeviceId, (i64, usize, String)> = BTreeMap::new();
        for (i, (_, b)) in storages.iter().enumerate() {
            for key in b.list(&prefix)? {
                let Some((dev, file)) = key.strip_prefix(&prefix).and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Some(t)) = (
                    DeviceId::from_hex(dev),
                    file.strip_suffix(".enc")
                        .and_then(|t| t.parse::<i64>().ok()),
                ) else {
                    continue;
                };
                if newest.get(&dev).is_none_or(|(n, _, _)| t > *n) {
                    newest.insert(dev, (t, i, key));
                }
            }
        }
        let metas = fk.meta_keys();
        let mut read = 0;
        for (dev, (t, i, key)) in newest {
            let known =
                self.devices.devices.contains_key(&dev) || self.devices.members.contains_key(&dev);
            if dev == self.vault.device_id || !known || self.is_revoked(&dev) {
                continue;
            }
            if cache.remote.get(&dev).is_some_and(|r| r.written_utc >= t) {
                continue;
            }
            let Some(blob) = storages[i].1.get(&key)? else {
                continue;
            };
            let a = aad(&self.vault.vault_id, &fk.folder, &dev, t);
            let Some(packed) = metas
                .iter()
                .find_map(|m| crypto::decrypt(&record_key(m, &fk.folder), &a, &blob).ok())
            else {
                continue;
            };
            let Ok(json) = zstd::bulk::decompress(&packed, 256 << 20) else {
                continue;
            };
            let Ok(body) = serde_json::from_slice::<AccessBody>(&json) else {
                continue;
            };
            if body.device != dev || body.folder != fk.folder || body.written_utc != t {
                continue;
            }
            cache.remote.insert(
                dev,
                RemoteAccess {
                    written_utc: t,
                    accessed: body.accessed,
                },
            );
            read += 1;
        }
        Ok(read)
    }
}
