// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Last-accessed times across devices (`docs/spec/alpha-0-format.md`
//! section 13, format 3: section 77).
//!
//! Each device records when it last used a file (fetch, open, read, the
//! access time seen at scan) in its folder state. To make "idle for 90
//! days" mean idle on every device, each device publishes that map as an
//! *access record* per folder (record kind 20, stream
//! `access/<folder>/<device>/`, sealed under the folder's metadata key of
//! its epoch), replaced as a whole: a device writes a new record only when
//! its map changed, at most once per [`ACCESS_INTERVAL_SECS`] from the
//! background sync, and deletes its older ones; readers keep the newest
//! accepted record per device. The merged time of a file is the newest
//! over this device and every other device that is not removed.
//!
//! Why not ledger events: access times change with every use, and the
//! ledger is append-only and replicated to every device forever
//! (checkpoints bound it, they do not erase it). One replaceable record per
//! device and folder costs O(files) bytes regardless of how often files are
//! used, and is not announced. The ledger keeps facts about data; this is a
//! hint for advice.

use super::*;
use crate::record::{Id16, KeyId, RecordStore};
use crate::records3::{self, AccessBody};

/// Least time between two access exchanges started by a sync.
pub const ACCESS_INTERVAL_SECS: i64 = 3600;

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
        crate::logged_op!("exchange access records", "", {
            self.exchange_access_records_inner()
        })
    }

    fn exchange_access_records_inner(&mut self) -> Result<AccessExchangeReport> {
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
        let folder = members3::bin(&fk.folder)?;
        let me = self.me3();
        let stream = records3::access_stream(folder, me);
        let key = KeyId::Meta {
            folder,
            epoch: fk.epoch,
        };
        let written = now.max(cache.published_utc + 1);
        let accessed: Vec<(String, i64)> = state
            .accessed
            .iter()
            .filter(|(p, _)| crate::names::check_synced_path(p).is_ok())
            .map(|(p, t)| (p.clone(), *t))
            .collect();
        let published = self.write_record3(storages, &stream, &key, |seq| AccessBody {
            folder,
            device: me,
            seq,
            updated_utc: written,
            accessed: accessed.clone(),
        })?;
        // Only the newest record of a device is ever read.
        let view = self.view3()?;
        self.each_store3(storages, &view, |_, store, _| {
            for l in store.list_after(&stream, 0)? {
                if l.seq < published.seq {
                    for n in &l.names {
                        store.storage.delete(n)?;
                    }
                }
            }
            Ok(())
        })?;
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
        let folder = members3::bin(&fk.folder)?;
        let me = self.me3();
        let writers: Vec<Id16> = self
            .stream_writers3()
            .into_iter()
            .filter(|d| *d != me && !self.is_revoked(&DeviceId::from_bytes(d)))
            .collect();
        let streams: Vec<crate::record::StreamRef> = writers
            .iter()
            .map(|d| records3::access_stream(folder, *d))
            .collect();
        let view = self.view3()?;
        let mut newest: BTreeMap<Id16, AccessBody> = BTreeMap::new();
        self.each_store3(storages, &view, |_, store: &RecordStore<'_>, counter| {
            for b in records3::read_newest::<AccessBody>(store, &streams, counter)? {
                if newest.get(&b.device).is_none_or(|n| n.seq < b.seq) {
                    newest.insert(b.device, b);
                }
            }
            Ok(())
        })?;
        let mut read = 0;
        for (dev, body) in newest {
            let dev = DeviceId::from_bytes(&dev);
            if cache
                .remote
                .get(&dev)
                .is_some_and(|r| r.written_utc >= body.updated_utc)
            {
                continue;
            }
            cache.remote.insert(
                dev,
                RemoteAccess {
                    written_utc: body.updated_utc,
                    accessed: body.accessed.into_iter().collect(),
                },
            );
            read += 1;
        }
        Ok(read)
    }
}
