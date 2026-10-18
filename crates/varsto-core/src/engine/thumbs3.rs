// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Thumbnails of storage format 3 (`docs/spec/format-3-design.md`
//! section 5, record kind 22; `crate::thumbs` makes the pictures).
//!
//! A thumbnail is made once on a device that holds the plaintext and is
//! small, so a device writes the thumbnails of one pass as one `thumbs`
//! record in its own stream `thumbs/<folder>/<device>/`, sealed under the
//! folder's metadata key. Readers take the union of every writer's records
//! (`records3::thumbnails`): the picture of a content hash is the first of
//! (writer, seq). Records are not announced and stay until their folder
//! goes; a storage added later gets them copied (`replicate_records3`).
//!
//! Each device keeps the pictures it made or read in a local cache,
//! `state/thumbs3/<folder>/<content hash>.enc`, sealed under a key derived
//! from the device's master key: nothing readable is left outside the
//! process (a folder kept encrypted here stays so).

use super::*;
use crate::crypto::SecretKey;
use crate::record::{Id16, KeyId};
use crate::records3::{self, ThumbsBody};

/// How far the thumbnail records of each writer were read, and when the
/// storages were last asked.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ThumbsApplied {
    #[serde(default)]
    checked_utc: i64,
    #[serde(default)]
    seqs: BTreeMap<String, u64>,
}

/// A miss asks the storages for new records at most this often.
const PULL_EVERY_SECS: i64 = 5;

fn hash32(content_hash: &str) -> Option<[u8; 32]> {
    hex::decode(content_hash).ok()?.try_into().ok()
}

impl Engine {
    fn thumb_dir(&self, folder: &FolderId) -> PathBuf {
        self.home
            .join("state")
            .join("thumbs3")
            .join(folder.as_str())
    }

    fn thumb_cache_key(&self) -> SecretKey {
        self.keys.master.derive("thumbnail-cache", &[])
    }

    fn thumb_aad(&self, folder: &FolderId, hash: &[u8; 32]) -> Vec<u8> {
        crypto::aad(
            "thumbnail-cache",
            &[
                self.vault.vault_id.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                hash,
            ],
        )
    }

    fn thumb_file(&self, folder: &FolderId, hash: &[u8; 32]) -> PathBuf {
        self.thumb_dir(folder)
            .join(format!("{}.enc", hex::encode(hash)))
    }

    /// Whether this device holds the thumbnail of a content hash.
    pub(super) fn thumb_cached(&self, folder: &FolderId, content_hash: &str) -> bool {
        hash32(content_hash).is_some_and(|h| self.thumb_file(folder, &h).is_file())
    }

    fn thumb_put(&self, folder: &FolderId, hash: &[u8; 32], jpeg: &[u8]) -> Result<()> {
        let blob = crypto::encrypt(&self.thumb_cache_key(), &self.thumb_aad(folder, hash), jpeg)?;
        let path = self.thumb_file(folder, hash);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        util::write_atomic(&path, &blob)
    }

    fn thumb_get(&self, folder: &FolderId, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let blob = fs::read(self.thumb_file(folder, hash)).ok()?;
        crypto::decrypt(
            &self.thumb_cache_key(),
            &self.thumb_aad(folder, hash),
            &blob,
        )
        .ok()
    }

    /// Forget a removed folder's thumbnails on this device.
    pub(super) fn forget_thumbs3(&self, folder: &FolderId) {
        let _ = fs::remove_dir_all(self.thumb_dir(folder));
    }

    /// The hot metadata storages thumbnail records go to.
    fn thumb_storages(&self) -> Result<OpenStorages> {
        Ok(self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect())
    }

    /// Write `made` as one record of this device and keep the pictures.
    fn publish_thumbs3(
        &self,
        rec: &FolderRecord,
        storages: &OpenStorages,
        made: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<()> {
        if made.is_empty() {
            return Ok(());
        }
        let fk = self.folder_keys(rec)?;
        let folder = members3::bin(&rec.folder_id)?;
        let me = self.me3();
        let stream = records3::thumbs_stream(folder, me);
        let key = KeyId::Meta {
            folder,
            epoch: fk.epoch,
        };
        let mut thumbs: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        for (h, j) in made {
            thumbs.entry(h).or_insert(j);
        }
        let thumbs: Vec<([u8; 32], Vec<u8>)> = thumbs.into_iter().collect();
        self.write_record3(storages, &stream, &key, |seq| ThumbsBody {
            folder,
            device: me,
            seq,
            thumbs: thumbs.clone(),
        })?;
        for (h, j) in &thumbs {
            self.thumb_put(&rec.folder_id, h, j)?;
        }
        Ok(())
    }

    /// Read the thumbnail records of every writer past what was read,
    /// from the hot storages, into the local cache. Returns how many
    /// pictures were new here.
    fn pull_thumbs3(&self, rec: &FolderRecord, force: bool) -> Result<usize> {
        let storages = self.thumb_storages()?;
        if storages.is_empty() {
            return Ok(0);
        }
        let path = self.thumb_dir(&rec.folder_id).join("applied.json");
        let mut applied: ThumbsApplied = util::read_json_or_default(&path).unwrap_or_default();
        let now = util::now_utc();
        if !force && now - applied.checked_utc < PULL_EVERY_SECS {
            return Ok(0);
        }
        let folder = members3::bin(&rec.folder_id)?;
        let writers: Vec<Id16> = self.stream_writers3();
        let view = self.view3()?;
        let mut fresh: Vec<ThumbsBody> = Vec::new();
        let mut top: BTreeMap<String, u64> = applied.seqs.clone();
        self.each_store3(&storages, &view, |_, store, counter| {
            for d in &writers {
                let stream = records3::thumbs_stream(folder, *d);
                let after = applied.seqs.get(&hex::encode(d)).copied().unwrap_or(0);
                let read = store.read_after::<ThumbsBody>(&stream, after, counter)?;
                for r in read.accepted {
                    let e = top.entry(hex::encode(d)).or_insert(0);
                    *e = (*e).max(r.body.seq);
                    fresh.push(r.body);
                }
            }
            Ok(())
        })?;
        let mut added = 0;
        for (h, j) in records3::thumbnails(fresh.iter()) {
            if !self.thumb_file(&rec.folder_id, &h).is_file() {
                self.thumb_put(&rec.folder_id, &h, j)?;
                added += 1;
            }
        }
        applied.seqs = top;
        applied.checked_utc = now;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        util::write_json(&path, &applied)?;
        Ok(added)
    }

    /// Encrypted thumbnails for image and video files that have none yet (F-046).
    ///
    /// Bounded: at most `limit` pictures and `budget` of time per call (a
    /// low-priority background pass; the rest follows on the next sync). With
    /// no storage to put them on nothing is made and nothing is marked done.
    pub(super) fn make_thumbnails(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
        limit: usize,
        budget: std::time::Duration,
    ) -> Result<u64> {
        if state.thumbs_rev < 2 {
            let videos: Vec<String> = state
                .files
                .values()
                .filter(|f| thumbs::is_video(&f.path))
                .map(|f| f.content_hash.clone())
                .collect();
            for h in videos {
                state.thumbs_done.remove(&h);
            }
            state.thumbs_rev = 2;
        }
        let storages = self.thumb_storages()?;
        if storages.is_empty() {
            return Ok(0);
        }
        // Thumbnails other devices made are not made again.
        let _ = self.pull_thumbs3(rec, false);
        self.replicate_thumbnails(rec, state, &storages);
        let videos_here = thumbs::video_tool_available();
        let candidates: Vec<(String, String)> = state
            .files
            .values()
            .filter(|f| {
                !f.deleted
                    && !f.is_symlink()
                    && (thumbs::is_image(&f.path) || thumbs::is_video(&f.path))
                    && !state.thumbs_done.contains(&f.content_hash)
            })
            .map(|f| (f.path.clone(), f.content_hash.clone()))
            .collect();
        if candidates.is_empty() {
            return Ok(0);
        }
        let fk = self.folder_keys(rec)?;
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        let mut made: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut done: Vec<String> = Vec::new();
        let started = std::time::Instant::now();
        let mut attempts = 0usize;
        for (path, hash) in candidates {
            if attempts >= limit || started.elapsed() >= budget {
                break;
            }
            // Without a tool for videos (a phone, a computer without ffmpeg)
            // they wait: the app around the service may hand in a frame
            // (`store_thumbnail`), or ffmpeg is installed later.
            if thumbs::is_video(&path) && !encrypted_here && !videos_here {
                continue;
            }
            let Some(h32) = hash32(&hash) else {
                continue;
            };
            if self.thumb_cached(&rec.folder_id, &hash) {
                state.thumbs_done.insert(hash);
                continue;
            }
            let made_here = if encrypted_here {
                // Pictures are decoded in memory from their cached blocks;
                // videos would need a plain file, so none is made here.
                if thumbs::is_video(&path) {
                    state.thumbs_done.insert(hash);
                    continue;
                }
                if !state.local_index.contains_key(&path) {
                    continue;
                }
                // Blocks evicted from the cache: try again when they are back,
                // do not give the picture up for good.
                let cached = state.files.get(&path).is_some_and(|f| {
                    f.chunks
                        .iter()
                        .all(|c| self.cached_object(&c.object).is_some())
                });
                if !cached {
                    continue;
                }
                self.thumbnail_from_cache(&fk, state, &path)
            } else {
                let disk = self.disk_of(root, state, &path);
                if !disk.exists() {
                    continue;
                }
                thumbs::make_with(&disk, &path, &self.config.thumbnails)
            };
            attempts += 1;
            let Some(bytes) = made_here else {
                state.thumbs_done.insert(hash); // cannot make one; do not retry every time
                continue;
            };
            if bytes.is_empty() || bytes.len() > records3::MAX_THUMB {
                state.thumbs_done.insert(hash);
                continue;
            }
            made.push((h32, bytes));
            done.push(hash);
        }
        let count = made.len() as u64;
        // The record first: a thumbnail is done once it is on the storages.
        self.publish_thumbs3(rec, &storages, made)?;
        state.thumbs_done.extend(done);
        Ok(count)
    }

    /// Copy the thumbnail records other storages hold to a storage that was
    /// added later. A device that only reaches the new storage (a phone with
    /// a bucket) sees no previews otherwise. Best effort: a storage that
    /// cannot be reached now is tried again at the next sync.
    fn replicate_thumbnails(
        &self,
        rec: &FolderRecord,
        state: &mut FolderState,
        storages: &OpenStorages,
    ) {
        if storages.len() < 2 {
            for (spec, _) in storages {
                state.thumbs_replicated.insert(spec.name().to_string());
            }
            return;
        }
        if storages
            .iter()
            .all(|(s, _)| state.thumbs_replicated.contains(s.name()))
        {
            return;
        }
        let prefix = format!("thumbs/{}/", rec.folder_id);
        if self.replicate_records3(storages, &prefix).is_ok() {
            for (spec, _) in storages {
                state.thumbs_replicated.insert(spec.name().to_string());
            }
        }
    }

    /// Videos in plain folders on this device that have no thumbnail yet,
    /// for an app that makes frames itself (a phone): (folder, path, file).
    pub fn videos_without_thumbnails(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, PathBuf)>> {
        let mut out = Vec::new();
        for (rec, root) in self.folders() {
            let Some(root) = root else { continue };
            if self.mount_is_encrypted(&rec.folder_id) {
                continue;
            }
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| {
                !f.deleted
                    && thumbs::is_video(&f.path)
                    && !f.content_hash.is_empty()
                    && !state.thumbs_done.contains(&f.content_hash)
            }) {
                let disk = self.disk_of(&root, &state, &f.path);
                if disk.is_file() {
                    out.push((rec.name.clone(), f.path.clone(), disk));
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Store a thumbnail made outside the engine (a video frame from the
    /// phone's media framework) for the current version of a file: it is
    /// decoded and encoded again, and written as a record like any other.
    pub fn store_thumbnail(&mut self, folder: &str, path: &str, picture: &[u8]) -> Result<()> {
        let (rec, _) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .filter(|f| !f.deleted && !f.content_hash.is_empty())
            .ok_or_else(|| anyhow!("{path} is not a file of {folder}"))?;
        let hash = file.content_hash.clone();
        let h32 = hash32(&hash).ok_or_else(|| anyhow!("{path} has no content hash"))?;
        let jpeg = thumbs::normalize(picture).ok_or_else(|| anyhow!("not a picture"))?;
        let storages = self.thumb_storages()?;
        if storages.is_empty() {
            bail!("add a storage first: thumbnails are kept on the vault's storages");
        }
        self.publish_thumbs3(&rec, &storages, vec![(h32, jpeg)])?;
        state.thumbs_done.insert(hash);
        self.save_state(&rec.folder_id, &state)
    }

    /// Decrypted thumbnail of a file: from this device's cache, else from
    /// the thumbnail records of the storages.
    pub fn thumbnail(&self, folder: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let Some(file) = state.files.get(path) else {
            return Ok(None);
        };
        if file.deleted || file.content_hash.is_empty() {
            return Ok(None);
        }
        let Some(h) = hash32(&file.content_hash) else {
            return Ok(None);
        };
        // The folder's keys first: a device without them has no pictures.
        self.folder_keys(&rec)?;
        if let Some(t) = self.thumb_get(&rec.folder_id, &h) {
            return Ok(Some(t));
        }
        self.pull_thumbs3(&rec, false)?;
        Ok(self.thumb_get(&rec.folder_id, &h))
    }
}
