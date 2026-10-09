// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Strongroom conversion and key management (S-012).
//!
//! Converting a folder: the folder gets a new folder id and a new random
//! key wrapped by the security key; every current file is re-encrypted under
//! the new key (from the local copy, or downloaded under the old key first);
//! the new chunks and a manifest are stored and recorded in the ledger;
//! a conversion record tells the other devices; only then is the folder
//! switched here and are the old manifests, chunks, thumbnails, policy and
//! folder records deleted from the storages. Each step can be repeated: the
//! conversion is journalled in the encrypted keyring, uploads are
//! put-if-absent, and nothing old is removed before the new copy exists.
//! A new folder id keeps old and new objects, manifests and ledger facts
//! apart, so a device that still writes under the old key cannot mix the two.

use super::*;
use crate::strongroom::{
    self, Conversion, ConversionRecord, EnrolledKey, KeysRecord, SecurityKey, StrongroomInfo,
};

/// What a conversion did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct ConvertReport {
    pub folder: String,
    pub old_folder_id: String,
    pub folder_id: String,
    /// Current files re-encrypted under the new key.
    pub files: u64,
    /// Files that were placeholders here and were downloaded to re-encrypt them.
    pub files_fetched: u64,
    pub chunks_uploaded: u64,
    pub bytes_uploaded: u64,
    pub cleanup: CleanupReport,
}

/// What the removal of old copies did (summed over finished conversions).
#[derive(Clone, Debug, Serialize, Default)]
pub struct CleanupReport {
    pub objects_deleted: u64,
    pub manifests_deleted: u64,
    pub records_deleted: u64,
    /// Storages that could not be cleaned now; the clean-up is retried on
    /// every sync until it succeeds.
    pub failures: Vec<String>,
}

/// One enrolled key of a Strongroom, for lists (no secret, no wrap).
#[derive(Clone, Debug, Serialize)]
pub struct StrongroomKeySummary {
    /// Position in the list, from 1 (`strongroom remove-key` accepts it).
    pub number: usize,
    pub label: String,
    pub method: strongroom::Method,
    pub credential: String,
    pub name: String,
    pub added_utc: i64,
}

fn mtime_ns(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl Engine {
    // ----- conversion ---------------------------------------------------------

    /// The new folder id and key wraps of an interrupted conversion of
    /// `folder` on this device, so it can be resumed under the same key.
    pub fn strongroom_conversion(&self, folder: &str) -> Option<(FolderId, StrongroomInfo)> {
        let rec = self.keyring.find(folder)?;
        let c = self.keyring.converting.get(&rec.folder_id)?;
        Some((c.new_folder.clone(), c.info.clone()?))
    }

    /// Conversions this device has not finished: (folder name, switched).
    pub fn strongroom_conversions(&self) -> Vec<(String, bool)> {
        self.keyring
            .converting
            .values()
            .map(|c| (c.old.name.clone(), c.switched))
            .collect()
    }

    /// Convert an existing folder into a Strongroom with `key` (two touches:
    /// credential and wrap; one touch when resuming an interrupted
    /// conversion). See `convert_to_strongroom_with`.
    pub fn convert_to_strongroom(
        &mut self,
        folder: &str,
        method: strongroom::Method,
        key: &dyn SecurityKey,
        unlock_minutes: u64,
    ) -> Result<ConvertReport> {
        let (new_id, info, fk) = match self.strongroom_conversion(folder) {
            Some((id, info)) => {
                let fk = strongroom::unlock(key, &id, &info)?;
                (id, info, fk)
            }
            None => {
                if self.keyring.find(folder).is_some_and(|r| r.is_strongroom()) {
                    let cleanup = self.finish_strongroom_conversions();
                    return Ok(ConvertReport {
                        folder: folder.to_string(),
                        cleanup,
                        ..Default::default()
                    });
                }
                let id = FolderId::random();
                let fk = SecretKey::random();
                let info = strongroom::enroll(key, method, &id, &fk)?;
                (id, info, fk)
            }
        };
        self.convert_to_strongroom_with(folder, &new_id, &fk, info, unlock_minutes)
    }

    /// Convert `folder` into a Strongroom whose new id, key and key wraps
    /// were made already (the command line touched the security key and
    /// hands them to the running service). Steps, each safe to repeat:
    ///
    /// 1. journal the conversion in the keyring, sync the folder under its
    ///    old key (refused while remote versions could not be downloaded);
    /// 2. re-encrypt every current file under the new key and store each
    ///    chunk on every storage that takes it (at least one non-carrier
    ///    storage must hold every chunk), publish the manifest, commit the
    ///    ledger batch;
    /// 3. publish the conversion record, then switch this device to the new
    ///    folder (selective mount, unlocked for `unlock_minutes`) and publish
    ///    its folder record;
    /// 4. delete the old copies from every storage
    ///    (`finish_strongroom_conversions`, retried on every sync).
    pub fn convert_to_strongroom_with(
        &mut self,
        folder: &str,
        new_id: &FolderId,
        folder_key: &SecretKey,
        info: StrongroomInfo,
        unlock_minutes: u64,
    ) -> Result<ConvertReport> {
        self.convert_into(folder, new_id, folder_key, info, unlock_minutes, false)
    }

    /// Rotate a Strongroom's key: the conversion above, from a Strongroom to
    /// a Strongroom. The folder gets a new id and a new random key wrapped
    /// for every enrolled security key (`strongroom::rewrap_enrolled`), its
    /// content is re-encrypted, and the old copies (chunks, manifests, the
    /// old key wraps) are deleted from the storages. The folder must be
    /// unlocked here under its current key. Run it again with the same new
    /// key to resume (`strongroom_conversion` names it).
    pub fn rekey_strongroom_with(
        &mut self,
        folder: &str,
        new_id: &FolderId,
        folder_key: &SecretKey,
        info: StrongroomInfo,
        unlock_minutes: u64,
    ) -> Result<ConvertReport> {
        self.convert_into(folder, new_id, folder_key, info, unlock_minutes, true)
    }

    /// Rotate a Strongroom's key with the security keys this device can
    /// use (software key files in the vault directory, or the libfido2
    /// tools: one touch to unlock, then one per enrolled key).
    pub fn rekey_strongroom(&mut self, folder: &str, unlock_minutes: u64) -> Result<ConvertReport> {
        if let Some((id, info)) = self.strongroom_conversion(folder) {
            let (fk, _) = strongroom::unlock_enrolled(&self.home, &id, &info)?;
            if !self
                .keyring
                .find(folder)
                .is_some_and(|r| self.is_unlocked(&r.folder_id))
            {
                self.unlock_strongroom_enrolled(folder, unlock_minutes)?;
            }
            return self.rekey_strongroom_with(folder, &id, &fk, info, unlock_minutes);
        }
        let (rec, info) = self.strongroom_record(folder)?;
        if !self.is_unlocked(&rec.folder_id) {
            self.unlock_strongroom_enrolled(folder, unlock_minutes)?;
        }
        let id = FolderId::random();
        let fk = SecretKey::random();
        let new_info = strongroom::rewrap_enrolled(&self.home, &id, &fk, &info)?;
        self.rekey_strongroom_with(folder, &id, &fk, new_info, unlock_minutes)
    }

    fn convert_into(
        &mut self,
        folder: &str,
        new_id: &FolderId,
        folder_key: &SecretKey,
        info: StrongroomInfo,
        unlock_minutes: u64,
        rekey: bool,
    ) -> Result<ConvertReport> {
        if self.vault.member {
            bail!("a member device cannot convert folders of the owner's vault");
        }
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if rekey {
            if !rec.is_strongroom() {
                bail!(
                    "{} is not a Strongroom; convert it first (varsto strongroom convert)",
                    rec.name
                );
            }
            self.with_key(&rec)?;
        } else if rec.is_strongroom() {
            let cleanup = self.finish_strongroom_conversions();
            return Ok(ConvertReport {
                folder: rec.name.clone(),
                folder_id: rec.folder_id.to_string(),
                cleanup,
                ..Default::default()
            });
        }
        if rec.shared {
            bail!("a shared folder cannot become a Strongroom (other users hold its key)");
        }
        let old_id = rec.folder_id.clone();
        match self.keyring.converting.get(&old_id) {
            Some(c) if &c.new_folder != new_id => bail!(
                "a conversion of {} is already in progress; run the same command again to resume it with its security key",
                rec.name
            ),
            Some(_) => {}
            None => {
                self.keyring.converting.insert(
                    old_id.clone(),
                    Conversion {
                        old: rec.clone(),
                        new_folder: new_id.clone(),
                        info: Some(info.clone()),
                        switched: false,
                    },
                );
                self.save_keyring()?;
            }
        }

        // 1. Bring the folder up to date under its old key.
        let id = old_id.to_string();
        self.pull(&id)?;
        if let Some(other) = self.conversion_record(&old_id)? {
            if &other.new_folder != new_id {
                self.keyring.converting.remove(&old_id);
                self.save_keyring()?;
                bail!(
                    "{} was converted into a Strongroom by another device already; sync to adopt it",
                    rec.name
                );
            }
        }
        self.push(&id)?;
        let (rec, root) = self.resolve_folder(&id)?;
        let state = self.load_state(&old_id)?;
        if !state.pending_remote.is_empty() {
            bail!(
                "{} has versions from other devices that could not be downloaded yet ({}); the conversion would leave them behind. Make them reachable and sync first",
                rec.name,
                state
                    .pending_remote
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let me = self.vault.device_id.clone();
        let mut covered = state.last_seen.clone();
        covered.insert(me.clone(), state.published_seq);

        // 2. Re-encrypt under the new key.
        let mut report = ConvertReport {
            folder: rec.name.clone(),
            old_folder_id: old_id.to_string(),
            folder_id: new_id.to_string(),
            ..Default::default()
        };
        let old_keys = self.folder_keys(&rec)?;
        let new_keys = FolderKeys::from_folder_key(new_id, folder_key.clone())?;
        let readable = self.open_storages(false)?;
        let targets: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .open_storages(true)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        if targets.is_empty() {
            bail!("no storage to hold the re-encrypted copy: add one first");
        }
        let previous = self.load_state(new_id)?; // a resumed conversion
        let mut new_state = FolderState {
            published_seq: previous.published_seq,
            published_hash: previous.published_hash,
            accessed: state.accessed.clone(),
            ..Default::default()
        };
        let tmp_dir = self.home.join("convert-tmp");
        fs::create_dir_all(&tmp_dir)?;
        for file in state.files.values() {
            if file.deleted {
                new_state.files.insert(file.path.clone(), file.clone());
                continue;
            }
            let disk = root.join(&file.path);
            let local = fs::metadata(&disk).ok().filter(|md| {
                state.local_index.get(&file.path).is_some_and(|ix| {
                    ix.size == md.len()
                        && ix.mtime == mtime_ns(md)
                        && ix.content_hash == file.content_hash
                })
            });
            if local.is_none() && disk.exists() {
                bail!(
                    "{} changed during the conversion; run the command again",
                    file.path
                );
            }
            let source = if local.is_some() {
                disk.clone()
            } else {
                let tmp = tmp_dir.join(format!("{}", report.files));
                let mut pr = PullReport::default();
                self.download_to(&rec, &old_keys, &tmp, file, &readable, &mut pr)
                    .with_context(|| {
                        format!(
                            "{}: download it under the old key to re-encrypt it",
                            file.path
                        )
                    })?;
                report.files_fetched += 1;
                tmp
            };
            let result =
                self.reencrypt_file(&source, &old_keys, &new_keys, file, &targets, &mut report);
            if source != disk {
                let _ = fs::remove_file(&source);
            }
            let (chunks, content_hash) = result?;
            if let Some(md) = local {
                new_state.local_index.insert(
                    file.path.clone(),
                    LocalIndexEntry {
                        size: md.len(),
                        mtime: mtime_ns(&md),
                        content_hash: content_hash.clone(),
                    },
                );
                new_state.pinned.insert(file.path.clone());
            }
            new_state.files.insert(
                file.path.clone(),
                FileState {
                    content_hash,
                    chunks,
                    ..file.clone()
                },
            );
            report.files += 1;
        }
        let _ = fs::remove_dir_all(&tmp_dir);
        let mut new_rec = FolderRecord {
            folder_id: new_id.clone(),
            name: rec.name.clone(),
            key_hex: folder_key.to_hex(),
            created_by: me.clone(),
            created_utc: util::now_utc(),
            shared: false,
            policy: rec.policy.clone(),
            policy_updated_utc: rec.policy_updated_utc,
            strongroom: Some(info),
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
        };
        self.publish_manifest(&new_rec, &mut new_state)?;
        self.ensure_manifest_everywhere(&new_rec, &new_state)?;
        self.save_state(new_id, &new_state)?;
        self.pending.push(Event::FolderAdded {
            folder: new_id.clone(),
        });
        self.commit_batch()?;

        // 3. Tell the other devices, then switch here.
        let record = ConversionRecord {
            old_folder: old_id.clone(),
            new_folder: new_id.clone(),
            device: me.clone(),
            converted_utc: util::now_utc(),
            covered,
            rekey,
        };
        let fr_key = self.folder_record_key_now();
        let blob = record.seal(&self.vault.vault_id, &fr_key)?;
        let key = ConversionRecord::storage_key(&old_id);
        for (_, backend) in self.metadata_storages(true)? {
            // Replaced on a resumed conversion: `covered` may have grown.
            backend.delete(&key)?;
            backend.put_if_absent(&key, &blob)?;
        }
        new_rec.key_hex = String::new();
        self.keyring.folders.remove(&old_id);
        self.keyring.folders.insert(new_id.clone(), new_rec);
        if let Some(c) = self.keyring.converting.get_mut(&old_id) {
            c.switched = true;
            c.info = None;
        }
        self.save_keyring()?;
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == old_id)
        {
            m.folder_id = new_id.clone();
            m.selective = true;
        }
        self.config.save(&self.home)?;
        let _ = fs::remove_file(self.state_path(&old_id));
        self.unlocked.remove(&old_id);
        self.unlocked.insert(
            new_id.clone(),
            (
                folder_key.clone(),
                util::now_utc() + unlock_minutes as i64 * 60,
            ),
        );
        self.publish_registry()?;

        // 4. Remove the old copies.
        report.cleanup = self.finish_strongroom_conversions();
        Ok(report)
    }

    /// Re-encrypt one file under the new key, checking it against the old
    /// content hash on the way, and store every chunk. Returns the new chunk
    /// list and content hash.
    fn reencrypt_file(
        &mut self,
        source: &Path,
        old: &FolderKeys,
        new: &FolderKeys,
        file: &FileState,
        targets: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut ConvertReport,
    ) -> Result<(Vec<ChunkRef>, String)> {
        let handle = fs::File::open(source)?;
        let mut old_hash = KeyedHasher::new(&old.hash);
        let mut new_hash = KeyedHasher::new(&new.hash);
        let mut chunks = Vec::new();
        for chunk in Chunker::new(std::io::BufReader::new(handle), self.chunker)? {
            let chunk = chunk?;
            old_hash.update(&chunk);
            new_hash.update(&chunk);
            let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&new.hash, &chunk));
            let ct = crypto::encrypt_with_nonce(
                &new.chunk_key(new.epoch, &chunk_id)?,
                &new.chunk_nonce(new.epoch, &chunk_id)?,
                &new.chunk_aad(&self.vault.vault_id, &chunk_id, chunk.len() as u64),
                &crate::pack::pack(&chunk),
            )?;
            let object = ObjectName::from_bytes(&crypto::hash(&ct));
            let key = chunk_storage_key(&object);
            let mut held = false;
            for (spec, backend) in targets {
                match backend.put_if_absent(&key, &ct) {
                    Ok(true) => {
                        report.chunks_uploaded += 1;
                        report.bytes_uploaded += ct.len() as u64;
                    }
                    Ok(false) => {}
                    // A pool with no disk attached (or no room) gets the
                    // chunk from a later push, like any other new chunk.
                    Err(e)
                        if matches!(
                            pool::pool_error(&e),
                            Some(PoolError::NoDiskAttached { .. } | PoolError::NoRoom { .. })
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                held = true;
                self.pending.push(Event::ChunkStored {
                    folder: new.folder.clone(),
                    chunk: chunk_id.clone(),
                    object: object.clone(),
                    storage: spec.name().to_string(),
                    size: ct.len() as u64,
                });
            }
            if !held {
                bail!(
                    "no storage took a block of {}; attach a disk or add a storage and run again",
                    file.path
                );
            }
            self.pending.push(Event::ChunkOnDevice {
                folder: new.folder.clone(),
                chunk: chunk_id.clone(),
                object: object.clone(),
                size: chunk.len() as u64,
            });
            chunks.push(ChunkRef {
                chunk: chunk_id,
                object,
                size: chunk.len() as u64,
                epoch: new.epoch,
            });
        }
        if hex::encode(old_hash.finalize()) != file.content_hash {
            bail!(
                "{} changed during the conversion; run the command again",
                file.path
            );
        }
        Ok((chunks, hex::encode(new_hash.finalize())))
    }

    fn conversion_record(&self, old: &FolderId) -> Result<Option<ConversionRecord>> {
        let fr_keys = self.folder_record_keys();
        for (_, backend) in self.metadata_storages(false)? {
            if let Some(blob) = backend.get(&ConversionRecord::storage_key(old))? {
                if let Ok(r) = fr_keys
                    .iter()
                    .find_map(|k| ConversionRecord::open(&blob, &self.vault.vault_id, old, k).ok())
                    .ok_or(())
                {
                    return Ok(Some(r));
                }
            }
        }
        Ok(None)
    }

    fn save_keyring(&self) -> Result<()> {
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Delete the old copies of every switched conversion from the storages
    /// of this device; a conversion leaves the keyring (and the old key this
    /// device) only when every storage was cleaned. Never fails: what could
    /// not be done is reported and retried on the next sync.
    pub fn finish_strongroom_conversions(&mut self) -> CleanupReport {
        let mut report = CleanupReport::default();
        let pending: Vec<Conversion> = self
            .keyring
            .converting
            .values()
            .filter(|c| c.switched)
            .cloned()
            .collect();
        if pending.is_empty() {
            return report;
        }
        // The new folder record, in case an earlier run stopped before it.
        if let Err(e) = self.publish_registry() {
            report
                .failures
                .push(format!("publish folder records: {e:#}"));
        }
        let mut done = Vec::new();
        for c in pending {
            let before = report.failures.len();
            self.remove_old_copies(&c.old, &mut report);
            if report.failures.len() == before {
                done.push(c.old.folder_id.clone());
            }
        }
        if !done.is_empty() {
            for id in &done {
                self.keyring.converting.remove(id);
            }
            if let Err(e) = self.save_keyring() {
                report.failures.push(format!("save keyring: {e:#}"));
            }
        }
        report
    }

    /// Every object, manifest, thumbnail and record of the old folder, on
    /// every storage of this device (cold ones too). Objects are found from
    /// the ledger and from the old manifests (opened with the old key).
    fn remove_old_copies(&mut self, old: &FolderRecord, report: &mut CleanupReport) {
        let storages = match self.open_storages(true) {
            Ok(s) => s,
            Err(e) => {
                report.failures.push(format!("open storages: {e:#}"));
                return;
            }
        };
        let mut objects: BTreeSet<ObjectName> = BTreeSet::new();
        if let Ok(view) = self.view() {
            for ((folder, _), r) in view.chunks.iter() {
                if folder == &old.folder_id {
                    objects.insert(r.object.clone());
                }
            }
        }
        let meta = old.keys().ok().map(|k| k.meta);
        let manifest_prefix = format!("manifests/{}/", old.folder_id);
        for (_, backend) in storages.iter().filter(|(s, _)| !s.is_data_only()) {
            let Ok(keys) = backend.list(&manifest_prefix) else {
                continue; // reported when deleting below
            };
            for key in keys {
                let Some((dev, file)) = key
                    .strip_prefix(&manifest_prefix)
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Some(seq)) = (
                    DeviceId::from_hex(dev),
                    file.strip_suffix(".enc")
                        .and_then(|s| s.parse::<u64>().ok()),
                ) else {
                    continue;
                };
                let (Some(meta), Ok(Some(blob))) = (&meta, backend.get(&key)) else {
                    continue;
                };
                if let Ok(m) =
                    Manifest::open(&blob, &self.vault.vault_id, &old.folder_id, &dev, seq, meta)
                {
                    for f in m.files.values() {
                        objects.extend(f.chunks.iter().map(|c| c.object.clone()));
                    }
                }
            }
        }
        let record_key = FolderRecord::storage_key(&old.created_by, &old.folder_id);
        for (spec, backend) in &storages {
            let r: Result<()> = (|| {
                let present: HashSet<String> = backend.list("chunks/")?.into_iter().collect();
                for o in &objects {
                    let key = chunk_storage_key(o);
                    if present.contains(&key) {
                        backend.delete(&key)?;
                        report.objects_deleted += 1;
                    }
                }
                if spec.is_data_only() {
                    return Ok(());
                }
                for key in backend.list(&manifest_prefix)? {
                    backend.delete(&key)?;
                    report.manifests_deleted += 1;
                }
                let prefixes = [
                    format!("thumbs/{}/", old.folder_id),
                    format!("{}{}/", vault::PolicyRecord::PREFIX, old.folder_id),
                    // A re-keyed Strongroom's old key wraps.
                    format!("{}{}/", KeysRecord::PREFIX, old.folder_id),
                    // Last-accessed records under the old key name files.
                    format!("vault/access/{}/", old.folder_id),
                ];
                for prefix in prefixes {
                    for key in backend.list(&prefix)? {
                        backend.delete(&key)?;
                        report.records_deleted += 1;
                    }
                }
                // The old folder record holds the old key under the vault
                // key: it must go. The conversion record (no key) stays, for
                // devices that have not synced since.
                if backend.exists(&record_key)? {
                    backend.delete(&record_key)?;
                    report.records_deleted += 1;
                }
                Ok(())
            })();
            if let Err(e) = r {
                report.failures.push(format!("{}: {e:#}", spec.name()));
            }
        }
    }

    /// Learn conversions and key-list changes that other devices published
    /// (called from `pull_registry`).
    pub(super) fn pull_strongroom_records(&mut self) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        let fr_keys = self.folder_record_keys();
        let mut changed = false;
        let mut conversions: BTreeMap<FolderId, ConversionRecord> = BTreeMap::new();
        for (_, backend) in self.metadata_storages(false)? {
            for key in backend.list(KeysRecord::PREFIX)? {
                let Some((fid, stamp)) = key
                    .strip_prefix(KeysRecord::PREFIX)
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let Ok(fid) = FolderId::from_hex(fid) else {
                    continue;
                };
                let stamp: i64 = stamp
                    .strip_suffix(".enc")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let Some(local) = self
                    .keyring
                    .folders
                    .get(&fid)
                    .and_then(|r| r.strongroom.as_ref())
                else {
                    continue;
                };
                if stamp <= local.updated_utc {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Ok(r) = fr_keys
                        .iter()
                        .find_map(|k| KeysRecord::open(&blob, &self.vault.vault_id, &fid, k).ok())
                        .ok_or(())
                    {
                        if let Some(f) = self.keyring.folders.get_mut(&fid) {
                            if f.strongroom
                                .as_ref()
                                .is_some_and(|i| r.info.updated_utc > i.updated_utc)
                            {
                                f.strongroom = Some(r.info);
                                changed = true;
                            }
                        }
                    }
                }
            }
            for key in backend.list(ConversionRecord::PREFIX)? {
                let Some(old) = key
                    .strip_prefix(ConversionRecord::PREFIX)
                    .and_then(|r| r.strip_suffix(".enc"))
                    .and_then(|r| FolderId::from_hex(r).ok())
                else {
                    continue;
                };
                // A Strongroom is "converted" again when its key is rotated.
                let known = self.keyring.folders.contains_key(&old);
                if !known || self.keyring.converting.contains_key(&old) {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Ok(r) = fr_keys
                        .iter()
                        .find_map(|k| {
                            ConversionRecord::open(&blob, &self.vault.vault_id, &old, k).ok()
                        })
                        .ok_or(())
                    {
                        conversions.insert(old, r);
                    }
                }
            }
        }
        for (_, c) in conversions {
            // Wait until the new folder's record has arrived too.
            if self.keyring.folders.contains_key(&c.new_folder) {
                self.adopt_conversion(&c)?;
                changed = true;
            }
        }
        if changed {
            self.save_keyring()?;
        }
        Ok(())
    }

    /// Another device converted a folder into a Strongroom: mount the new
    /// folder in the old one's place (selective, locked), replace the plain
    /// copies that are stored elsewhere with placeholders, forget the old
    /// key once the old copies are removed. Files with changes the
    /// converted copy may not include stay as they are: after the next
    /// unlock they are synced like new local files (identical content
    /// merges, different content becomes a conflict copy).
    fn adopt_conversion(&mut self, c: &ConversionRecord) -> Result<()> {
        let Some(old) = self.keyring.folders.get(&c.old_folder).cloned() else {
            return Ok(());
        };
        let me = self.vault.device_id.clone();
        if let Some(root) = self
            .config
            .folders
            .iter()
            .find(|m| m.folder_id == old.folder_id)
            .map(|m| m.path.clone())
        {
            let state = self.load_state(&old.folder_id)?;
            let included = state.published_seq <= c.covered.get(&me).copied().unwrap_or(0);
            if included {
                for f in state.files.values().filter(|f| !f.deleted) {
                    let disk = root.join(&f.path);
                    let Ok(md) = fs::metadata(&disk) else {
                        continue;
                    };
                    let synced = state.local_index.get(&f.path).is_some_and(|ix| {
                        ix.content_hash == f.content_hash
                            && ix.size == md.len()
                            && ix.mtime == mtime_ns(&md)
                    });
                    if synced {
                        fs::remove_file(&disk)?;
                        Self::write_placeholder(&disk, f)?;
                    }
                }
            }
            for m in self
                .config
                .folders
                .iter_mut()
                .filter(|m| m.folder_id == old.folder_id)
            {
                m.folder_id = c.new_folder.clone();
                m.selective = true;
            }
            self.config.save(&self.home)?;
            let _ = fs::remove_file(self.state_path(&old.folder_id));
        }
        self.unlocked.remove(&old.folder_id);
        self.keyring.folders.remove(&old.folder_id);
        self.keyring.converting.insert(
            old.folder_id.clone(),
            Conversion {
                old,
                new_folder: c.new_folder.clone(),
                info: None,
                switched: true,
            },
        );
        self.save_keyring()
    }

    // ----- enrolled keys ------------------------------------------------------

    fn strongroom_record(&self, folder: &str) -> Result<(FolderRecord, StrongroomInfo)> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let info = rec
            .strongroom
            .clone()
            .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
        Ok((rec, info))
    }

    /// The security keys enrolled for a Strongroom.
    pub fn strongroom_keys(&self, folder: &str) -> Result<Vec<StrongroomKeySummary>> {
        let (_, info) = self.strongroom_record(folder)?;
        Ok(info
            .keys()
            .into_iter()
            .enumerate()
            .map(|(i, k)| StrongroomKeySummary {
                number: i + 1,
                name: k.short(),
                label: k.label,
                method: k.method,
                credential: k.credential,
                added_utc: k.added_utc,
            })
            .collect())
    }

    /// Unwrap with every enrolled key this device can use (hardware through
    /// the libfido2 tools, software key files in the vault directory).
    pub fn unlock_strongroom_enrolled(&mut self, folder: &str, minutes: u64) -> Result<SecretKey> {
        let (rec, info) = self.strongroom_record(folder)?;
        let (fk, _) = strongroom::unlock_enrolled(&self.home, &rec.folder_id, &info)?;
        self.unlocked.insert(
            rec.folder_id.clone(),
            (fk.clone(), util::now_utc() + minutes as i64 * 60),
        );
        Ok(fk)
    }

    /// Enrol a backup security key (two touches of the new key). The folder
    /// must be unlocked here with a key that is enrolled already.
    pub fn add_strongroom_key(
        &mut self,
        folder: &str,
        method: strongroom::Method,
        key: &dyn SecurityKey,
        label: &str,
    ) -> Result<usize> {
        let (rec, _) = self.strongroom_record(folder)?;
        let unlocked = self
            .with_key(&rec)
            .with_context(|| format!("unlock {} with an enrolled key first", rec.name))?;
        let k =
            strongroom::enroll_key(key, method, &rec.folder_id, &unlocked.folder_key()?, label)?;
        self.add_strongroom_key_enrolled(folder, k)
    }

    /// Add a key that was enrolled elsewhere (the command line touched the
    /// keys and hands the new wrap to the running service). Returns the
    /// number of enrolled keys.
    pub fn add_strongroom_key_enrolled(&mut self, folder: &str, key: EnrolledKey) -> Result<usize> {
        let (rec, info) = self.strongroom_record(folder)?;
        let mut keys = info.keys();
        if keys.iter().any(|k| k.credential == key.credential) {
            bail!("this security key is enrolled already");
        }
        if !key.label.is_empty() && keys.iter().any(|k| k.label == key.label) {
            bail!("a key labelled {} is enrolled already", key.label);
        }
        keys.push(key);
        self.set_strongroom_keys(&rec, &info, keys)
    }

    /// Remove an enrolled key (by number, label or credential). The last key
    /// is never removed. Returns the removed key.
    ///
    /// This stops Varsto from offering the key and removes its wrap from the
    /// storages, but it does not change the folder key: a removed key, used
    /// with an older copy of the records, still opens the folder.
    pub fn remove_strongroom_key(&mut self, folder: &str, which: &str) -> Result<EnrolledKey> {
        let (rec, info) = self.strongroom_record(folder)?;
        let mut keys = info.keys();
        if keys.len() < 2 {
            bail!(
                "{} has only one security key; enrol another before removing it",
                rec.name
            );
        }
        let gone = keys.remove(info.find_key(which)?);
        self.set_strongroom_keys(&rec, &info, keys)?;
        Ok(gone)
    }

    fn set_strongroom_keys(
        &mut self,
        rec: &FolderRecord,
        info: &StrongroomInfo,
        keys: Vec<EnrolledKey>,
    ) -> Result<usize> {
        let n = keys.len();
        let updated = util::now_utc().max(info.updated_utc + 1);
        let new_info = StrongroomInfo::from_keys(keys, updated)?;
        let mut new_rec = rec.clone();
        new_rec.strongroom = Some(new_info.clone());
        self.keyring
            .folders
            .insert(rec.folder_id.clone(), new_rec.clone());
        self.save_keyring()?;
        if self.vault.member {
            return Ok(n);
        }
        let record = KeysRecord {
            folder_id: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            info: new_info,
        };
        let fr_key = self.folder_record_key_now();
        let blob = record.seal(&self.vault.vault_id, &fr_key)?;
        let key = record.storage_key();
        let prefix = format!("{}{}/", KeysRecord::PREFIX, rec.folder_id);
        let folder_key = FolderRecord::storage_key(&new_rec.created_by, &new_rec.folder_id);
        let folder_blob = new_rec.seal(&self.vault.vault_id, &fr_key)?;
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&key, &blob)?;
            // Older lists, and the folder record's first copy, hold wraps
            // of keys that may be gone now.
            for k in backend.list(&prefix)? {
                if k != key {
                    backend.delete(&k)?;
                }
            }
            backend.delete(&folder_key)?;
            backend.put_if_absent(&folder_key, &folder_blob)?;
        }
        Ok(n)
    }
}
