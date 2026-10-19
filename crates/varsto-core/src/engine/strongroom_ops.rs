// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Strongroom conversion and key management (S-012) on storage format 3
//! (`docs/spec/format-3-design.md` section 5, "Strongroom keys and
//! conversion"; `alpha-0-format.md` section 77.16).
//!
//! A Strongroom's key K13 takes the place of K9 for its folder. It is never
//! granted and never under the vault key: a `strongroom` record carries its
//! wraps, one per enrolled security key, and each device unwraps it with a
//! touch. The folder id comes from the key (`membership3::strongrooms`).
//!
//! Converting a folder makes a new folder (new id, new K13) whose record
//! names the old one in `converted_from`: every current file is brought to
//! this device (placeholders are fetched under the old key) and pushed into
//! the new folder; only then is the old folder removed (its folder record
//! carries `removed`) and are its packs and records deleted from the
//! storages. Each step can be repeated: the conversion is journalled in the
//! encrypted keyring, and nothing old is removed before the new copy
//! exists. A new key for a Strongroom (`rekey`) is the same conversion from
//! a Strongroom to a Strongroom. The other devices take the new folder in
//! the old one's place when they read its record.

use super::*;
use crate::membership3::strongrooms::StrongroomRecord;
use crate::strongroom::{self, Conversion, EnrolledKey, SecurityKey, StrongroomInfo};

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
    // ----- records --------------------------------------------------------------

    /// The id of a Strongroom this device makes with key `k13`.
    pub fn strongroom_id_for(&self, k13: &SecretKey) -> FolderId {
        let nonce = crate::membership3::strongrooms::creation_nonce(k13);
        FolderId::from_bytes(&crate::membership3::folders::folder_id(&self.me3(), &nonce))
    }

    /// Create the Strongroom folder `name` with key `k13` in the
    /// membership records (folder record and key wraps). `others` take
    /// part with their roles; `converted_from` names the folder it
    /// replaces.
    pub(super) fn publish_strongroom(
        &mut self,
        name: &str,
        k13: &SecretKey,
        info: &StrongroomInfo,
        converted_from: Option<(crate::record::Id16, Vec<(crate::record::Id16, u64)>)>,
        others: &[(crate::record::Id16, crate::membership3::Role)],
        rekey: bool,
    ) -> Result<()> {
        let id = members3::bin(&self.strongroom_id_for(k13))?;
        if self.f3.members.strongrooms.contains_key(&id) {
            return Ok(()); // a resumed conversion wrote it already
        }
        let (from, covered) = match converted_from {
            Some((f, c)) => (Some(f), c),
            None => (None, Vec::new()),
        };
        let record = StrongroomRecord {
            folder: id,
            epoch: 0,
            wraps: StrongroomRecord::wraps_of(info)?,
            check_hex: info.check_hex.clone(),
            updated_utc: info.updated_utc,
            stamp: Default::default(),
            escrow: None,
            converted_from: from,
            covered,
            rekey,
        };
        let others = others.to_vec();
        let k13 = k13.clone();
        let name = name.to_string();
        self.with_enrolled(|m| {
            if m.registry.get(&id).is_none() {
                m.create_strongroom(&name, &k13, record, &others)?;
            } else {
                m.write_strongroom(record)?;
            }
            Ok(())
        })?
        .ok_or_else(|| anyhow!("this device has no storage to publish the Strongroom to"))
    }

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
                let fk = strongroom::unlock(key, &self.vault.vault_id, &id, &info)?;
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
                let fk = SecretKey::random();
                let id = self.strongroom_id_for(&fk);
                let info = strongroom::enroll(key, method, &self.vault.vault_id, &id, &fk)?;
                (id, info, fk)
            }
        };
        self.convert_to_strongroom_with(folder, &new_id, &fk, info, unlock_minutes)
    }

    /// Convert `folder` into a Strongroom whose key and key wraps were made
    /// already (the command line touched the security key and hands them to
    /// the running service; `new_id` is `strongroom_id_for` the key).
    /// Steps, each safe to repeat:
    ///
    /// 1. journal the conversion in the keyring, sync the folder under its
    ///    old key (refused while remote versions could not be downloaded),
    ///    and bring every current file here (placeholders are fetched);
    /// 2. publish the new folder's records, switch this device to it
    ///    (selective mount, unlocked for `unlock_minutes`) and push every
    ///    file into it; files that were placeholders become placeholders
    ///    again;
    /// 3. remove the old folder (`finish_strongroom_conversions`: its
    ///    record carries `removed`, its packs and records are deleted;
    ///    retried on every sync).
    pub fn convert_to_strongroom_with(
        &mut self,
        folder: &str,
        new_id: &FolderId,
        folder_key: &SecretKey,
        info: StrongroomInfo,
        unlock_minutes: u64,
    ) -> Result<ConvertReport> {
        crate::logged_op_plain!("convert to strongroom with", folder, {
            self.convert_into(folder, new_id, folder_key, info, unlock_minutes, false)
        })
    }

    /// Rotate a Strongroom's key: the conversion above, from a Strongroom to
    /// a Strongroom. The folder gets a new id and a new random key wrapped
    /// for every enrolled security key (`strongroom::rewrap_enrolled`), its
    /// content is re-encrypted, and the old copies (packs, records, the old
    /// key wraps) are deleted from the storages. The folder must be
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
        crate::logged_op_plain!("rekey strongroom with", folder, {
            self.convert_into(folder, new_id, folder_key, info, unlock_minutes, true)
        })
    }

    /// Rotate a Strongroom's key with the security keys this device can
    /// use (software key files in the vault directory, or the libfido2
    /// tools: one touch to unlock, then one per enrolled key).
    pub fn rekey_strongroom(&mut self, folder: &str, unlock_minutes: u64) -> Result<ConvertReport> {
        if let Some((id, info)) = self.strongroom_conversion(folder) {
            let (fk, _) =
                strongroom::unlock_enrolled(&self.home, &self.vault.vault_id, &id, &info)?;
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
        let fk = SecretKey::random();
        let id = self.strongroom_id_for(&fk);
        let new_info =
            strongroom::rewrap_enrolled(&self.home, &self.vault.vault_id, &id, &fk, &info)?;
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
        // The key and the wraps come from the caller (the command line): the
        // key must be the one the wraps' commitment names, and the id the
        // one the key gives.
        info.verify_key(new_id, folder_key)?;
        if &self.strongroom_id_for(folder_key) != new_id {
            bail!("the new folder id is not the one this key gives (use `strongroom_id_for`)");
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
            bail!("a shared folder cannot become a Strongroom (other people hold its key)");
        }
        let old_id = rec.folder_id.clone();
        let old_bin = members3::bin(&old_id)?;
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

        // 1. Bring the folder up to date under its old key, every file here.
        let id = old_id.to_string();
        self.pull(&id)?;
        let new_bin = members3::bin(new_id)?;
        if self
            .f3
            .members
            .strongrooms
            .values()
            .any(|r| r.converted_from == Some(old_bin) && r.folder != new_bin)
        {
            self.keyring.converting.remove(&old_id);
            self.save_keyring()?;
            bail!(
                "{} was converted into a Strongroom by another device already; sync to adopt it",
                rec.name
            );
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
        let mut report = ConvertReport {
            folder: rec.name.clone(),
            old_folder_id: old_id.to_string(),
            folder_id: new_id.to_string(),
            ..Default::default()
        };
        let live: Vec<FileState> = state
            .files
            .values()
            .filter(|f| !f.deleted)
            .cloned()
            .collect();
        let task = crate::activity::start(
            crate::activity::STRONGROOM_CONVERT,
            &rec.name,
            live.len() as u64,
            crate::activity::Unit::Items,
        );
        let mut fetched = Vec::new();
        for file in &live {
            task.advance(1);
            let disk = self.disk_of(&root, &state, &file.path);
            let here = fs::metadata(&disk).ok().filter(|md| {
                state.local_index.get(&file.path).is_some_and(|ix| {
                    ix.size == md.len()
                        && ix.mtime == mtime_ns(md)
                        && ix.content_hash == file.content_hash
                })
            });
            if here.is_none() && disk.exists() {
                bail!(
                    "{} changed during the conversion; run the command again",
                    file.path
                );
            }
            if here.is_none() {
                self.fetch_file(&id, &file.path).with_context(|| {
                    format!(
                        "{}: download it under the old key to re-encrypt it",
                        file.path
                    )
                })?;
                fetched.push(file.path.clone());
            }
            report.files += 1;
        }
        report.files_fetched = fetched.len() as u64;
        let mut covered: Vec<(crate::record::Id16, u64)> = state
            .last_seen
            .iter()
            .filter_map(|(d, s)| Some((members3::bin(d).ok()?, *s)))
            .collect();
        covered.push((self.me3(), state.published_seq));
        let others: Vec<(crate::record::Id16, crate::membership3::Role)> = self
            .f3
            .members
            .registry
            .get(&old_bin)
            .map(|st| {
                st.participants()
                    .into_iter()
                    .map(|p| (p.device, p.role))
                    .collect()
            })
            .unwrap_or_default();

        // 2. The new folder's records, then switch here and push into it.
        self.publish_strongroom(
            &rec.name,
            folder_key,
            &info,
            Some((old_bin, covered)),
            &others,
            rekey,
        )?;
        let new_rec = FolderRecord {
            folder_id: new_id.clone(),
            name: rec.name.clone(),
            key_hex: String::new(),
            k11_hex: String::new(),
            created_by: self.vault.device_id.clone(),
            created_utc: util::now_utc(),
            shared: false,
            policy: rec.policy.clone(),
            policy_updated_utc: rec.policy_updated_utc,
            placement: rec.placement.clone(),
            placement_updated_utc: rec.placement_updated_utc,
            strongroom: Some(info),
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
            backup: None,
        };
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
            folder_safety::rekey_marker(&m.path, &old_id, new_id);
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
        let new_name = new_id.to_string();
        let pushed = self.push(&new_name)?;
        report.chunks_uploaded = pushed.chunks_uploaded;
        report.bytes_uploaded = pushed.bytes_uploaded;
        for p in &fetched {
            self.free_file(&new_name, p)?;
        }
        // File analyses stay with the files (content hashes are per key).
        let new_state = self.load_state(new_id)?;
        self.notes_rekeyed(&old_id, new_id, &state, &new_state);

        // 3. Remove the old folder.
        report.cleanup = self.finish_strongroom_conversions();
        Ok(report)
    }

    fn save_keyring(&self) -> Result<()> {
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Remove the old folder of every switched conversion: its folder
    /// record carries `removed`, its packs and records leave this device's
    /// storages. A conversion leaves the keyring only when that worked.
    /// Never fails: what could not be done is reported and retried on the
    /// next sync.
    pub fn finish_strongroom_conversions(&mut self) -> CleanupReport {
        let mut report = CleanupReport::default();
        let pending: Vec<Conversion> = self
            .keyring
            .converting
            .values()
            .filter(|c| c.switched)
            .cloned()
            .collect();
        let mut done = Vec::new();
        for c in pending {
            match self.remove_old_copies(&c.old) {
                Ok((objects, records)) => {
                    report.objects_deleted += objects;
                    report.records_deleted += records;
                    done.push(c.old.folder_id.clone());
                }
                Err(e) => report.failures.push(format!("{}: {e:#}", c.old.name)),
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

    /// The old folder's removal and every pack and record of it on this
    /// device's storages. Returns (block objects in the deleted packs,
    /// records deleted).
    fn remove_old_copies(&mut self, old: &FolderRecord) -> Result<(u64, u64)> {
        let id = members3::bin(&old.folder_id)?;
        let removed = self
            .f3
            .members
            .registry
            .get(&id)
            .is_none_or(|st| st.is_removed());
        if !removed {
            self.with_enrolled(|m| m.remove_folder(&id))?
                .ok_or_else(|| anyhow!("no storage to publish the removal to"))?;
        }
        // The blocks the deleted packs held (one pack holds many).
        let objects: BTreeSet<[u8; 32]> = match self.table3(&id) {
            Ok(t) => {
                let t = t.read().unwrap_or_else(|e| e.into_inner());
                t.scan().filter_map(|r| r.ok()).map(|r| r.object).collect()
            }
            Err(_) => BTreeSet::new(),
        };
        let (packs, records) = self.purge_folder(&id, &old.name)?;
        let objects = if packs == 0 { 0 } else { objects.len() as u64 };
        let _ = fs::remove_file(self.state_path(&old.folder_id));
        Ok((objects, records))
    }

    /// Another device converted a folder into a Strongroom (or gave one a
    /// new key): mount the new folder in the old one's place (selective,
    /// locked), replace the plain copies that the converted copy includes
    /// with placeholders, and forget the old folder. Files with changes the
    /// converted copy may not include stay as they are: after the next
    /// unlock they are synced like new local files (identical content
    /// merges, different content becomes a conflict copy).
    pub(super) fn adopt_conversions(&mut self) -> Result<()> {
        let me = self.me3();
        let found: Vec<(FolderId, FolderId, Option<u64>)> = self
            .f3
            .members
            .strongrooms
            .values()
            .filter_map(|r| {
                let old = FolderId::from_bytes(&r.converted_from?);
                let covered = r.covered.iter().find(|(d, _)| *d == me).map(|(_, s)| *s);
                Some((old, FolderId::from_bytes(&r.folder), covered))
            })
            .filter(|(old, new, _)| {
                self.keyring
                    .folders
                    .get(old)
                    .is_some_and(|f| !f.is_removed())
                    && !self.keyring.converting.contains_key(old)
                    && old != new
            })
            .collect();
        for (old_id, new_id, covered) in found {
            let Some(old) = self.keyring.folders.get(&old_id).cloned() else {
                continue;
            };
            if let Some(root) = self
                .config
                .folders
                .iter()
                .find(|m| m.folder_id == old_id)
                .map(|m| m.path.clone())
            {
                let state = self.load_state(&old_id)?;
                let included = state.published_seq <= covered.unwrap_or(0);
                if included {
                    for f in state.files.values().filter(|f| !f.deleted) {
                        let disk = self.disk_of(&root, &state, &f.path);
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
                    .filter(|m| m.folder_id == old_id)
                {
                    m.folder_id = new_id.clone();
                    m.selective = true;
                    folder_safety::rekey_marker(&m.path, &old_id, &new_id);
                }
                self.config.save(&self.home)?;
                let _ = fs::remove_file(self.state_path(&old_id));
                // The converting device carried the analyses over.
                self.forget_notes(&old_id);
            }
            self.unlocked.remove(&old.folder_id);
            self.keyring.folders.remove(&old.folder_id);
            self.save_keyring()?;
        }
        Ok(())
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
        let (fk, _) =
            strongroom::unlock_enrolled(&self.home, &self.vault.vault_id, &rec.folder_id, &info)?;
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
        crate::logged_op_plain!("add strongroom key", folder, {
            self.add_strongroom_key_inner(folder, method, key, label)
        })
    }

    fn add_strongroom_key_inner(
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
        let k = strongroom::enroll_key(
            key,
            method,
            &self.vault.vault_id,
            &rec.folder_id,
            &unlocked.folder_key()?,
            label,
        )?;
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
        crate::logged_op_plain!("remove strongroom key", folder, {
            self.remove_strongroom_key_inner(folder, which)
        })
    }

    fn remove_strongroom_key_inner(&mut self, folder: &str, which: &str) -> Result<EnrolledKey> {
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
        let mut new_info = StrongroomInfo::from_keys(keys, updated)?;
        new_info.check_hex = info.check_hex.clone();
        if self.vault.member {
            bail!("a member device cannot change the keys of the owner's Strongroom");
        }
        let id = members3::bin(&rec.folder_id)?;
        let old = self.f3.members.strongrooms.get(&id).cloned();
        let record = StrongroomRecord {
            folder: id,
            epoch: 0,
            wraps: StrongroomRecord::wraps_of(&new_info)?,
            check_hex: new_info.check_hex.clone(),
            updated_utc: updated,
            stamp: Default::default(),
            escrow: None,
            converted_from: old.as_ref().and_then(|o| o.converted_from),
            covered: old.as_ref().map(|o| o.covered.clone()).unwrap_or_default(),
            rekey: old.as_ref().is_some_and(|o| o.rekey),
        };
        self.with_enrolled(|m| m.write_strongroom(record))?
            .ok_or_else(|| anyhow!("this device has no storage to publish the keys to"))?;
        let mut new_rec = rec.clone();
        new_rec.strongroom = Some(new_info);
        self.keyring.folders.insert(rec.folder_id.clone(), new_rec);
        self.save_keyring()?;
        // This device's older lists hold wraps of keys that may be gone now
        // (another owner's go when it writes its next list).
        let prefix = format!(
            "vault/strongroom/{}/{}/",
            hex::encode(id),
            hex::encode(self.me3())
        );
        for (_, backend) in self.metadata_storages(true)? {
            let names = backend.list(&prefix)?;
            let seq = |k: &String| {
                crate::record::RecordName::parse_as(crate::record::Kind::Strongroom, k)
                    .map(|n| n.seq)
            };
            let newest = names.iter().filter_map(seq).max().unwrap_or(0);
            for k in &names {
                if seq(k).is_some_and(|s| s < newest) {
                    backend.delete(k)?;
                }
            }
        }
        Ok(n)
    }
}
