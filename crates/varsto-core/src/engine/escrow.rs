// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Recovery copies of folder keys (`docs/spec/format-2-design.md` section 5).
//!
//! The recovery kit carries two word sets: the vault key (K3) and the
//! recovery key (K1). K1 is never stored on a device. Every key epoch of a
//! folder is kept on the storages as an **escrow** record,
//! `vault/folder-escrow/<folder>/<epoch>.enc`: a signed record of kind
//! `escrow` written by the device that made the epoch (or any device that
//! holds it later), its body (the epoch's key and the folder's first-epoch
//! key, which gives the dedup-hash key) sealed under K2 = derive(K1,
//! "recovery-wrap"). Writing needs K1 in memory: the session that made the
//! vault, `--with-recovery-key`, or `varsto recovery escrow`; until a
//! folder's escrow exists, the status and the Help page say so.
//!
//! `varsto join --recovery-words` rebuilds a device that lost everything:
//! the vault words open the registry (who wrote the escrows, which folders
//! exist) and the recovery words open the escrows. The vault words alone
//! give names and sizes only; the recovery words alone give nothing (the
//! registry, and so the writers' keys, stay closed).
//!
//! A recovery check (`vault/recovery-check.json`, signed, under the
//! registry key) lets a device tell the vault's recovery words from a
//! mistyped or foreign set before it writes anything with them.

use super::*;
use crate::record::{self, RecordKind, SignedRecord};

/// `vault/folder-escrow/<folder>/<epoch, 10 digits>.enc`.
pub const ESCROW_PREFIX: &str = "vault/folder-escrow/";
/// The signed recovery check of the vault.
pub const RECOVERY_CHECK_KEY: &str = "vault/recovery-check.json";
/// Folders this device holds whose current keys have no escrow, as the last
/// sync found them.
const ESCROW_SEEN_FILE: &str = "state/folder-escrow.json";
/// Key id of escrow bodies.
const ESCROW_KEY_ID: &str = "recovery";
/// How often a sync looks again for missing recovery copies.
const ESCROW_CHECK_SECS: i64 = 15 * 60;

#[derive(Default, Serialize, Deserialize)]
struct EscrowSeen {
    #[serde(default)]
    checked_utc: i64,
    #[serde(default)]
    missing: Vec<String>,
}

/// K2: wraps folder keys for recovery.
pub fn recovery_wrap_key(recovery_key: &SecretKey) -> SecretKey {
    recovery_key.derive("recovery-wrap", &[])
}

fn check_value(k2: &SecretKey, vault: &VaultId) -> String {
    hex::encode(
        &crypto::keyed_hash(
            &k2.derive("recovery-check", &[vault.as_str().as_bytes()]),
            b"varsto recovery check",
        )[..16],
    )
}

fn escrow_key(folder: &FolderId, epoch: u32) -> String {
    format!("{ESCROW_PREFIX}{folder}/{epoch:010}.enc")
}

#[derive(Serialize, Deserialize)]
struct EscrowBody {
    folder: FolderId,
    epoch: u32,
    key_hex: String,
    base_hex: String,
}

impl Drop for EscrowBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
        self.base_hex.zeroize();
    }
}

/// What `recover_folders` restored.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecoverReport {
    /// Folders whose keys came back.
    pub folders: Vec<String>,
    /// Folders of the vault without a readable escrow (their content stays
    /// closed to this device).
    pub missing: Vec<String>,
}

impl Engine {
    /// Hold the recovery key for this session (as K2; never written to
    /// disk). The words must be this vault's: they are checked against the
    /// vault's recovery check when one exists, and one is published when
    /// none does.
    pub fn set_recovery_key(&mut self, recovery_key_hex: &str) -> Result<()> {
        let k1 = SecretKey::from_hex(recovery_key_hex)?;
        crate::logging::register_key(k1.as_bytes());
        let k2 = recovery_wrap_key(&k1);
        crate::logging::register_key(k2.as_bytes());
        let want = check_value(&k2, &self.vault.vault_id);
        match self.read_recovery_check()? {
            Some(have) if !crypto::ct_eq(have.as_bytes(), want.as_bytes()) => bail!(
                "these are not the recovery words of this vault (their key check does not match)"
            ),
            Some(_) => {}
            None if !self.vault.member => self.publish_recovery_check(&want)?,
            None => {}
        }
        self.recovery = Some(k2);
        Ok(())
    }

    /// Whether this session holds the recovery key.
    pub fn has_recovery_key(&self) -> bool {
        self.recovery.is_some()
    }

    fn read_recovery_check(&self) -> Result<Option<String>> {
        let key_for = |id: &str| self.registry_key_for(id);
        let writer = |d: &DeviceId| {
            if self.trusted(d) {
                self.device_key(d)
            } else {
                None
            }
        };
        for (_, b) in self.metadata_storages(false)? {
            let Some(blob) = b.get(RECOVERY_CHECK_KEY)? else {
                continue;
            };
            let Ok(env) = SignedRecord::parse(&blob) else {
                continue;
            };
            if env.scope != "recovery-check" {
                continue;
            }
            if let Ok(plain) = env.accept(
                &record::Expect::new(RecordKind::Escrow, &self.vault.vault_id)
                    .scope("recovery-check"),
                &writer,
                &key_for,
            ) {
                return Ok(Some(String::from_utf8(plain)?));
            }
        }
        Ok(None)
    }

    fn publish_recovery_check(&mut self, value: &str) -> Result<()> {
        let (key_id, key) = self.registry_key_id_now();
        let env = record::Header {
            kind: RecordKind::Escrow,
            vault: &self.vault.vault_id,
            scope: "recovery-check",
            device: &self.vault.device_id,
            seq: 0,
            key_id: &key_id,
        }
        .seal(&key, value.as_bytes(), &self.keys.signer)?;
        for (spec, b) in self.metadata_storages(true)? {
            if spec.is_carrier() {
                continue;
            }
            // Junk under the name is replaced; a valid check stays.
            if let Some(old) = b.get(RECOVERY_CHECK_KEY)? {
                if SignedRecord::parse(&old).is_ok_and(|e| {
                    self.trusted(&e.device)
                        && self
                            .device_key(&e.device)
                            .is_some_and(|pk| e.verify(&pk).is_ok())
                }) {
                    continue;
                }
                b.delete(RECOVERY_CHECK_KEY)?;
            }
            b.put_if_absent(RECOVERY_CHECK_KEY, &env.to_bytes())?;
        }
        Ok(())
    }

    /// Every key epoch of a folder this device holds: (epoch, key).
    fn held_epochs(rec: &FolderRecord) -> Result<Vec<(u32, SecretKey)>> {
        let mut out = vec![(0, rec.folder_key()?)];
        for (e, k) in &rec.epoch_keys {
            out.push((*e, SecretKey::from_hex(k)?));
        }
        Ok(out)
    }

    /// Whether a valid escrow of `folder`'s `epoch` is on the storages
    /// (signed by a trusted device of the vault).
    fn escrow_present(
        &self,
        storages: &OpenStorages,
        folder: &FolderId,
        epoch: u32,
    ) -> Result<bool> {
        let key = escrow_key(folder, epoch);
        for (_, b) in storages {
            let Some(blob) = b.get(&key)? else {
                continue;
            };
            let Ok(env) = SignedRecord::parse(&blob) else {
                continue;
            };
            if env
                .expect(
                    &record::Expect::new(RecordKind::Escrow, &self.vault.vault_id)
                        .scope(folder.as_str())
                        .seq(epoch as u64),
                )
                .is_ok()
                && self.trusted(&env.device)
                && self
                    .device_key(&env.device)
                    .is_some_and(|pk| env.verify(&pk).is_ok())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Write the escrow of every key epoch of every folder this device
    /// holds that has none yet (needs the recovery key in this session).
    /// Returns how many were written.
    pub fn write_escrows(&mut self) -> Result<usize> {
        let Some(k2) = self.recovery.clone() else {
            bail!("the recovery key is not in this session: give the recovery words (varsto recovery escrow)");
        };
        let storages = self.metadata_storages(false)?;
        let writable = self.metadata_storages(true)?;
        // The vault's recovery check goes out with the first copies (the
        // session that made the vault had no storage yet).
        if !self.vault.member && self.read_recovery_check()?.is_none() {
            self.publish_recovery_check(&check_value(&k2, &self.vault.vault_id))?;
        }
        let folders: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_strongroom() && !r.key_hex.is_empty())
            .cloned()
            .collect();
        let mut written = 0;
        for rec in folders {
            let base = rec.folder_key()?;
            for (e, k) in Self::held_epochs(&rec)? {
                if self.escrow_present(&storages, &rec.folder_id, e)? {
                    continue;
                }
                let body = EscrowBody {
                    folder: rec.folder_id.clone(),
                    epoch: e,
                    key_hex: k.to_hex(),
                    base_hex: base.to_hex(),
                };
                let env = record::Header {
                    kind: RecordKind::Escrow,
                    vault: &self.vault.vault_id,
                    scope: rec.folder_id.as_str(),
                    device: &self.vault.device_id,
                    seq: e as u64,
                    key_id: ESCROW_KEY_ID,
                }
                .seal(
                    &k2,
                    &zeroize::Zeroizing::new(serde_json::to_vec(&body)?),
                    &self.keys.signer,
                )?;
                let path = escrow_key(&rec.folder_id, e);
                for (spec, b) in &writable {
                    if spec.is_carrier() {
                        continue;
                    }
                    // Junk under the name (no valid escrow was found) goes.
                    let _ = b.delete(&path);
                    b.put_if_absent(&path, &env.to_bytes())?;
                }
                written += 1;
            }
        }
        self.note_escrow_state(true);
        Ok(written)
    }

    /// Remember which held folders lack an escrow (for the status and the
    /// Help page): at most every few minutes unless `force`.
    pub(super) fn note_escrow_state(&mut self, force: bool) {
        if self.vault.member {
            return;
        }
        let path = self.home.join(ESCROW_SEEN_FILE);
        let now = util::now_utc();
        let seen: EscrowSeen = util::read_json_or_default(&path).unwrap_or_default();
        if !force && now >= seen.checked_utc && now - seen.checked_utc < ESCROW_CHECK_SECS {
            return;
        }
        let Ok(storages) = self.metadata_storages(false) else {
            return;
        };
        let mut missing = Vec::new();
        for rec in self.keyring.folders.values() {
            if rec.is_removed() || rec.is_strongroom() || rec.key_hex.is_empty() {
                continue;
            }
            let Ok(epochs) = Self::held_epochs(rec) else {
                continue;
            };
            let newest = epochs.iter().map(|(e, _)| *e).max().unwrap_or(0);
            if !self
                .escrow_present(&storages, &rec.folder_id, newest)
                .unwrap_or(true)
            {
                missing.push(rec.name.clone());
            }
        }
        let _ = util::write_json(
            &path,
            &EscrowSeen {
                checked_utc: now,
                missing,
            },
        );
    }

    /// Folders this device holds whose newest key has no recovery copy,
    /// as the last check found them.
    pub fn folders_without_escrow(&self) -> Vec<String> {
        util::read_json_or_default::<EscrowSeen>(&self.home.join(ESCROW_SEEN_FILE))
            .map(|s| s.missing)
            .unwrap_or_default()
    }

    /// Escrow what this session made when it holds the recovery key (a new
    /// folder, a new epoch); otherwise note what lacks a copy, so the status
    /// warns until it is done.
    pub(super) fn escrow_if_possible(&mut self) {
        self.escrow_now(true);
    }

    /// On every sync: write missing copies when the words are at hand, else
    /// look for them now and then.
    pub(super) fn escrow_on_sync(&mut self) {
        self.escrow_now(false);
    }

    fn escrow_now(&mut self, force: bool) {
        if self.recovery.is_some() {
            if let Err(e) = self.write_escrows() {
                log::warn!("writing recovery copies: {e:#}");
            }
        } else {
            self.note_escrow_state(force);
        }
    }

    /// Rebuild the folder keys of a device that lost everything: open every
    /// escrow with the recovery key and keep the keys whose escrow a trusted
    /// device of the vault signed and that match the folder's key check.
    pub fn recover_folders(&mut self, recovery_key_hex: &str) -> Result<RecoverReport> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device holds only the folders shared with it");
        }
        self.set_recovery_key(recovery_key_hex)?;
        let k2 = self.recovery.clone().expect("set above");
        self.pull_registry()?;
        let storages = self.metadata_storages(false)?;
        let mut found: BTreeMap<FolderId, (SecretKey, BTreeMap<u32, SecretKey>)> = BTreeMap::new();
        for (_, b) in &storages {
            for key in b.list(ESCROW_PREFIX)? {
                let Some((f, e)) = key
                    .strip_prefix(ESCROW_PREFIX)
                    .and_then(|r| r.strip_suffix(".enc"))
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(fid), Ok(epoch)) = (FolderId::from_hex(f), e.parse::<u32>()) else {
                    continue;
                };
                let Some(blob) = b.get(&key)? else {
                    continue;
                };
                let Ok(env) = SignedRecord::parse(&blob) else {
                    continue;
                };
                let writer = |d: &DeviceId| {
                    if self.trusted(d) {
                        self.device_key(d)
                    } else {
                        None
                    }
                };
                let key_for = |id: &str| (id == ESCROW_KEY_ID).then(|| k2.clone());
                let Ok(plain) = env.accept(
                    &record::Expect::new(RecordKind::Escrow, &self.vault.vault_id)
                        .scope(fid.as_str())
                        .seq(epoch as u64),
                    &writer,
                    &key_for,
                ) else {
                    continue;
                };
                let Ok(body) = serde_json::from_slice::<EscrowBody>(&plain) else {
                    continue;
                };
                if body.folder != fid || body.epoch != epoch {
                    continue;
                }
                let (Ok(k), Ok(base)) = (
                    SecretKey::from_hex(&body.key_hex),
                    SecretKey::from_hex(&body.base_hex),
                ) else {
                    continue;
                };
                // The first-epoch key must be the one the folder's creator
                // committed to.
                let Some(rec) = self.keyring.folders.get(&fid) else {
                    continue;
                };
                if rec.key_check.is_empty()
                    || !crypto::ct_eq(
                        super::folder_grants::folder_key_check(&base, &fid).as_bytes(),
                        rec.key_check.as_bytes(),
                    )
                {
                    continue;
                }
                let entry = found
                    .entry(fid)
                    .or_insert_with(|| (base.clone(), BTreeMap::new()));
                if epoch > 0 {
                    entry.1.insert(epoch, k);
                }
            }
        }
        let mut report = RecoverReport::default();
        for (fid, (base, later)) in found {
            if let Some(r) = self.keyring.folders.get_mut(&fid) {
                r.key_hex = base.to_hex();
                for (e, k) in later {
                    r.epoch_keys.insert(e, k.to_hex());
                }
                report.folders.push(r.name.clone());
            }
        }
        report.missing = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !self.has_folder_key(r))
            .map(|r| r.name.clone())
            .collect();
        self.save_keyring_now()?;
        self.note_escrow_state(true);
        Ok(report)
    }
}

impl Engine {
    /// Make a new recovery key: a new recovery check, and a new recovery
    /// copy of every key epoch of every folder this device holds. Returns
    /// the key (hex, to print once) and the folders this device does not
    /// hold, whose copies stay under the old key.
    pub fn rotate_recovery_key(&mut self) -> Result<(String, Vec<String>)> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device has no recovery key of its own");
        }
        let k1 = SecretKey::random();
        let hex_key = k1.to_hex();
        crate::logging::register_secret(&hex_key);
        let k2 = recovery_wrap_key(&k1);
        for (_, b) in self.metadata_storages(true)? {
            let _ = b.delete(RECOVERY_CHECK_KEY);
        }
        self.publish_recovery_check(&check_value(&k2, &self.vault.vault_id))?;
        self.recovery = Some(k2);
        // The old copies of what this device holds go; new ones follow.
        let held: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_strongroom() && !r.key_hex.is_empty())
            .cloned()
            .collect();
        for rec in &held {
            for (e, _) in Self::held_epochs(rec)? {
                for (_, b) in self.metadata_storages(true)? {
                    let _ = b.delete(&escrow_key(&rec.folder_id, e));
                }
            }
        }
        self.write_escrows()?;
        let not_held = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_strongroom() && r.key_hex.is_empty())
            .map(|r| r.name.clone())
            .collect();
        Ok((hex_key, not_held))
    }
}
