// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Vault identity, keys, device and folder records, local configuration.
//!
//! Alpha-0 key hierarchy (subset of `docs/spec/key-hierarchy.md`):
//! - master key K3: random 256 bits, wrapped locally under an Argon2id
//!   passphrase key; shared between devices as the "vault key" through
//!   pairing (`pair`), the recovery kit (`recovery`) or an organization's
//!   approval token (`org`), which is sealed through the hybrid KEM;
//! - device signing key K6/K7 (Ed25519 + ML-DSA-65) per device, wrapped with
//!   K3 locally;
//! - derived from K3: ledger key, device-registry key, folder-record key,
//!   local-keyring key;
//! - folder key K9 per folder (random), from which the folder hash key,
//!   metadata key and per-chunk keys are derived.

use crate::crypto::{self, PassphraseParams, SecretKey, SigningKey, VerifyingKey};
use crate::ids::{ChunkId, DeviceId, FolderId, VaultId};
use crate::storage::StorageSpec;
use crate::util;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Public vault identity, stored in every storage as `vault/meta.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub format_version: u16,
    pub vault_id: VaultId,
    pub created_utc: i64,
}

impl VaultMeta {
    pub const STORAGE_KEY: &'static str = "vault/meta.json";
}

/// Local vault file: `home/vault.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalVault {
    pub format_version: u16,
    pub vault_id: VaultId,
    pub device_id: DeviceId,
    pub device_name: String,
    pub created_utc: i64,
    /// A member device holds no master key: only shared folders (F-047).
    #[serde(default)]
    pub member: bool,
}

/// Prefix of a share request code.
pub const SHARE_REQUEST_PREFIX: &str = "vsr1.";

/// Recipient-side state for a pending share request: the device keys of
/// the member device it will become (format 3: K6 signs everything it
/// writes, K8 receives its grants), kept in the device directory until the
/// share is accepted (they then move into the device's key files).
#[derive(Serialize, Deserialize)]
pub struct ShareRequest {
    pub kem_alg: String,
    /// K8 private key.
    pub secret_hex: String,
    /// K6 private key (`SigningKey::to_bytes`).
    #[serde(default)]
    pub signing_hex: String,
    /// Name bound to the request code (covered by its fingerprint).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

impl Drop for ShareRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_hex.zeroize();
        self.signing_hex.zeroize();
    }
}

/// A parsed request code: the requester's K6 and K8 public keys, the name
/// it bound, its device id and the fingerprint both sides compare.
pub struct RequestCode {
    /// K6 public key (`VerifyingKey::to_bytes`).
    pub k6: Vec<u8>,
    /// K8 public key.
    pub key: crate::kem::EncapsKey,
    pub name: String,
    /// BLAKE3(K6)[..16].
    pub device: [u8; 16],
    pub fingerprint: String,
}

impl ShareRequest {
    pub const FILE: &'static str = "share-request.json";

    /// Load or create the request keys for `home` and return the request code.
    pub fn code_for(home: &Path) -> Result<String> {
        Self::code_for_named(home, None)
    }

    /// Like `code_for`, binding `name` to the code when given (the keys stay
    /// the same; only the name and with it the fingerprint change).
    pub fn code_for_named(home: &Path, name: Option<&str>) -> Result<String> {
        std::fs::create_dir_all(home)?;
        let path = home.join(Self::FILE);
        let mut r: ShareRequest = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            ShareRequest {
                kem_alg: crate::kem::KEM_ALG.to_string(),
                secret_hex: hex::encode(crate::kem::DecapsKey::generate().to_bytes()),
                signing_hex: String::new(),
                name: String::new(),
            }
        };
        let mut changed = !path.exists();
        if r.signing_hex.is_empty() {
            r.signing_hex = hex::encode(SigningKey::generate().to_bytes());
            changed = true;
        }
        let name = name.map(|n| n.trim().to_string());
        if let Some(n) = &name {
            crate::names::check_display_name(n)?;
        }
        changed |= name.as_ref().is_some_and(|n| *n != r.name);
        if let Some(n) = name {
            r.name = n;
        }
        if changed {
            util::write_atomic(&path, &serde_json::to_vec_pretty(&r)?)?;
        }
        let (sign, dk) = r.keys()?;
        Ok(Self::code_of(
            &sign.public().to_bytes(),
            &dk.public().to_bytes(),
            &r.name,
        ))
    }

    /// The text form of a request code: `vsr1.<K6 hex>.<K8 hex>[.<name>]`.
    pub fn code_of(k6: &[u8], k8: &[u8], name: &str) -> String {
        let mut code = format!(
            "{SHARE_REQUEST_PREFIX}{}.{}",
            hex::encode(k6),
            hex::encode(k8)
        );
        if !name.is_empty() {
            code.push('.');
            code.push_str(name);
        }
        code
    }

    fn keys(&self) -> Result<(SigningKey, crate::kem::DecapsKey)> {
        let sign = SigningKey::from_bytes(&hex::decode(&self.signing_hex)?)?;
        let dk = crate::kem::DecapsKey::from_bytes(&hex::decode(&self.secret_hex)?)?;
        Ok((sign, dk))
    }

    /// Keys, bound name, device id and fingerprint of a request code.
    /// Accepts the text form or a `varsto://share/request` link.
    pub fn parse(code: &str) -> Result<RequestCode> {
        if crate::qr::is_link(code) {
            return match crate::qr::Link::from_text(code)? {
                crate::qr::Link::ShareRequest(c) => Self::parse(&c),
                other => bail!("this is a {} link, not a share request code", other.kind()),
            };
        }
        let rest = code
            .trim()
            .strip_prefix(SHARE_REQUEST_PREFIX)
            .ok_or_else(|| anyhow!("not a share request code (expected the vsr1. prefix)"))?;
        let mut it = rest.splitn(3, '.');
        let k6_hex = it.next().unwrap_or_default();
        let k8_hex = it.next().ok_or_else(|| {
            anyhow!("this share request code is from an older version of Varsto: ask for a new one")
        })?;
        let name = it.next().unwrap_or_default().trim().to_string();
        let k6 = hex::decode(k6_hex).map_err(|_| anyhow!("the request code is damaged"))?;
        let vk = VerifyingKey::from_bytes(&k6).map_err(|_| {
            anyhow!("this share request code is from an older version of Varsto: ask for a new one")
        })?;
        let key = crate::kem::EncapsKey::from_bytes(
            &hex::decode(k8_hex).map_err(|_| anyhow!("the request code is damaged"))?,
        )?;
        crate::names::check_display_name(&name)?;
        let k8 = key.to_bytes();
        Ok(RequestCode {
            fingerprint: crate::share::fingerprint(&k6, &k8, &name),
            device: crate::membership3::device_id(&vk),
            k6,
            key,
            name,
        })
    }

    fn load(home: &Path) -> Result<ShareRequest> {
        let path = home.join(Self::FILE);
        if !path.exists() {
            bail!(
                "no share request in {}: run `varsto share request` there first and give its code to the owner",
                home.display()
            );
        }
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }

    /// The device keys of the pending request in `home` (K6, K8), if there
    /// is one.
    pub fn device_keys(home: &Path) -> Result<(SigningKey, crate::kem::DecapsKey, String)> {
        let r = Self::load(home)?;
        let (sign, dk) = r.keys()?;
        Ok((sign, dk, r.name.clone()))
    }

    /// The fingerprint of the pending request in `home`.
    pub fn fingerprint_for(home: &Path) -> Result<String> {
        let r = Self::load(home)?;
        let (sign, dk) = r.keys()?;
        Ok(crate::share::fingerprint(
            &sign.public().to_bytes(),
            &dk.public().to_bytes(),
            &r.name,
        ))
    }

    pub fn clear(home: &Path) {
        let _ = std::fs::remove_file(home.join(Self::FILE));
    }
}

/// A policy change for a folder, published append-only at
/// `vault/policies/<folder>/<device>/<updated_utc>.enc` under the folder
/// record key; every device adopts the newest one it can read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub folder_id: FolderId,
    pub device: DeviceId,
    pub updated_utc: i64,
    pub policy: Option<crate::policy::Policy>,
}

impl PolicyRecord {
    pub const PREFIX: &'static str = "vault/policies/";
    pub fn storage_key(&self) -> String {
        format!(
            "{}{}/{}/{:020}.enc",
            Self::PREFIX,
            self.folder_id,
            self.device,
            self.updated_utc
        )
    }
    fn aad(vault: &VaultId, folder: &FolderId) -> Vec<u8> {
        crypto::aad(
            "policy-record",
            &[vault.as_str().as_bytes(), folder.as_str().as_bytes()],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.folder_id),
            &serde_json::to_vec(self)?,
        )
    }
    pub fn open(blob: &[u8], vault: &VaultId, folder: &FolderId, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, folder), blob)?;
        let rec: PolicyRecord = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder {
            bail!("policy record folder mismatch");
        }
        Ok(rec)
    }
    /// Seal and sign (alpha.10): the device that sets a policy signs the
    /// envelope, so a holder of the vault key cannot pass a policy off as
    /// another device's (an administrator's, in an organization).
    pub fn seal_signed(
        &self,
        vault: &VaultId,
        key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Vec<u8>> {
        let ct = self.seal(vault, key)?;
        SignedRecord::wrap(
            "policy-record-signature",
            vault,
            &self.folder_id,
            &self.device,
            self.updated_utc,
            ct,
            signer,
        )
    }
    /// Open a signed envelope or, when `allow_unsigned`, a bare record from
    /// before alpha.10. `verify` gives the writer's key; a signed envelope
    /// whose issuer is unknown or whose signature fails is refused. The
    /// `<device>` in the object name must be the writer.
    pub fn open_any(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        named_device: &DeviceId,
        keys: &[SecretKey],
        verify: &dyn Fn(&DeviceId) -> Option<VerifyingKey>,
        allow_unsigned: bool,
    ) -> Result<Self> {
        match SignedRecord::parse(blob) {
            Some(env) => {
                let pk = verify(&env.device).ok_or_else(|| anyhow!("unknown writer"))?;
                let ct = env.verify("policy-record-signature", vault, folder, &pk)?;
                let rec = keys
                    .iter()
                    .find_map(|k| Self::open(&ct, vault, folder, k).ok())
                    .ok_or_else(|| anyhow!("policy record does not open"))?;
                if rec.device != env.device
                    || &rec.device != named_device
                    || rec.updated_utc != env.updated_utc
                {
                    bail!("policy record does not match its envelope");
                }
                Ok(rec)
            }
            None if allow_unsigned => {
                let rec = keys
                    .iter()
                    .find_map(|k| Self::open(blob, vault, folder, k).ok())
                    .ok_or_else(|| anyhow!("policy record does not open"))?;
                if &rec.device != named_device {
                    bail!("policy record does not match its name");
                }
                Ok(rec)
            }
            None => bail!("unsigned policy record"),
        }
    }
}

/// A signed envelope around a sealed per-folder record (policies and
/// placement): the writer's device signature over vault, folder, device,
/// time and the ciphertext hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRecord {
    pub format_version: u16,
    pub folder: FolderId,
    pub device: DeviceId,
    pub updated_utc: i64,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedRecord {
    fn message(
        kind: &str,
        vault: &VaultId,
        folder: &FolderId,
        device: &DeviceId,
        updated_utc: i64,
        body_hash: &[u8],
    ) -> Vec<u8> {
        crypto::aad(
            kind,
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                device.as_str().as_bytes(),
                &updated_utc.to_le_bytes(),
                body_hash,
            ],
        )
    }
    pub fn wrap(
        kind: &str,
        vault: &VaultId,
        folder: &FolderId,
        device: &DeviceId,
        updated_utc: i64,
        ct: Vec<u8>,
        signer: &SigningKey,
    ) -> Result<Vec<u8>> {
        let sig = signer.sign(&Self::message(
            kind,
            vault,
            folder,
            device,
            updated_utc,
            &crypto::hash(&ct),
        ));
        Ok(serde_json::to_vec(&SignedRecord {
            format_version: crate::FORMAT_VERSION,
            folder: folder.clone(),
            device: device.clone(),
            updated_utc,
            body_hex: hex::encode(ct),
            sig_alg: signer.alg().to_string(),
            sig_hex: hex::encode(sig),
        })?)
    }
    pub fn parse(blob: &[u8]) -> Option<SignedRecord> {
        serde_json::from_slice(blob).ok()
    }
    /// Verify and return the ciphertext inside.
    pub fn verify(
        &self,
        kind: &str,
        vault: &VaultId,
        folder: &FolderId,
        pk: &VerifyingKey,
    ) -> Result<Vec<u8>> {
        if &self.folder != folder {
            bail!("signed record names another folder");
        }
        let ct = hex::decode(&self.body_hex)?;
        pk.verify(
            &self.sig_alg,
            &Self::message(
                kind,
                vault,
                folder,
                &self.device,
                self.updated_utc,
                &crypto::hash(&ct),
            ),
            &hex::decode(&self.sig_hex)?,
        )?;
        Ok(ct)
    }
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    params: PassphraseParams,
    blob_hex: String,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct KeyMaterial {
    master_hex: String,
    signing_hex: String,
}

pub struct Keys {
    pub master: SecretKey,
    pub signer: SigningKey,
}

crate::redacted_opaque!(Keys);

impl Keys {
    pub fn ledger_key(&self) -> SecretKey {
        self.master.derive("ledger", &[])
    }
    pub fn registry_key(&self) -> SecretKey {
        self.master.derive("device-registry", &[])
    }
    pub fn folder_record_key(&self) -> SecretKey {
        self.master.derive("folder-record", &[])
    }
    pub fn local_keyring_key(&self) -> SecretKey {
        self.master.derive("local-keyring", &[])
    }

    fn keyfile_aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "keyfile",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }

    pub fn save(
        &self,
        home: &Path,
        passphrase: &str,
        vault: &VaultId,
        device: &DeviceId,
    ) -> Result<()> {
        crypto::check_passphrase(passphrase)?;
        let params = PassphraseParams::new();
        let wrap = crypto::passphrase_key(passphrase, &params)?;
        let material = KeyMaterial {
            master_hex: self.master.to_hex(),
            signing_hex: hex::encode(self.signer.to_bytes()),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&material)?);
        let blob = crypto::encrypt(&wrap, &Self::keyfile_aad(vault, device), &plain)?;
        util::write_json(
            &home.join("keys.enc"),
            &KeyFile {
                params,
                blob_hex: hex::encode(blob),
            },
        )
    }

    pub fn load(home: &Path, passphrase: &str, vault: &VaultId, device: &DeviceId) -> Result<Self> {
        let kf: KeyFile = util::read_json(&home.join("keys.enc"))?;
        let blob = hex::decode(&kf.blob_hex)?;
        let aad = Self::keyfile_aad(vault, device);
        let wrap = crypto::passphrase_key(passphrase, &kf.params)?;
        let opened = crypto::decrypt(&wrap, &aad, &blob).or_else(|e| {
            // A key file from before alpha.10, written with the passphrase as
            // typed: try it unnormalised when normalisation changed it.
            if crypto::normalize_passphrase(passphrase) != passphrase {
                let raw = crypto::passphrase_key_raw(passphrase, &kf.params)?;
                crypto::decrypt(&raw, &aad, &blob)
            } else {
                Err(e)
            }
        });
        let plain =
            Zeroizing::new(opened.context("unlock failed: wrong passphrase or damaged key file")?);
        let material: KeyMaterial = serde_json::from_slice(&plain)?;
        // Cut from the log should a hex form ever reach it (by hash only).
        if let Ok(raw) = hex::decode(&material.master_hex) {
            crate::logging::register_key(&raw);
        }
        log::debug!("device keys unlocked");
        Ok(Keys {
            master: SecretKey::from_hex(&material.master_hex)?,
            signer: SigningKey::from_bytes(&hex::decode(&material.signing_hex)?)?,
        })
    }
}

/// Encrypted device record published to `vault/devices/<device>.enc`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub name: String,
    pub pubkey_hex: String,
    pub enrolled_utc: i64,
}

impl DeviceRecord {
    pub fn storage_key(device: &DeviceId) -> String {
        format!("vault/devices/{}.enc", device)
    }
    pub const PREFIX: &'static str = "vault/devices/";

    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "device-record",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.device_id),
            &serde_json::to_vec(self)?,
        )
    }
    pub fn open(blob: &[u8], vault: &VaultId, device: &DeviceId, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, device), blob)?;
        let rec: DeviceRecord = serde_json::from_slice(&plain)?;
        let pk = VerifyingKey::from_bytes(&hex::decode(&rec.pubkey_hex)?)?;
        if crate::ledger::device_id_for(&pk) != rec.device_id || &rec.device_id != device {
            bail!("device record identity does not match its key");
        }
        Ok(rec)
    }
    pub fn pubkey(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&hex::decode(&self.pubkey_hex)?)
    }
}

/// Encrypted folder record published to `vault/folders/<device>/<folder>.enc`
/// by the device that created the folder (single writer per device).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderRecord {
    pub folder_id: FolderId,
    pub name: String,
    /// K9 of folder epoch 0 (hex), when this device holds it (format 3:
    /// from a grant to this device, never from a published record).
    pub key_hex: String,
    /// K11 (hex): fixed at the folder's first epoch, carried in every
    /// grant; empty when it follows from `key_hex`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub k11_hex: String,
    pub created_by: DeviceId,
    pub created_utc: i64,
    /// Shared with other users: member records and batches live under
    /// folder-derived keys (local flag, never published).
    #[serde(default)]
    pub shared: bool,
    /// Durability policy (F-032), published with the record; the newest
    /// `policy_updated_utc` wins across devices.
    #[serde(default)]
    pub policy: Option<crate::policy::Policy>,
    #[serde(default)]
    pub policy_updated_utc: i64,
    /// Which storages the folder's blocks are written to (default: every
    /// storage), published like the policy (`crate::placement`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<crate::placement::Placement>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub placement_updated_utc: i64,
    /// Strongroom (S-012): the folder key is not stored here (`key_hex` is
    /// empty); it is wrapped under a security-key secret and held in memory
    /// only while unlocked.
    #[serde(default)]
    pub strongroom: Option<crate::strongroom::StrongroomInfo>,
    /// Removed from the vault (local flag, from the folder record's `removed` stamp).
    #[serde(default)]
    pub removed_utc: i64,
    /// Folder keys of later epochs held besides those derived from the vault
    /// key: share epochs (`share`), and on a member device the vault-epoch
    /// folder keys the owner handed over. Hex by epoch; never published.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub epoch_keys: BTreeMap<u32, String>,
    /// A backup (`engine::backups`): read-only snapshots of a directory on
    /// one device, kept on storages only. It is never mounted, synced or
    /// served to peers, and only its source device writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupInfo>,
}

crate::redacted_debug!(FolderRecord { folder_id, name, created_by, created_utc, shared, strongroom, removed_utc, backup, placement, policy ; key_hex, k11_hex, epoch_keys });

impl Drop for FolderRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
        self.k11_hex.zeroize();
        for v in self.epoch_keys.values_mut() {
            v.zeroize();
        }
    }
}

/// What a backup's folder record says about it (published with the record).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupInfo {
    /// The only device that takes snapshots.
    pub source_device: DeviceId,
    /// The directory backed up, as the source device names it (shown only).
    pub source_path: String,
    /// Retention when the backup was made; each snapshot fixes its own
    /// expiry when it is taken.
    pub retention_days: u32,
    pub created_utc: i64,
}

/// Retention of a new backup unless told otherwise.
pub const DEFAULT_BACKUP_RETENTION_DAYS: u32 = 90;

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl FolderRecord {
    /// The policy that applies: the folder's own, or the default for
    /// folders that never had one; None when it was cleared by hand.
    pub fn effective_policy(&self) -> Option<crate::policy::Policy> {
        let p = self
            .policy
            .clone()
            .unwrap_or_else(crate::policy::Policy::folder_default);
        (!p.is_empty()).then_some(p)
    }

    pub fn is_removed(&self) -> bool {
        self.removed_utc > 0
    }
    pub fn is_strongroom(&self) -> bool {
        self.strongroom.is_some()
    }
    pub fn is_backup(&self) -> bool {
        self.backup.is_some()
    }
    pub fn storage_key(device: &DeviceId, folder: &FolderId) -> String {
        format!("vault/folders/{}/{}.enc", device, folder)
    }
    pub const PREFIX: &'static str = "vault/folders/";

    fn aad(vault: &VaultId, device: &DeviceId, folder: &FolderId) -> Vec<u8> {
        crypto::aad(
            "folder-record",
            &[
                vault.as_str().as_bytes(),
                device.as_str().as_bytes(),
                folder.as_str().as_bytes(),
            ],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        // Keys of later epochs travel in their own records.
        let mut published = self.clone();
        published.epoch_keys.clear();
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.created_by, &self.folder_id),
            &serde_json::to_vec(&published)?,
        )
    }
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        device: &DeviceId,
        folder: &FolderId,
        key: &SecretKey,
    ) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, device, folder), blob)?;
        let rec: FolderRecord = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder || &rec.created_by != device {
            bail!("folder record does not match its name");
        }
        Ok(rec)
    }
    /// The folder keys this record holds: K9 of epoch 0 (`key_hex`) and of
    /// later epochs (`epoch_keys`), and K11.
    pub fn keys(&self) -> Result<FolderKeys> {
        let mut epochs = BTreeMap::new();
        if !self.key_hex.is_empty() {
            epochs.insert(0, SecretKey::from_hex(&self.key_hex)?);
        }
        for (e, k) in &self.epoch_keys {
            epochs.insert(*e, SecretKey::from_hex(k)?);
        }
        let k11 = if !self.k11_hex.is_empty() {
            SecretKey::from_hex(&self.k11_hex)?
        } else {
            let k0 = epochs
                .get(&0)
                .ok_or_else(|| anyhow!("no key of folder {} is held here", self.name))?;
            FolderKeys::k11_of(&self.folder_id, k0)?
        };
        FolderKeys::new(&self.folder_id, epochs, k11)
    }
    pub fn folder_key(&self) -> Result<SecretKey> {
        SecretKey::from_hex(&self.key_hex)
    }
}

/// The keys of one folder (storage format 3, `docs/spec/format-3-design.md`
/// section 1): K9 of every folder epoch this device holds (from grants to
/// it, or a recovery), K11 (fixed at the folder's first epoch and carried
/// in every grant), K10 of the epoch new records and chunks are written
/// under, and what they give: K12 (the chunker seed), K14 (a chunk's key)
/// and the chunk nonce. Every derivation is the design's
/// `derive(K, purpose, scope...)` (context `e2ee-sync-format/3/<purpose>`)
/// over binary ids. Chunk ids and content hashes are keyed by K11, so a
/// new folder epoch moves no cut point and changes no chunk id; older
/// chunks stay under the epoch recorded in their `ChunkRef`.
pub struct FolderKeys {
    pub folder: FolderId,
    folder_bin: [u8; 16],
    /// K9 by folder epoch.
    epochs: BTreeMap<u32, SecretKey>,
    /// K11: keyed-hash key for chunk ids and content hashes.
    pub hash: SecretKey,
    /// K10 of the write epoch: manifests, maps, trash, thumbnails.
    pub meta: SecretKey,
    /// The epoch new chunks and records are written under.
    pub epoch: u32,
}

crate::redacted_opaque!(FolderKeys);

fn folder_bin(folder: &FolderId) -> Result<[u8; 16]> {
    folder
        .as_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("folder id {folder} is not 16 bytes"))
}

fn derive3(k: &SecretKey, purpose: &str, scope: &[&[u8]]) -> SecretKey {
    k.derive_with_prefix(crate::membership3::CONTEXT3, purpose, scope)
}

impl FolderKeys {
    /// The keys of `folder` from K9 of the epochs held and K11. The newest
    /// epoch is the write epoch.
    pub fn new(
        folder: &FolderId,
        epochs: BTreeMap<u32, SecretKey>,
        k11: SecretKey,
    ) -> Result<Self> {
        let fb = folder_bin(folder)?;
        for k in epochs.values() {
            crate::logging::register_key(k.as_bytes());
        }
        let (epoch, meta) = match epochs.iter().next_back() {
            Some((e, k)) => (*e, derive3(k, "folder-metadata", &[&fb])),
            None => bail!("no key of folder {folder} is held here"),
        };
        Ok(FolderKeys {
            folder: folder.clone(),
            folder_bin: fb,
            epochs,
            hash: k11,
            meta,
            epoch,
        })
    }

    /// The keys of a folder from its first epoch's K9 alone (K11 follows
    /// from it): a new folder, or a test.
    pub fn from_folder_key(folder: &FolderId, base: SecretKey) -> Result<Self> {
        let fb = folder_bin(folder)?;
        let k11 = derive3(&base, "dedup-hash", &[&fb]);
        Self::new(folder, BTreeMap::from([(0, base)]), k11)
    }

    /// K11 of a folder whose first epoch's K9 is `k9_0`.
    pub fn k11_of(folder: &FolderId, k9_0: &SecretKey) -> Result<SecretKey> {
        Ok(derive3(k9_0, "dedup-hash", &[&folder_bin(folder)?]))
    }

    /// Add K9 of later epochs; the newest becomes the write epoch.
    pub fn with_epochs(mut self, later: BTreeMap<u32, SecretKey>) -> Self {
        self.epochs.extend(later);
        if let Some((e, k)) = self.epochs.iter().next_back() {
            self.epoch = *e;
            self.meta = derive3(k, "folder-metadata", &[&self.folder_bin]);
        }
        self
    }

    /// Write under the oldest epoch held.
    pub fn write_at_base(self) -> Self {
        let first = self.epochs.keys().next().copied().unwrap_or(0);
        self.write_at(first)
    }

    /// Write under `epoch` when it is held (else the keys stay as they are).
    pub fn write_at(mut self, epoch: u32) -> Self {
        if let Some(k) = self.epochs.get(&epoch) {
            self.meta = derive3(k, "folder-metadata", &[&self.folder_bin]);
            self.epoch = epoch;
        }
        self
    }

    fn epoch_key(&self, epoch: u32) -> Result<&SecretKey> {
        self.epochs.get(&epoch).ok_or_else(|| {
            anyhow!(
                "folder key epoch {epoch} is not known on this device yet (it arrives with the next sync)"
            )
        })
    }

    /// The epochs held, oldest first.
    pub fn epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.epochs.keys().copied()
    }

    /// K9 of `epoch`, when held.
    pub fn k9(&self, epoch: u32) -> Option<&SecretKey> {
        self.epochs.get(&epoch)
    }

    /// K10 of `epoch`, when held.
    pub fn meta_of(&self, epoch: u32) -> Option<SecretKey> {
        Some(derive3(
            self.epochs.get(&epoch)?,
            "folder-metadata",
            &[&self.folder_bin],
        ))
    }

    /// K10 of every epoch held, newest first.
    pub fn meta_keys(&self) -> Vec<SecretKey> {
        self.epochs
            .values()
            .rev()
            .map(|k| derive3(k, "folder-metadata", &[&self.folder_bin]))
            .collect()
    }

    /// K12 = derive(K11, "chunker-seed", folder): the folder's Gear table
    /// seed (`crate::chunking`).
    pub fn chunker_seed(&self) -> [u8; 32] {
        derive3(&self.hash, "chunker-seed", &[&self.folder_bin]).0
    }

    /// K14 = derive(K9ₑ, "chunk-key", folder, chunk id): convergent inside
    /// the folder and epoch, so the same content encrypts to the same
    /// object on every device (offline deduplication).
    pub fn chunk_key(&self, epoch: u32, chunk: &ChunkId) -> Result<SecretKey> {
        Ok(derive3(
            self.epoch_key(epoch)?,
            "chunk-key",
            &[&self.folder_bin, &chunk.as_bytes()],
        ))
    }

    /// The nonce of one chunk object: keyed_hash(derive(K9ₑ, "chunk-nonce",
    /// folder), packed)[..24], from the exact bytes that are encrypted.
    pub fn chunk_nonce(&self, epoch: u32, packed: &[u8]) -> Result<[u8; crypto::NONCE_LEN]> {
        let k = derive3(self.epoch_key(epoch)?, "chunk-nonce", &[&self.folder_bin]);
        let mut n = [0u8; crypto::NONCE_LEN];
        n.copy_from_slice(&crypto::keyed_hash(&k, packed)[..crypto::NONCE_LEN]);
        Ok(n)
    }

    /// aad("chunk", [vault, folder, epoch u32, chunk id, plaintext length
    /// u64, packed length u64]), binary ids.
    pub fn chunk_aad(
        &self,
        vault: &VaultId,
        epoch: u32,
        chunk: &ChunkId,
        plain_len: u64,
        packed_len: u64,
    ) -> Vec<u8> {
        crypto::aad(
            "chunk",
            &[
                &vault.as_bytes(),
                &self.folder_bin,
                &epoch.to_le_bytes(),
                &chunk.as_bytes(),
                &plain_len.to_le_bytes(),
                &packed_len.to_le_bytes(),
            ],
        )
    }
}

/// Local, encrypted copy of the folder records this device knows.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Keyring {
    pub folders: BTreeMap<FolderId, FolderRecord>,
    /// Folders being converted into Strongrooms, by old folder id (S-012).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub converting: BTreeMap<FolderId, crate::strongroom::Conversion>,
}

impl Keyring {
    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "local-keyring",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }
    pub fn load(home: &Path, keys: &Keys, vault: &VaultId, device: &DeviceId) -> Result<Self> {
        let p = home.join("keyring.enc");
        if !p.exists() {
            return Ok(Keyring::default());
        }
        let blob = std::fs::read(&p)?;
        let plain = crypto::decrypt(&keys.local_keyring_key(), &Self::aad(vault, device), &blob)?;
        Ok(serde_json::from_slice(&plain)?)
    }
    pub fn save(&self, home: &Path, keys: &Keys, vault: &VaultId, device: &DeviceId) -> Result<()> {
        let blob = crypto::encrypt(
            &keys.local_keyring_key(),
            &Self::aad(vault, device),
            &serde_json::to_vec(self)?,
        )?;
        util::write_atomic(&home.join("keyring.enc"), &blob)
    }
    /// A folder by name or id; backups are not folders here.
    pub fn find(&self, name_or_id: &str) -> Option<&FolderRecord> {
        self.find_where(name_or_id, |r| !r.is_backup())
    }
    /// A backup by name or id.
    pub fn find_backup(&self, name_or_id: &str) -> Option<&FolderRecord> {
        self.find_where(name_or_id, |r| r.is_backup())
    }
    fn find_where(
        &self,
        name_or_id: &str,
        keep: impl Fn(&FolderRecord) -> bool,
    ) -> Option<&FolderRecord> {
        self.folders
            .values()
            .filter(|r| !r.is_removed() && keep(r))
            .find(|r| {
                r.name == name_or_id
                    || r.folder_id.as_str() == name_or_id
                    || r.folder_id.as_str().starts_with(name_or_id) && name_or_id.len() >= 8
            })
    }
}

/// Where a folder of the vault lives on this device.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderMount {
    pub folder_id: FolderId,
    pub path: PathBuf,
    /// Selective sync (F-039): files are placeholders until fetched.
    #[serde(default)]
    pub selective: bool,
    /// "Encrypted on this device" (phones): no plain file is kept; the
    /// folder's files are kept as encrypted blocks in the device's block
    /// cache and read through the app (see `engine::block_cache`). Selective
    /// sync works as in any folder. Absent in older configurations, which
    /// means plain files as on a desktop.
    #[serde(default)]
    pub encrypted: bool,
    /// Whether this device publishes its own changes and applies the other
    /// devices' (local setting; `FolderMode`).
    #[serde(default, skip_serializing_if = "FolderMode::is_normal")]
    pub mode: FolderMode,
    /// When a scan or another device deletes too many files at once (absent:
    /// `DeletionGuard::default`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_guard: Option<DeletionGuard>,
    /// Ignore patterns of this device only (not synced), gitignore syntax,
    /// before the folder's `.varstoignore` files (`crate::ignore_rules`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_local: Vec<String>,
    /// Which file metadata this device syncs for the folder (`crate::fsmeta`).
    #[serde(
        default,
        skip_serializing_if = "crate::fsmeta::MetaSettings::is_default"
    )]
    pub meta: crate::fsmeta::MetaSettings,
    /// Free space kept on the disk holding the folder: downloads into it
    /// stop below it (`freespace`; default 5 %).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_free: Option<crate::freespace::MinFree>,
}

/// How a folder takes part in syncing on this device (a local setting: the
/// same folder can be send-only on a camera phone and normal elsewhere).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FolderMode {
    /// Publishes its changes and applies everyone else's.
    #[default]
    Normal,
    /// Publishes its changes; never applies other devices' changes to its
    /// files (it still reads their file lists to know what differs).
    SendOnly,
    /// Applies other devices' changes; never publishes its own local changes.
    ReceiveOnly,
}

impl FolderMode {
    pub fn is_normal(&self) -> bool {
        *self == FolderMode::Normal
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            FolderMode::Normal => "normal",
            FolderMode::SendOnly => "send-only",
            FolderMode::ReceiveOnly => "receive-only",
        }
    }
}

impl std::str::FromStr for FolderMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "normal" | "send-receive" => Ok(FolderMode::Normal),
            "send-only" | "send" => Ok(FolderMode::SendOnly),
            "receive-only" | "receive" => Ok(FolderMode::ReceiveOnly),
            other => bail!("unknown folder mode {other}: use normal, send-only or receive-only"),
        }
    }
}

/// The mass-deletion guard of a folder: a scan that finds more files gone at
/// once than this, or another device's file list that would delete that
/// many here, is held until the user confirms it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeletionGuard {
    /// Off: deletions are never held.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// More than this share of the folder's files (percent; 100 or more:
    /// no share rule) ...
    pub percent: u32,
    /// ... and more than this many files.
    pub min_files: u64,
    /// More than this many files whatever the share (0: no such limit).
    pub max_files: u64,
}

fn yes() -> bool {
    true
}

impl Default for DeletionGuard {
    fn default() -> Self {
        DeletionGuard {
            enabled: true,
            percent: 50,
            min_files: 100,
            max_files: 1000,
        }
    }
}

impl DeletionGuard {
    /// Whether deleting `deleted` of `total` files at once is held.
    pub fn trips(&self, deleted: u64, total: u64) -> bool {
        if !self.enabled || deleted == 0 {
            return false;
        }
        let share = self.percent < 100
            && deleted.saturating_mul(100) > (self.percent as u64).saturating_mul(total)
            && deleted > self.min_files;
        let count = self.max_files > 0 && deleted > self.max_files;
        share || count
    }

    pub fn describe(&self) -> String {
        if !self.enabled {
            return "off".into();
        }
        let mut parts = Vec::new();
        if self.percent < 100 {
            parts.push(format!(
                "more than {} % and more than {} files",
                self.percent, self.min_files
            ));
        }
        if self.max_files > 0 {
            parts.push(format!("more than {} files", self.max_files));
        }
        if parts.is_empty() {
            return "off".into();
        }
        parts.join(", or ")
    }
}

/// Storage credentials: `home/secrets.enc`, encrypted under a key derived
/// from this device's master key, so they are only readable when the vault is
/// unlocked. Keyed by secret reference (by default the storage name).
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SecretStore {
    pub secrets: BTreeMap<String, String>,
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.secrets.keys().map(|k| (k, crate::logging::Redacted)))
            .finish()
    }
}

impl SecretStore {
    const FILE: &'static str = "secrets.enc";
    fn key(keys: &Keys) -> SecretKey {
        keys.master.derive("storage-secrets", &[])
    }
    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "storage-secrets",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }
    pub fn load(home: &Path, keys: &Keys, vault: &VaultId, device: &DeviceId) -> Result<Self> {
        let p = home.join(Self::FILE);
        if !p.exists() {
            return Ok(Self::default());
        }
        let plain = crypto::decrypt(
            &Self::key(keys),
            &Self::aad(vault, device),
            &std::fs::read(&p)?,
        )
        .context("open secrets.enc")?;
        let store: SecretStore = serde_json::from_slice(&plain)?;
        for v in store.secrets.values() {
            crate::logging::register_secret(v);
        }
        Ok(store)
    }
    pub fn save(&self, home: &Path, keys: &Keys, vault: &VaultId, device: &DeviceId) -> Result<()> {
        let blob = crypto::encrypt(
            &Self::key(keys),
            &Self::aad(vault, device),
            &serde_json::to_vec(self)?,
        )?;
        util::write_atomic(&home.join(Self::FILE), &blob)
    }
}

/// Local configuration: `home/config.json` (no secrets).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub storages: Vec<StorageSpec>,
    pub folders: Vec<FolderMount>,
    #[serde(default)]
    pub p2p: P2pConfig,
    /// Automatic verification schedule and budget (`crate::autoverify`).
    #[serde(default)]
    pub verify: crate::autoverify::VerifySchedule,
    /// Bit-rot check (scrub) schedule, budgets and cold storages opted in (`crate::scrub`).
    #[serde(default)]
    pub scrub: crate::scrub::ScrubSchedule,
    /// Storage prices set by the user, by storage name (`crate::price`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub prices: std::collections::BTreeMap<String, crate::price::StoragePrice>,
    /// Destination devices of transferrers, by storage name: such a
    /// transferrer carries what those devices lack and is emptied as they
    /// receive it. Absent: any device that lacks a block.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub carrier_for: std::collections::BTreeMap<String, Vec<DeviceId>>,
    /// Backups this device is the source of: what it backs up and when.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<BackupSource>,
    /// Backups with restic: this device keeps the plaintext mirror
    /// (`crate::restic`, `engine::restic_mirror`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restic: Option<crate::restic::ResticConfig>,
    /// When large fetches propose pool disks instead of the network.
    #[serde(default)]
    pub disk_fetch: crate::engine::DiskFetchSettings,
    /// How verification reads each place (`crate::parverify`): by storage or
    /// pool name, `folder:<name>`, `block-cache`, or `*` for every one not
    /// named; `"auto"` (by the medium, the default), `"sequential"` or a
    /// number of readers. For when the medium is detected wrongly.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub verify_parallelism: std::collections::BTreeMap<String, crate::parverify::Parallelism>,
    /// Thumbnail generation (`crate::thumbs`).
    #[serde(
        default,
        skip_serializing_if = "crate::thumbs::ThumbnailSettings::is_default"
    )]
    pub thumbnails: crate::thumbs::ThumbnailSettings,
    /// The "next disk to dock" reminder (`crate::disksuggest`).
    #[serde(default)]
    pub disk_suggest: crate::disksuggest::SuggestSettings,
    /// Quotas and drains of the storages, by storage name: this device's
    /// copy of the vault-wide settings (`crate::storage_settings`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub storage_settings:
        std::collections::BTreeMap<String, crate::storage_settings::SettingsEntry>,
    /// Detail of the local debug log (`crate::logging`): a level or a
    /// filter; absent means debug. `VARSTO_LOG` and `--log-level` win.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// How much change history of files this device keeps (`crate::changes`).
    #[serde(
        default,
        skip_serializing_if = "crate::changes::ChangeLimits::is_default"
    )]
    pub changes: crate::changes::ChangeLimits,
    /// Whether each S3 storage honours `If-None-Match: *`, by storage name:
    /// learned by a probe on the first write (`crate::s3`). Storages that do
    /// get one PUT per object, the others HEAD-then-PUT.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub conditional_writes: std::collections::BTreeMap<String, bool>,
    /// Forwarding other devices' blocks to the storages (`engine::forward`).
    #[serde(
        default,
        skip_serializing_if = "crate::engine::ForwardSettings::is_default"
    )]
    pub forward: crate::engine::ForwardSettings,
    /// The mailbox for offline pool disks (`engine::mailbox`).
    #[serde(
        default,
        skip_serializing_if = "crate::mailbox::MailboxSettings::is_default"
    )]
    pub mailbox: crate::mailbox::MailboxSettings,
}

/// A backup taken on this device (local, never published).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupSource {
    pub folder_id: FolderId,
    /// The directory backed up; only ever read.
    pub path: PathBuf,
    pub schedule: BackupSchedule,
    /// Retention of the snapshots taken from now on.
    pub retention_days: u32,
    #[serde(default)]
    pub last_taken_utc: i64,
    /// Sequence number of the newest snapshot written from here.
    #[serde(default)]
    pub last_seq: u64,
    /// Stopped: no more snapshots; the ones kept expire as they would.
    #[serde(default)]
    pub stopped: bool,
    /// A snapshot was asked for (a new backup, or "take a snapshot now"):
    /// the service takes it on its next run, whatever the schedule.
    #[serde(default)]
    pub take_now: bool,
}

/// When the background service takes a backup's snapshots.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackupSchedule {
    /// Only when asked (`varsto backup take`, the interface).
    Manual,
    /// Once this many hours have passed since the last snapshot.
    EveryHours(u32),
}

impl Default for BackupSchedule {
    fn default() -> Self {
        BackupSchedule::EveryHours(24)
    }
}

impl BackupSchedule {
    pub fn describe(&self) -> String {
        match self {
            BackupSchedule::Manual => "manual".to_string(),
            BackupSchedule::EveryHours(24) => "daily".to_string(),
            BackupSchedule::EveryHours(168) => "weekly".to_string(),
            BackupSchedule::EveryHours(h) => format!("every {h} h"),
        }
    }
}

/// Peer-to-peer settings (per device, local).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pConfig {
    pub enabled: bool,
    /// TCP port to listen on (0 = pick one at start).
    #[serde(default)]
    pub port: u16,
    /// Addresses other devices can reach this one at across the internet
    /// (a forwarded port, a public IP, a VPN address).
    #[serde(default)]
    pub public_addrs: Vec<std::net::SocketAddr>,
    /// STUN servers (`host:port`) asked for our public UDP address. An empty
    /// list disables STUN; a missing key means the defaults.
    #[serde(default = "default_stun")]
    pub stun: Vec<String>,
    /// The user turned peer-to-peer off (`varsto p2p disable`, the
    /// interface). Peer-to-peer is on by default; settings written before
    /// it was are switched on unless this is set.
    #[serde(default)]
    pub user_disabled: bool,
    /// Ask the home router to forward the port (PCP, NAT-PMP, UPnP) before
    /// the other ways through NAT; `varsto p2p port-mapping on|off`.
    #[serde(default = "yes")]
    pub port_mapping: bool,
}

/// The port peer-to-peer listens on unless told otherwise: a fixed one is
/// easier to forward, and the same on every start keeps NAT mappings.
pub const DEFAULT_P2P_PORT: u16 = 17893;

pub fn default_stun() -> Vec<String> {
    crate::p2p::stun::DEFAULT_SERVERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for P2pConfig {
    fn default() -> Self {
        P2pConfig {
            enabled: true,
            port: DEFAULT_P2P_PORT,
            public_addrs: Vec::new(),
            stun: default_stun(),
            user_disabled: false,
            port_mapping: true,
        }
    }
}

impl Config {
    pub fn load(home: &Path) -> Result<Self> {
        let mut c: Config = util::read_json_or_default(&home.join("config.json"))?;
        // Peer-to-peer is on unless the user turned it off.
        if !c.p2p.user_disabled && !c.p2p.enabled {
            c.p2p.enabled = true;
            if c.p2p.port == 0 {
                c.p2p.port = DEFAULT_P2P_PORT;
            }
        }
        Ok(c)
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join("config.json"), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_codes_with_control_or_direction_characters_are_refused() {
        let key = format!(
            "{}.{}",
            hex::encode(SigningKey::generate().public().to_bytes()),
            hex::encode(crate::kem::DecapsKey::generate().public().to_bytes())
        );
        assert!(ShareRequest::parse(&format!("vsr1.{key}.Ville")).is_ok());
        // A code of format 2 (the KEM key alone) is refused with a reason.
        let old = hex::encode(crate::kem::DecapsKey::generate().public().to_bytes());
        let e = ShareRequest::parse(&format!("vsr1.{old}.Ville"))
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("older version"), "{e:#}");
        for bad in ["x\u{1b}[2Ay", "a\u{202e}b", "a\u{200b}b", "tab\there"] {
            let e = ShareRequest::parse(&format!("vsr1.{key}.{bad}"))
                .err()
                .unwrap();
            assert!(format!("{e:#}").contains("name"), "{bad:?}: {e:#}");
        }
        let dir = tempfile::tempdir().unwrap();
        for bad in ["x\u{1b}[2Ay", "a\u{202e}b"] {
            assert!(ShareRequest::code_for_named(dir.path(), Some(bad)).is_err());
        }
        assert!(ShareRequest::code_for_named(dir.path(), Some("Ville")).is_ok());
    }

    #[test]
    fn debug_output_shows_no_key_material() {
        let key = "ab".repeat(32);
        let later = "cd".repeat(32);
        let rec: FolderRecord = serde_json::from_value(serde_json::json!({
            "folder_id": FolderId::random(),
            "name": "docs",
            "key_hex": key,
            "created_by": DeviceId::random(),
            "created_utc": 1,
            "epoch_keys": {"1": later},
        }))
        .unwrap();
        let shown = format!("{rec:?}");
        assert!(shown.contains("docs"), "{shown}");
        for s in [&key, &later] {
            assert!(!shown.contains(s.as_str()), "{shown}");
        }
    }
}
