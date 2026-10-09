// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Vault identity, keys, device and folder records, local configuration.
//!
//! Alpha-0 key hierarchy (subset of `docs/spec/key-hierarchy.md`):
//! - master key K3: random 256 bits, wrapped locally under an Argon2id
//!   passphrase key; shared between devices out of band as the "vault key"
//!   (pairing and recovery through a hybrid KEM are not implemented yet);
//! - device signing key K6/K7 (Ed25519) per device, wrapped with K3 locally;
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

/// Token the owner gives to another Varsto user to share one folder (F-047):
/// `<vault-id>.<folder-id>.<folder-key-hex>.<name>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareToken {
    pub vault_id: VaultId,
    pub folder_id: FolderId,
    pub key_hex: String,
    pub name: String,
}

impl ShareToken {
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.vault_id, self.folder_id, self.key_hex, self.name
        )
    }
    pub fn decode(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.trim().splitn(4, '.').collect();
        if parts.len() != 4 {
            bail!("share token must be <vault-id>.<folder-id>.<key-hex>.<name>");
        }
        SecretKey::from_hex(parts[2])?;
        Ok(ShareToken {
            vault_id: VaultId::from_hex(parts[0])?,
            folder_id: FolderId::from_hex(parts[1])?,
            key_hex: parts[2].to_string(),
            name: parts[3].to_string(),
        })
    }
}

impl ShareToken {
    /// Seal the folder key to a recipient's encapsulation key so the token
    /// can travel over an untrusted channel. Everything but the key stays in
    /// clear: vault id, folder id and name are not secrets.
    pub fn seal(&self, to: &crate::kem::EncapsKey) -> Result<SealedShareToken> {
        let (kem_ct, key) = to.encapsulate()?;
        let aad = crypto::aad(
            "share-token",
            &[
                self.vault_id.as_str().as_bytes(),
                self.folder_id.as_str().as_bytes(),
                self.name.as_bytes(),
            ],
        );
        let folder_key = hex::decode(&self.key_hex)?;
        let sealed = crypto::encrypt(&key, &aad, &folder_key)?;
        Ok(SealedShareToken {
            vault_id: self.vault_id.clone(),
            folder_id: self.folder_id.clone(),
            name: self.name.clone(),
            kem_alg: crate::kem::KEM_ALG.to_string(),
            kem_ct_hex: hex::encode(kem_ct),
            sealed_key_hex: hex::encode(sealed),
        })
    }
}

/// A share token whose folder key is encapsulated to one recipient
/// (hybrid X25519 + ML-KEM-768). Encoded as
/// `vst1.<vault-id>.<folder-id>.<kem-alg>.<kem-ct-hex>.<sealed-key-hex>.<name>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedShareToken {
    pub vault_id: VaultId,
    pub folder_id: FolderId,
    pub name: String,
    pub kem_alg: String,
    pub kem_ct_hex: String,
    pub sealed_key_hex: String,
}

pub const SEALED_SHARE_PREFIX: &str = "vst1.";
pub const SHARE_REQUEST_PREFIX: &str = "vsr1.";

impl SealedShareToken {
    pub fn encode(&self) -> String {
        format!(
            "{SEALED_SHARE_PREFIX}{}.{}.{}.{}.{}.{}",
            self.vault_id,
            self.folder_id,
            self.kem_alg,
            self.kem_ct_hex,
            self.sealed_key_hex,
            self.name
        )
    }
    pub fn is_sealed(s: &str) -> bool {
        s.trim().starts_with(SEALED_SHARE_PREFIX)
    }
    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let rest = s
            .strip_prefix(SEALED_SHARE_PREFIX)
            .ok_or_else(|| anyhow!("not a sealed share token"))?;
        let parts: Vec<&str> = rest.splitn(6, '.').collect();
        if parts.len() != 6 {
            bail!("sealed share token has the wrong shape");
        }
        Ok(SealedShareToken {
            vault_id: VaultId::from_hex(parts[0])?,
            folder_id: FolderId::from_hex(parts[1])?,
            kem_alg: parts[2].to_string(),
            kem_ct_hex: parts[3].to_string(),
            sealed_key_hex: parts[4].to_string(),
            name: parts[5].to_string(),
        })
    }
    /// Open with the recipient's private key.
    pub fn open(&self, dk: &crate::kem::DecapsKey) -> Result<ShareToken> {
        if self.kem_alg != crate::kem::KEM_ALG {
            bail!("unsupported key encapsulation algorithm {}", self.kem_alg);
        }
        let key = dk.decapsulate(&hex::decode(&self.kem_ct_hex)?)?;
        let aad = crypto::aad(
            "share-token",
            &[
                self.vault_id.as_str().as_bytes(),
                self.folder_id.as_str().as_bytes(),
                self.name.as_bytes(),
            ],
        );
        let folder_key =
            crypto::decrypt(&key, &aad, &hex::decode(&self.sealed_key_hex)?).map_err(|_| {
                anyhow!("this share token was not sealed to this device's request code")
            })?;
        SecretKey::from_bytes(&folder_key)?;
        Ok(ShareToken {
            vault_id: self.vault_id.clone(),
            folder_id: self.folder_id.clone(),
            key_hex: hex::encode(folder_key),
            name: self.name.clone(),
        })
    }
}

/// Recipient-side state for a pending share request: the private half of the
/// request code, kept in the device directory until the token is accepted.
#[derive(Serialize, Deserialize)]
pub struct ShareRequest {
    pub kem_alg: String,
    pub secret_hex: String,
}

impl ShareRequest {
    pub const FILE: &'static str = "share-request.json";

    /// Load or create the request key for `home` and return the request code.
    pub fn code_for(home: &Path) -> Result<String> {
        std::fs::create_dir_all(home)?;
        let path = home.join(Self::FILE);
        let dk = if path.exists() {
            let r: ShareRequest = serde_json::from_slice(&std::fs::read(&path)?)?;
            crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex)?)?
        } else {
            let dk = crate::kem::DecapsKey::generate();
            let r = ShareRequest {
                kem_alg: crate::kem::KEM_ALG.to_string(),
                secret_hex: hex::encode(dk.to_bytes()),
            };
            util::write_atomic(&path, &serde_json::to_vec_pretty(&r)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            dk
        };
        Ok(format!(
            "{SHARE_REQUEST_PREFIX}{}",
            hex::encode(dk.public().to_bytes())
        ))
    }
    pub fn parse_code(code: &str) -> Result<crate::kem::EncapsKey> {
        let rest = code
            .trim()
            .strip_prefix(SHARE_REQUEST_PREFIX)
            .ok_or_else(|| anyhow!("not a share request code (expected the vsr1. prefix)"))?;
        crate::kem::EncapsKey::from_bytes(&hex::decode(rest)?)
    }
    /// Open a sealed token with the request key stored in `home`.
    pub fn open_token(home: &Path, token: &str) -> Result<ShareToken> {
        let path = home.join(Self::FILE);
        if !path.exists() {
            bail!(
                "no share request in {}: run `varsto share request` there first and give its code to the owner",
                home.display()
            );
        }
        let r: ShareRequest = serde_json::from_slice(&std::fs::read(&path)?)?;
        let dk = crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex)?)?;
        SealedShareToken::decode(token)?.open(&dk)
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
}

/// Prefix of member device records: `vault/shares/<folder>/<device>.enc`.
pub const SHARE_PREFIX: &str = "vault/shares/";

pub fn share_record_key(folder: &FolderId, device: &DeviceId) -> String {
    format!("{SHARE_PREFIX}{folder}/{device}.enc")
}

/// Key id of a member device's ledger batches for one shared folder.
pub fn share_key_id(folder: &FolderId) -> String {
    format!("share:{folder}")
}

/// Members encrypt their ledger batches for a shared folder under this key,
/// derived from the folder key, so every holder of the folder key can read them.
pub fn share_ledger_key(folder_key: &SecretKey, folder: &FolderId) -> SecretKey {
    folder_key.derive("share-ledger", &[folder.as_str().as_bytes()])
}

pub fn share_registry_key(folder_key: &SecretKey, folder: &FolderId) -> SecretKey {
    folder_key.derive("share-registry", &[folder.as_str().as_bytes()])
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
        let wrap = crypto::passphrase_key(passphrase, &kf.params)?;
        let plain = Zeroizing::new(
            crypto::decrypt(
                &wrap,
                &Self::keyfile_aad(vault, device),
                &hex::decode(&kf.blob_hex)?,
            )
            .context("unlock failed: wrong passphrase or damaged key file")?,
        );
        let material: KeyMaterial = serde_json::from_slice(&plain)?;
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderRecord {
    pub folder_id: FolderId,
    pub name: String,
    pub key_hex: String,
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
    /// Strongroom (S-012): the folder key is not stored here (`key_hex` is
    /// empty); it is wrapped under a security-key secret and held in memory
    /// only while unlocked.
    #[serde(default)]
    pub strongroom: Option<crate::strongroom::StrongroomInfo>,
}

impl FolderRecord {
    pub fn is_strongroom(&self) -> bool {
        self.strongroom.is_some()
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
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.created_by, &self.folder_id),
            &serde_json::to_vec(self)?,
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
    pub fn keys(&self) -> Result<FolderKeys> {
        FolderKeys::from_folder_key(&self.folder_id, SecretKey::from_hex(&self.key_hex)?)
    }
    pub fn folder_key(&self) -> Result<SecretKey> {
        SecretKey::from_hex(&self.key_hex)
    }
    pub fn share_token(&self, vault: &VaultId) -> ShareToken {
        ShareToken {
            vault_id: vault.clone(),
            folder_id: self.folder_id.clone(),
            key_hex: self.key_hex.clone(),
            name: self.name.clone(),
        }
    }
}

/// Keys derived from one folder key.
pub struct FolderKeys {
    pub folder: FolderId,
    base: SecretKey,
    /// Keyed-hash key for chunk ids and file content hashes (dedup domain = folder).
    pub hash: SecretKey,
    /// Encrypts manifests.
    pub meta: SecretKey,
}

impl FolderKeys {
    pub fn from_folder_key(folder: &FolderId, base: SecretKey) -> Result<Self> {
        let scope: &[&[u8]] = &[folder.as_str().as_bytes()];
        Ok(FolderKeys {
            folder: folder.clone(),
            hash: base.derive("dedup-hash", scope),
            meta: base.derive("folder-metadata", scope),
            base,
        })
    }

    /// Alpha-0 decision: the chunk key is derived from the chunk's keyed hash
    /// (convergent inside the folder), so the same content encrypts to the same
    /// object on every device, which makes offline deduplication work. Rotation
    /// therefore re-encrypts data; shared folders will use random keys instead.
    pub fn chunk_key(&self, chunk: &ChunkId) -> SecretKey {
        self.base.derive(
            "chunk-key",
            &[self.folder.as_str().as_bytes(), chunk.as_str().as_bytes()],
        )
    }

    pub fn chunk_nonce(&self, chunk: &ChunkId) -> [u8; crypto::NONCE_LEN] {
        let k = self.base.derive(
            "chunk-nonce",
            &[self.folder.as_str().as_bytes(), chunk.as_str().as_bytes()],
        );
        let mut n = [0u8; crypto::NONCE_LEN];
        n.copy_from_slice(&k.0[..crypto::NONCE_LEN]);
        n
    }

    pub fn chunk_aad(&self, vault: &VaultId, chunk: &ChunkId, len: u64) -> Vec<u8> {
        crypto::aad(
            "chunk",
            &[
                vault.as_str().as_bytes(),
                self.folder.as_str().as_bytes(),
                chunk.as_str().as_bytes(),
                &len.to_le_bytes(),
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
    pub fn find(&self, name_or_id: &str) -> Option<&FolderRecord> {
        self.folders.values().find(|r| {
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
    /// "Encrypted on this device" (phones): the folder lives in the app's
    /// private space, files are fetched when opened and their plaintext copies
    /// are removed when the vault locks. Absent in older configurations, which
    /// means plain files as on a desktop.
    #[serde(default)]
    pub encrypted: bool,
}

/// Storage credentials: `home/secrets.enc`, encrypted under a key derived
/// from this device's master key, so they are only readable when the vault is
/// unlocked. Keyed by secret reference (by default the storage name).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecretStore {
    pub secrets: BTreeMap<String, String>,
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
        Ok(serde_json::from_slice(&plain)?)
    }
    pub fn save(&self, home: &Path, keys: &Keys, vault: &VaultId, device: &DeviceId) -> Result<()> {
        let blob = crypto::encrypt(
            &Self::key(keys),
            &Self::aad(vault, device),
            &serde_json::to_vec(self)?,
        )?;
        util::write_atomic(&home.join(Self::FILE), &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                home.join(Self::FILE),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        Ok(())
    }
}

/// Local configuration: `home/config.json` (no secrets).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub storages: Vec<StorageSpec>,
    pub folders: Vec<FolderMount>,
    #[serde(default)]
    pub p2p: P2pConfig,
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
}

pub fn default_stun() -> Vec<String> {
    crate::p2p::stun::DEFAULT_SERVERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for P2pConfig {
    fn default() -> Self {
        P2pConfig {
            enabled: false,
            port: 0,
            public_addrs: Vec::new(),
            stun: default_stun(),
        }
    }
}

impl Config {
    pub fn load(home: &Path) -> Result<Self> {
        util::read_json_or_default(&home.join("config.json"))
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join("config.json"), self)
    }
}
