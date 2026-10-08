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
use anyhow::{bail, Context, Result};
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
}

impl FolderRecord {
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
}

/// Local configuration: `home/config.json` (no secrets).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub storages: Vec<StorageSpec>,
    pub folders: Vec<FolderMount>,
}

impl Config {
    pub fn load(home: &Path) -> Result<Self> {
        util::read_json_or_default(&home.join("config.json"))
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join("config.json"), self)
    }
}
