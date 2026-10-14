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

/// Token the owner gives to another Varsto user to share one folder (F-047):
/// `<vault-id>.<folder-id>.<folder-key-hex>.<name>`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ShareToken {
    pub vault_id: VaultId,
    pub folder_id: FolderId,
    pub key_hex: String,
    pub name: String,
    /// Folder keys of later epochs (a folder re-keyed with the vault key,
    /// share epochs), hex by epoch. Only sealed tokens carry them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub epoch_keys: BTreeMap<u32, String>,
    /// Fingerprint of the request code the owner confirmed (sealed tokens).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// The owner's devices when the token was made: a member accepts new
    /// folder keys only from them (and from devices a later share epoch of
    /// theirs names). Only sealed tokens carry them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<DeviceId>,
    /// What the recipient may do (sealed tokens; a plain token is always an
    /// editor's).
    #[serde(default)]
    pub role: crate::share::ShareRole,
    /// Invitation id and secret the member derives its join proof from
    /// (sealed tokens only; see `share::JoinProof`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invite: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub join_secret_hex: String,
}

crate::redacted_debug!(ShareToken { vault_id, folder_id, name, fingerprint, owners, role, invite ; key_hex, epoch_keys, join_secret_hex });

impl Drop for ShareToken {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
        self.join_secret_hex.zeroize();
        for v in self.epoch_keys.values_mut() {
            v.zeroize();
        }
    }
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
            epoch_keys: BTreeMap::new(),
            fingerprint: String::new(),
            owners: Vec::new(),
            role: Default::default(),
            invite: String::new(),
            join_secret_hex: String::new(),
        })
    }
    /// The plain form, refused when the folder has keys of later epochs
    /// (the plain format has no room for them).
    pub fn encode_plain(&self) -> Result<String> {
        if !self.epoch_keys.is_empty() {
            bail!(
                "{} has newer folder keys than a plain token can carry; ask the recipient for a request code (varsto share request) and seal the token to it",
                self.name
            );
        }
        Ok(self.encode())
    }
}

/// What a version-2 sealed token carries inside its ciphertext.
#[derive(Serialize, Deserialize)]
struct TokenPayload {
    key_hex: String,
    #[serde(default)]
    epoch_keys: BTreeMap<u32, String>,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    owners: Vec<DeviceId>,
    #[serde(default)]
    role: crate::share::ShareRole,
    #[serde(default)]
    invite: String,
    #[serde(default)]
    join_secret_hex: String,
}

impl Drop for TokenPayload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
        self.join_secret_hex.zeroize();
        for v in self.epoch_keys.values_mut() {
            v.zeroize();
        }
    }
}

impl ShareToken {
    /// Seal the folder key to a recipient's encapsulation key so the token
    /// can travel over an untrusted channel. Everything but the key stays in
    /// clear: vault id, folder id and name are not secrets.
    pub fn seal(&self, to: &crate::kem::EncapsKey) -> Result<SealedShareToken> {
        let (kem_ct, key) = to.encapsulate()?;
        let mut t = SealedShareToken {
            version: 1,
            vault_id: self.vault_id.clone(),
            folder_id: self.folder_id.clone(),
            name: self.name.clone(),
            kem_alg: crate::kem::KEM_ALG.to_string(),
            kem_ct_hex: hex::encode(&kem_ct),
            sealed_key_hex: String::new(),
        };
        let sealed = if self.epoch_keys.is_empty()
            && self.fingerprint.is_empty()
            && self.owners.is_empty()
            && self.role.is_editor()
            && self.join_secret_hex.is_empty()
        {
            // Version 1: the folder key alone, readable by older versions.
            crypto::encrypt(&key, &t.aad(), &hex::decode(&self.key_hex)?)?
        } else {
            t.version = 2;
            let payload = TokenPayload {
                key_hex: self.key_hex.clone(),
                epoch_keys: self.epoch_keys.clone(),
                fingerprint: self.fingerprint.clone(),
                owners: self.owners.clone(),
                role: self.role,
                invite: self.invite.clone(),
                join_secret_hex: self.join_secret_hex.clone(),
            };
            crypto::encrypt(
                &key,
                &t.aad(),
                &Zeroizing::new(serde_json::to_vec(&payload)?),
            )?
        };
        t.sealed_key_hex = hex::encode(sealed);
        Ok(t)
    }
}

/// A share token whose folder key is encapsulated to one recipient
/// (hybrid X25519 + ML-KEM-768). Encoded as
/// `vst1.<vault-id>.<folder-id>.<kem-alg>.<kem-ct-hex>.<sealed-key-hex>.<name>`;
/// version 2 (`vst2.`, same fields) seals a JSON payload instead of the bare
/// key: the folder key, the keys of later epochs and the fingerprint the
/// owner confirmed.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedShareToken {
    #[serde(default = "one")]
    pub version: u8,
    pub vault_id: VaultId,
    pub folder_id: FolderId,
    pub name: String,
    pub kem_alg: String,
    pub kem_ct_hex: String,
    pub sealed_key_hex: String,
}

crate::redacted_debug!(SealedShareToken { version, vault_id, folder_id, name, kem_alg ; kem_ct_hex, sealed_key_hex });

fn one() -> u8 {
    1
}

pub const SEALED_SHARE_PREFIX: &str = "vst1.";
pub const SEALED_SHARE_PREFIX_V2: &str = "vst2.";
pub const SHARE_REQUEST_PREFIX: &str = "vsr1.";

impl SealedShareToken {
    fn aad(&self) -> Vec<u8> {
        if self.version >= 2 {
            crypto::aad(
                "share-token-v2",
                &[
                    self.vault_id.as_str().as_bytes(),
                    self.folder_id.as_str().as_bytes(),
                    self.name.as_bytes(),
                    self.kem_ct_hex.as_bytes(),
                ],
            )
        } else {
            crypto::aad(
                "share-token",
                &[
                    self.vault_id.as_str().as_bytes(),
                    self.folder_id.as_str().as_bytes(),
                    self.name.as_bytes(),
                ],
            )
        }
    }
    pub fn encode(&self) -> String {
        format!(
            "{}{}.{}.{}.{}.{}.{}",
            if self.version >= 2 {
                SEALED_SHARE_PREFIX_V2
            } else {
                SEALED_SHARE_PREFIX
            },
            self.vault_id,
            self.folder_id,
            self.kem_alg,
            self.kem_ct_hex,
            self.sealed_key_hex,
            self.name
        )
    }
    /// A sealed token in text form or as a `varsto://share/token` link.
    pub fn is_sealed(s: &str) -> bool {
        let s = s.trim();
        if crate::qr::is_link(s) {
            return s[crate::qr::SCHEME.len()..]
                .to_ascii_lowercase()
                .starts_with("share/token");
        }
        s.starts_with(SEALED_SHARE_PREFIX) || s.starts_with(SEALED_SHARE_PREFIX_V2)
    }
    /// Decode a token, given as text or as a `varsto://share/token` link.
    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        if crate::qr::is_link(s) {
            return match crate::qr::Link::from_text(s)? {
                crate::qr::Link::ShareToken(t) => Self::decode(&t),
                other => bail!("this is a {} link, not a share token", other.kind()),
            };
        }
        let (version, rest) = if let Some(r) = s.strip_prefix(SEALED_SHARE_PREFIX_V2) {
            (2, r)
        } else {
            (
                1,
                s.strip_prefix(SEALED_SHARE_PREFIX)
                    .ok_or_else(|| anyhow!("not a sealed share token"))?,
            )
        };
        let parts: Vec<&str> = rest.splitn(6, '.').collect();
        if parts.len() != 6 {
            bail!("sealed share token has the wrong shape");
        }
        Ok(SealedShareToken {
            version,
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
        let plain = Zeroizing::new(
            crypto::decrypt(&key, &self.aad(), &hex::decode(&self.sealed_key_hex)?).map_err(
                |_| anyhow!("this share token was not sealed to this device's request code"),
            )?,
        );
        let payload = if self.version >= 2 {
            serde_json::from_slice::<TokenPayload>(&plain)?
        } else {
            TokenPayload {
                key_hex: hex::encode(&*plain),
                epoch_keys: BTreeMap::new(),
                fingerprint: String::new(),
                owners: Vec::new(),
                role: Default::default(),
                invite: String::new(),
                join_secret_hex: String::new(),
            }
        };
        SecretKey::from_hex(&payload.key_hex)?;
        for k in payload.epoch_keys.values() {
            SecretKey::from_hex(k)?;
        }
        Ok(ShareToken {
            vault_id: self.vault_id.clone(),
            folder_id: self.folder_id.clone(),
            key_hex: payload.key_hex.clone(),
            name: self.name.clone(),
            epoch_keys: payload.epoch_keys.clone(),
            fingerprint: payload.fingerprint.clone(),
            owners: payload.owners.clone(),
            role: payload.role,
            invite: payload.invite.clone(),
            join_secret_hex: payload.join_secret_hex.clone(),
        })
    }
}

/// Recipient-side state for a pending share request: the private half of the
/// request code, kept in the device directory until the token is accepted
/// (the member device then keeps it as its KEM key, see `share_ops`).
#[derive(Serialize, Deserialize)]
pub struct ShareRequest {
    pub kem_alg: String,
    pub secret_hex: String,
    /// Name bound to the request code (covered by its fingerprint).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// A parsed request code: the requester's KEM key, the name it bound, and
/// the fingerprint both sides compare.
pub struct RequestCode {
    pub key: crate::kem::EncapsKey,
    pub name: String,
    pub fingerprint: String,
}

impl ShareRequest {
    pub const FILE: &'static str = "share-request.json";

    /// Load or create the request key for `home` and return the request code.
    pub fn code_for(home: &Path) -> Result<String> {
        Self::code_for_named(home, None)
    }

    /// Like `code_for`, binding `name` to the code when given (the key stays
    /// the same; only the name and with it the fingerprint change).
    pub fn code_for_named(home: &Path, name: Option<&str>) -> Result<String> {
        std::fs::create_dir_all(home)?;
        let path = home.join(Self::FILE);
        let mut r = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            ShareRequest {
                kem_alg: crate::kem::KEM_ALG.to_string(),
                secret_hex: hex::encode(crate::kem::DecapsKey::generate().to_bytes()),
                name: String::new(),
            }
        };
        let name = name.map(|n| n.trim().to_string());
        if let Some(n) = &name {
            crate::names::check_display_name(n)?;
        }
        let changed = !path.exists() || name.as_ref().is_some_and(|n| *n != r.name);
        if let Some(n) = name {
            r.name = n;
        }
        if changed {
            util::write_atomic(&path, &serde_json::to_vec_pretty(&r)?)?;
        }
        let dk = crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex)?)?;
        let mut code = format!(
            "{SHARE_REQUEST_PREFIX}{}",
            hex::encode(dk.public().to_bytes())
        );
        if !r.name.is_empty() {
            code.push('.');
            code.push_str(&r.name);
        }
        Ok(code)
    }
    /// The KEM key of a request code (`vsr1.<key hex>[.<name>]`).
    pub fn parse_code(code: &str) -> Result<crate::kem::EncapsKey> {
        Ok(Self::parse(code)?.key)
    }
    /// Key, bound name and fingerprint of a request code.
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
        let (hex_part, name) = rest.split_once('.').unwrap_or((rest, ""));
        let key = crate::kem::EncapsKey::from_bytes(&hex::decode(hex_part)?)?;
        let name = name.trim().to_string();
        crate::names::check_display_name(&name)?;
        Ok(RequestCode {
            fingerprint: crate::share::fingerprint(&key, &name),
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
    /// The private key of the pending request in `home`, if there is one.
    pub fn key(home: &Path) -> Option<crate::kem::DecapsKey> {
        let r = Self::load(home).ok()?;
        crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex).ok()?).ok()
    }
    /// The fingerprint of the pending request in `home`.
    pub fn fingerprint_for(home: &Path) -> Result<String> {
        let r = Self::load(home)?;
        let dk = crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex)?)?;
        Ok(crate::share::fingerprint(&dk.public(), &r.name))
    }
    /// Open a sealed token with the request key stored in `home`. A token
    /// that names the fingerprint the owner confirmed must name this
    /// request's fingerprint.
    pub fn open_token(home: &Path, token: &str) -> Result<ShareToken> {
        let r = Self::load(home)?;
        let dk = crate::kem::DecapsKey::from_bytes(&hex::decode(&r.secret_hex)?)?;
        let t = SealedShareToken::decode(token)?.open(&dk)?;
        let mine = crate::share::fingerprint(&dk.public(), &r.name);
        if !t.fingerprint.is_empty() && !crate::share::fingerprint_matches(&mine, &t.fingerprint) {
            bail!(
                "the owner confirmed the fingerprint \"{}\" but this device's request has \"{mine}\": the request code was changed on its way; ask the owner for a new token",
                t.fingerprint
            );
        }
        Ok(t)
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
    /// Seal and sign (storage format 2: every policy record is a signed
    /// record of kind `policy`, scope the folder, sequence number the time
    /// in its name): a holder of the vault key cannot pass a policy off as
    /// another device's.
    pub fn seal_signed(
        &self,
        vault: &VaultId,
        key_id: &str,
        key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Vec<u8>> {
        let header = crate::record::Header {
            kind: crate::record::RecordKind::Policy,
            vault,
            scope: self.folder_id.as_str(),
            device: &self.device,
            seq: self.updated_utc.max(0) as u64,
            key_id,
        };
        Ok(header
            .seal(key, &serde_json::to_vec(self)?, signer)?
            .to_bytes())
    }
    /// Open a signed policy record found under `named_device`'s part of its
    /// object name; the writer's key comes from `verify`, the body's key
    /// from `key_for`.
    pub fn open_any(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        named_device: &DeviceId,
        key_for: &dyn Fn(&str) -> Option<SecretKey>,
        verify: &dyn Fn(&DeviceId) -> Option<VerifyingKey>,
    ) -> Result<Self> {
        let env = crate::record::SignedRecord::parse(blob)?;
        let plain = env.accept(
            &crate::record::Expect::new(crate::record::RecordKind::Policy, vault)
                .scope(folder.as_str())
                .device(named_device),
            verify,
            key_for,
        )?;
        let rec: PolicyRecord = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder
            || rec.device != env.device
            || rec.updated_utc.max(0) as u64 != env.seq
        {
            bail!("policy record does not match its envelope");
        }
        Ok(rec)
    }
}

/// A folder removed from the vault, published so every device stops
/// syncing it: `vault/removed/<folder>/<device>.enc`. Files on devices stay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderRemoval {
    pub folder_id: FolderId,
    pub device: DeviceId,
    pub removed_utc: i64,
}

impl FolderRemoval {
    pub const PREFIX: &'static str = "vault/removed/";
    pub fn storage_key(&self) -> String {
        format!("{}{}/{}.enc", Self::PREFIX, self.folder_id, self.device)
    }
    fn aad(vault: &VaultId, folder: &FolderId) -> Vec<u8> {
        crypto::aad(
            "folder-removal",
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
        let rec: FolderRemoval = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder {
            bail!("folder removal record mismatch");
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
        let opened = crypto::decrypt(&wrap, &aad, &blob);
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
    /// Removed from the vault (local flag, learned from a `FolderRemoval`).
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
    /// On a member device: the invitation it joined through, with the
    /// secret its join proof is derived from and the role the token gave.
    /// Local only, never published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_join: Option<ShareJoin>,
}

/// See `FolderRecord::share_join`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareJoin {
    pub invite: String,
    pub secret_hex: String,
    pub role: crate::share::ShareRole,
}

crate::redacted_debug!(ShareJoin { invite, role ; secret_hex });

impl Drop for ShareJoin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_hex.zeroize();
    }
}

crate::redacted_debug!(FolderRecord { folder_id, name, created_by, created_utc, shared, strongroom, removed_utc, backup, placement, policy, share_join ; key_hex, epoch_keys });

impl Drop for FolderRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
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
            epoch_keys: BTreeMap::new(),
            fingerprint: String::new(),
            owners: Vec::new(),
            role: Default::default(),
            invite: String::new(),
            join_secret_hex: String::new(),
        }
    }
}

/// Keys derived from one folder key.
///
/// A folder has key *epochs* (`docs/spec/alpha-0-format.md` section 20):
/// epoch 0 is the key in the folder record; each device revocation starts a
/// new vault key epoch, and the folder key of epoch `e >= 1` is derived from
/// that epoch's vault key. New chunks and manifests use the newest epoch the
/// device knows; older chunks stay under the epoch recorded in their
/// `ChunkRef`. The keyed-hash key stays the one of epoch 0, so chunk ids and
/// content hashes (and with them deduplication and merging) do not change.
pub struct FolderKeys {
    pub folder: FolderId,
    base: SecretKey,
    /// Keyed-hash key for chunk ids and file content hashes (dedup domain = folder).
    pub hash: SecretKey,
    /// Encrypts manifests (and thumbnails) written now: the newest epoch.
    pub meta: SecretKey,
    /// The epoch new chunks and manifests are written under.
    pub epoch: u32,
    /// Folder keys of epochs 1 and later.
    later: BTreeMap<u32, SecretKey>,
}

crate::redacted_opaque!(FolderKeys);

impl FolderKeys {
    pub fn from_folder_key(folder: &FolderId, base: SecretKey) -> Result<Self> {
        crate::logging::register_key(base.as_bytes());
        let scope: &[&[u8]] = &[folder.as_str().as_bytes()];
        Ok(FolderKeys {
            folder: folder.clone(),
            hash: base.derive("dedup-hash", scope),
            meta: base.derive("folder-metadata", scope),
            base,
            epoch: 0,
            later: BTreeMap::new(),
        })
    }

    /// Add the folder keys of later epochs; the newest becomes the write epoch.
    pub fn with_epochs(mut self, later: BTreeMap<u32, SecretKey>) -> Self {
        if let Some((e, k)) = later.iter().next_back() {
            self.epoch = *e;
            self.meta = k.derive("folder-metadata", &[self.folder.as_str().as_bytes()]);
        }
        self.later = later;
        self
    }

    /// Keep writing under epoch 0 while still reading later epochs (folders
    /// shared with other users, Strongroom).
    pub fn write_at_base(mut self) -> Self {
        self.epoch = 0;
        self.meta = self
            .base
            .derive("folder-metadata", &[self.folder.as_str().as_bytes()]);
        self
    }

    /// Write under a later epoch this key set knows (a folder's newest
    /// share epoch); falls back to epoch 0 when the epoch is unknown.
    pub fn write_at(mut self, epoch: u32) -> Self {
        match self.later.get(&epoch) {
            Some(k) => {
                self.meta = k.derive("folder-metadata", &[self.folder.as_str().as_bytes()]);
                self.epoch = epoch;
                self
            }
            None => self.write_at_base(),
        }
    }

    fn epoch_base(&self, epoch: u32) -> Result<&SecretKey> {
        if epoch == 0 {
            return Ok(&self.base);
        }
        self.later.get(&epoch).ok_or_else(|| {
            anyhow!(
                "folder key epoch {epoch} is not known on this device yet (it arrives with the next sync)"
            )
        })
    }

    /// The metadata key of one epoch, when this key set knows it: what a
    /// record's `meta@<epoch>` key id names.
    pub fn meta_key_for(&self, epoch: u32) -> Option<SecretKey> {
        self.epoch_base(epoch)
            .ok()
            .map(|k| k.derive("folder-metadata", &[self.folder.as_str().as_bytes()]))
    }

    /// Metadata keys of every known epoch, newest first: manifests and
    /// thumbnails are opened with the first that fits.
    pub fn meta_keys(&self) -> Vec<SecretKey> {
        let scope: &[&[u8]] = &[self.folder.as_str().as_bytes()];
        self.later
            .values()
            .rev()
            .chain(std::iter::once(&self.base))
            .map(|k| k.derive("folder-metadata", scope))
            .collect()
    }

    /// Seed of the folder's Gear table (`crate::chunking`): derived from the
    /// hash key, which stays the same across epochs, so a rotation does not
    /// move any cut point.
    pub fn chunker_seed(&self) -> [u8; 32] {
        self.hash
            .derive("chunker-seed", &[self.folder.as_str().as_bytes()])
            .0
    }

    /// Alpha-0 decision: the chunk key is derived from the chunk's keyed hash
    /// (convergent inside the folder and epoch), so the same content encrypts
    /// to the same object on every device, which makes offline deduplication
    /// work. Rotation therefore applies to new chunks only.
    pub fn chunk_key(&self, epoch: u32, chunk: &ChunkId) -> Result<SecretKey> {
        Ok(self.epoch_base(epoch)?.derive(
            "chunk-key",
            &[self.folder.as_str().as_bytes(), chunk.as_str().as_bytes()],
        ))
    }

    /// The nonce of one chunk object: a keyed hash of the exact bytes that
    /// are encrypted (the packed chunk, `crate::pack`), under a key of the
    /// folder and epoch. Two different encodings of one chunk (another zstd
    /// version, raw against compressed) therefore never share a nonce under
    /// the chunk key, while the same bytes always give the same nonce, so
    /// objects stay deterministic and deduplicate (format 2, audit H1).
    pub fn chunk_nonce(&self, epoch: u32, packed: &[u8]) -> Result<[u8; crypto::NONCE_LEN]> {
        let k = self
            .epoch_base(epoch)?
            .derive("chunk-nonce", &[self.folder.as_str().as_bytes()]);
        let mut n = [0u8; crypto::NONCE_LEN];
        n.copy_from_slice(&crypto::keyed_hash(&k, packed)[..crypto::NONCE_LEN]);
        Ok(n)
    }

    /// Associated data of a chunk object: vault, folder, key epoch, chunk
    /// id, plaintext length and packed length.
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
                vault.as_str().as_bytes(),
                self.folder.as_str().as_bytes(),
                &epoch.to_le_bytes(),
                chunk.as_str().as_bytes(),
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
        let key = hex::encode(crate::kem::DecapsKey::generate().public().to_bytes());
        assert!(ShareRequest::parse(&format!("vsr1.{key}.Ville")).is_ok());
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
        let secret = "ef".repeat(32);
        let token = ShareToken {
            vault_id: VaultId::random(),
            folder_id: FolderId::random(),
            key_hex: key.clone(),
            name: "docs".into(),
            epoch_keys: BTreeMap::from([(1_048_576, later.clone())]),
            fingerprint: "one two three".into(),
            owners: vec![],
            role: Default::default(),
            invite: "inv".into(),
            join_secret_hex: secret.clone(),
        };
        let shown = format!("{token:?}");
        assert!(shown.contains("docs") && shown.contains("inv"), "{shown}");
        for s in [&key, &later, &secret] {
            assert!(!shown.contains(s.as_str()), "{shown}");
        }

        let join = ShareJoin {
            invite: "inv".into(),
            secret_hex: secret.clone(),
            role: Default::default(),
        };
        let shown = format!("{join:?}");
        assert!(shown.contains("inv") && !shown.contains(&secret), "{shown}");

        let rec: FolderRecord = serde_json::from_value(serde_json::json!({
            "folder_id": FolderId::random(),
            "name": "docs",
            "key_hex": key,
            "created_by": DeviceId::random(),
            "created_utc": 1,
            "epoch_keys": {"1048576": later},
            "share_join": join,
        }))
        .unwrap();
        let shown = format!("{rec:?}");
        assert!(shown.contains("docs"), "{shown}");
        for s in [&key, &later, &secret] {
            assert!(!shown.contains(s.as_str()), "{shown}");
        }
    }
}
