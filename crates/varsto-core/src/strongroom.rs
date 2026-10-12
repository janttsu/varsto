// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Strongroom folders (S-012): a folder whose key exists only while a FIDO2
//! security key is touched. The folder key is wrapped with a secret that the
//! authenticator derives with the `hmac-secret` extension from a per-folder
//! salt; the wrapped key is what gets stored and published, never the key
//! itself. Every device of the vault can open the folder with the same
//! physical key (hmac-secret is deterministic for a credential and salt),
//! and nothing derivable from the vault's master key opens it.
//!
//! A Strongroom can have several security keys (a spare kept in a safe):
//! each enrolled credential has its own salt and its own wrap of the same
//! folder key, and unlocking tries them in turn. An existing folder can be
//! converted into a Strongroom: it gets a new folder id and a new random key,
//! its content is re-encrypted under that key, and the old copies are
//! removed from the storages once the new ones are stored (see
//! `Engine::convert_to_strongroom`).
//!
//! Backends: `fido2` runs the libfido2 command-line tools (`fido2-cred`,
//! `fido2-assert`), available on Linux, macOS and Windows, so the core needs
//! no native HID dependency; `software` keeps the secret in a file and
//! exists for tests and for trying the flow without hardware. The software
//! backend gives no protection beyond the passphrase and says so.
//!
//! Honest limits: once unlocked, the folder key is in the memory of the
//! process for the chosen window; files you fetched stay on disk until you
//! free them; malware active during the window sees what you see.

use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, FolderId, VaultId};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub const RP_ID: &str = "varsto.local";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// FIDO2 security key through the libfido2 tools.
    Fido2,
    /// A secret kept in a file; test and demonstration only.
    Software,
}

/// Published with the folder: how to derive the wrapping secret and the
/// wrapped folder key, for the first enrolled security key and any backup
/// keys. Contains no secret. The first key's fields stay at the top level so
/// records written before backup keys existed read unchanged.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrongroomInfo {
    pub method: Method,
    /// Credential id (base64) for fido2; a label for software.
    pub credential: String,
    /// 32-byte salt for hmac-secret (hex).
    pub salt_hex: String,
    /// Folder key encrypted under the derived secret (hex).
    pub wrapped_key_hex: String,
    /// Name the user gave the first key, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub added_utc: i64,
    /// More security keys that open the same folder key (a spare kept in a safe).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<EnrolledKey>,
    /// When the list of keys last changed; the newest list wins across devices.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_utc: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// One enrolled security key: its credential, salt and its own wrap of the
/// folder key (each credential derives a different secret).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolledKey {
    pub method: Method,
    pub credential: String,
    pub salt_hex: String,
    pub wrapped_key_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub added_utc: i64,
}

impl StrongroomInfo {
    /// Every enrolled key, the first one first.
    pub fn keys(&self) -> Vec<EnrolledKey> {
        let mut out = vec![EnrolledKey {
            method: self.method.clone(),
            credential: self.credential.clone(),
            salt_hex: self.salt_hex.clone(),
            wrapped_key_hex: self.wrapped_key_hex.clone(),
            label: self.label.clone(),
            added_utc: self.added_utc,
        }];
        out.extend(self.backups.iter().cloned());
        out
    }

    /// Rebuild from a list of keys; the first becomes the top-level one.
    pub fn from_keys(mut keys: Vec<EnrolledKey>, updated_utc: i64) -> Result<Self> {
        if keys.is_empty() {
            bail!("a Strongroom needs at least one security key");
        }
        let first = keys.remove(0);
        Ok(StrongroomInfo {
            method: first.method,
            credential: first.credential,
            salt_hex: first.salt_hex,
            wrapped_key_hex: first.wrapped_key_hex,
            label: first.label,
            added_utc: first.added_utc,
            backups: keys,
            updated_utc,
        })
    }

    /// Index of the key named by `which`: its number in `keys()` (from 1),
    /// its label, or its credential (whole, or a prefix of at least 6
    /// characters that matches one key only).
    pub fn find_key(&self, which: &str) -> Result<usize> {
        let keys = self.keys();
        if let Ok(n) = which.parse::<usize>() {
            if (1..=keys.len()).contains(&n) {
                return Ok(n - 1);
            }
        }
        if let Some(i) = keys
            .iter()
            .position(|k| k.credential == which || (!k.label.is_empty() && k.label == which))
        {
            return Ok(i);
        }
        let hits: Vec<usize> = keys
            .iter()
            .enumerate()
            .filter(|(_, k)| which.len() >= 6 && k.credential.starts_with(which))
            .map(|(i, _)| i)
            .collect();
        match hits.as_slice() {
            [i] => Ok(*i),
            [] => bail!("no enrolled key matches {which}"),
            _ => bail!("{which} matches more than one key; give more of the credential"),
        }
    }
}

impl EnrolledKey {
    /// A short, stable name for lists: the label, or the start of the credential.
    pub fn short(&self) -> String {
        let cred: String = match self.method {
            Method::Software => Path::new(self.credential.trim_start_matches("software:"))
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| self.credential.clone()),
            Method::Fido2 => self.credential.chars().take(12).collect(),
        };
        if self.label.is_empty() {
            cred
        } else {
            format!("{} ({cred})", self.label)
        }
    }
}

/// Something that turns (credential, salt) into a 32-byte secret after the
/// user's touch.
pub trait SecurityKey {
    fn make_credential(&self) -> Result<String>;
    fn hmac_secret(&self, credential: &str, salt: &[u8; 32]) -> Result<[u8; 32]>;
}

/// libfido2's command-line tools. The device path can be given explicitly
/// (`VARSTO_FIDO2_DEVICE`) or the first key found is used.
pub struct Fido2Tools {
    pub device: Option<String>,
}

impl Fido2Tools {
    fn first_device() -> Result<String> {
        let out = Command::new("fido2-token").arg("-L").output().context(
            "run fido2-token (install the libfido2 tools: libfido2 on Arch/Debian, brew install libfido2, or the Windows build)",
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let dev = text
            .lines()
            .next()
            .and_then(|l| l.split(':').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("no FIDO2 security key found: plug one in"))?;
        Ok(dev)
    }
    fn device(&self) -> Result<String> {
        match &self.device {
            Some(d) => Ok(d.clone()),
            None => std::env::var("VARSTO_FIDO2_DEVICE").or_else(|_| Self::first_device()),
        }
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

impl SecurityKey for Fido2Tools {
    fn make_credential(&self) -> Result<String> {
        let dev = self.device()?;
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        let user_id = [0x56u8; 16];
        // fido2-cred -M reads: client data hash, rp id, user name, user id (base64) from stdin.
        let input = format!(
            "{}\n{}\nvarsto\n{}\n",
            b64(&challenge),
            RP_ID,
            b64(&user_id)
        );
        eprintln!("Touch your security key to create the Strongroom credential.");
        let mut child = Command::new("fido2-cred")
            .args(["-M", "-h", "-r", &dev])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("run fido2-cred")?;
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("fido2-cred failed (PIN, touch or hmac-secret support?)");
        }
        // Output lines: client data hash, rp id, credential format, auth data, credential id, pubkey, ...
        let text = String::from_utf8_lossy(&out.stdout);
        let cred = text
            .lines()
            .nth(4)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("fido2-cred output had no credential id"))?;
        Ok(cred)
    }

    fn hmac_secret(&self, credential: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
        if credential.is_empty()
            || !credential.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || b == b'+'
                    || b == b'/'
                    || b == b'='
                    || b == b'-'
                    || b == b'_'
            })
        {
            bail!("the stored credential id is not base64");
        }
        let dev = self.device()?;
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        // fido2-assert -G reads: client data hash, rp id, credential id, hmac salt (base64) from stdin.
        let input = format!(
            "{}\n{}\n{}\n{}\n",
            b64(&challenge),
            RP_ID,
            credential,
            b64(salt)
        );
        eprintln!("Touch your security key to open the Strongroom.");
        let mut child = Command::new("fido2-assert")
            .args(["-G", "-h", &dev])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("run fido2-assert")?;
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("fido2-assert failed (wrong key, PIN or no touch?)");
        }
        // Output lines: client data hash, rp id, auth data, signature, hmac secret.
        let text = String::from_utf8_lossy(&out.stdout);
        let secret_b64 = text
            .lines()
            .nth(4)
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow!("fido2-assert output had no hmac secret"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(secret_b64.as_bytes())
            .context("decode hmac secret")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("hmac secret is not 32 bytes"))?;
        Ok(arr)
    }
}

/// Test and demonstration backend: the "touch" is a secret file.
pub struct SoftwareKey {
    pub path: std::path::PathBuf,
}

impl SecurityKey for SoftwareKey {
    fn make_credential(&self) -> Result<String> {
        if !self.path.exists() {
            let k = SecretKey::random();
            std::fs::write(&self.path, k.to_hex())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(format!("software:{}", self.path.display()))
    }
    fn hmac_secret(&self, _credential: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
        let k = SecretKey::from_hex(std::fs::read_to_string(&self.path)?.trim())
            .context("software security key file")?;
        Ok(crypto::keyed_hash(&k, salt))
    }
}

pub fn backend(method: &Method, home: &Path) -> Box<dyn SecurityKey> {
    match method {
        Method::Fido2 => Box::new(Fido2Tools { device: None }),
        Method::Software => Box::new(SoftwareKey {
            path: home.join("software-security-key"),
        }),
    }
}

/// The backend that can answer for one enrolled key on this device. A
/// software key's file is looked up by name in `home`, so a copy of the file
/// works on any device of the vault.
pub fn backend_for(key: &EnrolledKey, home: &Path) -> Box<dyn SecurityKey> {
    match key.method {
        Method::Fido2 => Box::new(Fido2Tools { device: None }),
        Method::Software => {
            let name = Path::new(key.credential.trim_start_matches("software:"))
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_else(|| "software-security-key".into());
            Box::new(SoftwareKey {
                path: home.join(name),
            })
        }
    }
}

/// A software key file for a backup key, next to the vault.
pub fn new_software_key(home: &Path) -> SoftwareKey {
    let mut tag = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
    SoftwareKey {
        path: home.join(format!("software-security-key-{}", hex::encode(tag))),
    }
}

fn wrap_key(secret: &[u8; 32], folder: &FolderId) -> SecretKey {
    SecretKey::from_bytes(&blake3::derive_key(
        &format!("{}/strongroom-wrap", crypto::CONTEXT_PREFIX),
        secret,
    ))
    .expect("32 bytes")
    .derive("strongroom", &[folder.as_str().as_bytes()])
}

fn aad(folder: &FolderId) -> Vec<u8> {
    crypto::aad("strongroom-key", &[folder.as_str().as_bytes()])
}

/// Create the credential (touch 1) and wrap `folder_key` (touch 2).
pub fn enroll(
    key: &dyn SecurityKey,
    method: Method,
    folder: &FolderId,
    folder_key: &SecretKey,
) -> Result<StrongroomInfo> {
    let k = enroll_key(key, method, folder, folder_key, "")?;
    StrongroomInfo::from_keys(vec![k], crate::util::now_utc())
}

/// Enrol one more security key for a folder key already in hand (two
/// touches of the new key: credential, then wrap).
pub fn enroll_key(
    key: &dyn SecurityKey,
    method: Method,
    folder: &FolderId,
    folder_key: &SecretKey,
    label: &str,
) -> Result<EnrolledKey> {
    let credential = key.make_credential()?;
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let secret = key.hmac_secret(&credential, &salt)?;
    let wrapped = crypto::encrypt(
        &wrap_key(&secret, folder),
        &aad(folder),
        folder_key.as_bytes(),
    )?;
    Ok(EnrolledKey {
        method,
        credential,
        salt_hex: hex::encode(salt),
        wrapped_key_hex: hex::encode(wrapped),
        label: label.to_string(),
        added_utc: crate::util::now_utc(),
    })
}

fn unwrap_one(key: &dyn SecurityKey, folder: &FolderId, k: &EnrolledKey) -> Result<SecretKey> {
    let salt: [u8; 32] = hex::decode(&k.salt_hex)?
        .try_into()
        .map_err(|_| anyhow!("strongroom salt must be 32 bytes"))?;
    let secret = key.hmac_secret(&k.credential, &salt)?;
    let plain = crypto::decrypt(
        &wrap_key(&secret, folder),
        &aad(folder),
        &hex::decode(&k.wrapped_key_hex)?,
    )
    .map_err(|_| anyhow!("the security key did not open this Strongroom (wrong key?)"))?;
    SecretKey::from_bytes(&plain)
}

/// Unwrap the folder key with `key` (one touch per enrolled credential
/// tried): every enrolled key is tried until one opens.
pub fn unlock(
    key: &dyn SecurityKey,
    folder: &FolderId,
    info: &StrongroomInfo,
) -> Result<SecretKey> {
    let mut last = None;
    for k in info.keys() {
        match unwrap_one(key, folder, &k) {
            Ok(fk) => return Ok(fk),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no security key is enrolled")))
}

/// Unwrap with whatever this device has for each enrolled key (the libfido2
/// tools for hardware keys, the key file for software keys). Returns the
/// folder key and the index of the key that opened it.
pub fn unlock_enrolled(
    home: &Path,
    folder: &FolderId,
    info: &StrongroomInfo,
) -> Result<(SecretKey, usize)> {
    let keys = info.keys();
    let mut errors = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        if keys.len() > 1 {
            eprintln!(
                "Trying enrolled key {} of {}: {}",
                i + 1,
                keys.len(),
                k.short()
            );
        }
        match unwrap_one(backend_for(k, home).as_ref(), folder, k) {
            Ok(fk) => return Ok((fk, i)),
            Err(e) => errors.push(format!("{}: {e:#}", k.short())),
        }
    }
    bail!(
        "no enrolled security key opened this Strongroom ({})",
        errors.join("; ")
    )
}

/// Re-key: wrap a new folder key (of a new folder id) for every enrolled
/// security key, each with a fresh salt, using whatever this device has for
/// each (one touch per hardware key; software keys are key files in `home`).
/// Credentials, labels and methods stay; every key must answer.
pub fn rewrap_enrolled(
    home: &Path,
    folder: &FolderId,
    folder_key: &SecretKey,
    info: &StrongroomInfo,
) -> Result<StrongroomInfo> {
    let keys = info.keys();
    let mut out = Vec::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        if keys.len() > 1 {
            eprintln!(
                "Wrapping the new key for enrolled key {} of {}: {}",
                i + 1,
                keys.len(),
                k.short()
            );
        }
        out.push(
            rewrap_one(backend_for(k, home).as_ref(), folder, folder_key, k).with_context(
                || {
                    format!(
                        "{}: every enrolled key must take the new folder key (remove a key that is gone first: varsto strongroom remove-key)",
                        k.short()
                    )
                },
            )?,
        );
    }
    StrongroomInfo::from_keys(out, crate::util::now_utc().max(info.updated_utc + 1))
}

/// Wrap `folder_key` for one enrolled credential with a fresh salt (one touch).
pub fn rewrap_one(
    key: &dyn SecurityKey,
    folder: &FolderId,
    folder_key: &SecretKey,
    k: &EnrolledKey,
) -> Result<EnrolledKey> {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let secret = key.hmac_secret(&k.credential, &salt)?;
    let wrapped = crypto::encrypt(
        &wrap_key(&secret, folder),
        &aad(folder),
        folder_key.as_bytes(),
    )?;
    Ok(EnrolledKey {
        salt_hex: hex::encode(salt),
        wrapped_key_hex: hex::encode(wrapped),
        ..k.clone()
    })
}

/// Published once a folder has been converted into a Strongroom
/// (`vault/converted/<old folder>.enc`, under the folder-record key). It
/// names the folder that replaces the old one and how far each device's
/// changes were included, and carries no key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversionRecord {
    pub old_folder: FolderId,
    pub new_folder: FolderId,
    pub device: DeviceId,
    pub converted_utc: i64,
    /// Highest manifest sequence of each device that the converted copy
    /// includes: a device that published more after that keeps its plain files.
    pub covered: BTreeMap<DeviceId, u64>,
    /// The old folder was a Strongroom already: its key was rotated.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rekey: bool,
}

impl ConversionRecord {
    pub const PREFIX: &'static str = "vault/converted/";
    pub fn storage_key(old: &FolderId) -> String {
        format!("{}{}.enc", Self::PREFIX, old)
    }
    fn aad(vault: &VaultId, old: &FolderId) -> Vec<u8> {
        crypto::aad(
            "strongroom-conversion",
            &[vault.as_str().as_bytes(), old.as_str().as_bytes()],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.old_folder),
            &serde_json::to_vec(self)?,
        )
    }
    pub fn open(blob: &[u8], vault: &VaultId, old: &FolderId, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, old), blob)?;
        let rec: ConversionRecord = serde_json::from_slice(&plain)?;
        if &rec.old_folder != old {
            bail!("conversion record does not match its name");
        }
        Ok(rec)
    }
}

/// The current list of enrolled keys of a Strongroom, published when a key
/// is added or removed (`vault/strongroom-keys/<folder>/<updated>.enc`, under
/// the folder-record key); the newest list wins.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeysRecord {
    pub folder_id: FolderId,
    pub device: DeviceId,
    pub info: StrongroomInfo,
}

impl KeysRecord {
    pub const PREFIX: &'static str = "vault/strongroom-keys/";
    pub fn storage_key(&self) -> String {
        format!(
            "{}{}/{:020}.enc",
            Self::PREFIX,
            self.folder_id,
            self.info.updated_utc
        )
    }
    fn aad(vault: &VaultId, folder: &FolderId) -> Vec<u8> {
        crypto::aad(
            "strongroom-keys",
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
        let rec: KeysRecord = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder || rec.info.keys().is_empty() {
            bail!("strongroom keys record does not match its name");
        }
        Ok(rec)
    }
}

/// A conversion in progress or awaiting clean-up, kept in this device's
/// encrypted keyring until the old copies are gone from every storage. It
/// holds the old folder record (with the old key, needed to read the old
/// manifests) and, on the converting device, the new key's wraps so an
/// interrupted conversion resumes under the same key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Conversion {
    pub old: crate::vault::FolderRecord,
    pub new_folder: FolderId,
    #[serde(default)]
    pub info: Option<StrongroomInfo>,
    /// The new folder has replaced the old one on this device; only the
    /// removal of old copies remains.
    pub switched: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_key_wraps_and_unwraps_and_other_keys_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let k = SoftwareKey {
            path: tmp.path().join("key"),
        };
        let folder = FolderId::random();
        let fk = SecretKey::random();
        let info = enroll(&k, Method::Software, &folder, &fk).unwrap();
        assert!(!info.wrapped_key_hex.contains(&fk.to_hex()));
        assert_eq!(unlock(&k, &folder, &info).unwrap().to_hex(), fk.to_hex());
        let other = SoftwareKey {
            path: tmp.path().join("other"),
        };
        other.make_credential().unwrap();
        assert!(unlock(&other, &folder, &info).is_err());
        // The same wrapped key does not open a different folder id.
        assert!(unlock(&k, &FolderId::random(), &info).is_err());
    }

    #[test]
    fn backup_key_opens_the_same_folder_key_and_old_records_still_read() {
        let tmp = tempfile::tempdir().unwrap();
        let first = SoftwareKey {
            path: tmp.path().join("first"),
        };
        let spare = SoftwareKey {
            path: tmp.path().join("spare"),
        };
        let folder = FolderId::random();
        let fk = SecretKey::random();
        let mut info = enroll(&first, Method::Software, &folder, &fk).unwrap();
        let k = enroll_key(&spare, Method::Software, &folder, &fk, "safe").unwrap();
        let mut keys = info.keys();
        keys.push(k);
        info = StrongroomInfo::from_keys(keys, 2).unwrap();
        assert_eq!(info.keys().len(), 2);
        for key in [&first, &spare] {
            assert_eq!(unlock(key, &folder, &info).unwrap().to_hex(), fk.to_hex());
        }
        assert_eq!(info.find_key("safe").unwrap(), 1);
        assert_eq!(info.find_key("1").unwrap(), 0);
        assert!(info.find_key("nothing-like-it").is_err());
        assert!(StrongroomInfo::from_keys(vec![], 3).is_err());
        // A record written before backup keys existed reads as one key.
        let old = r#"{"method":"software","credential":"software:/x/key","salt_hex":"00","wrapped_key_hex":"00"}"#;
        let parsed: StrongroomInfo = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.keys().len(), 1);
        assert_eq!(parsed.keys()[0].short(), "key");
    }
}
