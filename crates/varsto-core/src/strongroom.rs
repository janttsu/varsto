// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Strongroom folders (S-012): a folder whose key exists only while a FIDO2
//! security key is touched. The folder key is wrapped with a secret that the
//! authenticator derives with the `hmac-secret` extension from a per-folder
//! salt; the wrapped key is what gets stored and published, never the key
//! itself. Every device of the vault can open the folder with the same
//! physical key (hmac-secret is deterministic for a credential and salt),
//! and nothing derivable from the vault's master key opens it.
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
use crate::ids::FolderId;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
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
/// wrapped folder key. Contains no secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrongroomInfo {
    pub method: Method,
    /// Credential id (base64) for fido2; a label for software.
    pub credential: String,
    /// 32-byte salt for hmac-secret (hex).
    pub salt_hex: String,
    /// Folder key encrypted under the derived secret (hex).
    pub wrapped_key_hex: String,
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
    let credential = key.make_credential()?;
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let secret = key.hmac_secret(&credential, &salt)?;
    let wrapped = crypto::encrypt(
        &wrap_key(&secret, folder),
        &aad(folder),
        folder_key.as_bytes(),
    )?;
    Ok(StrongroomInfo {
        method,
        credential,
        salt_hex: hex::encode(salt),
        wrapped_key_hex: hex::encode(wrapped),
    })
}

/// Unwrap the folder key (one touch).
pub fn unlock(
    key: &dyn SecurityKey,
    folder: &FolderId,
    info: &StrongroomInfo,
) -> Result<SecretKey> {
    let salt: [u8; 32] = hex::decode(&info.salt_hex)?
        .try_into()
        .map_err(|_| anyhow!("strongroom salt must be 32 bytes"))?;
    let secret = key.hmac_secret(&info.credential, &salt)?;
    let plain = crypto::decrypt(
        &wrap_key(&secret, folder),
        &aad(folder),
        &hex::decode(&info.wrapped_key_hex)?,
    )
    .map_err(|_| anyhow!("the security key did not open this Strongroom (wrong key?)"))?;
    SecretKey::from_bytes(&plain)
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
}
