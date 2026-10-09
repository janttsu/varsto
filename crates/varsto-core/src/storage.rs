// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage backends. A backend is a dumb object store: it never sees keys or
//! plaintext. Alpha-0 ships the local-folder backend (which also covers
//! removable disks and network mounts); S3 and rclone remotes follow, and a
//! pool of removable disks (`crate::pool`) that holds chunk objects only.
//!
//! Object keys use forward slashes. Layout written by the engine:
//! - `vault/meta.json`                       vault identity (not secret)
//! - `vault/devices/<device>.enc`            device record (encrypted)
//! - `vault/folders/<device>/<folder>.enc`   folder record (encrypted)
//! - `ledger/<device>/<seq>.json`            signed, encrypted ledger batches
//! - `manifests/<folder>/<device>/<seq>.enc` encrypted folder manifests
//! - `chunks/<xx>/<objectname>`              encrypted chunks

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub trait Storage: Send + Sync {
    fn name(&self) -> &str;
    /// Write an object unless it already exists. Returns true when written.
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn exists(&self, key: &str) -> Result<bool>;
    /// List object keys under a prefix, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
    fn delete(&self, key: &str) -> Result<()>;
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StorageSpec {
    /// A directory on this device (local disk, removable disk, network mount).
    LocalDir {
        name: String,
        path: PathBuf,
        #[serde(default)]
        cold: bool,
        /// A "transferrer" (F-048): removable media that travels between devices.
        /// It only receives objects that other devices still lack, and objects
        /// are removed from it once another device holds them.
        #[serde(default)]
        carrier: bool,
        /// Where this storage is, for durability policies: "home", "cloud", "offsite", ... (default "home").
        #[serde(default)]
        place: String,
    },
    /// An S3-compatible bucket. The secret access key is not stored here
    /// (config.json is plain text) but in the encrypted secret store under
    /// `secret_ref`, or in the environment variable `VARSTO_S3_SECRET_<NAME>`.
    S3 {
        name: String,
        endpoint: String,
        region: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        access_key_id: String,
        #[serde(default)]
        secret_ref: String,
        #[serde(default = "default_true")]
        path_style: bool,
        #[serde(default)]
        storage_class: Option<String>,
        #[serde(default)]
        cold: bool,
        #[serde(default)]
        place: String,
    },
    /// Any rclone remote (`remote:bucket/path`); credentials stay in rclone's config.
    Rclone {
        name: String,
        remote: String,
        #[serde(default)]
        cold: bool,
        #[serde(default)]
        place: String,
    },
    /// A pool of removable disks (plan 6.35, 6.41): local directories with an
    /// identity marker that are attached and detached over time. Holds chunk
    /// objects only; records, ledger batches and manifests go to the other
    /// storages. Opened through the engine, which derives the pool identity.
    Pool {
        name: String,
        #[serde(default)]
        place: String,
        /// Share of a disk kept free (default 5 %).
        #[serde(default = "default_reserve_percent")]
        reserve_percent: u32,
        /// At least this much is kept free on every disk (default 2 GiB).
        #[serde(default = "default_min_reserve_bytes")]
        min_reserve_bytes: u64,
        #[serde(default)]
        disks: Vec<crate::pool::PoolDisk>,
        /// Extra directories scanned one level deep for attached disks, in
        /// addition to the platform's mount roots.
        #[serde(default)]
        scan_roots: Vec<PathBuf>,
    },
}

fn default_true() -> bool {
    true
}

fn default_reserve_percent() -> u32 {
    crate::pool::DEFAULT_RESERVE_PERCENT
}

fn default_min_reserve_bytes() -> u64 {
    crate::pool::DEFAULT_MIN_RESERVE_BYTES
}

/// Resolves a secret by reference; `None` means "unknown".
pub type SecretLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

impl StorageSpec {
    pub fn name(&self) -> &str {
        match self {
            StorageSpec::LocalDir { name, .. }
            | StorageSpec::S3 { name, .. }
            | StorageSpec::Rclone { name, .. }
            | StorageSpec::Pool { name, .. } => name,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            StorageSpec::LocalDir { .. } => "local-dir",
            StorageSpec::S3 { .. } => "s3",
            StorageSpec::Rclone { .. } => "rclone",
            StorageSpec::Pool { .. } => "pool",
        }
    }
    /// Holds chunk objects only: records, ledger batches, manifests and
    /// thumbnails are not written to it and not looked for there.
    pub fn is_data_only(&self) -> bool {
        matches!(self, StorageSpec::Pool { .. })
    }
    /// One-line description for listings (no secrets).
    pub fn describe(&self) -> String {
        match self {
            StorageSpec::LocalDir { path, .. } => path.display().to_string(),
            StorageSpec::S3 {
                endpoint,
                bucket,
                prefix,
                storage_class,
                ..
            } => format!(
                "{endpoint} bucket {bucket}{}{}",
                if prefix.is_empty() {
                    String::new()
                } else {
                    format!("/{prefix}")
                },
                storage_class
                    .as_ref()
                    .map(|c| format!(" class {c}"))
                    .unwrap_or_default()
            ),
            StorageSpec::Rclone { remote, .. } => remote.clone(),
            StorageSpec::Pool { disks, .. } => format!(
                "pool of {} disk{}",
                disks.len(),
                if disks.len() == 1 { "" } else { "s" }
            ),
        }
    }
    /// Place for durability policies: the configured one, or "home" for a
    /// directory and "cloud" for a bucket or rclone remote.
    pub fn place(&self) -> String {
        let explicit = match self {
            StorageSpec::LocalDir { place, .. }
            | StorageSpec::S3 { place, .. }
            | StorageSpec::Rclone { place, .. }
            | StorageSpec::Pool { place, .. } => place.as_str(),
        };
        if !explicit.is_empty() {
            return explicit.to_string();
        }
        match self {
            StorageSpec::LocalDir { .. } | StorageSpec::Pool { .. } => "home".to_string(),
            _ => "cloud".to_string(),
        }
    }
    pub fn is_cold(&self) -> bool {
        match self {
            StorageSpec::LocalDir { cold, .. }
            | StorageSpec::S3 { cold, .. }
            | StorageSpec::Rclone { cold, .. } => *cold,
            StorageSpec::Pool { .. } => false,
        }
    }
    pub fn is_carrier(&self) -> bool {
        match self {
            StorageSpec::LocalDir { carrier, .. } => *carrier,
            _ => false,
        }
    }
    /// Open with secrets taken from the environment only.
    pub fn open(&self) -> Result<Box<dyn Storage>> {
        self.open_with(&|_| None)
    }
    /// Open; `secrets` resolves `secret_ref` for backends that need one.
    pub fn open_with(&self, secrets: SecretLookup) -> Result<Box<dyn Storage>> {
        match self {
            StorageSpec::LocalDir { name, path, .. } => {
                Ok(Box::new(LocalDirStorage::new(name.clone(), path.clone())?))
            }
            StorageSpec::S3 {
                name,
                endpoint,
                region,
                bucket,
                prefix,
                access_key_id,
                secret_ref,
                path_style,
                storage_class,
                ..
            } => {
                let reference = if secret_ref.is_empty() {
                    name
                } else {
                    secret_ref
                };
                let env_name = format!(
                    "VARSTO_S3_SECRET_{}",
                    name.to_uppercase()
                        .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                );
                let secret = secrets(reference)
                    .or_else(|| std::env::var(&env_name).ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no secret access key for storage {name}: unlock the vault that stored it or set {env_name}"
                        )
                    })?;
                Ok(Box::new(crate::s3::S3Storage::new(crate::s3::S3Config {
                    name: name.clone(),
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    bucket: bucket.clone(),
                    prefix: prefix.clone(),
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret,
                    path_style: *path_style,
                    storage_class: storage_class.clone(),
                })?))
            }
            StorageSpec::Rclone { name, remote, .. } => Ok(Box::new(
                crate::rclone::RcloneStorage::new(name.clone(), remote.clone())?,
            )),
            StorageSpec::Pool { name, .. } => {
                anyhow::bail!("disk pool {name} must be opened through the engine, which derives its identity from the vault key")
            }
        }
    }
}

pub struct LocalDirStorage {
    name: String,
    root: PathBuf,
}

impl LocalDirStorage {
    pub fn new(name: String, root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
        Ok(LocalDirStorage { name, root })
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty()
            || key.starts_with('/')
            || key
                .split('/')
                .any(|c| c == ".." || c.is_empty() || c == ".")
        {
            anyhow::bail!("invalid object key {key:?}");
        }
        Ok(self.root.join(key))
    }
}

impl Storage for LocalDirStorage {
    fn name(&self) -> &str {
        &self.name
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let path = self.path_for(key)?;
        if path.exists() {
            return Ok(false);
        }
        crate::util::write_atomic(&path, data)?;
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key)?;
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key)?.is_file())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let base = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix)
        };
        let mut out = Vec::new();
        if !base.exists() {
            return Ok(out);
        }
        for entry in walkdir::WalkDir::new(&base)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue; // temporary files
            }
            let rel = entry.path().strip_prefix(&self.root)?;
            if let Some(k) = rel.to_str() {
                out.push(k.replace(std::path::MAIN_SEPARATOR, "/"));
            }
        }
        out.sort();
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Helper for tests and tools: open a local storage at `path`.
pub fn local(name: &str, path: &Path) -> Result<Box<dyn Storage>> {
    Ok(Box::new(LocalDirStorage::new(
        name.to_string(),
        path.to_path_buf(),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalDirStorage::new("t".into(), dir.path().join("store")).unwrap();
        assert!(s.put_if_absent("chunks/ab/one", b"1").unwrap());
        assert!(!s.put_if_absent("chunks/ab/one", b"2").unwrap());
        assert_eq!(s.get("chunks/ab/one").unwrap().unwrap(), b"1");
        assert!(s.get("chunks/ab/none").unwrap().is_none());
        s.put_if_absent("ledger/dev/000", b"x").unwrap();
        assert_eq!(s.list("chunks").unwrap(), vec!["chunks/ab/one".to_string()]);
        assert_eq!(s.list("").unwrap().len(), 2);
        s.delete("chunks/ab/one").unwrap();
        assert!(!s.exists("chunks/ab/one").unwrap());
        assert!(s.get("../x").is_err());
    }
}
