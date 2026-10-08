// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage backends. A backend is a dumb object store: it never sees keys or
//! plaintext. Alpha-0 ships the local-folder backend (which also covers
//! removable disks and network mounts); S3 and rclone remotes follow.
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
    },
}

impl StorageSpec {
    pub fn name(&self) -> &str {
        match self {
            StorageSpec::LocalDir { name, .. } => name,
        }
    }
    pub fn is_cold(&self) -> bool {
        match self {
            StorageSpec::LocalDir { cold, .. } => *cold,
        }
    }
    pub fn open(&self) -> Result<Box<dyn Storage>> {
        match self {
            StorageSpec::LocalDir { name, path, .. } => {
                Ok(Box::new(LocalDirStorage::new(name.clone(), path.clone())?))
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
