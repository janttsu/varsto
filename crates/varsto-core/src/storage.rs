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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Object keys are relative paths with `/` separators and plain
/// components: nothing that could leave the storage's root on any
/// platform. Keys that come from untrusted places (another user's storage
/// listed by a replica, a disk's own index) go through this before a
/// backend touches a path or builds a remote target.
pub fn validate_key(key: &str) -> Result<()> {
    crate::util::check_portable_rel_path(key)
        .map_err(|_| anyhow::anyhow!("invalid object key {key:?}"))
}

/// Largest block object (`chunks/`) a storage read returns: a chunk is at
/// most `MAX_CHUNK_SIZE` plus its nonce, tag and header.
pub const MAX_BLOCK_OBJECT: u64 = crate::manifest::MAX_CHUNK_SIZE + 64;
/// Largest pack (`packs/<xx>/<id>`) a storage read returns, and the longest
/// ranged read: the largest size class (256 MiB, cold storages). A `PackStore`
/// reads its own whole packs up to its top size class.
pub const MAX_PACK: u64 = crate::packs::COLD_TARGET as u64;
/// Largest record (`vault/`, `manifests/`, `ledger/`, `org/`, ...) a storage
/// read returns.
pub const MAX_RECORD: u64 = 256 << 20;

/// How many bytes a read of `key` may return: nothing a storage holds can
/// make the program allocate more.
pub fn read_limit(key: &str) -> u64 {
    #[cfg(feature = "format3")]
    if key.ends_with(".rec") {
        return crate::record::MAX_PART_READ;
    }
    if key.starts_with("chunks/") {
        MAX_BLOCK_OBJECT
    } else if key.starts_with(crate::packs::PREFIX)
        && !key.starts_with(crate::packs::INDEX_PREFIX)
        && !key.starts_with(crate::packs::TOMBSTONE_PREFIX)
    {
        MAX_PACK
    } else {
        MAX_RECORD
    }
}

/// A read that found an object larger than allowed (`too_large`); callers
/// that treat it as a property of the object, not a failed read, find it
/// with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
#[error(
    "{key} is {size} bytes, more than the {max} bytes an object of that kind may have; not read"
)]
pub struct TooLarge {
    pub key: String,
    pub size: u64,
    pub max: u64,
}

/// The error of a read that found an object larger than allowed.
pub fn too_large(key: &str, size: u64, max: u64) -> anyhow::Error {
    anyhow::Error::new(TooLarge {
        key: key.to_string(),
        size,
        max,
    })
}

/// Run one storage operation so that a panic in it (a malformed object name
/// or index met on the way) is an error for this object, not the end of the
/// whole pass.
pub fn guarded<T>(what: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!(
            "{what}: internal error while handling the object"
        )),
    }
}

pub trait Storage: Send + Sync {
    fn name(&self) -> &str;
    /// Write an object unless it already exists. Returns true when written.
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Like `get`, refusing an object larger than `max` bytes. Backends
    /// override it to stop before the whole body is in memory; this default
    /// only checks after the read.
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        match self.get(key)? {
            Some(b) if b.len() as u64 > max => Err(too_large(key, b.len() as u64, max)),
            other => Ok(other),
        }
    }
    fn exists(&self, key: &str) -> Result<bool>;
    /// List object keys under a prefix, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
    /// Keys under `prefix` that sort after `start_after`, sorted. Lets the
    /// ledger mailbox read only what is newer than what a device already
    /// holds; backends that can start a listing in the middle override it.
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        Ok(self
            .list(prefix)?
            .into_iter()
            .filter(|k| k.as_str() > start_after)
            .collect())
    }
    fn delete(&self, key: &str) -> Result<()>;
    /// `len` bytes of an object from `offset` (a block inside a pack).
    /// Backends that can read part of an object override it.
    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key)?.map(|b| {
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(b.len());
            let end = start
                .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
                .min(b.len());
            b[start..end].to_vec()
        }))
    }
    /// Write several block objects (name, bytes). A storage that keeps
    /// packs (`packs::PackStore`) writes them as packs; others write them
    /// one by one. One flag per object: written now.
    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        members
            .iter()
            .map(|(o, b)| self.put_if_absent(&format!("chunks/{}/{o}", o.get(..2).unwrap_or(o)), b))
            .collect()
    }
    /// Write a pack built elsewhere (`packs::build`), byte for byte, so
    /// that every storage of one target set holds it under one id: `id`
    /// and `data` as built, `members` the places of its block objects.
    /// `Ok(None)` when this storage does not take a built pack (it keeps
    /// no packs, or holds one of the members already); the caller then
    /// writes the members with `put_pack`. `Some`: one flag per member,
    /// written now.
    fn put_built_pack(
        &self,
        _id: &str,
        _data: &[u8],
        _members: &[(String, crate::packs::PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        Ok(None)
    }
    /// The size of the packs written here (0: block objects are not packed).
    fn pack_target(&self) -> usize {
        0
    }
    /// Where a block object is here, as far as this device knows.
    fn pack_location(&self, _object: &str) -> Option<crate::packs::PackLoc> {
        None
    }
    /// The packs written since the last call, for the pack index.
    fn take_new_packs(&self) -> Vec<crate::packs::NewPack> {
        Vec::new()
    }
    /// Write the tombstones of the pack members deleted since the last call.
    fn flush_deletions(&self) -> Result<()> {
        Ok(())
    }
    /// Rewrite the packs here that are mostly dead (`packs::PackStore`):
    /// the new location of every moved block.
    fn collect_pack_garbage(
        &self,
        _keep: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<(String, crate::packs::PackLoc)>> {
        Ok(Vec::new())
    }
    /// Whether the storage honours a conditional write (S3 `If-None-Match:
    /// *`): known (true or false) once the backend has probed it, `None`
    /// for backends where the question does not arise or before the probe.
    fn conditional_writes(&self) -> Option<bool> {
        None
    }
}

/// One opened storage shared by every phase of an operation: the engine
/// keeps the backend (its connection pool, its view of the packs) in an
/// `Arc` and hands out these handles instead of opening the storage again.
pub struct SharedStorage(pub std::sync::Arc<dyn Storage>);

impl Storage for SharedStorage {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        self.0.put_if_absent(key, data)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.0.get_bounded(key, max)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.0.exists(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.0.list(prefix)
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        self.0.list_after(prefix, start_after)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key)
    }
    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        self.0.get_range(key, offset, len)
    }
    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        self.0.put_pack(members)
    }
    fn put_built_pack(
        &self,
        id: &str,
        data: &[u8],
        members: &[(String, crate::packs::PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        self.0.put_built_pack(id, data, members)
    }
    fn pack_target(&self) -> usize {
        self.0.pack_target()
    }
    fn pack_location(&self, object: &str) -> Option<crate::packs::PackLoc> {
        self.0.pack_location(object)
    }
    fn take_new_packs(&self) -> Vec<crate::packs::NewPack> {
        self.0.take_new_packs()
    }
    fn flush_deletions(&self) -> Result<()> {
        self.0.flush_deletions()
    }
    fn collect_pack_garbage(
        &self,
        keep: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<(String, crate::packs::PackLoc)>> {
        self.0.collect_pack_garbage(keep)
    }
    fn conditional_writes(&self) -> Option<bool> {
        self.0.conditional_writes()
    }
}

/// What the engine knows about a storage when opening it, beyond its spec.
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    /// S3: whether the server honours `If-None-Match: *`, when a probe
    /// answered it earlier (`config.json`, `conditional_writes`).
    pub conditional_writes: Option<bool>,
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    #[test]
    fn reads_are_bounded_by_the_kind_of_object() {
        let t = tempfile::tempdir().unwrap();
        let s = LocalDirStorage::new("box".into(), t.path().to_path_buf()).unwrap();
        let big = vec![1u8; (MAX_BLOCK_OBJECT + 1) as usize];
        s.put_if_absent("chunks/ab/big", &big).unwrap();
        s.put_if_absent("manifests/big", &big).unwrap();
        s.put_if_absent("chunks/ab/small", &[2u8; 100]).unwrap();
        let e = s.get("chunks/ab/big").unwrap_err();
        assert!(format!("{e:#}").contains("more than"), "{e:#}");
        assert_eq!(s.get("manifests/big").unwrap().unwrap().len(), big.len());
        assert!(s.get_bounded("chunks/ab/small", 99).is_err());
        assert_eq!(
            s.get_bounded("chunks/ab/small", 100)
                .unwrap()
                .unwrap()
                .len(),
            100
        );
        assert!(s.get_bounded("chunks/ab/none", 10).unwrap().is_none());
        // A claimed range cannot allocate more than a block object, nor overflow.
        assert_eq!(
            s.get_range("chunks/ab/small", 0, u64::MAX)
                .unwrap()
                .unwrap()
                .len(),
            100
        );
        assert!(s
            .get_range("chunks/ab/small", u64::MAX - 1, u64::MAX)
            .unwrap()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_pack_is_read_up_to_the_largest_pack_and_a_range_spans_blocks() {
        let t = tempfile::tempdir().unwrap();
        let s = LocalDirStorage::new("box".into(), t.path().to_path_buf()).unwrap();
        // Larger than a block object: a pack, a pack index and a record may be.
        let big = vec![3u8; (MAX_BLOCK_OBJECT + 1) as usize];
        let pack = format!("packs/ab/{}", "ab".repeat(32));
        s.put_if_absent(&pack, &big).unwrap();
        assert_eq!(read_limit(&pack), MAX_PACK);
        assert_eq!(read_limit("packs/index/d/0000000000000001.enc"), MAX_RECORD);
        assert_eq!(
            read_limit("packs/tombstones/d/0000000000000001.enc"),
            MAX_RECORD
        );
        assert_eq!(read_limit("chunks/ab/cd"), MAX_BLOCK_OBJECT);
        assert_eq!(s.get(&pack).unwrap().unwrap().len(), big.len());
        // A span of several blocks is one ranged read.
        assert_eq!(
            s.get_range(&pack, 1, MAX_BLOCK_OBJECT)
                .unwrap()
                .unwrap()
                .len(),
            MAX_BLOCK_OBJECT as usize
        );
        assert!(s.get_bounded(&pack, MAX_BLOCK_OBJECT).is_err());
    }

    #[test]
    fn a_panic_in_a_read_is_an_error_for_that_object() {
        let r: Result<()> = guarded("chunks/ab/x", || panic!("bad name"));
        assert!(format!("{:#}", r.unwrap_err()).contains("internal error"));
        assert_eq!(guarded("k", || Ok(3)).unwrap(), 3);
    }
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
        /// Free space kept on its disk: block writes stop below it
        /// (`freespace`; default 5 %).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_free: Option<crate::freespace::MinFree>,
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
        /// The user chose to reach an `http://` endpoint outside this
        /// computer without transport encryption (`--insecure-http`).
        #[serde(default, skip_serializing_if = "is_false")]
        allow_insecure_http: bool,
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
        /// Disk group rule: keep this many copies of every object on disks
        /// in different places (each disk has a place; default 1, one copy).
        #[serde(default = "default_copies", skip_serializing_if = "is_one")]
        copies: u32,
        /// Copies on a disk whose last check is older than this many days
        /// are re-hashed when the disk is inserted (default 180).
        #[serde(default = "default_verify_after_days")]
        verify_after_days: u32,
    },
}

fn default_verify_after_days() -> u32 {
    crate::pool::DEFAULT_VERIFY_AFTER_DAYS
}

fn default_copies() -> u32 {
    1
}

fn is_one(v: &u32) -> bool {
    *v == 1
}

fn default_true() -> bool {
    true
}

fn is_false(b: &bool) -> bool {
    !*b
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
    /// Where the storage really is, spelled one way: S3 by endpoint host,
    /// bucket and prefix (scheme, default port, case and slashes ignored),
    /// rclone by remote name and path, a directory by its path. Two entries
    /// with the same key are the same place. `None` for a disk pool.
    pub fn location_key(&self) -> Option<String> {
        fn trim_slashes(s: &str) -> String {
            s.split('/')
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("/")
        }
        match self {
            StorageSpec::S3 {
                endpoint,
                bucket,
                prefix,
                ..
            } => {
                let e = endpoint.trim().to_lowercase();
                let e = e
                    .strip_prefix("https://")
                    .or_else(|| e.strip_prefix("http://"))
                    .unwrap_or(&e)
                    .trim_end_matches('/')
                    .to_string();
                let e = e
                    .strip_suffix(":443")
                    .or_else(|| e.strip_suffix(":80"))
                    .unwrap_or(&e)
                    .to_string();
                Some(format!(
                    "s3:{e}|{}|{}",
                    bucket.trim().to_lowercase(),
                    trim_slashes(prefix)
                ))
            }
            StorageSpec::Rclone { remote, .. } => {
                let (name, path) = remote.trim().split_once(':')?;
                Some(format!("rclone:{}:{}", name.trim(), trim_slashes(path)))
            }
            StorageSpec::LocalDir { path, .. } => Some(format!(
                "dir:{}",
                trim_slashes(&path.to_string_lossy().replace('\\', "/"))
            )),
            StorageSpec::Pool { .. } => None,
        }
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
        self.open_with_options(secrets, &OpenOptions::default())
    }

    /// `open_with` with what the engine learned about the storage earlier.
    pub fn open_with_options(
        &self,
        secrets: SecretLookup,
        options: &OpenOptions,
    ) -> Result<Box<dyn Storage>> {
        match self {
            StorageSpec::LocalDir {
                name,
                path,
                min_free,
                ..
            } => Ok(Box::new(
                LocalDirStorage::new(name.clone(), path.clone())?
                    .with_min_free(min_free.unwrap_or(crate::freespace::DEFAULT)),
            )),
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
                allow_insecure_http,
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
                    allow_insecure_http: *allow_insecure_http,
                    conditional_writes: options.conditional_writes,
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
    /// Block objects are not written when the disk would keep less free.
    min_free: Option<crate::freespace::MinFree>,
}

impl LocalDirStorage {
    pub fn new(name: String, root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
        Ok(LocalDirStorage {
            name,
            root,
            min_free: None,
        })
    }

    /// Keep `min` free on the disk: block objects (`chunks/`, `packs/`)
    /// are refused with `freespace::LowSpace` below it. Records, ledger
    /// batches and manifests are small and still written.
    pub fn with_min_free(mut self, min: crate::freespace::MinFree) -> Self {
        self.min_free = Some(min);
        self
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }
}

impl Storage for LocalDirStorage {
    fn name(&self) -> &str {
        &self.name
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.path_for(key)?;
        let mut f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
        };
        // A length from the ledger is a claim: never allocate more than a
        // pack may be, and read no more than the file has.
        let len = len.min(MAX_PACK);
        if offset > i64::MAX as u64 {
            return Ok(Some(Vec::new())); // past any file
        }
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::new();
        f.take(len).read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let path = self.path_for(key)?;
        if path.exists() {
            return Ok(false);
        }
        if let Some(min) = self.min_free {
            if key.starts_with("chunks/") || key.starts_with(crate::packs::PREFIX) {
                crate::freespace::check(
                    &crate::freespace::Place::storage(&self.name),
                    &self.root,
                    min,
                    data.len() as u64,
                )?;
            }
        }
        crate::util::write_atomic(&path, data)?;
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_bounded(key, read_limit(key))
    }

    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        let path = self.path_for(key)?;
        let f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let size = f
            .metadata()
            .with_context(|| format!("read {}", path.display()))?
            .len();
        if size > max {
            return Err(too_large(key, size, max));
        }
        let mut buf = Vec::with_capacity(size as usize);
        // The file may grow while it is read: one byte past the limit is the answer.
        f.take(max + 1)
            .read_to_end(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if buf.len() as u64 > max {
            return Err(too_large(key, buf.len() as u64, max));
        }
        Ok(Some(buf))
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key)?.is_file())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_after(prefix, "")
    }

    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
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
                let k = k.replace(std::path::MAIN_SEPARATOR, "/");
                if k.as_str() > start_after {
                    out.push(k);
                }
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

/// Calls made through `CountingStorage`, for tests and measurements.
#[derive(Debug, Default)]
pub struct StorageCalls {
    pub lists: AtomicU64,
    /// Keys returned by all listings together.
    pub listed_keys: AtomicU64,
    pub gets: AtomicU64,
    pub puts: AtomicU64,
    pub exists: AtomicU64,
    pub deletes: AtomicU64,
    /// The part of the above under `ledger/`.
    pub ledger_lists: AtomicU64,
    pub ledger_listed_keys: AtomicU64,
    pub ledger_gets: AtomicU64,
    /// The part under `manifests/`.
    pub manifest_lists: AtomicU64,
    pub manifest_listed_keys: AtomicU64,
    pub manifest_gets: AtomicU64,
    /// Reads of chunk objects (`chunks/`).
    pub chunk_gets: AtomicU64,
}

/// A plain copy of `StorageCalls` at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallCounts {
    pub lists: u64,
    pub listed_keys: u64,
    pub gets: u64,
    pub puts: u64,
    pub exists: u64,
    pub deletes: u64,
    pub ledger_lists: u64,
    pub ledger_listed_keys: u64,
    pub ledger_gets: u64,
    pub manifest_lists: u64,
    pub manifest_listed_keys: u64,
    pub manifest_gets: u64,
    pub chunk_gets: u64,
}

impl StorageCalls {
    pub fn snapshot(&self) -> CallCounts {
        CallCounts {
            lists: self.lists.load(Ordering::Relaxed),
            listed_keys: self.listed_keys.load(Ordering::Relaxed),
            gets: self.gets.load(Ordering::Relaxed),
            puts: self.puts.load(Ordering::Relaxed),
            exists: self.exists.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            ledger_lists: self.ledger_lists.load(Ordering::Relaxed),
            ledger_listed_keys: self.ledger_listed_keys.load(Ordering::Relaxed),
            ledger_gets: self.ledger_gets.load(Ordering::Relaxed),
            manifest_lists: self.manifest_lists.load(Ordering::Relaxed),
            manifest_listed_keys: self.manifest_listed_keys.load(Ordering::Relaxed),
            manifest_gets: self.manifest_gets.load(Ordering::Relaxed),
            chunk_gets: self.chunk_gets.load(Ordering::Relaxed),
        }
    }
}

impl std::ops::Sub for CallCounts {
    type Output = CallCounts;
    fn sub(self, o: CallCounts) -> CallCounts {
        CallCounts {
            lists: self.lists - o.lists,
            listed_keys: self.listed_keys - o.listed_keys,
            gets: self.gets - o.gets,
            puts: self.puts - o.puts,
            exists: self.exists - o.exists,
            deletes: self.deletes - o.deletes,
            ledger_lists: self.ledger_lists - o.ledger_lists,
            ledger_listed_keys: self.ledger_listed_keys - o.ledger_listed_keys,
            ledger_gets: self.ledger_gets - o.ledger_gets,
            manifest_lists: self.manifest_lists - o.manifest_lists,
            manifest_listed_keys: self.manifest_listed_keys - o.manifest_listed_keys,
            manifest_gets: self.manifest_gets - o.manifest_gets,
            chunk_gets: self.chunk_gets - o.chunk_gets,
        }
    }
}

/// Wraps a storage and counts the calls made to it.
pub struct CountingStorage {
    inner: Box<dyn Storage>,
    calls: Arc<StorageCalls>,
}

impl CountingStorage {
    pub fn new(inner: Box<dyn Storage>, calls: Arc<StorageCalls>) -> Self {
        CountingStorage { inner, calls }
    }

    fn listed(&self, prefix: &str, keys: &[String]) {
        let n = keys.len() as u64;
        self.calls.lists.fetch_add(1, Ordering::Relaxed);
        self.calls.listed_keys.fetch_add(n, Ordering::Relaxed);
        if prefix.starts_with("ledger/") {
            self.calls.ledger_lists.fetch_add(1, Ordering::Relaxed);
        }
        let in_ledger = keys.iter().filter(|k| k.starts_with("ledger/")).count();
        self.calls
            .ledger_listed_keys
            .fetch_add(in_ledger as u64, Ordering::Relaxed);
        if prefix.starts_with("manifests/") {
            self.calls.manifest_lists.fetch_add(1, Ordering::Relaxed);
        }
        let in_manifests = keys.iter().filter(|k| k.starts_with("manifests/")).count();
        self.calls
            .manifest_listed_keys
            .fetch_add(in_manifests as u64, Ordering::Relaxed);
    }
}

impl Storage for CountingStorage {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        self.calls.gets.fetch_add(1, Ordering::Relaxed);
        self.inner.get_range(key, offset, len)
    }
    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        self.calls.puts.fetch_add(1, Ordering::Relaxed);
        self.inner.put_pack(members)
    }
    fn put_built_pack(
        &self,
        id: &str,
        data: &[u8],
        members: &[(String, crate::packs::PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        self.calls.puts.fetch_add(1, Ordering::Relaxed);
        self.inner.put_built_pack(id, data, members)
    }
    fn pack_target(&self) -> usize {
        self.inner.pack_target()
    }
    fn pack_location(&self, object: &str) -> Option<crate::packs::PackLoc> {
        self.inner.pack_location(object)
    }
    fn take_new_packs(&self) -> Vec<crate::packs::NewPack> {
        self.inner.take_new_packs()
    }
    fn flush_deletions(&self) -> Result<()> {
        self.inner.flush_deletions()
    }
    fn collect_pack_garbage(
        &self,
        keep: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<(String, crate::packs::PackLoc)>> {
        self.inner.collect_pack_garbage(keep)
    }
    fn conditional_writes(&self) -> Option<bool> {
        self.inner.conditional_writes()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        self.calls.puts.fetch_add(1, Ordering::Relaxed);
        self.inner.put_if_absent(key, data)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.calls.gets.fetch_add(1, Ordering::Relaxed);
        if key.starts_with("ledger/") {
            self.calls.ledger_gets.fetch_add(1, Ordering::Relaxed);
        }
        if key.starts_with("manifests/") {
            self.calls.manifest_gets.fetch_add(1, Ordering::Relaxed);
        }
        if key.starts_with("chunks/") {
            self.calls.chunk_gets.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.get(key)
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.calls.gets.fetch_add(1, Ordering::Relaxed);
        if key.starts_with("ledger/") {
            self.calls.ledger_gets.fetch_add(1, Ordering::Relaxed);
        }
        if key.starts_with("manifests/") {
            self.calls.manifest_gets.fetch_add(1, Ordering::Relaxed);
        }
        if key.starts_with("chunks/") {
            self.calls.chunk_gets.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.get_bounded(key, max)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.calls.exists.fetch_add(1, Ordering::Relaxed);
        self.inner.exists(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let out = self.inner.list(prefix)?;
        self.listed(prefix, &out);
        Ok(out)
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        let out = self.inner.list_after(prefix, start_after)?;
        self.listed(prefix, &out);
        Ok(out)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.calls.deletes.fetch_add(1, Ordering::Relaxed);
        self.inner.delete(key)
    }
}

/// Log one request of a storage backend: debug for errors and for objects
/// other than blocks, trace for block reads and writes (many per sync).
#[allow(clippy::too_many_arguments)]
pub fn log_request(
    storage: &str,
    backend: &str,
    op: &str,
    key: &str,
    sent: u64,
    status: Option<u16>,
    got: u64,
    ms: u64,
    err: Option<&anyhow::Error>,
) {
    let chatty = is_block_key(key);
    let failed = err.is_some() || status.map(|s| s >= 400 && s != 404).unwrap_or(false);
    let level = if failed || !chatty {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    if !log::log_enabled!(level) {
        return;
    }
    // `result`: bytes read, keys listed, or 1/0 for put (new / already
    // there) and exists; `status` and `got` for HTTP requests.
    match (err, status) {
        (Some(e), _) => {
            log::log!(level, storage = storage, backend = backend, op = op, key = key, sent = sent, ms = ms; "storage request failed: {e:#}")
        }
        (None, Some(st)) => {
            log::log!(level, storage = storage, backend = backend, op = op, key = key, sent = sent, status = st, got = got, ms = ms; "storage request")
        }
        (None, None) => {
            log::log!(level, storage = storage, backend = backend, op = op, key = key, sent = sent, result = got, ms = ms; "storage request")
        }
    }
}

/// Block objects: chunks and packs, read and written by the thousand.
fn is_block_key(key: &str) -> bool {
    let k = key.trim_start_matches('/');
    let k = k.split_once("chunks/").map(|_| "chunks/").unwrap_or(k);
    k.starts_with("chunks/")
        || k.starts_with("packs/")
        || key.contains("/chunks/")
        || key.contains("/packs/")
}

/// Logs every call made through it (the engine's storages): operation,
/// object name, bytes, result and duration. Object names are fine in the
/// local log; contents never appear.
pub struct LoggedStorage {
    inner: Box<dyn Storage>,
    backend: &'static str,
}

impl LoggedStorage {
    pub fn new(inner: Box<dyn Storage>, backend: &'static str) -> Self {
        LoggedStorage { inner, backend }
    }
    fn done<T>(
        &self,
        op: &str,
        key: &str,
        sent: u64,
        got: impl Fn(&T) -> u64,
        t: crate::logging::Timer,
        r: &Result<T>,
    ) {
        let (got, err) = match r {
            Ok(v) => (got(v), None),
            Err(e) => (0, Some(e)),
        };
        log_request(
            self.inner.name(),
            self.backend,
            op,
            key,
            sent,
            None,
            got,
            t.ms(),
            err,
        );
    }
}

impl Storage for LoggedStorage {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.get_range(key, offset, len);
        self.done(
            "get_range",
            key,
            0,
            |v: &Option<Vec<u8>>| v.as_ref().map(|b| b.len() as u64).unwrap_or(0),
            t,
            &r,
        );
        r
    }
    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        let t = crate::logging::Timer::start();
        let sent: u64 = members.iter().map(|(_, d)| d.len() as u64).sum();
        let r = self.inner.put_pack(members);
        let first = members.first().map(|m| m.0.as_str()).unwrap_or("");
        if log::log_enabled!(log::Level::Debug) {
            match &r {
                Ok(v) => {
                    log::debug!(storage = self.inner.name(), op = "put_pack", members = members.len(), new = v.iter().filter(|b| **b).count(), first = first, sent = sent, ms = t.ms(); "storage request")
                }
                Err(e) => {
                    log::debug!(storage = self.inner.name(), op = "put_pack", members = members.len(), first = first, ms = t.ms(); "storage request failed: {e:#}")
                }
            }
        }
        r
    }
    fn put_built_pack(
        &self,
        id: &str,
        data: &[u8],
        members: &[(String, crate::packs::PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.put_built_pack(id, data, members);
        if log::log_enabled!(log::Level::Debug) {
            match &r {
                Ok(v) => {
                    log::debug!(storage = self.inner.name(), op = "put_built_pack", members = members.len(), taken = v.is_some(), sent = data.len(), ms = t.ms(); "storage request")
                }
                Err(e) => {
                    log::debug!(storage = self.inner.name(), op = "put_built_pack", members = members.len(), ms = t.ms(); "storage request failed: {e:#}")
                }
            }
        }
        r
    }
    fn pack_target(&self) -> usize {
        self.inner.pack_target()
    }
    fn pack_location(&self, object: &str) -> Option<crate::packs::PackLoc> {
        self.inner.pack_location(object)
    }
    fn take_new_packs(&self) -> Vec<crate::packs::NewPack> {
        self.inner.take_new_packs()
    }
    fn flush_deletions(&self) -> Result<()> {
        self.inner.flush_deletions()
    }
    fn collect_pack_garbage(
        &self,
        keep: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<(String, crate::packs::PackLoc)>> {
        self.inner.collect_pack_garbage(keep)
    }
    fn conditional_writes(&self) -> Option<bool> {
        self.inner.conditional_writes()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let t = crate::logging::Timer::start();
        let r = self.inner.put_if_absent(key, data);
        self.done(
            "put",
            key,
            data.len() as u64,
            |new: &bool| *new as u64,
            t,
            &r,
        );
        r
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.get(key);
        self.done(
            "get",
            key,
            0,
            |v: &Option<Vec<u8>>| v.as_ref().map(|b| b.len() as u64).unwrap_or(0),
            t,
            &r,
        );
        r
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.get_bounded(key, max);
        self.done(
            "get",
            key,
            0,
            |v: &Option<Vec<u8>>| v.as_ref().map(|b| b.len() as u64).unwrap_or(0),
            t,
            &r,
        );
        r
    }
    fn exists(&self, key: &str) -> Result<bool> {
        let t = crate::logging::Timer::start();
        let r = self.inner.exists(key);
        self.done("exists", key, 0, |b: &bool| *b as u64, t, &r);
        r
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.list(prefix);
        self.done("list", prefix, 0, |v: &Vec<String>| v.len() as u64, t, &r);
        r
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        let t = crate::logging::Timer::start();
        let r = self.inner.list_after(prefix, start_after);
        self.done(
            "list_after",
            prefix,
            0,
            |v: &Vec<String>| v.len() as u64,
            t,
            &r,
        );
        r
    }
    fn delete(&self, key: &str) -> Result<()> {
        let t = crate::logging::Timer::start();
        let r = self.inner.delete(key);
        self.done("delete", key, 0, |_: &()| 0, t, &r);
        r
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
        assert_eq!(
            s.list_after("ledger/", "ledger/dev/000").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            s.list_after("", "chunks/ab/one").unwrap(),
            vec!["ledger/dev/000".to_string()]
        );
        s.delete("chunks/ab/one").unwrap();
        assert!(!s.exists("chunks/ab/one").unwrap());
        assert!(s.get("../x").is_err());
    }
}
