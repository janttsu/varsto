// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The sync engine: ties keys, storages, the ledger and folder manifests
//! together. One `Engine` is one device of one vault.
//!
//! Flow of a `sync`:
//! 1. scan local folders (detect local changes, bump version vectors);
//! 2. pull: fetch device and folder records and everyone's ledger batches from
//!    every hot storage (the mailbox), fetch newer manifests, merge them,
//!    download and verify the chunks that are needed, write files;
//! 3. push: upload chunks of changed files, publish our manifest, append our
//!    ledger batch and push it to every storage.
//!
//! Cold storages (F-043) are written but never read without an explicit
//! confirmation; alpha-0 simply never reads them.

use crate::chunking::{Chunker, ChunkerParams};
use crate::crypto::{self, KeyedHasher, SecretKey};
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName, VaultId};
use crate::ledger::{
    self, Event, Ingest, KeyDirectory, LedgerStore, LedgerView, SignedBatch, KEY_LEDGER,
    KEY_REPLICA,
};
use crate::manifest::{self, ChunkRef, FileState, Manifest, Merge};
use crate::policy::{Policy, PolicyReport};
use crate::pool::{self, DiskStatus, PoolDisk, PoolError, PoolIdentity, PoolStorage};
use crate::replica::{self, ReplicaToken, REPLICA_PREFIX};
use crate::storage::{Storage, StorageSpec};
use crate::thumbs;
use crate::util;
use crate::vault::{self, SecretStore, ShareToken, SHARE_PREFIX};
use crate::vault::{
    Config, DeviceRecord, FolderKeys, FolderMount, FolderRecord, Keyring, Keys, LocalVault,
    VaultMeta,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

mod devinfo;
mod membership;
mod placement;
mod strongroom_ops;
mod verify;
mod view;
pub use devinfo::DeviceDetails;
pub use membership::{
    removal_notice, DeviceInfo, DeviceRemoved, EpochRecord, Grant, KemRecord, Removal, Revocation,
    RevokeReport, Revoked, SignedRevocation,
};
pub use strongroom_ops::{CleanupReport, ConvertReport, StrongroomKeySummary};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct LocalIndexEntry {
    size: u64,
    mtime: i64,
    content_hash: String,
}

/// Per-folder state on this device: `home/state/<folder>.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FolderState {
    /// Merged view as applied to disk (including tombstones).
    files: BTreeMap<String, FileState>,
    /// What is on disk, keyed by manifest path.
    local_index: BTreeMap<String, LocalIndexEntry>,
    /// Highest manifest sequence applied per other device.
    last_seen: BTreeMap<DeviceId, u64>,
    published_seq: u64,
    published_hash: String,
    /// Selective sync: paths the user wants kept on this device.
    #[serde(default)]
    pinned: BTreeSet<String>,
    /// Content hashes whose thumbnail this device has generated and stored.
    #[serde(default)]
    thumbs_done: BTreeSet<String>,
    /// Varsto's own "last accessed" record per path (seconds since the Unix
    /// epoch): updated when a file is fetched, opened or read through Varsto
    /// (interface, CLI, MCP) and from the filesystem access time seen at scan.
    /// Kept per device; it feeds the cold-storage advice (MCP).
    #[serde(default)]
    accessed: BTreeMap<String, i64>,
    /// Remote versions that could not be downloaded yet (no readable copy);
    /// retried on every pull, including from peers that appear later.
    #[serde(default)]
    pending_remote: BTreeMap<String, FileState>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Clock {
    lamport: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct DeviceCache {
    devices: BTreeMap<DeviceId, DeviceRecord>,
    #[serde(default)]
    replicas: BTreeMap<DeviceId, DeviceRecord>,
    /// Member devices of shared folders (other users), by device id.
    #[serde(default)]
    members: BTreeMap<DeviceId, DeviceRecord>,
    /// Devices removed from the vault (signed revocations this device accepted).
    #[serde(default)]
    revoked: BTreeMap<DeviceId, membership::Revoked>,
    /// Key epoch whose registry key opened each device record (absent = 0).
    #[serde(default)]
    record_epochs: BTreeMap<DeviceId, u32>,
    /// System and version each device last published (`devinfo`).
    #[serde(default)]
    details: BTreeMap<DeviceId, devinfo::DeviceDetails>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct PushReport {
    pub folder: String,
    pub files_scanned: u64,
    pub files_changed: u64,
    pub chunks_uploaded: u64,
    pub bytes_uploaded: u64,
    pub manifest_seq: Option<u64>,
    pub batch_seq: Option<u64>,
    #[serde(default)]
    pub thumbnails: u64,
    /// Storages that took nothing this time (a disk pool with no disk
    /// attached or no room); the next push tries them again.
    #[serde(default)]
    pub storages_unavailable: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct PullReport {
    /// Chunks fetched from peers instead of storages.
    #[serde(default)]
    pub chunks_from_peers: u64,
    pub folder: String,
    pub manifests_applied: u64,
    pub files_updated: u64,
    pub files_deleted: u64,
    pub conflicts: u64,
    pub chunks_downloaded: u64,
    pub bytes_downloaded: u64,
    pub files_unavailable: Vec<String>,
    pub forked_devices: Vec<String>,
    /// Pool disks that must be attached for unavailable files: "label (place)".
    #[serde(default)]
    pub disks_needed: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FolderStatus {
    pub folder_id: String,
    pub name: String,
    pub path: Option<PathBuf>,
    pub files: u64,
    pub bytes: u64,
    pub chunks: u64,
    /// Chunks of current files that no storage claims to hold.
    pub chunks_without_storage_copy: u64,
    /// Chunks that at least one device other than the writer has verified on a storage.
    pub chunks_verified_elsewhere: u64,
    pub published_seq: u64,
    pub shared: bool,
    pub selective: bool,
    /// Plain files on this device (false: "encrypted on this device", see `FolderMount::encrypted`).
    #[serde(default)]
    pub plain: bool,
    pub placeholders: u64,
    pub pinned: u64,
    /// Durability policy, if one is set (human-readable).
    #[serde(default)]
    pub policy: Option<String>,
    /// Strongroom state: "locked" or "unlocked until <utc>".
    #[serde(default)]
    pub strongroom: Option<String>,
}

/// See `Engine::plan_storage_removal`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageRemovalPlan {
    pub storage: String,
    /// Blocks on the storage that files still use.
    pub blocks: u64,
    /// Of those, blocks that already have enough copies elsewhere.
    pub blocks_ok: u64,
    pub copies: Vec<PlannedCopy>,
    pub bytes_to_copy: u64,
    /// Storages that receive copies.
    pub targets: Vec<String>,
    /// Why the storage cannot be removed now, if it cannot.
    pub blocked: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlannedCopy {
    pub folder: FolderId,
    pub chunk: ChunkId,
    pub object: ObjectName,
    pub target: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageRemovalReport {
    pub storage: String,
    pub blocks_copied: u64,
    pub bytes_copied: u64,
    pub objects_deleted: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub vault_id: String,
    pub device_id: String,
    pub device_name: String,
    pub format_version: u16,
    pub storages: Vec<StorageSpec>,
    pub devices: BTreeMap<String, String>,
    /// Devices removed from the vault (name by device id).
    pub revoked: BTreeMap<String, String>,
    /// Vault key epoch: 0 until a device is removed, then one more per removal.
    pub key_epoch: u32,
    /// Untrusted replicas that hold encrypted copies (name by device id).
    pub replicas: BTreeMap<String, String>,
    /// Other users' devices that share folders with this vault (name by device id).
    pub members: BTreeMap<String, String>,
    /// This device holds only shared folders of another user's vault.
    pub member: bool,
    pub folders: Vec<FolderStatus>,
    pub ledger_batches: u64,
    pub lamport: u64,
    pub forked_devices: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct FsckReport {
    pub chunks_referenced: u64,
    pub chunks_with_storage_copy: u64,
    pub chunks_verified_elsewhere: u64,
    pub chunks_claimed_only: u64,
    /// Referenced by a current file but present in no readable storage listing.
    pub chunks_missing: Vec<String>,
    /// The ledger claims an object on a storage but the listing does not have it.
    pub claims_without_object: u64,
    pub objects_unreferenced: u64,
    pub objects_verified_now: u64,
    pub objects_corrupt: Vec<String>,
    pub forked_devices: Vec<String>,
    pub storages_skipped_cold: Vec<String>,
    /// Referenced objects on pool disks that are not attached (not verified now).
    #[serde(default)]
    pub objects_offline: u64,
    /// Pool disks that are away, with their last verification: "label (place), last verified <date>".
    #[serde(default)]
    pub disks_offline: Vec<String>,
}

/// What `disk add` did.
#[derive(Clone, Debug, Serialize)]
pub struct DiskAddReport {
    pub pool: String,
    pub disk: PoolDisk,
    pub objects_added: u64,
    pub bytes_added: u64,
}

/// What `disk check` did (the reattach routine).
#[derive(Clone, Debug, Serialize, Default)]
pub struct DiskCheckReport {
    pub pool: String,
    pub label: String,
    pub mount: PathBuf,
    pub objects_checked: u64,
    pub bytes_checked: u64,
    /// Objects whose size or hash did not match (dropped from the index).
    pub bad: Vec<String>,
    /// Objects the index listed but the disk did not have.
    pub missing: Vec<String>,
    /// Objects found on the disk that this device did not know.
    pub adopted: u64,
    /// Pending deletions applied.
    pub objects_removed: u64,
    pub bytes_removed: u64,
    /// New objects written.
    pub objects_added: u64,
    pub bytes_added: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    /// "local", "placeholder" or "missing".
    pub state: String,
    pub pinned: bool,
    pub content_hash: String,
    pub selective: bool,
    /// Where the file is (or would be) on this device's disk.
    pub disk: PathBuf,
    /// Image or video: a thumbnail may exist.
    pub media: bool,
    /// Last modification (seconds since the Unix epoch) from the manifest.
    pub modified_utc: i64,
    /// Varsto's own last-accessed time on this device, if any.
    pub last_accessed_utc: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DupeGroup {
    pub content_hash: String,
    pub size: u64,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LedgerEntry {
    pub device: String,
    pub seq: u64,
    pub lamport: u64,
    pub created_utc: i64,
    pub events: usize,
    pub hash: String,
}

pub struct Engine {
    /// Peers to try before storages when downloading (set by the service).
    peers: Option<std::sync::Arc<crate::p2p::Peers>>,
    /// Strongroom folder keys held in memory until the expiry time (UTC seconds).
    unlocked: BTreeMap<FolderId, (SecretKey, i64)>,
    home: PathBuf,
    vault: LocalVault,
    keys: Keys,
    config: Config,
    keyring: Keyring,
    ledger: LedgerStore,
    clock: Clock,
    devices: DeviceCache,
    pending: Vec<Event>,
    forked_self: bool,
    /// Vault keys per epoch (they change when a device is revoked).
    epochs: membership::VaultEpochs,
    /// Set once this device has seen its own revocation: it no longer syncs.
    removal: Option<Removal>,
    pub chunker: ChunkerParams,
}

/// Open storages with their specs.
type OpenStorages = Vec<(StorageSpec, Box<dyn Storage>)>;

/// Suffix of placeholder files in selective folders (plan 6.34, Resilio-style).
pub const PLACEHOLDER_SUFFIX: &str = ".varsto-placeholder";

fn placeholder_path(disk: &Path) -> PathBuf {
    let mut s = disk.as_os_str().to_os_string();
    s.push(PLACEHOLDER_SUFFIX);
    PathBuf::from(s)
}

fn chunk_storage_key(object: &ObjectName) -> String {
    format!("chunks/{}/{}", &object.as_str()[..2], object)
}

/// Absolute path without the `\\?\` verbatim prefix Windows adds, so that
/// paths shown to people and written to the ledger stay readable.
fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    let p = path.canonicalize()?;
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{rest}")));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return Ok(PathBuf::from(rest));
    }
    Ok(p)
}

impl Engine {
    // ----- lifecycle -------------------------------------------------------

    /// Create a new vault and its first device. Returns the engine and the
    /// vault key (hex) that other devices need to join. The vault key is shown
    /// once and never stored in clear text.
    pub fn init(home: &Path, device_name: &str, passphrase: &str) -> Result<(Engine, String)> {
        if home.join("vault.json").exists() {
            bail!("{} already holds a vault", home.display());
        }
        fs::create_dir_all(home)?;
        let keys = Keys {
            master: SecretKey::random(),
            signer: crypto::SigningKey::generate(),
        };
        let device_id = ledger::device_id_for(&keys.signer.public());
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id: VaultId::random(),
            device_id,
            device_name: device_name.to_string(),
            created_utc: util::now_utc(),
            member: false,
        };
        let vault_key_hex = keys.master.to_hex();
        let epochs = membership::VaultEpochs::genesis(&keys.master);
        Self::write_new(home, vault, keys, passphrase, epochs).map(|e| (e, vault_key_hex))
    }

    /// Join an existing vault with its vault key, through a storage that holds it.
    pub fn join(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
    ) -> Result<Engine> {
        Self::join_with_secret(home, device_name, passphrase, vault_key_hex, storage, None)
    }

    /// Like `join`, with the storage's secret (S3 secret access key) in hand;
    /// it goes into this device's encrypted secret store.
    pub fn join_with_secret(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        if home.join("vault.json").exists() {
            bail!("{} already holds a vault", home.display());
        }
        let backend = storage.open_with(&|_| secret.clone())?;
        let meta_bytes = backend.get(VaultMeta::STORAGE_KEY)?.ok_or_else(|| {
            anyhow!(
                "storage {} holds no vault (no {})",
                storage.name(),
                VaultMeta::STORAGE_KEY
            )
        })?;
        let meta: VaultMeta = serde_json::from_slice(&meta_bytes)?;
        if meta.format_version != crate::FORMAT_VERSION {
            bail!(
                "vault format version {} is not readable by this version ({})",
                meta.format_version,
                crate::FORMAT_VERSION
            );
        }
        let master = SecretKey::from_hex(vault_key_hex)?;
        let epochs = membership::discover_epochs(backend.as_ref(), &meta.vault_id, &master)?;
        fs::create_dir_all(home)?;
        let keys = Keys {
            master,
            signer: crypto::SigningKey::generate(),
        };
        let device_id = ledger::device_id_for(&keys.signer.public());
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id: meta.vault_id,
            device_id,
            device_name: device_name.to_string(),
            created_utc: meta.created_utc,
            member: false,
        };
        let mut engine = Self::write_new(home, vault, keys, passphrase, epochs)?;
        engine.add_storage_with_secret(storage, secret)?;
        engine.pull_registry()?;
        engine.pull_ledger()?;
        // Publish the enrolment now: the other devices list this one from
        // the ledger, and a phone may not sync a folder for a long time.
        engine.push_own_batches()?;
        Ok(engine)
    }

    /// Join with what a paired device sent (`pair::Bundle`): through the first
    /// of its storages that this device can reach, then add the other
    /// reachable ones. Returns the engine and one note per storage.
    pub fn join_paired(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
    ) -> Result<(Engine, Vec<String>)> {
        let mut notes = Vec::new();
        let mut first = None;
        for (i, s) in bundle.storages.iter().enumerate() {
            match Self::reachable(s) {
                Ok(()) => {
                    first = Some(i);
                    break;
                }
                Err(e) => notes.push(format!("{}: not reachable here ({e:#})", s.spec.name())),
            }
        }
        let Some(first) = first else {
            bail!(
                "none of the vault's storages can be reached from this device: {}. Add a storage both devices can reach (an S3 bucket or an rclone remote) on {} and pair again",
                if notes.is_empty() { "it has none".to_string() } else { notes.join("; ") },
                bundle.from
            );
        };
        let chosen = &bundle.storages[first];
        let mut engine = Self::join_with_secret(
            home,
            device_name,
            passphrase,
            &bundle.vault_key,
            chosen.spec.clone(),
            chosen.secret.clone(),
        )?;
        if engine.vault.vault_id.to_string() != bundle.vault_id {
            bail!(
                "storage {} holds another vault than the one paired with",
                chosen.spec.name()
            );
        }
        notes.push(format!("{}: joined through it", chosen.spec.name()));
        for s in bundle.storages.iter().skip(first + 1) {
            let r = Self::reachable(s)
                .and_then(|()| engine.add_storage_with_secret(s.spec.clone(), s.secret.clone()));
            notes.push(match r {
                Ok(()) => format!("{}: added", s.spec.name()),
                Err(e) => format!("{}: not reachable here ({e:#})", s.spec.name()),
            });
        }
        Ok((engine, notes))
    }

    /// Whether a paired storage holds the vault and can be opened from here.
    /// A directory must already exist (it is the other device's path), and
    /// disk pools are attached per device, never taken over.
    fn reachable(s: &crate::pair::BundleStorage) -> Result<()> {
        match &s.spec {
            StorageSpec::LocalDir { path, .. } if !path.is_dir() => {
                bail!("no directory {} on this device", path.display())
            }
            StorageSpec::Pool { .. } => bail!("disk pools are attached on each device"),
            _ => {}
        }
        let secret = s.secret.clone();
        match s
            .spec
            .open_with(&|_| secret.clone())?
            .get(VaultMeta::STORAGE_KEY)?
        {
            Some(_) => Ok(()),
            None => bail!("holds no vault"),
        }
    }

    /// Everything a new device needs to join, for pairing: the vault key and
    /// the storage settings with their secrets. Only a full device can pair.
    pub fn pairing_bundle(&self) -> Result<crate::pair::Bundle> {
        if self.vault.member {
            bail!("a member device cannot add devices");
        }
        let store = self.secret_store()?;
        let storages = self
            .config
            .storages
            .iter()
            .filter(|s| !matches!(s, StorageSpec::Pool { .. }))
            .map(|spec| {
                let secret = match spec {
                    StorageSpec::S3 {
                        name, secret_ref, ..
                    } => {
                        let r = if secret_ref.is_empty() {
                            name
                        } else {
                            secret_ref
                        };
                        let env = format!(
                            "VARSTO_S3_SECRET_{}",
                            name.to_uppercase()
                                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                        );
                        store
                            .secrets
                            .get(r)
                            .cloned()
                            .or_else(|| std::env::var(env).ok())
                    }
                    _ => None,
                };
                crate::pair::BundleStorage {
                    spec: spec.clone(),
                    secret,
                }
            })
            .collect();
        Ok(crate::pair::Bundle {
            vault_id: self.vault.vault_id.to_string(),
            vault_key: self.export_vault_key()?,
            from: self.vault.device_name.clone(),
            storages,
        })
    }

    fn write_new(
        home: &Path,
        vault: LocalVault,
        keys: Keys,
        passphrase: &str,
        epochs: membership::VaultEpochs,
    ) -> Result<Engine> {
        keys.save(home, passphrase, &vault.vault_id, &vault.device_id)?;
        util::write_json(&home.join("vault.json"), &vault)?;
        let mut engine = Engine {
            peers: None,
            unlocked: BTreeMap::new(),
            home: home.to_path_buf(),
            vault,
            keys,
            config: Config::default(),
            keyring: Keyring::default(),
            ledger: LedgerStore::open(&home.join("ledger"))?,
            clock: Clock::default(),
            devices: DeviceCache::default(),
            pending: Vec::new(),
            forked_self: false,
            epochs,
            removal: None,
            chunker: ChunkerParams::DEFAULT,
        };
        engine.config.save(home)?;
        if !engine.vault.member {
            engine.save_epochs()?;
        }
        engine.keyring.save(
            home,
            &engine.keys,
            &engine.vault.vault_id,
            &engine.vault.device_id,
        )?;
        if !engine.vault.member {
            let rec = engine.own_record();
            engine.devices.devices.insert(rec.device_id.clone(), rec);
            engine.save_devices()?;
            engine.pending.push(Event::DeviceEnrolled {
                name: engine.vault.device_name.clone(),
            });
            engine.commit_batch()?;
        }
        Ok(engine)
    }

    /// Become a member of one shared folder of another user's vault (F-047).
    /// This device gets the folder key only: it can read and write that folder
    /// through the shared storage, nothing else of the vault.
    pub fn accept_share(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        token: &ShareToken,
        storage: StorageSpec,
    ) -> Result<Engine> {
        if home.join("vault.json").exists() {
            bail!("{} already holds a vault", home.display());
        }
        let backend = storage.open()?;
        let meta: VaultMeta = serde_json::from_slice(
            &backend
                .get(VaultMeta::STORAGE_KEY)?
                .ok_or_else(|| anyhow!("storage {} holds no vault", storage.name()))?,
        )?;
        if meta.vault_id != token.vault_id {
            bail!(
                "the storage holds vault {} but the token is for {}",
                meta.vault_id,
                token.vault_id
            );
        }
        fs::create_dir_all(home)?;
        // The "master" of a member is a local random root used only for the
        // local keyring; it never leaves the device and opens nothing shared.
        let keys = Keys {
            master: SecretKey::random(),
            signer: crypto::SigningKey::generate(),
        };
        let device_id = ledger::device_id_for(&keys.signer.public());
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id: meta.vault_id.clone(),
            device_id: device_id.clone(),
            device_name: device_name.to_string(),
            created_utc: meta.created_utc,
            member: true,
        };
        let epochs = membership::VaultEpochs::genesis(&keys.master);
        let mut engine = Self::write_new(home, vault, keys, passphrase, epochs)?;
        let rec = FolderRecord {
            folder_id: token.folder_id.clone(),
            name: token.name.clone(),
            key_hex: token.key_hex.clone(),
            created_by: device_id,
            created_utc: util::now_utc(),
            shared: true,
            policy: None,
            policy_updated_utc: 0,
            strongroom: None,
            removed_utc: 0,
        };
        engine.keyring.folders.insert(rec.folder_id.clone(), rec);
        engine.keyring.save(
            home,
            &engine.keys,
            &engine.vault.vault_id,
            &engine.vault.device_id,
        )?;
        engine.add_storage(storage)?;
        engine.pending.push(Event::DeviceEnrolled {
            name: engine.vault.device_name.clone(),
        });
        engine.commit_batch()?;
        engine.pull_registry()?;
        Ok(engine)
    }

    /// Owner: share a folder with another user. The token carries the folder key.
    pub fn share_create(&mut self, folder: &str) -> Result<ShareToken> {
        if self.vault.member {
            bail!("a member device cannot share folders further");
        }
        if self.keyring.find(folder).is_some_and(|r| r.is_strongroom()) {
            bail!("a Strongroom folder cannot be shared");
        }
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if self.key_epoch() > 0 && !self.is_frozen(&rec) {
            bail!(
                "{} was re-keyed when a device was removed; sharing a re-keyed folder is not supported yet",
                rec.name
            );
        }
        if let Some(r) = self.keyring.folders.get_mut(&rec.folder_id) {
            r.shared = true;
        }
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.publish_registry()?;
        Ok(rec.share_token(&self.vault.vault_id))
    }

    pub fn is_member(&self) -> bool {
        self.vault.member
    }

    /// Which key opens a ledger batch with this key id, on this device.
    fn key_for_id(&self, id: &str) -> Option<SecretKey> {
        match id {
            KEY_REPLICA if !self.vault.member => Some(replica::replica_key(self.root_key())),
            id if !self.vault.member && id.starts_with(KEY_LEDGER) => self.ledger_key_for(id),
            other => {
                let fid = other.strip_prefix("share:")?;
                let rec = self.keyring.folders.get(&FolderId::from_hex(fid).ok()?)?;
                Some(vault::share_ledger_key(
                    &rec.folder_key().ok()?,
                    &rec.folder_id,
                ))
            }
        }
    }

    /// Unlock an existing device directory.
    pub fn open(home: &Path, passphrase: &str) -> Result<Engine> {
        let vault: LocalVault = util::read_json(&home.join("vault.json"))
            .with_context(|| format!("no vault in {}", home.display()))?;
        if vault.format_version != crate::FORMAT_VERSION {
            bail!(
                "local vault format {} is not readable by this version",
                vault.format_version
            );
        }
        let keys = Keys::load(home, passphrase, &vault.vault_id, &vault.device_id)?;
        let keyring = Keyring::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let epochs = membership::VaultEpochs::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let removal = util::read_json(&home.join("removed.json")).ok();
        let mut engine = Engine {
            peers: None,
            unlocked: BTreeMap::new(),
            config: Config::load(home)?,
            ledger: LedgerStore::open(&home.join("ledger"))?,
            clock: util::read_json_or_default(&home.join("clock.json"))?,
            devices: util::read_json_or_default(&home.join("devices.json"))?,
            home: home.to_path_buf(),
            vault,
            keys,
            keyring,
            pending: Vec::new(),
            forked_self: false,
            epochs,
            removal,
            chunker: ChunkerParams::DEFAULT,
        };
        // Command-line runs use the peers other devices advertised, over TCP
        // only; the service adds LAN peers and the QUIC node.
        if engine.config.p2p.enabled {
            if let Ok(list) = engine.peer_record_list() {
                if !list.is_empty() {
                    let p = crate::p2p::Peers::build(
                        engine.peer_key(),
                        engine.vault.device_id.clone(),
                        &list,
                        &[],
                        None,
                    );
                    engine.set_peers(Some(std::sync::Arc::new(p)));
                }
            }
        }
        Ok(engine)
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.vault.device_id
    }
    /// This device's own name.
    pub fn own_device_name(&self) -> &str {
        &self.vault.device_name
    }
    pub fn vault_id(&self) -> &VaultId {
        &self.vault.vault_id
    }
    pub fn home(&self) -> &Path {
        &self.home
    }

    fn own_record(&self) -> DeviceRecord {
        DeviceRecord {
            device_id: self.vault.device_id.clone(),
            name: self.vault.device_name.clone(),
            pubkey_hex: hex::encode(self.keys.signer.public().to_bytes()),
            enrolled_utc: util::now_utc(),
        }
    }

    fn save_devices(&self) -> Result<()> {
        util::write_json(&self.home.join("devices.json"), &self.devices)
    }

    fn key_directory(&self) -> Result<KeyDirectory> {
        let mut dir = KeyDirectory::new();
        // Revoked devices stay in the directory: their batches up to the
        // cut-off remain valid. Devices enrolled with an out-of-date vault
        // key are left out.
        for (id, rec) in self
            .devices
            .devices
            .iter()
            .filter(|(id, _)| self.trusted(id) || self.is_revoked(id))
            .chain(self.devices.replicas.iter())
            .chain(self.devices.members.iter())
        {
            dir.insert(id.clone(), rec.pubkey()?);
        }
        dir.insert(self.vault.device_id.clone(), self.keys.signer.public());
        Ok(dir)
    }

    fn tick(&mut self) -> Result<u64> {
        self.clock.lamport += 1;
        util::write_json(&self.home.join("clock.json"), &self.clock)?;
        Ok(self.clock.lamport)
    }

    fn observe_clock(&mut self, seen: u64) -> Result<()> {
        if seen > self.clock.lamport {
            self.clock.lamport = seen;
            util::write_json(&self.home.join("clock.json"), &self.clock)?;
        }
        Ok(())
    }

    // ----- storages and folders ---------------------------------------------

    pub fn add_storage(&mut self, spec: StorageSpec) -> Result<()> {
        self.add_storage_with_secret(spec, None)
    }

    /// Resolve storage secrets (S3 secret access keys) from the encrypted
    /// secret store of this device.
    fn secret_store(&self) -> Result<SecretStore> {
        SecretStore::load(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    fn open_spec(&self, spec: &StorageSpec) -> Result<Box<dyn Storage>> {
        if let StorageSpec::Pool { .. } = spec {
            return Ok(Box::new(self.open_pool(spec)?));
        }
        let store = self.secret_store()?;
        spec.open_with(&|r| store.secrets.get(r).cloned())
    }

    /// Open a configured storage by name (tests and tools).
    pub fn open_storage(&self, name: &str) -> Result<Box<dyn Storage>> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        self.open_spec(spec)
    }

    /// Identity of a disk pool: both values are keyed hashes under a key
    /// derived from the vault key, so every device of the vault computes the
    /// same pool id for the same pool name, and a disk marker reveals neither
    /// the vault id nor the pool name.
    fn pool_identity(&self, name: &str) -> PoolIdentity {
        let k = self.root_key().derive("disk-pool", &[]);
        PoolIdentity {
            pool_id: hex::encode(&crypto::keyed_hash(&k, format!("pool:{name}").as_bytes())[..16]),
            vault_tag: hex::encode(
                &crypto::keyed_hash(&k, format!("vault:{}", self.vault.vault_id).as_bytes())[..16],
            ),
        }
    }

    fn open_pool(&self, spec: &StorageSpec) -> Result<PoolStorage> {
        PoolStorage::open(spec, &self.home, self.pool_identity(spec.name()))
    }

    /// Keep a storage secret (S3 secret access key) in `secrets.enc`, for a
    /// storage that was configured without one (for example at `join`).
    pub fn store_secret(&mut self, reference: &str, secret: &str) -> Result<()> {
        let mut store = self.secret_store()?;
        store
            .secrets
            .insert(reference.to_string(), secret.to_string());
        store.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Add a storage; `secret` (for S3: the secret access key) is kept in
    /// `secrets.enc`, never in `config.json`.
    pub fn add_storage_with_secret(
        &mut self,
        spec: StorageSpec,
        secret: Option<String>,
    ) -> Result<()> {
        if self.config.storages.iter().any(|s| s.name() == spec.name()) {
            bail!("a storage named {} already exists", spec.name());
        }
        if let StorageSpec::Pool {
            reserve_percent, ..
        } = &spec
        {
            if self.vault.member {
                bail!("a member device cannot add disk pools");
            }
            if *reserve_percent > 90 {
                bail!("reserve percent must be at most 90");
            }
            // A pool holds chunks only; the vault identity lives in each
            // disk's marker (keyed tag), so no meta object is written.
            self.open_pool(&spec)?;
            self.config.storages.push(spec);
            self.config.save(&self.home)?;
            return Ok(());
        }
        if let Some(secret) = secret {
            let reference = match &spec {
                StorageSpec::S3 {
                    secret_ref, name, ..
                } if !secret_ref.is_empty() => secret_ref.clone(),
                _ => spec.name().to_string(),
            };
            let mut store = self.secret_store()?;
            store.secrets.insert(reference, secret);
            store.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            )?;
        }
        let backend = self.open_spec(&spec)?;
        let meta = VaultMeta {
            format_version: crate::FORMAT_VERSION,
            vault_id: self.vault.vault_id.clone(),
            created_utc: self.vault.created_utc,
        };
        if let Some(existing) = backend.get(VaultMeta::STORAGE_KEY)? {
            let existing: VaultMeta = serde_json::from_slice(&existing)?;
            if existing.vault_id != meta.vault_id {
                bail!("storage {} belongs to another vault", spec.name());
            }
        } else {
            backend.put_if_absent(VaultMeta::STORAGE_KEY, &serde_json::to_vec_pretty(&meta)?)?;
        }
        self.config.storages.push(spec);
        self.config.save(&self.home)?;
        self.publish_registry()?;
        Ok(())
    }

    pub fn storages(&self) -> &[StorageSpec] {
        &self.config.storages
    }

    /// What removing a storage takes: every block on it must keep enough
    /// copies on the other storages (at least one, or the folder policy's
    /// minimum and per-place rules), so blocks short of that are copied first.
    pub fn plan_storage_removal(&self, name: &str) -> Result<StorageRemovalPlan> {
        if !self.config.storages.iter().any(|s| s.name() == name) {
            bail!("unknown storage {name}");
        }
        let mut plan = StorageRemovalPlan {
            storage: name.to_string(),
            ..Default::default()
        };
        // Copies count on this device's other storages that are not
        // transferrers, and on replicas; claims on storages this device does
        // not know are not counted.
        let others: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != name && !s.is_carrier())
            .collect();
        if others.is_empty() {
            plan.blocked = Some(format!(
                "{name} is the last storage of this vault: add another storage first"
            ));
            return Ok(plan);
        }
        let place_of: HashMap<&str, String> =
            others.iter().map(|s| (s.name(), s.place())).collect();
        let view = self.view()?;
        let mut targets_used = BTreeSet::new();
        for (rec, _) in self.folders() {
            let policy = rec.policy.clone().unwrap_or_default();
            let required = policy.min_copies.max(1) as usize;
            // Blocks no file refers to any more need no copies; a folder never
            // pulled here has no state, so then every block counts.
            let referenced: HashSet<ChunkId> = self
                .load_state(&rec.folder_id)
                .map(|st| {
                    st.files
                        .values()
                        .filter(|f| !f.deleted)
                        .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
                        .collect()
                })
                .unwrap_or_default();
            for ((folder, chunk), cr) in &view.chunks {
                if folder != &rec.folder_id || !cr.storages.contains_key(name) {
                    continue;
                }
                if !referenced.is_empty() && !referenced.contains(chunk) {
                    continue;
                }
                plan.blocks += 1;
                let holders: Vec<&String> = cr
                    .storages
                    .keys()
                    .filter(|n| {
                        n.as_str() != name
                            && (n.starts_with("replica:") || place_of.contains_key(n.as_str()))
                    })
                    .collect();
                let mut targets: Vec<&str> = Vec::new();
                let free = |targets: &Vec<&str>, s: &&StorageSpec| {
                    !holders.iter().any(|h| h.as_str() == s.name()) && !targets.contains(&s.name())
                };
                for (place, min) in &policy.min_per_place {
                    let have = holders
                        .iter()
                        .filter(|h| place_of.get(h.as_str()) == Some(place))
                        .count();
                    for _ in have..*min as usize {
                        match others
                            .iter()
                            .find(|s| &s.place() == place && free(&targets, s))
                        {
                            Some(s) => targets.push(s.name()),
                            None => {
                                plan.blocked = Some(format!(
                                    "folder {} needs {min} copies {} and no other storage there can take them: add one first",
                                    rec.name,
                                    crate::policy::place_phrase(place)
                                ));
                                return Ok(plan);
                            }
                        }
                    }
                }
                while holders.len() + targets.len() < required {
                    // Prefer warm storages: a cold one is written, rarely read.
                    let pick = others
                        .iter()
                        .filter(|s| free(&targets, s))
                        .min_by_key(|s| s.is_cold());
                    match pick {
                        Some(s) => targets.push(s.name()),
                        None => {
                            plan.blocked = Some(format!(
                                "folder {} needs {required} copies and only {} other storages exist: add one first",
                                rec.name,
                                others.len()
                            ));
                            return Ok(plan);
                        }
                    }
                }
                if targets.is_empty() {
                    plan.blocks_ok += 1;
                }
                for t in targets {
                    targets_used.insert(t.to_string());
                    plan.bytes_to_copy += cr.size;
                    plan.copies.push(PlannedCopy {
                        folder: folder.clone(),
                        chunk: chunk.clone(),
                        object: cr.object.clone(),
                        target: t.to_string(),
                    });
                }
            }
        }
        plan.targets = targets_used.into_iter().collect();
        Ok(plan)
    }

    /// Remove a storage: copy what the plan says, check again, record the
    /// retirement in the ledger so no device counts it as a copy any more,
    /// and drop it from this device. With `delete_data` everything Varsto
    /// wrote there is deleted afterwards.
    pub fn remove_storage(
        &mut self,
        name: &str,
        delete_data: bool,
    ) -> Result<StorageRemovalReport> {
        let plan = self.plan_storage_removal(name)?;
        if let Some(why) = plan.blocked {
            bail!("{why}");
        }
        let mut report = StorageRemovalReport {
            storage: name.to_string(),
            ..Default::default()
        };
        if !plan.copies.is_empty() || delete_data {
            let source = self.open_storage(name).with_context(|| {
                format!("{name} must be reachable to copy its blocks elsewhere first")
            })?;
            let mut targets: HashMap<String, Box<dyn Storage>> = HashMap::new();
            for c in &plan.copies {
                let key = chunk_storage_key(&c.object);
                let bytes = source
                    .get(&key)?
                    .ok_or_else(|| anyhow!("block {} is missing on {name}; run fsck", c.object))?;
                if !targets.contains_key(&c.target) {
                    targets.insert(c.target.clone(), self.open_storage(&c.target)?);
                }
                targets[&c.target].put_if_absent(&key, &bytes)?;
                self.pending.push(Event::ChunkStored {
                    folder: c.folder.clone(),
                    chunk: c.chunk.clone(),
                    object: c.object.clone(),
                    storage: c.target.clone(),
                    size: bytes.len() as u64,
                });
                report.blocks_copied += 1;
                report.bytes_copied += bytes.len() as u64;
            }
            self.commit_batch()?;
            let again = self.plan_storage_removal(name)?;
            if again.blocked.is_some() || !again.copies.is_empty() {
                bail!("{name} still holds blocks without enough copies elsewhere; nothing was removed");
            }
            self.pending.push(Event::StorageRetired {
                storage: name.to_string(),
            });
            self.commit_batch()?;
            if delete_data {
                for key in source.list("")? {
                    source.delete(&key)?;
                    report.objects_deleted += 1;
                }
            }
        } else {
            self.pending.push(Event::StorageRetired {
                storage: name.to_string(),
            });
            self.commit_batch()?;
        }
        self.config.storages.retain(|s| s.name() != name);
        self.config.save(&self.home)?;
        self.publish_registry()?;
        Ok(report)
    }

    fn open_storages(&self, include_cold: bool) -> Result<OpenStorages> {
        let mut out = Vec::new();
        for spec in &self.config.storages {
            if spec.is_cold() && !include_cold {
                continue;
            }
            out.push((spec.clone(), self.open_spec(spec)?));
        }
        Ok(out)
    }

    /// Storages that carry records, ledger batches, manifests and thumbnails:
    /// everything except data-only disk pools.
    fn metadata_storages(&self, include_cold: bool) -> Result<OpenStorages> {
        Ok(self
            .open_storages(include_cold)?
            .into_iter()
            .filter(|(s, _)| !s.is_data_only())
            .collect())
    }

    /// Create a folder in the vault and mount it at `path` on this device.
    pub fn add_folder(&mut self, name: &str, path: &Path) -> Result<FolderId> {
        if self.vault.member {
            bail!("this device is a member of a shared folder only; it cannot create folders in the owner's vault");
        }
        self.ensure_unique_folder_name(name)?;
        fs::create_dir_all(path)?;
        let rec = FolderRecord {
            folder_id: FolderId::random(),
            name: name.to_string(),
            key_hex: SecretKey::random().to_hex(),
            created_by: self.vault.device_id.clone(),
            created_utc: util::now_utc(),
            shared: false,
            policy: None,
            policy_updated_utc: 0,
            strongroom: None,
            removed_utc: 0,
        };
        let id = rec.folder_id.clone();
        self.keyring.folders.insert(id.clone(), rec);
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.config.folders.push(FolderMount {
            folder_id: id.clone(),
            path: canonical(path)?,
            selective: false,
            encrypted: false,
        });
        self.config.save(&self.home)?;
        self.pending.push(Event::FolderAdded { folder: id.clone() });
        self.publish_registry()?;
        self.commit_batch()?;
        Ok(id)
    }

    /// Mount a folder that another device created (known from its record).
    pub fn attach_folder(
        &mut self,
        name_or_id: &str,
        path: &Path,
        selective: bool,
    ) -> Result<FolderId> {
        let rec = self
            .keyring
            .find(name_or_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {name_or_id}; run pull first"))?;
        if self
            .config
            .folders
            .iter()
            .any(|m| m.folder_id == rec.folder_id)
        {
            bail!("folder {} is already attached", rec.name);
        }
        fs::create_dir_all(path)?;
        self.config.folders.push(FolderMount {
            folder_id: rec.folder_id.clone(),
            path: canonical(path)?,
            selective,
            encrypted: false,
        });
        self.config.save(&self.home)?;
        Ok(rec.folder_id)
    }

    /// Known folders: (record, mount path if attached here).
    /// Top-level names are unique in the vault: learn the other devices'
    /// folders first (best effort when offline), compare without case.
    fn ensure_unique_folder_name(&mut self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("a folder needs a name");
        }
        let _ = self.pull_registry();
        if let Some(f) = self
            .keyring
            .folders
            .values()
            .find(|f| !f.is_removed() && f.name.to_lowercase() == name.trim().to_lowercase())
        {
            bail!(
                "the vault already has a folder named {}: attach that one, or choose another name",
                f.name
            );
        }
        Ok(())
    }

    /// Two devices that created a folder with the same name while offline:
    /// every device keeps the older one's name and numbers the newer ones,
    /// so all of them end up with the same unique names.
    fn dedupe_folder_names(&mut self) -> bool {
        let live_folders: Vec<&FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|f| !f.is_removed())
            .collect();
        // A folder being converted into a Strongroom briefly exists twice
        // under one name: the new Strongroom record arrives before the
        // conversion record retires the old one. That pair is no conflict.
        let converting = |f: &FolderRecord| {
            f.is_strongroom()
                && live_folders.iter().any(|o| {
                    !o.is_strongroom()
                        && o.created_utc <= f.created_utc
                        && o.name.to_lowercase() == f.name.to_lowercase()
                })
        };
        let mut live: Vec<(i64, FolderId, String)> = live_folders
            .iter()
            .filter(|f| !converting(f))
            .map(|f| (f.created_utc, f.folder_id.clone(), f.name.clone()))
            .collect();
        live.sort();
        let mut taken: HashSet<String> = HashSet::new();
        let mut changed = false;
        for (_, id, name) in live {
            let mut candidate = name.clone();
            let mut n = 2;
            while taken.contains(&candidate.to_lowercase()) {
                candidate = format!("{name} ({n})");
                n += 1;
            }
            taken.insert(candidate.to_lowercase());
            if candidate != name {
                if let Some(f) = self.keyring.folders.get_mut(&id) {
                    f.name = candidate;
                    changed = true;
                }
            }
        }
        changed
    }

    /// Stop syncing a folder on this device. Its files stay where they are;
    /// the sync state goes, so attaching it again later starts clean instead
    /// of reading missing files as deletions.
    pub fn detach_folder(&mut self, name: &str) -> Result<()> {
        let (rec, _) = self.resolve_folder(name)?;
        self.detach_mount(&rec.folder_id)
    }

    fn detach_mount(&mut self, folder: &FolderId) -> Result<()> {
        let before = self.config.folders.len();
        self.config.folders.retain(|m| &m.folder_id != folder);
        if self.config.folders.len() != before {
            self.config.save(&self.home)?;
        }
        let _ = fs::remove_file(self.state_path(folder));
        Ok(())
    }

    fn forget_folder(&mut self, folder: &FolderId, removed_utc: i64) -> Result<()> {
        self.detach_mount(folder)?;
        if let Some(f) = self.keyring.folders.get_mut(folder) {
            f.removed_utc = removed_utc.max(1);
        }
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Remove a folder from the vault on every device: each one stops syncing
    /// it when it next reads the storage, and files already on devices stay.
    /// With `purge` its encrypted data (blocks, manifests, thumbnails) is
    /// deleted from this device's storages. Returns the objects deleted.
    pub fn remove_folder(&mut self, name: &str, purge: bool) -> Result<u64> {
        if self.vault.member {
            bail!("a member device cannot remove the owner's folders");
        }
        let rec = self
            .keyring
            .find(name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {name}"))?;
        let removal = vault::FolderRemoval {
            folder_id: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            removed_utc: util::now_utc(),
        };
        let blob = removal.seal(&self.vault.vault_id, &self.folder_record_key_now())?;
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&removal.storage_key(), &blob)?;
        }
        let mut deleted = 0u64;
        if purge {
            let view = self.view()?;
            let objects: Vec<String> = view
                .chunks
                .iter()
                .filter(|((f, _), _)| f == &rec.folder_id)
                .map(|(_, c)| chunk_storage_key(&c.object))
                .collect();
            for (_, backend) in self.open_storages(true)? {
                for key in &objects {
                    if backend.exists(key).unwrap_or(false) {
                        backend.delete(key)?;
                        deleted += 1;
                    }
                }
                for prefix in [
                    format!("manifests/{}/", rec.folder_id),
                    format!("thumbs/{}/", rec.folder_id),
                ] {
                    for key in backend.list(&prefix)? {
                        backend.delete(&key)?;
                        deleted += 1;
                    }
                }
            }
        }
        self.forget_folder(&rec.folder_id, removal.removed_utc)?;
        Ok(deleted)
    }

    pub fn folders(&self) -> Vec<(FolderRecord, Option<PathBuf>)> {
        self.keyring
            .folders
            .values()
            .filter(|r| !r.is_removed())
            .map(|r| {
                let mount = self
                    .config
                    .folders
                    .iter()
                    .find(|m| m.folder_id == r.folder_id)
                    .map(|m| m.path.clone());
                (r.clone(), mount)
            })
            .collect()
    }

    fn mount_is_selective(&self, folder: &FolderId) -> bool {
        self.config
            .folders
            .iter()
            .any(|m| &m.folder_id == folder && m.selective)
    }

    /// Switch selective sync on or off for an attached folder.
    pub fn set_selective(&mut self, name_or_id: &str, selective: bool) -> Result<()> {
        let (rec, _) = self.resolve_folder(name_or_id)?;
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.selective = selective;
        }
        self.config.save(&self.home)
    }

    /// Whether an attached folder is kept "encrypted on this device".
    pub fn folder_is_encrypted_here(&self, folder: &FolderId) -> bool {
        self.mount_is_encrypted(folder)
    }

    fn mount_is_encrypted(&self, folder: &FolderId) -> bool {
        self.config
            .folders
            .iter()
            .any(|m| &m.folder_id == folder && m.encrypted)
    }

    /// Mark an attached folder as "encrypted on this device" (phones): files are
    /// fetched when opened and their plaintext copies are removed when the vault
    /// locks. Switching it on also makes the folder selective.
    pub fn set_encrypted_here(&mut self, name_or_id: &str, encrypted: bool) -> Result<()> {
        let (rec, _) = self.resolve_folder(name_or_id)?;
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.encrypted = encrypted;
            if encrypted {
                m.selective = true;
            }
        }
        self.config.save(&self.home)
    }

    /// Replace every local copy in a folder with a placeholder where the
    /// storages hold the content. Returns (freed, kept): files not yet stored
    /// elsewhere are kept.
    pub fn free_folder(&mut self, folder: &str) -> Result<(u64, u64)> {
        let (rec, root) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let paths: Vec<String> = state
            .files
            .values()
            .filter(|f| !f.deleted && root.join(&f.path).exists())
            .map(|f| f.path.clone())
            .collect();
        let (mut freed, mut kept) = (0u64, 0u64);
        for p in paths {
            match self.free_file(&rec.name, &p) {
                Ok(()) => freed += 1,
                Err(_) => kept += 1,
            }
        }
        Ok((freed, kept))
    }

    /// Remove the plaintext copies of every "encrypted on this device" folder
    /// (called when the vault locks). Returns (folder, freed, kept) per folder.
    pub fn free_encrypted_folders(&mut self) -> Vec<(String, u64, u64)> {
        let names: Vec<String> = self
            .folders()
            .into_iter()
            .filter(|(r, m)| m.is_some() && self.mount_is_encrypted(&r.folder_id))
            .map(|(r, _)| r.name)
            .collect();
        names
            .into_iter()
            .map(|n| match self.free_folder(&n) {
                Ok((f, k)) => (n, f, k),
                Err(_) => (n, 0, 0),
            })
            .collect()
    }

    /// Same, without the keys (the vault is locked, e.g. at service start after
    /// the app was killed). Only files whose on-disk content is exactly what the
    /// ledger already holds (local index matches the manifest and the file is
    /// unchanged since) are replaced; anything else is kept. Returns the number
    /// of files freed.
    pub fn wipe_encrypted_folders_locked(home: &Path) -> Result<u64> {
        let config = Config::load(home)?;
        let mut freed = 0u64;
        for m in config.folders.iter().filter(|m| m.encrypted) {
            let state_path = home.join("state").join(format!("{}.json", m.folder_id));
            let mut state: FolderState = util::read_json_or_default(&state_path)?;
            let mut changed = false;
            let files: Vec<_> = state
                .files
                .values()
                .filter(|f| !f.deleted)
                .cloned()
                .collect();
            for f in files {
                let disk = m.path.join(&f.path);
                let Ok(md) = fs::metadata(&disk) else {
                    continue;
                };
                let known = state.local_index.get(&f.path).is_some_and(|ix| {
                    ix.content_hash == f.content_hash
                        && ix.size == md.len()
                        && md
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_nanos() as i64)
                            == Some(ix.mtime)
                });
                if !known {
                    continue;
                }
                fs::remove_file(&disk)?;
                Self::write_placeholder(&disk, &f)?;
                state.local_index.remove(&f.path);
                state.pinned.remove(&f.path);
                freed += 1;
                changed = true;
            }
            if changed {
                util::write_json(&state_path, &state)?;
            }
        }
        Ok(freed)
    }

    /// The record with a usable key: a Strongroom folder must be unlocked.
    fn with_key(&self, rec: &FolderRecord) -> Result<FolderRecord> {
        if !rec.is_strongroom() {
            return Ok(rec.clone());
        }
        match self.unlocked.get(&rec.folder_id) {
            Some((key, until)) if *until > util::now_utc() => {
                let mut r = rec.clone();
                r.key_hex = key.to_hex();
                Ok(r)
            }
            _ => bail!(
                "Strongroom {} is locked: unlock it with your security key first (varsto strongroom unlock {})",
                rec.name,
                rec.name
            ),
        }
    }

    pub fn is_unlocked(&self, folder: &FolderId) -> bool {
        self.unlocked
            .get(folder)
            .is_some_and(|(_, until)| *until > util::now_utc())
    }

    fn resolve_folder(&self, name_or_id: &str) -> Result<(FolderRecord, PathBuf)> {
        let rec = self
            .keyring
            .find(name_or_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {name_or_id}"))?;
        let rec = self.with_key(&rec)?;
        let mount = self
            .config
            .folders
            .iter()
            .find(|m| m.folder_id == rec.folder_id)
            .ok_or_else(|| anyhow!("folder {} is not attached on this device", rec.name))?;
        Ok((rec, mount.path.clone()))
    }

    fn state_path(&self, folder: &FolderId) -> PathBuf {
        self.home.join("state").join(format!("{folder}.json"))
    }

    fn load_state(&self, folder: &FolderId) -> Result<FolderState> {
        util::read_json_or_default(&self.state_path(folder))
    }

    fn save_state(&self, folder: &FolderId, state: &FolderState) -> Result<()> {
        util::write_json(&self.state_path(folder), state)
    }

    // ----- registry (device and folder records) -----------------------------

    fn publish_registry(&mut self) -> Result<()> {
        let rec = self.own_record();
        let reg_key = self.registry_key_now();
        let fr_key = self.folder_record_key_now();
        for (_, backend) in self.metadata_storages(true)? {
            if !self.vault.member {
                backend.put_if_absent(
                    &DeviceRecord::storage_key(&rec.device_id),
                    &rec.seal(&self.vault.vault_id, &reg_key)?,
                )?;
                for f in self
                    .keyring
                    .folders
                    .values()
                    .filter(|f| f.created_by == self.vault.device_id && !self.vault.member)
                {
                    backend.put_if_absent(
                        &FolderRecord::storage_key(&f.created_by, &f.folder_id),
                        &f.seal(&self.vault.vault_id, &fr_key)?,
                    )?;
                }
            }
            // Shared folders: every participant (owner devices and members)
            // publishes its record under the folder-derived registry key.
            for f in self.keyring.folders.values().filter(|f| f.shared) {
                let k = vault::share_registry_key(&f.folder_key()?, &f.folder_id);
                backend.put_if_absent(
                    &vault::share_record_key(&f.folder_id, &rec.device_id),
                    &rec.seal(&self.vault.vault_id, &k)?,
                )?;
            }
        }
        // The key-exchange key a revocation seals the next vault key to.
        self.kem_record_stale();
        self.ensure_kem_record()?;
        Ok(())
    }

    fn pull_registry(&mut self) -> Result<()> {
        let reg_keys = self.registry_keys();
        let fr_keys = self.folder_record_keys();
        let mut changed_devices = false;
        let mut changed_folders = false;
        for (_, backend) in self.metadata_storages(false)? {
            for key in backend.list(DeviceRecord::PREFIX)? {
                let Some(id) = key
                    .strip_prefix(DeviceRecord::PREFIX)
                    .and_then(|s| s.strip_suffix(".enc"))
                else {
                    continue;
                };
                let id = DeviceId::from_hex(id)?;
                if self.devices.devices.contains_key(&id) {
                    continue;
                }
                if self.vault.member {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    // Newest epoch first; which key opened it decides whether
                    // a record written after a key change is trusted.
                    let opened = reg_keys.iter().find_map(|(epoch, k)| {
                        DeviceRecord::open(&blob, &self.vault.vault_id, &id, k)
                            .ok()
                            .map(|rec| (*epoch, rec))
                    });
                    if let Some((epoch, rec)) = opened {
                        if epoch > 0 {
                            self.devices.record_epochs.insert(id.clone(), epoch);
                        }
                        self.devices.devices.insert(id, rec);
                        changed_devices = true;
                    }
                }
            }
            let replica_key = replica::replica_key(self.root_key());
            for key in backend.list(REPLICA_PREFIX)? {
                let Some(id) = key
                    .strip_prefix(REPLICA_PREFIX)
                    .and_then(|s| s.strip_suffix(".enc"))
                else {
                    continue;
                };
                let id = DeviceId::from_hex(id)?;
                if self.devices.replicas.contains_key(&id) {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Ok(rec) =
                        DeviceRecord::open(&blob, &self.vault.vault_id, &id, &replica_key)
                    {
                        self.devices.replicas.insert(id, rec);
                        changed_devices = true;
                    }
                }
            }
            for key in backend.list(FolderRecord::PREFIX)? {
                let Some(rest) = key
                    .strip_prefix(FolderRecord::PREFIX)
                    .and_then(|s| s.strip_suffix(".enc"))
                else {
                    continue;
                };
                let Some((dev, fid)) = rest.split_once('/') else {
                    continue;
                };
                let (dev, fid) = (DeviceId::from_hex(dev)?, FolderId::from_hex(fid)?);
                if self.keyring.folders.contains_key(&fid) {
                    continue;
                }
                if self.vault.member {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Some(rec) = fr_keys.iter().find_map(|k| {
                        FolderRecord::open(&blob, &self.vault.vault_id, &dev, &fid, k).ok()
                    }) {
                        self.keyring.folders.insert(fid, rec);
                        changed_folders = true;
                    }
                }
            }
        }
        // Policy records: newest per folder wins (F-032).
        if !self.vault.member {
            for (_, backend) in self.metadata_storages(false)? {
                for key in backend.list(vault::PolicyRecord::PREFIX)? {
                    let Some(fid) = key
                        .strip_prefix(vault::PolicyRecord::PREFIX)
                        .and_then(|r| r.split('/').next())
                    else {
                        continue;
                    };
                    let Ok(fid) = FolderId::from_hex(fid) else {
                        continue;
                    };
                    let Some(local) = self.keyring.folders.get(&fid) else {
                        continue;
                    };
                    // The object name ends with the update time: skip anything not newer.
                    let stamp: i64 = key
                        .rsplit('/')
                        .next()
                        .and_then(|n| n.strip_suffix(".enc"))
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                    if stamp <= local.policy_updated_utc {
                        continue;
                    }
                    if let Some(blob) = backend.get(&key)? {
                        if let Some(rec) = fr_keys.iter().find_map(|k| {
                            vault::PolicyRecord::open(&blob, &self.vault.vault_id, &fid, k).ok()
                        }) {
                            if let Some(f) = self.keyring.folders.get_mut(&fid) {
                                if rec.updated_utc > f.policy_updated_utc {
                                    f.policy = rec.policy;
                                    f.policy_updated_utc = rec.updated_utc;
                                    changed_folders = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Folders removed from the vault: stop syncing them here (files stay).
        if !self.vault.member {
            for (_, backend) in self.metadata_storages(false)? {
                for key in backend.list(vault::FolderRemoval::PREFIX)? {
                    let Some(fid) = key
                        .strip_prefix(vault::FolderRemoval::PREFIX)
                        .and_then(|r| r.split('/').next())
                        .and_then(|f| FolderId::from_hex(f).ok())
                    else {
                        continue;
                    };
                    if !self
                        .keyring
                        .folders
                        .get(&fid)
                        .is_some_and(|f| !f.is_removed())
                    {
                        continue;
                    }
                    if let Some(blob) = backend.get(&key)? {
                        if let Some(rec) = fr_keys.iter().find_map(|k| {
                            vault::FolderRemoval::open(&blob, &self.vault.vault_id, &fid, k).ok()
                        }) {
                            self.forget_folder(&fid, rec.removed_utc)?;
                            changed_folders = true;
                        }
                    }
                }
            }
        }
        // Member records of shared folders, readable by every holder of the folder key.
        for (_, backend) in self.metadata_storages(false)? {
            for f in self.keyring.folders.values().filter(|f| f.shared) {
                let k = vault::share_registry_key(&f.folder_key()?, &f.folder_id);
                let prefix = format!("{SHARE_PREFIX}{}/", f.folder_id);
                for key in backend.list(&prefix)? {
                    let Some(id) = key
                        .strip_prefix(&prefix)
                        .and_then(|s| s.strip_suffix(".enc"))
                    else {
                        continue;
                    };
                    let id = DeviceId::from_hex(id)?;
                    if id == self.vault.device_id
                        || self.devices.members.contains_key(&id)
                        || self.devices.devices.contains_key(&id)
                    {
                        continue;
                    }
                    if let Some(blob) = backend.get(&key)? {
                        if let Ok(rec) = DeviceRecord::open(&blob, &self.vault.vault_id, &id, &k) {
                            self.devices.members.insert(id, rec);
                            changed_devices = true;
                        }
                    }
                }
            }
        }
        // Strongroom conversions and key lists (S-012).
        self.pull_strongroom_records()?;
        changed_devices |= self.pull_device_details().unwrap_or(false);
        changed_folders |= self.dedupe_folder_names();
        if changed_devices {
            self.save_devices()?;
        }
        if changed_folders {
            self.keyring.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            )?;
        }
        Ok(())
    }

    // ----- ledger mailbox ----------------------------------------------------

    fn commit_batch(&mut self) -> Result<Option<u64>> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        if self.removal.is_some() {
            // A removed device signs nothing more.
            self.pending.clear();
            return self.ensure_active().map(|_| None);
        }
        let lamport = self.tick()?;
        let events = std::mem::take(&mut self.pending);
        if !self.vault.member {
            let (key_id, ledger_key) = self.ledger_key_now();
            let signed = self.ledger.append_own_with(
                &self.vault.device_id,
                events,
                lamport,
                &ledger_key,
                &key_id,
                &self.keys.signer,
            )?;
            self.push_own_batches()?;
            return Ok(Some(signed.seq));
        }
        // A member has no vault ledger key: seal one batch per shared folder
        // under that folder's share key, so the owner and other members can read it.
        let mut by_folder: BTreeMap<FolderId, Vec<Event>> = BTreeMap::new();
        let all: Vec<FolderId> = self.keyring.folders.keys().cloned().collect();
        for ev in events {
            let folder = match &ev {
                Event::ChunkStored { folder, .. }
                | Event::ChunkVerified { folder, .. }
                | Event::ChunkOnDevice { folder, .. }
                | Event::ManifestPublished { folder, .. }
                | Event::FolderAdded { folder } => Some(folder.clone()),
                Event::DeviceEnrolled { .. } | Event::StorageRetired { .. } => None,
            };
            match folder {
                Some(f) => by_folder.entry(f).or_default().push(ev),
                None => {
                    for f in &all {
                        by_folder.entry(f.clone()).or_default().push(ev.clone());
                    }
                }
            }
        }
        let mut last = None;
        for (fid, evs) in by_folder {
            let Some(rec) = self.keyring.folders.get(&fid) else {
                continue;
            };
            let key = vault::share_ledger_key(&rec.folder_key()?, &fid);
            let signed = self.ledger.append_own_with(
                &self.vault.device_id,
                evs,
                lamport,
                &key,
                &vault::share_key_id(&fid),
                &self.keys.signer,
            )?;
            last = Some(signed.seq);
        }
        self.push_own_batches()?;
        Ok(last)
    }

    /// Push every own batch that a storage does not have yet; detect forks.
    fn push_own_batches(&mut self) -> Result<()> {
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me);
        for (_, backend) in self.metadata_storages(true)? {
            let prefix = format!("ledger/{}/", me);
            let present: HashSet<String> = backend.list(&prefix)?.into_iter().collect();
            for seq in 1..=head.seq {
                let Some(batch) = self.ledger.get(&me, seq)? else {
                    continue;
                };
                let key = SignedBatch::storage_key(&me, seq);
                if present.contains(&key) {
                    if seq == head.seq {
                        if let Some(remote) = backend.get(&key)? {
                            let remote: SignedBatch = serde_json::from_slice(&remote)?;
                            if remote.hash != batch.hash {
                                bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
                            }
                        }
                    }
                    continue;
                }
                let written = backend.put_if_absent(&key, &serde_json::to_vec(&batch)?)?;
                if !written {
                    bail!(
                        "ledger fork: batch {} of this device appeared on {} concurrently",
                        seq,
                        backend.name()
                    );
                }
            }
        }
        Ok(())
    }

    /// Pull everyone's batches from every hot storage.
    fn pull_ledger(&mut self) -> Result<Vec<DeviceId>> {
        self.pull_registry()?;
        self.sync_membership()?;
        let dir = self.key_directory()?;
        let me = self.vault.device_id.clone();
        let mut forks = BTreeSet::new();
        for (_, backend) in self.metadata_storages(false)? {
            for key in backend.list("ledger/")? {
                let Some(rest) = key.strip_prefix("ledger/") else {
                    continue;
                };
                let Some((dev, file)) = rest.split_once('/') else {
                    continue;
                };
                let Some(seq) = file
                    .strip_suffix(".json")
                    .and_then(|s| s.parse::<u64>().ok())
                else {
                    continue;
                };
                let dev = DeviceId::from_hex(dev)?;
                if !self.batch_accepted(&dev, seq) {
                    // Signed by a revoked device after its cut-off.
                    continue;
                }
                if self.ledger.get(&dev, seq)?.is_some() && !self.ledger.is_forked(&dev) {
                    // Known batch: re-check only our own head against the mailbox.
                    continue;
                }
                let Some(blob) = backend.get(&key)? else {
                    continue;
                };
                let signed: SignedBatch = serde_json::from_slice(&blob)?;
                let Some(pk) = dir.get(&dev) else { continue };
                let Some(key) = self.key_for_id(&signed.key_id) else {
                    continue;
                };
                if dev == me && seq > self.ledger.head(&me).seq {
                    // Another copy of this device identity published ahead of us.
                    forks.insert(me.clone());
                    let _ = self.ledger.ingest(signed, pk, &key);
                    self.mark_forked(&me)?;
                    continue;
                }
                match self.ledger.ingest(signed, pk, &key)? {
                    Ingest::Fork => {
                        forks.insert(dev.clone());
                    }
                    Ingest::New | Ingest::Known => {}
                }
            }
        }
        let view = self.view()?;
        self.observe_clock(view.max_lamport)?;
        Ok(forks.into_iter().collect())
    }

    fn mark_forked(&mut self, _device: &DeviceId) -> Result<()> {
        // Another copy of this device identity has published batches we never
        // wrote (restored from an old backup, or cloned). Refuse to sign more.
        self.forked_self = true;
        Ok(())
    }

    pub fn view(&self) -> Result<LedgerView> {
        self.ledger.view_filtered(
            |id| self.key_for_id(id),
            |d, seq| self.batch_accepted(d, seq),
        )
    }

    /// Token for an untrusted replica device (F-045): it can store and verify
    /// this vault's encrypted objects but cannot open anything.
    pub fn replica_token(&self) -> Result<ReplicaToken> {
        if self.vault.member {
            bail!("a member device cannot issue replica tokens");
        }
        Ok(replica::token_for(self.root_key(), &self.vault.vault_id))
    }

    // ----- scanning ---------------------------------------------------------

    /// Walk the folder, detect changes and update the folder state. Chunks are
    /// hashed and their object names computed; uploading is a separate step.
    fn scan(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
    ) -> Result<(u64, u64)> {
        let fk = self.folder_keys(rec)?;
        let me = self.vault.device_id.clone();
        // Chunks this folder already references keep their object (and key
        // epoch): after a key change, unchanged content is not re-uploaded.
        let known: std::collections::HashMap<ChunkId, ChunkRef> = state
            .files
            .values()
            .chain(state.pending_remote.values())
            .flat_map(|f| f.chunks.iter())
            .map(|c| (c.chunk.clone(), c.clone()))
            .collect();
        let mut seen = BTreeSet::new();
        let mut placeholders: BTreeSet<String> = BTreeSet::new();
        let mut scanned = 0u64;
        let mut changed = 0u64;
        let mut new_index = BTreeMap::new();
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !(e.depth() > 0 && e.file_name().to_string_lossy().starts_with(".varsto"))
            });
        for entry in walker {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry.path().strip_prefix(root)?;
            let Some(path) = util::manifest_path(rel) else {
                continue;
            };
            if let Some(real) = path.strip_suffix(PLACEHOLDER_SUFFIX) {
                placeholders.insert(real.to_string());
                continue;
            }
            let md = entry.metadata()?;
            let size = md.len();
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            scanned += 1;
            seen.insert(path.clone());
            // Last-accessed: the newest of what Varsto recorded, the file's
            // access time (when the filesystem keeps one) and its mtime.
            let atime = md
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
                .max(mtime / 1_000_000_000);
            let recorded = state.accessed.entry(path.clone()).or_insert(0);
            if atime > *recorded {
                *recorded = atime;
            }
            let unchanged = matches!(state.local_index.get(&path), Some(e) if e.size == size && e.mtime == mtime)
                && matches!(state.files.get(&path), Some(f) if !f.deleted);
            if unchanged {
                new_index.insert(path.clone(), state.local_index[&path].clone());
                continue;
            }
            // Changed or new: chunk, hash, (upload).
            let file = fs::File::open(entry.path())?;
            let mut hasher = KeyedHasher::new(&fk.hash);
            let mut chunks = Vec::new();
            for chunk in Chunker::new(std::io::BufReader::new(file), self.chunker)? {
                let chunk = chunk?;
                hasher.update(&chunk);
                let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &chunk));
                let (object, epoch) = match known.get(&chunk_id) {
                    Some(c) if c.size == chunk.len() as u64 => (c.object.clone(), c.epoch),
                    _ => {
                        let ct = crypto::encrypt_with_nonce(
                            &fk.chunk_key(fk.epoch, &chunk_id)?,
                            &fk.chunk_nonce(fk.epoch, &chunk_id)?,
                            &fk.chunk_aad(&self.vault.vault_id, &chunk_id, chunk.len() as u64),
                            &crate::pack::pack(&chunk),
                        )?;
                        (ObjectName::from_bytes(&crypto::hash(&ct)), fk.epoch)
                    }
                };
                self.pending.push(Event::ChunkOnDevice {
                    folder: rec.folder_id.clone(),
                    chunk: chunk_id.clone(),
                    object: object.clone(),
                    size: chunk.len() as u64,
                });
                chunks.push(ChunkRef {
                    chunk: chunk_id,
                    object,
                    size: chunk.len() as u64,
                    epoch,
                });
            }
            let content_hash = hex::encode(hasher.finalize());
            let previous = state.files.get(&path);
            if let Some(prev) = previous {
                if !prev.deleted && prev.content_hash == content_hash {
                    // Touched but identical: keep the version, refresh the index.
                    new_index.insert(
                        path.clone(),
                        LocalIndexEntry {
                            size,
                            mtime,
                            content_hash,
                        },
                    );
                    continue;
                }
            }
            let clock = self.tick()?;
            let mut version = previous.map(|p| p.version.clone()).unwrap_or_default();
            version.insert(me.clone(), clock);
            state.files.insert(
                path.clone(),
                FileState {
                    path: path.clone(),
                    version,
                    deleted: false,
                    size,
                    mtime,
                    content_hash: content_hash.clone(),
                    chunks,
                    modified_by: me.clone(),
                    modified_clock: clock,
                },
            );
            new_index.insert(
                path,
                LocalIndexEntry {
                    size,
                    mtime,
                    content_hash,
                },
            );
            changed += 1;
        }
        // Deletions.
        let gone: Vec<String> = state
            .files
            .iter()
            .filter(|(p, f)| !f.deleted && !seen.contains(*p) && !placeholders.contains(*p))
            .map(|(p, _)| p.clone())
            .collect();
        for path in gone {
            let clock = self.tick()?;
            let prev = state.files.get(&path).cloned().unwrap();
            let mut version = prev.version.clone();
            version.insert(me.clone(), clock);
            state.files.insert(
                path.clone(),
                FileState {
                    path: path.clone(),
                    version,
                    deleted: true,
                    size: 0,
                    mtime: 0,
                    content_hash: String::new(),
                    chunks: vec![],
                    modified_by: me.clone(),
                    modified_clock: clock,
                },
            );
            changed += 1;
        }
        state.local_index = new_index;
        Ok((scanned, changed))
    }

    // ----- push ---------------------------------------------------------------

    pub fn push(&mut self, folder: &str) -> Result<PushReport> {
        self.ensure_active()?;
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let (rec, root) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut report = PushReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        let (scanned, changed) = self.scan(&rec, &root, &mut state)?;
        report.files_scanned = scanned;
        report.files_changed = changed;
        self.upload_missing(&rec, &root, &state, &mut report)?;
        report.thumbnails = self.make_thumbnails(&rec, &root, &mut state)?;
        report.manifest_seq = self.publish_manifest(&rec, &mut state)?;
        self.ensure_manifest_everywhere(&rec, &state)?;
        report.batch_seq = self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
        Ok(report)
    }

    /// Upload every chunk of every current file that the ledger does not
    /// already show on every storage. Files whose chunks are all known are
    /// skipped without reading them; the others are re-chunked (chunking and
    /// encryption are deterministic, so the objects are identical).
    fn upload_missing(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &FolderState,
        report: &mut PushReport,
    ) -> Result<()> {
        let storages = self.open_storages(true)?;
        if storages.is_empty() {
            return Ok(());
        }
        let view = self.view()?;
        let fk = self.folder_keys(rec)?;
        let folder_id = rec.folder_id.clone();
        let me = self.vault.device_id.clone();
        let missing_on = |cref: &ChunkRef| -> Vec<String> {
            // The ledger record must be for this very object: after a key
            // change the same chunk id can stand for two objects.
            let known = view
                .locate(&folder_id, &cref.chunk)
                .filter(|r| r.object == cref.object);
            let held_elsewhere = known
                .map(|r| r.devices.iter().any(|d| d != &me))
                .unwrap_or(false);
            storages
                .iter()
                .filter(|(spec, _)| {
                    !known
                        .map(|r| r.storages.contains_key(spec.name()))
                        .unwrap_or(false)
                })
                // A carrier only takes what no other device has yet (F-048).
                .filter(|(spec, _)| !(spec.is_carrier() && held_elsewhere))
                .map(|(spec, _)| spec.name().to_string())
                .collect()
        };
        for file in state.files.values().filter(|f| !f.deleted) {
            if file.chunks.iter().all(|c| missing_on(c).is_empty()) {
                continue;
            }
            let disk = root.join(&file.path);
            let Ok(handle) = fs::File::open(&disk) else {
                continue;
            };
            for (index, chunk) in
                Chunker::new(std::io::BufReader::new(handle), self.chunker)?.enumerate()
            {
                let chunk = chunk?;
                let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &chunk));
                let Some(expected) = file.chunks.get(index) else {
                    break;
                };
                if expected.chunk != chunk_id {
                    // The file changed under us; the next scan will pick it up.
                    break;
                }
                let targets: Vec<String> = missing_on(expected)
                    .into_iter()
                    .filter(|t| !report.storages_unavailable.iter().any(|u| u == t))
                    .collect();
                if targets.is_empty() {
                    continue;
                }
                let ct = crypto::encrypt_with_nonce(
                    &fk.chunk_key(expected.epoch, &chunk_id)?,
                    &fk.chunk_nonce(expected.epoch, &chunk_id)?,
                    &fk.chunk_aad(&self.vault.vault_id, &chunk_id, chunk.len() as u64),
                    &crate::pack::pack(&chunk),
                )?;
                let object = ObjectName::from_bytes(&crypto::hash(&ct));
                let key = chunk_storage_key(&object);
                for (spec, backend) in storages
                    .iter()
                    .filter(|(spec, _)| targets.contains(&spec.name().to_string()))
                {
                    match backend.put_if_absent(&key, &ct) {
                        Ok(true) => {
                            report.chunks_uploaded += 1;
                            report.bytes_uploaded += ct.len() as u64;
                        }
                        Ok(false) => {}
                        // A pool with no disk attached (or no room) is left out
                        // for the rest of this push and tried again next time.
                        Err(e)
                            if matches!(
                                pool::pool_error(&e),
                                Some(PoolError::NoDiskAttached { .. } | PoolError::NoRoom { .. })
                            ) =>
                        {
                            report.storages_unavailable.push(spec.name().to_string());
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    self.pending.push(Event::ChunkStored {
                        folder: folder_id.clone(),
                        chunk: chunk_id.clone(),
                        object: object.clone(),
                        storage: spec.name().to_string(),
                        size: ct.len() as u64,
                    });
                }
            }
        }
        Ok(())
    }

    /// Encrypted thumbnails for image and video files that have none yet (F-046).
    fn make_thumbnails(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
    ) -> Result<u64> {
        let candidates: Vec<(String, String)> = state
            .files
            .values()
            .filter(|f| {
                !f.deleted
                    && (thumbs::is_image(&f.path) || thumbs::is_video(&f.path))
                    && !state.thumbs_done.contains(&f.content_hash)
            })
            .map(|f| (f.path.clone(), f.content_hash.clone()))
            .collect();
        if candidates.is_empty() {
            return Ok(0);
        }
        let storages: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let meta = self.folder_keys(rec)?.meta;
        let mut made = 0u64;
        for (path, hash) in candidates {
            let key = thumbs::storage_key(&rec.folder_id, &hash);
            if storages
                .iter()
                .any(|(_, b)| b.exists(&key).unwrap_or(false))
            {
                state.thumbs_done.insert(hash);
                continue;
            }
            let disk = root.join(&path);
            if !disk.exists() {
                continue;
            }
            let Some(bytes) = thumbs::make(&disk, &path) else {
                state.thumbs_done.insert(hash); // cannot make one; do not retry every time
                continue;
            };
            let blob = thumbs::seal(&bytes, &self.vault.vault_id, &rec.folder_id, &hash, &meta)?;
            for (_, backend) in &storages {
                backend.put_if_absent(&key, &blob)?;
            }
            state.thumbs_done.insert(hash);
            made += 1;
        }
        Ok(made)
    }

    /// Decrypted thumbnail of a file, fetched from the first storage that has it.
    pub fn thumbnail(&self, folder: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let Some(file) = state.files.get(path) else {
            return Ok(None);
        };
        if file.deleted || file.content_hash.is_empty() {
            return Ok(None);
        }
        let key = thumbs::storage_key(&rec.folder_id, &file.content_hash);
        let metas = self.folder_keys(&rec)?.meta_keys();
        for (_, backend) in self.metadata_storages(false)? {
            if let Some(blob) = backend.get(&key)? {
                let mut last = None;
                for meta in &metas {
                    match thumbs::open(
                        &blob,
                        &self.vault.vault_id,
                        &rec.folder_id,
                        &file.content_hash,
                        meta,
                    ) {
                        Ok(t) => return Ok(Some(t)),
                        Err(e) => last = Some(e),
                    }
                }
                if let Some(e) = last {
                    return Err(e);
                }
            }
        }
        Ok(None)
    }

    /// Storages added after a manifest was published get the latest manifest.
    fn ensure_manifest_everywhere(
        &mut self,
        rec: &FolderRecord,
        state: &FolderState,
    ) -> Result<()> {
        if state.published_seq == 0 {
            return Ok(());
        }
        let key = Manifest::storage_key(&rec.folder_id, &self.vault.device_id, state.published_seq);
        let storages = self.metadata_storages(true)?;
        let mut blob: Option<Vec<u8>> = None;
        for (_, backend) in &storages {
            if backend.exists(&key)? {
                if blob.is_none() {
                    blob = backend.get(&key)?;
                }
                continue;
            }
            if blob.is_none() {
                let m = Manifest {
                    format_version: crate::FORMAT_VERSION,
                    folder: rec.folder_id.clone(),
                    device: self.vault.device_id.clone(),
                    seq: state.published_seq,
                    lamport: self.clock.lamport,
                    created_utc: util::now_utc(),
                    files: state.files.clone(),
                };
                blob = Some(m.seal(&self.vault.vault_id, &self.folder_keys(rec)?.meta)?);
            }
            if let Some(b) = &blob {
                backend.put_if_absent(&key, b)?;
            }
        }
        Ok(())
    }

    fn publish_manifest(
        &mut self,
        rec: &FolderRecord,
        state: &mut FolderState,
    ) -> Result<Option<u64>> {
        let hash = Manifest::files_hash(&state.files);
        if hash == state.published_hash {
            return Ok(None);
        }
        let seq = state.published_seq + 1;
        let lamport = self.tick()?;
        let m = Manifest {
            format_version: crate::FORMAT_VERSION,
            folder: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            seq,
            lamport,
            created_utc: util::now_utc(),
            files: state.files.clone(),
        };
        let blob = m.seal(&self.vault.vault_id, &self.folder_keys(rec)?.meta)?;
        let key = Manifest::storage_key(&rec.folder_id, &self.vault.device_id, seq);
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&key, &blob)?;
        }
        self.pending.push(Event::ManifestPublished {
            folder: rec.folder_id.clone(),
            seq,
            manifest_hash: hex::encode(crypto::hash(&blob)),
            files: state.files.values().filter(|f| !f.deleted).count() as u64,
        });
        state.published_seq = seq;
        state.published_hash = hash;
        Ok(Some(seq))
    }

    // ----- pull ---------------------------------------------------------------

    pub fn pull(&mut self, folder: &str) -> Result<PullReport> {
        self.ensure_active()?;
        let (rec, root) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        self.scan(&rec, &root, &mut state)?;
        let forks = self.pull_ledger()?;
        report.forked_devices = forks.iter().map(|d| d.to_string()).collect();
        if !self.keyring.folders.contains_key(&rec.folder_id) {
            // Converted into a Strongroom by another device just now.
            return Ok(report);
        }
        let fk = self.folder_keys(&rec)?;
        let me = self.vault.device_id.clone();
        let storages = self.open_storages(false)?;

        // Files whose copies were unreachable last time: a storage or a peer
        // may have them now.
        let pending: Vec<FileState> = state.pending_remote.values().cloned().collect();
        for remote in pending {
            self.apply_remote(&rec, &fk, &root, &mut state, remote, &storages, &mut report)?;
        }

        // Newest manifest per other device, across storages.
        let mut newest: BTreeMap<DeviceId, (u64, usize)> = BTreeMap::new();
        for (idx, (_, backend)) in storages
            .iter()
            .enumerate()
            .filter(|(_, (s, _))| !s.is_data_only())
        {
            let prefix = format!("manifests/{}/", rec.folder_id);
            for key in backend.list(&prefix)? {
                let Some(rest) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let Some((dev, file)) = rest.split_once('/') else {
                    continue;
                };
                let Some(seq) = file
                    .strip_suffix(".enc")
                    .and_then(|s| s.parse::<u64>().ok())
                else {
                    continue;
                };
                let dev = DeviceId::from_hex(dev)?;
                if dev == me {
                    continue;
                }
                let e = newest.entry(dev).or_insert((0, idx));
                if seq > e.0 {
                    *e = (seq, idx);
                }
            }
        }

        // A revoked device's manifests count only up to the last one its
        // accepted ledger batches announced.
        let capped = if self.devices.revoked.is_empty() {
            BTreeMap::new()
        } else {
            self.view()?.manifests
        };
        let metas = fk.meta_keys();
        for (dev, (seq, idx)) in newest {
            let seq = if self.is_revoked(&dev) {
                seq.min(
                    capped
                        .get(&(rec.folder_id.clone(), dev.clone()))
                        .copied()
                        .unwrap_or(0),
                )
            } else {
                seq
            };
            if seq <= state.last_seen.get(&dev).copied().unwrap_or(0) {
                continue;
            }
            let key = Manifest::storage_key(&rec.folder_id, &dev, seq);
            let Some(blob) = storages[idx].1.get(&key)? else {
                continue;
            };
            let m = metas
                .iter()
                .find_map(|meta| {
                    Manifest::open(&blob, &self.vault.vault_id, &rec.folder_id, &dev, seq, meta)
                        .ok()
                })
                .ok_or_else(|| {
                    anyhow!(
                        "manifest {seq} of device {} does not open with any key this device holds (a newer vault key has not arrived yet?)",
                        dev.short()
                    )
                })?;
            self.observe_clock(m.lamport)?;
            report.manifests_applied += 1;
            for (path, remote) in &m.files {
                match manifest::merge(state.files.get(path), remote) {
                    Merge::KeepLocal => {}
                    Merge::TakeRemote => {
                        self.apply_remote(
                            &rec,
                            &fk,
                            &root,
                            &mut state,
                            remote.clone(),
                            &storages,
                            &mut report,
                        )?;
                    }
                    Merge::Conflict { winner, loser } => {
                        report.conflicts += 1;
                        if let Some(loser) = loser {
                            let cpath = manifest::conflict_path(path, &loser);
                            let local_is_loser = state
                                .files
                                .get(path)
                                .map(|l| l.content_hash == loser.content_hash)
                                .unwrap_or(false);
                            let disk = root.join(&cpath);
                            if let Some(parent) = disk.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            if local_is_loser && root.join(path).exists() {
                                fs::rename(root.join(path), &disk)?;
                            } else {
                                self.download_to(&rec, &fk, &disk, &loser, &storages, &mut report)?;
                            }
                            // The conflict copy is a new local file: it gets its own version.
                            let clock = self.tick()?;
                            let mut cstate = loser.clone();
                            cstate.path = cpath.clone();
                            cstate.version = BTreeMap::from([(me.clone(), clock)]);
                            cstate.modified_by = me.clone();
                            cstate.modified_clock = clock;
                            let md = fs::metadata(&disk)?;
                            let mtime = md
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_nanos() as i64)
                                .unwrap_or(0);
                            state.local_index.insert(
                                cpath.clone(),
                                LocalIndexEntry {
                                    size: md.len(),
                                    mtime,
                                    content_hash: cstate.content_hash.clone(),
                                },
                            );
                            state.files.insert(cpath, cstate);
                        }
                        let local_has_winner = state
                            .files
                            .get(path)
                            .map(|l| {
                                l.content_hash == winner.content_hash && l.deleted == winner.deleted
                            })
                            .unwrap_or(false)
                            && (winner.deleted || root.join(path).exists());
                        if local_has_winner {
                            state.files.insert(path.clone(), winner);
                        } else {
                            self.apply_remote(
                                &rec,
                                &fk,
                                &root,
                                &mut state,
                                winner,
                                &storages,
                                &mut report,
                            )?;
                        }
                    }
                }
            }
            state.last_seen.insert(dev, seq);
        }
        self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
        self.prune_carriers(&rec)?;
        Ok(report)
    }

    /// Remove from carrier storages the objects that another device already
    /// holds as well as this one: the media has done its job for them (F-048).
    fn prune_carriers(&mut self, rec: &FolderRecord) -> Result<()> {
        let carriers: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .open_storages(true)?
            .into_iter()
            .filter(|(s, _)| s.is_carrier())
            .collect();
        if carriers.is_empty() {
            return Ok(());
        }
        let view = self.view()?;
        let me = self.vault.device_id.clone();
        for ((folder, _chunk), r) in view.chunks.iter() {
            if folder != &rec.folder_id {
                continue;
            }
            let held_by_other = r.devices.iter().any(|d| d != &me);
            if !(held_by_other && r.devices.contains(&me)) {
                continue;
            }
            for (spec, backend) in &carriers {
                if r.storages.contains_key(spec.name()) {
                    backend.delete(&chunk_storage_key(&r.object))?;
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_remote(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        root: &Path,
        state: &mut FolderState,
        remote: FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let disk = root.join(&remote.path);
        if remote.deleted {
            let _ = fs::remove_file(placeholder_path(&disk));
            if disk.exists() {
                let trash = self
                    .home
                    .join("trash")
                    .join(rec.folder_id.as_str())
                    .join(format!("{}.{}", remote.path, util::now_utc()));
                if let Some(p) = trash.parent() {
                    fs::create_dir_all(p)?;
                }
                fs::rename(&disk, &trash).or_else(|_| {
                    fs::copy(&disk, &trash)
                        .map(|_| ())
                        .and_then(|_| fs::remove_file(&disk))
                })?;
                report.files_deleted += 1;
            }
            state.local_index.remove(&remote.path);
            state.pending_remote.remove(&remote.path);
            state.files.insert(remote.path.clone(), remote);
            return Ok(());
        }
        let selective = self.mount_is_selective(&rec.folder_id);
        if selective && !state.pinned.contains(&remote.path) && !disk.exists() {
            // Selective sync: show the file as a placeholder; fetch on demand.
            Self::write_placeholder(&disk, &remote)?;
            state.local_index.remove(&remote.path);
            state.pending_remote.remove(&remote.path);
            state.files.insert(remote.path.clone(), remote);
            report.files_updated += 1;
            return Ok(());
        }
        match self.download_to(rec, fk, &disk, &remote, storages, report) {
            Ok(()) => {
                let md = fs::metadata(&disk)?;
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                state.local_index.insert(
                    remote.path.clone(),
                    LocalIndexEntry {
                        size: md.len(),
                        mtime,
                        content_hash: remote.content_hash.clone(),
                    },
                );
                state.pending_remote.remove(&remote.path);
                state.files.insert(remote.path.clone(), remote);
                report.files_updated += 1;
            }
            Err(e) => {
                if let Some(PoolError::NeedsDisk { label, place, .. }) = pool::pool_error(&e) {
                    let d = format!("{label} ({place})");
                    if !report.disks_needed.contains(&d) {
                        report.disks_needed.push(d);
                    }
                }
                report
                    .files_unavailable
                    .push(format!("{}: {e}", remote.path));
                state.pending_remote.insert(remote.path.clone(), remote);
            }
        }
        Ok(())
    }

    /// Download, verify and decrypt every chunk of `file` into `disk`.
    #[allow(clippy::too_many_arguments)]
    fn download_to(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        disk: &Path,
        file: &FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = disk.with_file_name(format!(".varsto-tmp-{}", std::process::id()));
        {
            let mut out = fs::File::create(&tmp)?;
            for cref in &file.chunks {
                let key = chunk_storage_key(&cref.object);
                let mut got = None;
                if let Some(peers) = &self.peers {
                    if let Some((dev, ct)) = peers.get(&cref.object) {
                        report.chunks_from_peers += 1;
                        got = Some((format!("peer:{}", dev.short()), ct));
                    }
                }
                let mut needs_disk: Option<PoolError> = None;
                for (spec, backend) in storages {
                    if got.is_some() {
                        break;
                    }
                    match backend.get(&key) {
                        Ok(Some(ct)) => {
                            if ObjectName::from_bytes(&crypto::hash(&ct)) != cref.object {
                                continue; // corrupt copy; try the next storage
                            }
                            got = Some((spec.name().to_string(), ct));
                            break;
                        }
                        Ok(None) => {}
                        // The copy is on a pool disk that is away: remember
                        // which one, in case no other storage has the chunk.
                        Err(e) => match pool::pool_error(&e) {
                            Some(nd @ PoolError::NeedsDisk { .. }) => {
                                needs_disk.get_or_insert(nd.clone());
                            }
                            _ => return Err(e),
                        },
                    }
                }
                let Some((storage_name, ct)) = got else {
                    let _ = fs::remove_file(&tmp);
                    if let Some(nd) = needs_disk {
                        return Err(anyhow::Error::new(nd));
                    }
                    bail!(
                        "chunk {} is not available on any readable storage",
                        cref.chunk.short()
                    );
                };
                let plain = crate::pack::unpack(
                    &crypto::decrypt(
                        &fk.chunk_key(cref.epoch, &cref.chunk)?,
                        &fk.chunk_aad(&self.vault.vault_id, &cref.chunk, cref.size),
                        &ct,
                    )?,
                    cref.size,
                )?;
                if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain)) != cref.chunk {
                    let _ = fs::remove_file(&tmp);
                    bail!("chunk {} failed its content check", cref.chunk.short());
                }
                out.write_all(&plain)?;
                report.chunks_downloaded += 1;
                report.bytes_downloaded += plain.len() as u64;
                self.pending.push(Event::ChunkVerified {
                    folder: rec.folder_id.clone(),
                    chunk: cref.chunk.clone(),
                    object: cref.object.clone(),
                    storage: storage_name,
                });
                self.pending.push(Event::ChunkOnDevice {
                    folder: rec.folder_id.clone(),
                    chunk: cref.chunk.clone(),
                    object: cref.object.clone(),
                    size: cref.size,
                });
            }
            out.sync_all()?;
        }
        fs::rename(&tmp, disk)?;
        Ok(())
    }

    fn write_placeholder(disk: &Path, file: &FileState) -> Result<()> {
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
        }
        let info = serde_json::json!({ "varsto": "placeholder", "size": file.size, "mtime_ns": file.mtime, "hint": "run `varsto folder fetch` or use the app to download this file" });
        util::write_atomic(&placeholder_path(disk), &serde_json::to_vec(&info)?)
    }

    /// Download a placeholder file of a selective folder and keep it here.
    pub fn fetch_file(&mut self, folder: &str, path: &str) -> Result<PullReport> {
        let (rec, root) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("unknown file {path}"))?;
        if file.deleted {
            bail!("{path} is deleted");
        }
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(false)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        let disk = root.join(path);
        self.download_to(&rec, &fk, &disk, &file, &storages, &mut report)?;
        state.accessed.insert(path.to_string(), now_secs());
        let _ = fs::remove_file(placeholder_path(&disk));
        let md = fs::metadata(&disk)?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        state.local_index.insert(
            path.to_string(),
            LocalIndexEntry {
                size: md.len(),
                mtime,
                content_hash: file.content_hash.clone(),
            },
        );
        state.pinned.insert(path.to_string());
        report.files_updated += 1;
        self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
        Ok(report)
    }

    /// The folder (by id) and relative path of a file on this device, from its
    /// absolute path; a placeholder's path names the file it stands for.
    pub fn locate_path(&self, abs: &Path) -> Result<(String, String)> {
        let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let text = abs.to_string_lossy();
        let real = text
            .strip_suffix(PLACEHOLDER_SUFFIX)
            .map(PathBuf::from)
            .unwrap_or_else(|| abs.to_path_buf());
        // The file itself may not exist (a placeholder), its directory does.
        let name = real
            .file_name()
            .ok_or_else(|| anyhow!("{} is not a file", abs.display()))?;
        let full = canon(real.parent().unwrap_or(Path::new("/"))).join(name);
        for (rec, mount) in self.folders() {
            let Some(root) = mount else { continue };
            if let Ok(rel) = full.strip_prefix(canon(&root)) {
                let rel: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect();
                if rel.is_empty() {
                    bail!("{} is the folder itself", abs.display());
                }
                return Ok((rec.folder_id.to_string(), rel.join("/")));
            }
        }
        bail!("{} is not in a Varsto folder on this device", abs.display())
    }

    /// Replace a local file of a selective folder with a placeholder. Refused
    /// unless every chunk is on at least one storage that is not a carrier,
    /// and unless the file on disk is the version that was synced.
    pub fn free_file(&mut self, folder: &str, path: &str) -> Result<()> {
        let (rec, root) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("unknown file {path}"))?;
        let view = self.view()?;
        let durable: HashSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        for c in &file.chunks {
            let ok = view
                .locate(&rec.folder_id, &c.chunk)
                .map(|r| {
                    r.storages
                        .keys()
                        .any(|k| durable.contains(k) || k.starts_with("replica:"))
                })
                .unwrap_or(false);
            if !ok {
                bail!("{path} is not fully stored elsewhere yet; sync first");
            }
        }
        let disk = root.join(path);
        if disk.exists() {
            // Only the synced version may go: a file changed since the last
            // sync (or never indexed here) holds the only copy of its changes.
            let md = fs::metadata(&disk)?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            let synced = state.local_index.get(path).is_some_and(|e| {
                e.size == md.len() && e.mtime == mtime && e.content_hash == file.content_hash
            });
            if !synced {
                bail!("{path} has changes on this device that are not synced yet; sync first");
            }
            fs::remove_file(&disk)?;
        }
        Self::write_placeholder(&disk, &file)?;
        state.local_index.remove(path);
        state.pinned.remove(path);
        self.save_state(&rec.folder_id, &state)?;
        if !self.mount_is_selective(&rec.folder_id) {
            self.set_selective(folder, true)?;
        }
        Ok(())
    }

    /// Files of a folder with their local state (for the interface and CLI).
    /// Set (or clear) the durability policy of a folder and publish it so
    /// every device evaluates the same rule.
    pub fn set_policy(&mut self, folder: &str, policy: Option<Policy>) -> Result<()> {
        if self.vault.member {
            bail!("a member device cannot set policies on the owner's folders");
        }
        let (rec, _) = self.resolve_folder(folder)?;
        let now = util::now_utc();
        let f = self
            .keyring
            .folders
            .get_mut(&rec.folder_id)
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        f.policy = policy.clone();
        f.policy_updated_utc = now;
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        let prec = vault::PolicyRecord {
            folder_id: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            updated_utc: now,
            policy,
        };
        let fr_key = self.folder_record_key_now();
        let blob = prec.seal(&self.vault.vault_id, &fr_key)?;
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&prec.storage_key(), &blob)?;
        }
        Ok(())
    }

    /// Evaluate every folder that has a policy, from the ledger alone.
    pub fn policy_check(&self) -> Result<Vec<PolicyReport>> {
        self.policy_check_at(util::now_utc())
    }

    pub fn policy_check_at(&self, now_utc: i64) -> Result<Vec<PolicyReport>> {
        let view = self.view()?;
        let mut places: BTreeMap<String, (String, bool)> = BTreeMap::new(); // name -> (place, unreadable now)
        let mut carriers: BTreeSet<String> = BTreeSet::new();
        let mut unknown: Vec<String> = Vec::new();
        for spec in &self.config.storages {
            if spec.is_carrier() {
                carriers.insert(spec.name().to_string());
                continue;
            }
            let unreadable = spec.is_cold();
            if self.open_spec(spec).is_err() {
                unknown.push(spec.name().to_string());
            }
            places.insert(spec.name().to_string(), (spec.place(), unreadable));
        }
        let mut unreadable_places: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, (place, unreadable)) in &places {
            if *unreadable {
                unreadable_places
                    .entry(place.clone())
                    .or_default()
                    .push(name.clone());
            }
        }
        // Disk pools: a copy on a disk that is away counts as a copy verified
        // when that disk was last checked, on media that cannot be read now.
        let mut pools: BTreeMap<String, PoolStorage> = BTreeMap::new();
        for spec in &self.config.storages {
            if let StorageSpec::Pool { .. } = spec {
                if let Ok(p) = self.open_pool(spec) {
                    pools.insert(spec.name().to_string(), p);
                }
            }
        }
        let mut reports = Vec::new();
        for (rec, _) in self.folders() {
            let Some(policy) = rec.policy.clone() else {
                continue;
            };
            let state = self.load_state(&rec.folder_id)?;
            let mut seen = BTreeSet::new();
            let mut facts = Vec::new();
            for file in state.files.values().filter(|f| !f.deleted) {
                for cr in &file.chunks {
                    if !seen.insert(cr.chunk.clone()) {
                        continue;
                    }
                    let mut copies = Vec::new();
                    if let Some(record) = view.locate(&rec.folder_id, &cr.chunk) {
                        for (name, loc) in &record.storages {
                            if loc.claimed_by.is_empty() || carriers.contains(name) {
                                continue;
                            }
                            let place = if name.starts_with("replica:") {
                                "replica".to_string()
                            } else {
                                places
                                    .get(name)
                                    .map(|(p, _)| p.clone())
                                    .unwrap_or_else(|| "other".to_string())
                            };
                            let mut copy_name = name.clone();
                            let mut verified = loc.independently_verified(name);
                            let mut verified_utc = loc.verified_utc;
                            if let Some(pool) = pools.get(name) {
                                match pool.locate(&chunk_storage_key(&record.object)) {
                                    Some(l) if l.attached => {
                                        verified |= l.last_verified_utc > 0;
                                        verified_utc = verified_utc.max(l.last_verified_utc);
                                    }
                                    Some(l) => {
                                        copy_name = format!("{name}:{}", l.label);
                                        verified = l.last_verified_utc > 0;
                                        verified_utc = l.last_verified_utc;
                                    }
                                    None => {
                                        copy_name = format!("{name}:unknown disk");
                                        verified = false;
                                        verified_utc = 0;
                                    }
                                }
                                if copy_name != *name {
                                    let list = unreadable_places.entry(place.clone()).or_default();
                                    if !list.contains(&copy_name) {
                                        list.push(copy_name.clone());
                                    }
                                }
                            }
                            copies.push((copy_name, place, verified, verified_utc));
                        }
                    }
                    facts.push(crate::policy::ChunkFacts { copies });
                }
            }
            reports.push(crate::policy::evaluate(
                &rec.name,
                &policy,
                &facts,
                &unreadable_places,
                &unknown,
                now_utc,
            ));
        }
        Ok(reports)
    }

    /// The vault key (hex) for the recovery kit. Only an unlocked owner
    /// device can produce it; members hold no vault key.
    pub fn export_vault_key(&self) -> Result<String> {
        if self.vault.member {
            bail!("a member device holds folder keys only, not the vault key");
        }
        // The current epoch's key: it opens the older epochs through the
        // epoch records, while a key from before a revocation opens nothing new.
        Ok(self.current_vault_key().to_hex())
    }

    // ----- strongroom --------------------------------------------------------

    /// Create a folder whose key only exists while a security key is touched
    /// (two touches: credential, then wrap). The mount is selective, so files
    /// appear as placeholders and are fetched only while unlocked.
    pub fn create_strongroom(
        &mut self,
        name: &str,
        path: &Path,
        method: crate::strongroom::Method,
        key: &dyn crate::strongroom::SecurityKey,
        unlock_minutes: u64,
    ) -> Result<FolderId> {
        if self.vault.member {
            bail!("a member device cannot create folders in the owner's vault");
        }
        self.ensure_unique_folder_name(name)?;
        fs::create_dir_all(path)?;
        let folder_id = FolderId::random();
        let folder_key = SecretKey::random();
        let info = crate::strongroom::enroll(key, method, &folder_id, &folder_key)?;
        let rec = FolderRecord {
            folder_id: folder_id.clone(),
            name: name.to_string(),
            key_hex: String::new(),
            created_by: self.vault.device_id.clone(),
            created_utc: util::now_utc(),
            shared: false,
            policy: None,
            policy_updated_utc: 0,
            strongroom: Some(info),
            removed_utc: 0,
        };
        self.keyring.folders.insert(folder_id.clone(), rec);
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.config.folders.push(FolderMount {
            folder_id: folder_id.clone(),
            path: canonical(path)?,
            selective: true,
            encrypted: false,
        });
        self.config.save(&self.home)?;
        self.unlocked.insert(
            folder_id.clone(),
            (folder_key, util::now_utc() + unlock_minutes as i64 * 60),
        );
        self.pending.push(Event::FolderAdded {
            folder: folder_id.clone(),
        });
        self.publish_registry()?;
        self.commit_batch()?;
        Ok(folder_id)
    }

    /// Unlock with the security key (one touch) for `minutes`.
    pub fn unlock_strongroom(
        &mut self,
        folder: &str,
        key: &dyn crate::strongroom::SecurityKey,
        minutes: u64,
    ) -> Result<SecretKey> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let info = rec
            .strongroom
            .as_ref()
            .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
        let fk = crate::strongroom::unlock(key, &rec.folder_id, info)?;
        self.unlocked.insert(
            rec.folder_id.clone(),
            (fk.clone(), util::now_utc() + minutes as i64 * 60),
        );
        Ok(fk)
    }

    /// Unlock with a key obtained elsewhere (the command line touched the
    /// security key and hands the folder key to the running service).
    pub fn unlock_strongroom_with_key(
        &mut self,
        folder: &str,
        key_hex: &str,
        minutes: u64,
    ) -> Result<()> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if !rec.is_strongroom() {
            bail!("{folder} is not a Strongroom folder");
        }
        let fk = SecretKey::from_hex(key_hex)?;
        // Prove the key is right before accepting it: it must open the wrapped key's folder keys.
        let _ = FolderKeys::from_folder_key(&rec.folder_id, fk.clone());
        self.unlocked.insert(
            rec.folder_id.clone(),
            (fk, util::now_utc() + minutes as i64 * 60),
        );
        Ok(())
    }

    pub fn lock_strongroom(&mut self, folder: &str) -> Result<()> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        self.unlocked.remove(&rec.folder_id);
        Ok(())
    }

    /// Forget every key whose window has passed.
    pub fn expire_strongrooms(&mut self) {
        let now = util::now_utc();
        self.unlocked.retain(|_, (_, until)| *until > now);
    }

    /// (name, method, unlocked_until) for every Strongroom folder.
    pub fn strongrooms(&self) -> Vec<(String, crate::strongroom::Method, Option<i64>)> {
        self.folders()
            .into_iter()
            .filter_map(|(r, _)| {
                let info = r.strongroom.as_ref()?;
                let until = self
                    .unlocked
                    .get(&r.folder_id)
                    .filter(|(_, u)| *u > util::now_utc())
                    .map(|(_, u)| *u);
                Some((r.name.clone(), info.method.clone(), until))
            })
            .collect()
    }

    // ----- peer-to-peer ------------------------------------------------------

    pub fn p2p_config(&self) -> crate::vault::P2pConfig {
        self.config.p2p.clone()
    }

    pub fn set_p2p_config(&mut self, cfg: crate::vault::P2pConfig) -> Result<()> {
        self.config.p2p = cfg;
        self.config.save(&self.home)
    }

    /// Peers to try before storages (None disables).
    pub fn set_peers(&mut self, peers: Option<std::sync::Arc<crate::p2p::Peers>>) {
        self.peers = peers;
    }

    pub fn peer_key(&self) -> SecretKey {
        crate::p2p::peer_key(self.current_vault_key())
    }

    pub fn wire_vault_tag(&self) -> String {
        crate::p2p::wire_vault_tag(self.root_key(), &self.vault.vault_id)
    }

    /// What this device can serve to peers right now: every chunk of every
    /// file present on disk, plus objects in local-directory storages.
    pub fn peer_snapshot(&self) -> Result<crate::p2p::Snapshot> {
        let mut folder_keys = BTreeMap::new();
        let mut pieces = BTreeMap::new();
        for (rec, mount) in self.folders() {
            let Some(root) = mount else { continue };
            let Ok(rec) = self.with_key(&rec) else {
                continue;
            };
            let fk = self.folder_keys(&rec)?;
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| !f.deleted) {
                let disk = root.join(&f.path);
                if !disk.is_file() {
                    continue;
                }
                let mut offset = 0u64;
                for cr in &f.chunks {
                    pieces.insert(
                        cr.object.clone(),
                        crate::p2p::Piece {
                            folder: rec.folder_id.clone(),
                            chunk: cr.chunk.clone(),
                            epoch: cr.epoch,
                            path: disk.clone(),
                            offset,
                            len: cr.size,
                        },
                    );
                    offset += cr.size;
                }
            }
            folder_keys.insert(rec.folder_id.clone(), fk);
        }
        let local_roots = self
            .config
            .storages
            .iter()
            .filter_map(|s| match s {
                StorageSpec::LocalDir { path, .. } if !s.is_cold() => Some(path.clone()),
                _ => None,
            })
            .collect();
        Ok(crate::p2p::Snapshot {
            vault_id: self.vault.vault_id.clone(),
            device_id: self.vault.device_id.clone(),
            peer_key: self.peer_key(),
            folder_keys,
            pieces,
            local_roots,
            revoked: self.devices.revoked.keys().cloned().collect(),
        })
    }

    /// The device's QUIC certificate, created on first use (`p2p enable`).
    pub fn p2p_identity(&self) -> Result<crate::p2p::quic::Identity> {
        crate::p2p::quic::Identity::load_or_create(&self.home)
    }

    /// The rendezvous record this device would publish for `port` with the
    /// reachability facts the service learned; `publish_peer_record` writes it.
    pub fn peer_record_template(&self, port: u16) -> crate::p2p::PeerRecord {
        let lan = crate::p2p::local_ipv4_addrs();
        crate::p2p::PeerRecord {
            version: crate::p2p::PeerRecord::VERSION,
            device: self.vault.device_id.clone(),
            name: self.vault.device_name.clone(),
            port,
            udp_local: lan
                .iter()
                .map(|ip| std::net::SocketAddr::new(*ip, port))
                .collect(),
            lan_addrs: lan,
            public_addrs: self.config.p2p.public_addrs.clone(),
            updated_utc: util::now_utc(),
            udp_public: Vec::new(),
            cert_sha256: crate::p2p::quic::Identity::load(&self.home)
                .ok()
                .flatten()
                .map(|id| id.sha256)
                .unwrap_or_default(),
            nat: crate::p2p::stun::Nat::Unknown,
            relay_via: Vec::new(),
            reachable: !self.config.p2p.public_addrs.is_empty(),
        }
    }

    /// Publish where this device can be reached (rendezvous record).
    pub fn publish_peer_record(&self, rec: &crate::p2p::PeerRecord) -> Result<()> {
        self.ensure_active()?;
        let key = self.registry_key_now();
        let blob = rec.seal(&self.vault.vault_id, &key)?;
        let k = crate::p2p::PeerRecord::storage_key(&rec.device);
        for (_, backend) in self.metadata_storages(false)? {
            // Records change: delete then write (single writer per path).
            backend.delete(&k)?;
            backend.put_if_absent(&k, &blob)?;
        }
        Ok(())
    }

    /// Rendezvous records of the other devices, one per device (the newest
    /// copy when several storages hold one).
    pub fn peer_record_list(&self) -> Result<Vec<crate::p2p::PeerRecord>> {
        let keys = self.registry_keys();
        let mut out: Vec<crate::p2p::PeerRecord> = Vec::new();
        for (_, backend) in self.metadata_storages(false)? {
            for k in backend.list(crate::p2p::PeerRecord::PREFIX)? {
                let Some(id) = k
                    .strip_prefix(crate::p2p::PeerRecord::PREFIX)
                    .and_then(|r| r.strip_suffix(".enc"))
                else {
                    continue;
                };
                let Ok(dev) = DeviceId::from_hex(id) else {
                    continue;
                };
                // Revoked devices and devices with an out-of-date key are no peers.
                if dev == self.vault.device_id || !self.trusted(&dev) {
                    continue;
                }
                let Some(blob) = backend.get(&k)? else {
                    continue;
                };
                let Some(rec) = keys.iter().find_map(|(_, key)| {
                    crate::p2p::PeerRecord::open(&blob, &self.vault.vault_id, &dev, key).ok()
                }) else {
                    continue;
                };
                match out.iter_mut().find(|r| r.device == dev) {
                    Some(have) if have.updated_utc < rec.updated_utc => *have = rec,
                    Some(_) => {}
                    None => out.push(rec),
                }
            }
        }
        Ok(out)
    }

    /// Peers other devices advertised through the storages, as TCP addresses.
    pub fn peer_records(&self) -> Result<Vec<crate::p2p::PeerAddr>> {
        let mut out: Vec<crate::p2p::PeerAddr> = Vec::new();
        for rec in self.peer_record_list()? {
            for addr in rec.addrs() {
                if !out.iter().any(|p| p.addr == addr) {
                    out.push(crate::p2p::PeerAddr {
                        device: rec.device.clone(),
                        addr,
                        name: rec.name.clone(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Create or overwrite a file inside a folder (relative path), then push.
    /// Used by the MCP server for notes and reorganisation; refuses to leave the folder.
    pub fn write_file(&mut self, folder: &str, path: &str, bytes: &[u8]) -> Result<PushReport> {
        let (_, root) = self.resolve_folder(folder)?;
        if path.is_empty()
            || Path::new(path).is_absolute()
            || path.split('/').any(|c| c == ".." || c.is_empty())
        {
            bail!("path must be relative to the folder and must not contain '..': {path}");
        }
        let disk = root.join(path);
        if placeholder_path(&disk).exists() {
            bail!("{path} is a placeholder here; fetch it before overwriting");
        }
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&disk, bytes).with_context(|| format!("write {}", disk.display()))?;
        self.push(folder)
    }

    /// Create a new file inside a folder, never replacing one: refused when
    /// the path exists here, as a placeholder, or as a file another device
    /// published. The assistant (MCP) writes only through this.
    pub fn create_file(&mut self, folder: &str, path: &str, bytes: &[u8]) -> Result<PushReport> {
        self.ensure_path_free(folder, path)?;
        self.write_file(folder, path, bytes)
    }

    /// A path no file of the folder uses, on this device or any other.
    fn ensure_path_free(&self, folder: &str, path: &str) -> Result<()> {
        let (rec, root) = self.resolve_folder(folder)?;
        let disk = root.join(path);
        let known = self
            .load_state(&rec.folder_id)?
            .files
            .get(path)
            .is_some_and(|f| !f.deleted);
        if known || disk.exists() || placeholder_path(&disk).exists() {
            bail!("{path} already exists; files are never replaced, choose another name");
        }
        Ok(())
    }

    /// Create a directory inside a folder.
    pub fn mkdir(&mut self, folder: &str, path: &str) -> Result<()> {
        let (_, root) = self.resolve_folder(folder)?;
        if path.is_empty()
            || Path::new(path).is_absolute()
            || path.split('/').any(|c| c == ".." || c.is_empty())
        {
            bail!("path must be relative to the folder and must not contain '..': {path}");
        }
        fs::create_dir_all(root.join(path))?;
        Ok(())
    }

    /// Record that `path` was used now (open, read, export) on this device.
    pub fn touch_access(&mut self, folder: &str, path: &str) -> Result<()> {
        let (rec, _) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        if !state.files.get(path).is_some_and(|f| !f.deleted) {
            bail!("unknown file {path}");
        }
        state.accessed.insert(path.to_string(), now_secs());
        self.save_state(&rec.folder_id, &state)
    }

    /// Contents of a file, fetching it first if it is a placeholder. Counts
    /// as an access.
    pub fn read_file(&mut self, folder: &str, path: &str) -> Result<Vec<u8>> {
        let (_, root) = self.resolve_folder(folder)?;
        let disk = root.join(path);
        if !disk.exists() {
            self.fetch_file(folder, path)?;
        }
        let bytes = fs::read(&disk).with_context(|| format!("read {}", disk.display()))?;
        self.touch_access(folder, path)?;
        Ok(bytes)
    }

    /// Rename or move a file inside a folder (both paths relative to the
    /// folder root), then push so other devices see the move.
    pub fn move_file(&mut self, folder: &str, from: &str, to: &str) -> Result<PushReport> {
        let (_, root) = self.resolve_folder(folder)?;
        for p in [from, to] {
            if p.is_empty()
                || Path::new(p).is_absolute()
                || p.split('/').any(|c| c == ".." || c.is_empty())
            {
                bail!("path must be relative to the folder and must not contain '..': {p}");
            }
        }
        // Moving never replaces a file, also not one only another device has.
        self.ensure_path_free(folder, to)?;
        let src = root.join(from);
        let dst = root.join(to);
        if !src.exists() {
            // A placeholder can be moved as well.
            let ph = placeholder_path(&src);
            if ph.exists() {
                if dst.exists() || placeholder_path(&dst).exists() {
                    bail!("{to} already exists");
                }
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(&ph, placeholder_path(&dst))?;
                return self.push(folder);
            }
            bail!("unknown file {from}");
        }
        if dst.exists() || placeholder_path(&dst).exists() {
            bail!("{to} already exists");
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src, &dst).with_context(|| format!("move {from} to {to}"))?;
        self.push(folder)
    }

    pub fn list_files(&self, folder: &str) -> Result<Vec<FileEntry>> {
        let (rec, root) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let selective = self.mount_is_selective(&rec.folder_id);
        let mut out = Vec::new();
        for f in state.files.values().filter(|f| !f.deleted) {
            let disk = root.join(&f.path);
            let state_str = if disk.exists() {
                "local"
            } else if placeholder_path(&disk).exists() {
                "placeholder"
            } else {
                "missing"
            };
            out.push(FileEntry {
                path: f.path.clone(),
                size: f.size,
                state: state_str.to_string(),
                pinned: state.pinned.contains(&f.path),
                content_hash: f.content_hash.clone(),
                selective,
                disk: disk.clone(),
                media: thumbs::is_image(&f.path) || thumbs::is_video(&f.path),
                modified_utc: f.mtime / 1_000_000_000,
                last_accessed_utc: state.accessed.get(&f.path).copied(),
            });
        }
        Ok(out)
    }

    /// pull then push, for every attached folder (or one).
    pub fn sync(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        self.ensure_active()?;
        // A folder another device converted into a Strongroom must be
        // adopted before it is synced under its old key.
        self.pull_registry()?;
        self.finish_strongroom_conversions();
        let names: Vec<String> = match folder {
            Some(f) => vec![f.to_string()],
            None => self
                .folders()
                .into_iter()
                .filter(|(r, m)| {
                    m.is_some() && (!r.is_strongroom() || self.is_unlocked(&r.folder_id))
                })
                .map(|(r, _)| r.folder_id.to_string())
                .collect(),
        };
        let mut out = Vec::new();
        if names.is_empty() {
            // Nothing attached yet (a device that just joined): still learn the
            // other devices and where the blocks are.
            self.pull_ledger()?;
        }
        for name in names {
            let pull = self.pull(&name)?;
            if self.keyring.find(&name).is_none() {
                continue; // converted while pulling
            }
            let push = self.push(&name)?;
            out.push((pull, push));
        }
        Ok(out)
    }

    // ----- reporting ----------------------------------------------------------

    pub fn status(&self) -> Result<StatusReport> {
        let view = self.view()?;
        let mut folders = Vec::new();
        for (rec, mount) in self.folders() {
            let state = self.load_state(&rec.folder_id)?;
            let mut chunks = BTreeSet::new();
            let mut bytes = 0u64;
            let mut files = 0u64;
            for f in state.files.values().filter(|f| !f.deleted) {
                files += 1;
                bytes += f.size;
                for c in &f.chunks {
                    chunks.insert(c.chunk.clone());
                }
            }
            let mut without = 0u64;
            let mut verified = 0u64;
            for c in &chunks {
                match view.locate(&rec.folder_id, c) {
                    Some(r) if r.claimed_storages() > 0 => {
                        if r.verified_storages() > 0 {
                            verified += 1;
                        }
                    }
                    _ => without += 1,
                }
            }
            let placeholders_here = mount
                .as_ref()
                .map(|m| {
                    state
                        .files
                        .values()
                        .filter(|f| !f.deleted && placeholder_path(&m.join(&f.path)).exists())
                        .count() as u64
                })
                .unwrap_or(0);
            folders.push(FolderStatus {
                folder_id: rec.folder_id.to_string(),
                name: rec.name.clone(),
                path: mount,
                files,
                bytes,
                chunks: chunks.len() as u64,
                chunks_without_storage_copy: without,
                chunks_verified_elsewhere: verified,
                published_seq: state.published_seq,
                shared: rec.shared,
                policy: rec.policy.as_ref().map(|p| p.describe()),
                strongroom: rec.strongroom.as_ref().map(|_| {
                    match self.unlocked.get(&rec.folder_id) {
                        Some((_, until)) if *until > util::now_utc() => {
                            format!("unlocked until {until}")
                        }
                        _ => "locked".to_string(),
                    }
                }),
                selective: self.mount_is_selective(&rec.folder_id),
                plain: !self.mount_is_encrypted(&rec.folder_id),
                placeholders: placeholders_here,
                pinned: state.pinned.len() as u64,
            });
        }
        Ok(StatusReport {
            vault_id: self.vault.vault_id.to_string(),
            device_id: self.vault.device_id.to_string(),
            device_name: self.vault.device_name.clone(),
            format_version: crate::FORMAT_VERSION,
            storages: self.config.storages.clone(),
            // Devices from the ledger, and from the registry for devices whose
            // enrolment batch has not reached this one yet; removed ones go.
            devices: self
                .devices
                .devices
                .iter()
                .map(|(k, r)| (k, r.name.clone()))
                .chain(view.devices.iter().map(|(k, v)| (k, v.clone())))
                .filter(|(k, _)| self.trusted(k))
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            revoked: self
                .devices
                .revoked
                .keys()
                .map(|k| {
                    let name = view
                        .devices
                        .get(k)
                        .cloned()
                        .or_else(|| self.devices.devices.get(k).map(|r| r.name.clone()));
                    (k.to_string(), name.unwrap_or_default())
                })
                .collect(),
            key_epoch: self.key_epoch(),
            replicas: self
                .devices
                .replicas
                .iter()
                .map(|(k, v)| (k.to_string(), v.name.clone()))
                .collect(),
            members: self
                .devices
                .members
                .iter()
                .map(|(k, v)| (k.to_string(), v.name.clone()))
                .collect(),
            member: self.vault.member,
            folders,
            ledger_batches: view.batches,
            lamport: self.clock.lamport,
            forked_devices: view
                .forked
                .iter()
                .map(|d| d.to_string())
                .chain(if self.forked_self {
                    Some(self.vault.device_id.to_string())
                } else {
                    None
                })
                .collect(),
        })
    }

    /// Compare the ledger with what the storages actually hold. With
    /// `verify_content`, every referenced object is downloaded and hashed.
    pub fn fsck(&mut self, verify_content: bool) -> Result<FsckReport> {
        let _ = self.pull_ledger()?;
        let view = self.view()?;
        let mut report = FsckReport {
            forked_devices: view.forked.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        };
        // Objects per hot storage.
        let mut listings: BTreeMap<String, HashSet<String>> = BTreeMap::new();
        let storages = self.open_storages(false)?;
        for spec in &self.config.storages {
            if spec.is_cold() {
                report.storages_skipped_cold.push(spec.name().to_string());
            }
        }
        for (spec, backend) in &storages {
            listings.insert(
                spec.name().to_string(),
                backend.list("chunks/")?.into_iter().collect(),
            );
        }
        // Referenced chunks from every attached folder's current files.
        let mut referenced: BTreeMap<(FolderId, ChunkId), ObjectName> = BTreeMap::new();
        for (rec, _) in self.folders() {
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| !f.deleted) {
                for c in &f.chunks {
                    referenced.insert((rec.folder_id.clone(), c.chunk.clone()), c.object.clone());
                }
            }
        }
        report.chunks_referenced = referenced.len() as u64;
        let mut referenced_objects = HashSet::new();
        for ((folder, chunk), object) in &referenced {
            let key = chunk_storage_key(object);
            referenced_objects.insert(key.clone());
            let present_somewhere = listings.values().any(|l| l.contains(&key));
            if present_somewhere {
                report.chunks_with_storage_copy += 1;
            } else {
                report
                    .chunks_missing
                    .push(format!("{}/{}", folder.short(), chunk.short()));
            }
            match view.locate(folder, chunk) {
                Some(r) if r.verified_storages() > 0 => report.chunks_verified_elsewhere += 1,
                Some(r) if r.claimed_storages() > 0 => report.chunks_claimed_only += 1,
                _ => {}
            }
        }
        for ((folder, _), rec) in view.chunks.iter() {
            if !self.keyring.folders.contains_key(folder) {
                continue; // a folder converted into a Strongroom: its old objects are gone
            }
            let key = chunk_storage_key(&rec.object);
            for storage in rec.storages.keys() {
                if self
                    .config
                    .storages
                    .iter()
                    .any(|s| s.name() == storage && s.is_carrier())
                {
                    continue; // carriers are pruned on purpose
                }
                if let Some(l) = listings.get(storage) {
                    if !l.contains(&key) {
                        report.claims_without_object += 1;
                    }
                }
            }
        }
        for l in listings.values() {
            report.objects_unreferenced += l
                .iter()
                .filter(|k| !referenced_objects.contains(*k))
                .count() as u64;
        }
        if verify_content {
            let mut corrupt_pools: BTreeSet<String> = BTreeSet::new();
            for ((folder, chunk), object) in &referenced {
                let key = chunk_storage_key(object);
                for (spec, backend) in &storages {
                    let ct = match backend.get(&key) {
                        Ok(ct) => ct,
                        Err(e)
                            if matches!(
                                pool::pool_error(&e),
                                Some(PoolError::NeedsDisk { .. })
                            ) =>
                        {
                            report.objects_offline += 1;
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if let Some(ct) = ct {
                        if ObjectName::from_bytes(&crypto::hash(&ct)) == *object {
                            report.objects_verified_now += 1;
                            self.pending.push(Event::ChunkVerified {
                                folder: folder.clone(),
                                chunk: chunk.clone(),
                                object: object.clone(),
                                storage: spec.name().to_string(),
                            });
                        } else {
                            if spec.is_data_only() {
                                corrupt_pools.insert(spec.name().to_string());
                            }
                            report.objects_corrupt.push(format!(
                                "{}:{}",
                                spec.name(),
                                object.short()
                            ));
                        }
                    }
                }
            }
            self.commit_batch()?;
            // The attached disks of every pool were read in full: record the check.
            drop(storages);
            for spec in self.config.storages.clone() {
                if !spec.is_data_only() || corrupt_pools.contains(spec.name()) {
                    continue;
                }
                let pool = self.open_pool(&spec)?;
                let attached: Vec<String> = pool
                    .statuses()
                    .into_iter()
                    .filter(|d| d.attached)
                    .map(|d| d.disk_id)
                    .collect();
                pool.mark_verified(&attached)?;
                let disks = pool.disks();
                drop(pool);
                self.save_pool_disks(spec.name(), disks)?;
            }
        }
        for spec in &self.config.storages {
            if !spec.is_data_only() {
                continue;
            }
            for d in self.open_pool(spec)?.statuses() {
                if !d.attached && d.objects > 0 {
                    report.disks_offline.push(format!(
                        "{} ({}), last verified {}",
                        d.label,
                        d.place,
                        if d.last_verified_utc > 0 {
                            util::format_date(d.last_verified_utc)
                        } else {
                            "never".to_string()
                        }
                    ));
                }
            }
        }
        Ok(report)
    }

    // ----- disk pool ----------------------------------------------------------

    /// Mirror the disk registry a pool learned (adopted disks, mounts, checks)
    /// into the configuration, so `config.json` always lists every disk.
    fn save_pool_disks(&mut self, name: &str, disks: Vec<PoolDisk>) -> Result<()> {
        let Some(StorageSpec::Pool {
            disks: configured, ..
        }) = self.config.storages.iter_mut().find(|s| s.name() == name)
        else {
            return Ok(());
        };
        if *configured != disks {
            *configured = disks;
            self.config.save(&self.home)?;
        }
        Ok(())
    }

    fn pool_specs(&self) -> Vec<StorageSpec> {
        self.config
            .storages
            .iter()
            .filter(|s| s.is_data_only())
            .cloned()
            .collect()
    }

    /// Every disk of every pool with its attached state (refreshes the
    /// registry, adopting disks other devices filled).
    pub fn disks(&mut self) -> Result<Vec<DiskStatus>> {
        let mut out = Vec::new();
        for spec in self.pool_specs() {
            let pool = self.open_pool(&spec)?;
            out.extend(pool.statuses());
            let disks = pool.disks();
            drop(pool);
            self.save_pool_disks(spec.name(), disks)?;
        }
        Ok(out)
    }

    /// The pool and disk a label names (a disk id or its prefix also works).
    fn find_disk(&self, label: &str) -> Result<(StorageSpec, PoolStorage, PoolDisk)> {
        for spec in self.pool_specs() {
            let pool = self.open_pool(&spec)?;
            if let Some(d) = pool
                .disks()
                .into_iter()
                .find(|d| d.label == label || (label.len() >= 8 && d.id.starts_with(label)))
            {
                return Ok((spec, pool, d));
            }
        }
        bail!("unknown disk {label}")
    }

    /// Register the mounted directory as a new disk of a pool and fill it
    /// with what the pool does not hold yet.
    pub fn disk_add(
        &mut self,
        mount: &Path,
        pool_name: &str,
        label: &str,
    ) -> Result<DiskAddReport> {
        let spec = self
            .pool_specs()
            .into_iter()
            .find(|s| s.name() == pool_name)
            .ok_or_else(|| anyhow!("no disk pool named {pool_name}; add one with `varsto storage add-pool {pool_name}`"))?;
        if self.find_disk(label).is_ok() {
            bail!("a disk labelled {label} already exists");
        }
        let pool = self.open_pool(&spec)?;
        let disk = pool.add_disk(mount, label)?;
        let (objects_added, bytes_added) = self.fill_disk(&spec, &pool, &disk.id)?;
        pool.flush()?;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(DiskAddReport {
            pool: spec.name().to_string(),
            disk,
            objects_added,
            bytes_added,
        })
    }

    /// Reattach routine: verify the marker and the objects (sizes; hashes with
    /// `full`), apply queued deletions, then fill the disk with new objects.
    pub fn disk_check(&mut self, label: &str, full: bool) -> Result<DiskCheckReport> {
        let (spec, pool, disk) = self.find_disk(label)?;
        let mount = pool
            .mount_of(&disk.id)
            .ok_or_else(|| anyhow!("disk {} is not attached", disk.label))?;
        let (objects_removed, bytes_removed) = pool.apply_pending_deletes(&disk.id)?;
        let verified = pool.verify_disk(&disk.id, full)?;
        if full {
            // Every object on the disk was re-hashed: that is a verification
            // other devices can rely on through the ledger.
            let view = self.view()?;
            let mut by_object: BTreeMap<ObjectName, (FolderId, ChunkId)> = BTreeMap::new();
            for ((folder, chunk), r) in view.chunks.iter() {
                by_object.insert(r.object.clone(), (folder.clone(), chunk.clone()));
            }
            for (key, _) in pool.objects_on(&disk.id) {
                let Some(name) = key.rsplit('/').next() else {
                    continue;
                };
                let Ok(object) = ObjectName::from_hex(name) else {
                    continue;
                };
                if let Some((folder, chunk)) = by_object.get(&object) {
                    self.pending.push(Event::ChunkVerified {
                        folder: folder.clone(),
                        chunk: chunk.clone(),
                        object,
                        storage: spec.name().to_string(),
                    });
                }
            }
        }
        let (objects_added, bytes_added) = if disk.retired {
            (0, 0)
        } else {
            self.fill_disk(&spec, &pool, &disk.id)?
        };
        self.commit_batch()?;
        pool.flush()?;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(DiskCheckReport {
            pool: spec.name().to_string(),
            label: disk.label,
            mount,
            objects_checked: verified.objects_checked,
            bytes_checked: verified.bytes_checked,
            bad: verified.bad,
            missing: verified.missing,
            adopted: verified.adopted,
            objects_removed,
            bytes_removed,
            objects_added,
            bytes_added,
        })
    }

    /// Write the disk's index and sync it; the disk is then safe to remove
    /// (the program never unmounts). Returns the mount path.
    pub fn disk_eject(&mut self, label: &str) -> Result<PathBuf> {
        let (spec, pool, disk) = self.find_disk(label)?;
        let mount = pool
            .eject(&disk.id)
            .with_context(|| format!("eject disk {}", disk.label))?;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(mount)
    }

    /// Mark a disk retired: nothing new is written to it. Returns the number
    /// of objects that exist on this disk and on no other storage.
    pub fn disk_retire(&mut self, label: &str) -> Result<u64> {
        let (spec, pool, disk) = self.find_disk(label)?;
        pool.set_retired(&disk.id, true)?;
        let view = self.view()?;
        let mut elsewhere: HashSet<ObjectName> = HashSet::new();
        for r in view.chunks.values() {
            if r.storages.keys().any(|s| s != spec.name()) {
                elsewhere.insert(r.object.clone());
            }
        }
        let only_here = pool
            .objects_on(&disk.id)
            .iter()
            .filter(|(key, _)| {
                key.rsplit('/')
                    .next()
                    .and_then(|n| ObjectName::from_hex(n).ok())
                    .is_none_or(|o| !elsewhere.contains(&o))
            })
            .count() as u64;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(only_here)
    }

    /// The ciphertext of one chunk, re-encrypted from a local file (chunking
    /// and encryption are deterministic, so the object is identical).
    fn chunk_ciphertext_from_file(
        &self,
        fk: &FolderKeys,
        path: &Path,
        chunk: &ChunkId,
        epoch: u32,
    ) -> Result<Vec<u8>> {
        let file = fs::File::open(path)?;
        for piece in Chunker::new(std::io::BufReader::new(file), self.chunker)? {
            let piece = piece?;
            if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &piece)) != *chunk {
                continue;
            }
            return crypto::encrypt_with_nonce(
                &fk.chunk_key(epoch, chunk)?,
                &fk.chunk_nonce(epoch, chunk)?,
                &fk.chunk_aad(&self.vault.vault_id, chunk, piece.len() as u64),
                &crate::pack::pack(&piece),
            );
        }
        bail!("chunk {} is not in {}", chunk.short(), path.display())
    }

    /// Fill one attached disk with objects of current files that the pool
    /// holds on no disk, largest first, within the disk's reserve. Objects
    /// come from the other hot storages or are re-encrypted from local files;
    /// no other storage is changed. Returns (objects, bytes) written.
    fn fill_disk(
        &mut self,
        spec: &StorageSpec,
        pool: &PoolStorage,
        disk_id: &str,
    ) -> Result<(u64, u64)> {
        struct Need {
            folder: FolderId,
            chunk: ChunkId,
            epoch: u32,
            size: u64,
            files: Vec<PathBuf>,
        }
        let have = pool.objects();
        let mut needed: BTreeMap<ObjectName, Need> = BTreeMap::new();
        let mut folder_keys: BTreeMap<FolderId, FolderKeys> = BTreeMap::new();
        for (rec, mount) in self.folders() {
            let Ok(rec) = self.with_key(&rec) else {
                continue; // a locked Strongroom is skipped
            };
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| !f.deleted) {
                for c in &f.chunks {
                    if have.contains_key(&chunk_storage_key(&c.object)) {
                        continue;
                    }
                    let n = needed.entry(c.object.clone()).or_insert_with(|| Need {
                        folder: rec.folder_id.clone(),
                        chunk: c.chunk.clone(),
                        epoch: c.epoch,
                        size: c.size,
                        files: Vec::new(),
                    });
                    if let Some(m) = &mount {
                        n.files.push(m.join(&f.path));
                    }
                }
            }
            folder_keys.insert(rec.folder_id.clone(), self.folder_keys(&rec)?);
        }
        let mut order: Vec<ObjectName> = needed.keys().cloned().collect();
        order.sort_by(|a, b| needed[b].size.cmp(&needed[a].size).then(a.cmp(b)));
        let sources = self.metadata_storages(false)?;
        let (mut n, mut bytes) = (0u64, 0u64);
        for object in order {
            let need = &needed[&object];
            // Ciphertext is a little larger than the chunk; the exact size is
            // checked again by the pool when writing.
            if !pool.has_room(disk_id, need.size + 64) {
                continue;
            }
            let key = chunk_storage_key(&object);
            let mut ct: Option<Vec<u8>> = None;
            for (_, backend) in &sources {
                if let Ok(Some(c)) = backend.get(&key) {
                    if ObjectName::from_bytes(&crypto::hash(&c)) == object {
                        ct = Some(c);
                        break;
                    }
                }
            }
            if ct.is_none() {
                if let Some(fk) = folder_keys.get(&need.folder) {
                    for path in &need.files {
                        if let Ok(c) =
                            self.chunk_ciphertext_from_file(fk, path, &need.chunk, need.epoch)
                        {
                            ct = Some(c);
                            break;
                        }
                    }
                }
            }
            let Some(ct) = ct else { continue };
            match pool.put_on_disk(disk_id, &key, &ct) {
                Ok(true) => {
                    n += 1;
                    bytes += ct.len() as u64;
                    self.pending.push(Event::ChunkStored {
                        folder: need.folder.clone(),
                        chunk: need.chunk.clone(),
                        object: object.clone(),
                        storage: spec.name().to_string(),
                        size: ct.len() as u64,
                    });
                }
                Ok(false) => {}
                Err(e) if matches!(pool::pool_error(&e), Some(PoolError::NoRoom { .. })) => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        self.commit_batch()?;
        Ok((n, bytes))
    }

    /// Duplicate files inside one folder (same keyed content hash).
    pub fn dupes(&self, folder: &str) -> Result<Vec<DupeGroup>> {
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let mut groups: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
        for f in state.files.values().filter(|f| !f.deleted && f.size > 0) {
            let e = groups
                .entry(f.content_hash.clone())
                .or_insert((f.size, vec![]));
            e.1.push(f.path.clone());
        }
        Ok(groups
            .into_iter()
            .filter(|(_, (_, p))| p.len() > 1)
            .map(|(h, (size, paths))| DupeGroup {
                content_hash: h,
                size,
                paths,
            })
            .collect())
    }

    pub fn ledger_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut out = Vec::new();
        for s in self.ledger.all()? {
            let Some(key) = self.key_for_id(&s.key_id) else {
                continue;
            };
            let Ok(b) = s.open(&key) else { continue };
            out.push(LedgerEntry {
                device: s.device.to_string(),
                seq: s.seq,
                lamport: b.lamport,
                created_utc: b.created_utc,
                events: b.events.len(),
                hash: s.hash.clone(),
            });
        }
        Ok(out)
    }
}

/// Alpha helper: forget everything this device knows about its vault (keys,
/// ledger, state, configuration, secrets, grants) so it can start over. The
/// user's files in attached folders are left untouched; the storages are not
/// changed either, so other devices keep working.
pub fn reset_device(home: &Path) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    for name in [
        "vault.json",
        "keys.enc",
        "keyring.enc",
        "secrets.enc",
        "config.json",
        "devices.json",
        "clock.json",
        "mcp-grants.json",
        "share-request.json",
        "software-security-key",
        "service.log",
        membership::RESET_EXTRA[0],
        membership::RESET_EXTRA[1],
        membership::RESET_EXTRA[2],
    ] {
        let p = home.join(name);
        if p.exists() {
            fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(name.to_string());
        }
    }
    for dir in ["state", "ledger", "trash"] {
        let p = home.join(dir);
        if p.exists() {
            fs::remove_dir_all(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(format!("{dir}/"));
        }
    }
    Ok(removed)
}
