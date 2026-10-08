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
use crate::ledger::{self, Event, Ingest, KeyDirectory, LedgerStore, LedgerView, SignedBatch};
use crate::manifest::{self, ChunkRef, FileState, Manifest, Merge};
use crate::storage::{Storage, StorageSpec};
use crate::util;
use crate::vault::{
    Config, DeviceRecord, FolderKeys, FolderMount, FolderRecord, Keyring, Keys, LocalVault,
    VaultMeta,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Clock {
    lamport: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct DeviceCache {
    devices: BTreeMap<DeviceId, DeviceRecord>,
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
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct PullReport {
    pub folder: String,
    pub manifests_applied: u64,
    pub files_updated: u64,
    pub files_deleted: u64,
    pub conflicts: u64,
    pub chunks_downloaded: u64,
    pub bytes_downloaded: u64,
    pub files_unavailable: Vec<String>,
    pub forked_devices: Vec<String>,
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
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub vault_id: String,
    pub device_id: String,
    pub device_name: String,
    pub format_version: u16,
    pub storages: Vec<StorageSpec>,
    pub devices: BTreeMap<String, String>,
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
    pub chunker: ChunkerParams,
}

/// Open storages with their specs.
type OpenStorages = Vec<(StorageSpec, Box<dyn Storage>)>;

fn chunk_storage_key(object: &ObjectName) -> String {
    format!("chunks/{}/{}", &object.as_str()[..2], object)
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
        };
        let vault_key_hex = keys.master.to_hex();
        Self::write_new(home, vault, keys, passphrase).map(|e| (e, vault_key_hex))
    }

    /// Join an existing vault with its vault key, through a storage that holds it.
    pub fn join(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
    ) -> Result<Engine> {
        if home.join("vault.json").exists() {
            bail!("{} already holds a vault", home.display());
        }
        let backend = storage.open()?;
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
        fs::create_dir_all(home)?;
        let keys = Keys {
            master: SecretKey::from_hex(vault_key_hex)?,
            signer: crypto::SigningKey::generate(),
        };
        let device_id = ledger::device_id_for(&keys.signer.public());
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id: meta.vault_id,
            device_id,
            device_name: device_name.to_string(),
            created_utc: meta.created_utc,
        };
        let mut engine = Self::write_new(home, vault, keys, passphrase)?;
        engine.add_storage(storage)?;
        engine.pull_registry()?;
        Ok(engine)
    }

    fn write_new(home: &Path, vault: LocalVault, keys: Keys, passphrase: &str) -> Result<Engine> {
        keys.save(home, passphrase, &vault.vault_id, &vault.device_id)?;
        util::write_json(&home.join("vault.json"), &vault)?;
        let mut engine = Engine {
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
            chunker: ChunkerParams::DEFAULT,
        };
        engine.config.save(home)?;
        engine.keyring.save(
            home,
            &engine.keys,
            &engine.vault.vault_id,
            &engine.vault.device_id,
        )?;
        let rec = engine.own_record();
        engine.devices.devices.insert(rec.device_id.clone(), rec);
        engine.save_devices()?;
        engine.pending.push(Event::DeviceEnrolled {
            name: engine.vault.device_name.clone(),
        });
        engine.commit_batch()?;
        Ok(engine)
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
        Ok(Engine {
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
            chunker: ChunkerParams::DEFAULT,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.vault.device_id
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
        for (id, rec) in &self.devices.devices {
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
        if self.config.storages.iter().any(|s| s.name() == spec.name()) {
            bail!("a storage named {} already exists", spec.name());
        }
        let backend = spec.open()?;
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

    fn open_storages(&self, include_cold: bool) -> Result<OpenStorages> {
        let mut out = Vec::new();
        for spec in &self.config.storages {
            if spec.is_cold() && !include_cold {
                continue;
            }
            out.push((spec.clone(), spec.open()?));
        }
        Ok(out)
    }

    /// Create a folder in the vault and mount it at `path` on this device.
    pub fn add_folder(&mut self, name: &str, path: &Path) -> Result<FolderId> {
        if self.keyring.folders.values().any(|f| f.name == name) {
            bail!("a folder named {name} already exists in the vault");
        }
        fs::create_dir_all(path)?;
        let rec = FolderRecord {
            folder_id: FolderId::random(),
            name: name.to_string(),
            key_hex: SecretKey::random().to_hex(),
            created_by: self.vault.device_id.clone(),
            created_utc: util::now_utc(),
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
            path: path.canonicalize()?,
        });
        self.config.save(&self.home)?;
        self.pending.push(Event::FolderAdded { folder: id.clone() });
        self.publish_registry()?;
        self.commit_batch()?;
        Ok(id)
    }

    /// Mount a folder that another device created (known from its record).
    pub fn attach_folder(&mut self, name_or_id: &str, path: &Path) -> Result<FolderId> {
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
            path: path.canonicalize()?,
        });
        self.config.save(&self.home)?;
        Ok(rec.folder_id)
    }

    /// Known folders: (record, mount path if attached here).
    pub fn folders(&self) -> Vec<(FolderRecord, Option<PathBuf>)> {
        self.keyring
            .folders
            .values()
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

    fn resolve_folder(&self, name_or_id: &str) -> Result<(FolderRecord, PathBuf)> {
        let rec = self
            .keyring
            .find(name_or_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {name_or_id}"))?;
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
        let reg_key = self.keys.registry_key();
        let fr_key = self.keys.folder_record_key();
        for (_, backend) in self.open_storages(true)? {
            backend.put_if_absent(
                &DeviceRecord::storage_key(&rec.device_id),
                &rec.seal(&self.vault.vault_id, &reg_key)?,
            )?;
            for f in self
                .keyring
                .folders
                .values()
                .filter(|f| f.created_by == self.vault.device_id)
            {
                backend.put_if_absent(
                    &FolderRecord::storage_key(&f.created_by, &f.folder_id),
                    &f.seal(&self.vault.vault_id, &fr_key)?,
                )?;
            }
        }
        Ok(())
    }

    fn pull_registry(&mut self) -> Result<()> {
        let reg_key = self.keys.registry_key();
        let fr_key = self.keys.folder_record_key();
        let mut changed_devices = false;
        let mut changed_folders = false;
        for (_, backend) in self.open_storages(false)? {
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
                if let Some(blob) = backend.get(&key)? {
                    let rec = DeviceRecord::open(&blob, &self.vault.vault_id, &id, &reg_key)?;
                    self.devices.devices.insert(id, rec);
                    changed_devices = true;
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
                if let Some(blob) = backend.get(&key)? {
                    let rec = FolderRecord::open(&blob, &self.vault.vault_id, &dev, &fid, &fr_key)?;
                    self.keyring.folders.insert(fid, rec);
                    changed_folders = true;
                }
            }
        }
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
        let lamport = self.tick()?;
        let events = std::mem::take(&mut self.pending);
        let ledger_key = self.keys.ledger_key();
        let signed = self.ledger.append_own(
            &self.vault.device_id,
            events,
            lamport,
            &ledger_key,
            &self.keys.signer,
        )?;
        self.push_own_batches()?;
        Ok(Some(signed.seq))
    }

    /// Push every own batch that a storage does not have yet; detect forks.
    fn push_own_batches(&mut self) -> Result<()> {
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me);
        for (_, backend) in self.open_storages(true)? {
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
        let dir = self.key_directory()?;
        let ledger_key = self.keys.ledger_key();
        let me = self.vault.device_id.clone();
        let mut forks = BTreeSet::new();
        for (_, backend) in self.open_storages(false)? {
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
                if self.ledger.get(&dev, seq)?.is_some() && !self.ledger.is_forked(&dev) {
                    // Known batch: re-check only our own head against the mailbox.
                    continue;
                }
                let Some(blob) = backend.get(&key)? else {
                    continue;
                };
                let signed: SignedBatch = serde_json::from_slice(&blob)?;
                let Some(pk) = dir.get(&dev) else { continue };
                if dev == me && seq > self.ledger.head(&me).seq {
                    // Another copy of this device identity published ahead of us.
                    forks.insert(me.clone());
                    let _ = self.ledger.ingest(signed, pk, &ledger_key);
                    self.mark_forked(&me)?;
                    continue;
                }
                match self.ledger.ingest(signed, pk, &ledger_key)? {
                    Ingest::Fork => {
                        forks.insert(dev.clone());
                    }
                    Ingest::New | Ingest::Known => {}
                }
            }
        }
        let view = self.ledger.view(&ledger_key)?;
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
        self.ledger.view(&self.keys.ledger_key())
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
        let fk = rec.keys()?;
        let me = self.vault.device_id.clone();
        let mut seen = BTreeSet::new();
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
                let ct = crypto::encrypt_with_nonce(
                    &fk.chunk_key(&chunk_id),
                    &fk.chunk_nonce(&chunk_id),
                    &fk.chunk_aad(&self.vault.vault_id, &chunk_id, chunk.len() as u64),
                    &chunk,
                )?;
                let object = ObjectName::from_bytes(&crypto::hash(&ct));
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
            .filter(|(p, f)| !f.deleted && !seen.contains(*p))
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
        report.manifest_seq = self.publish_manifest(&rec, &mut state)?;
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
        let fk = rec.keys()?;
        let folder_id = rec.folder_id.clone();
        let missing_on = |chunk: &ChunkId| -> Vec<String> {
            let known = view.locate(&folder_id, chunk);
            storages
                .iter()
                .filter(|(spec, _)| {
                    !known
                        .map(|r| r.storages.contains_key(spec.name()))
                        .unwrap_or(false)
                })
                .map(|(spec, _)| spec.name().to_string())
                .collect()
        };
        for file in state.files.values().filter(|f| !f.deleted) {
            if file.chunks.iter().all(|c| missing_on(&c.chunk).is_empty()) {
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
                let targets = missing_on(&chunk_id);
                if targets.is_empty() {
                    continue;
                }
                let ct = crypto::encrypt_with_nonce(
                    &fk.chunk_key(&chunk_id),
                    &fk.chunk_nonce(&chunk_id),
                    &fk.chunk_aad(&self.vault.vault_id, &chunk_id, chunk.len() as u64),
                    &chunk,
                )?;
                let object = ObjectName::from_bytes(&crypto::hash(&ct));
                let key = chunk_storage_key(&object);
                for (spec, backend) in storages
                    .iter()
                    .filter(|(spec, _)| targets.contains(&spec.name().to_string()))
                {
                    if backend.put_if_absent(&key, &ct)? {
                        report.chunks_uploaded += 1;
                        report.bytes_uploaded += ct.len() as u64;
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
        let blob = m.seal(&self.vault.vault_id, &rec.keys()?.meta)?;
        let key = Manifest::storage_key(&rec.folder_id, &self.vault.device_id, seq);
        for (_, backend) in self.open_storages(true)? {
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
        let (rec, root) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        self.scan(&rec, &root, &mut state)?;
        let forks = self.pull_ledger()?;
        report.forked_devices = forks.iter().map(|d| d.to_string()).collect();
        let fk = rec.keys()?;
        let me = self.vault.device_id.clone();
        let storages = self.open_storages(false)?;

        // Newest manifest per other device, across storages.
        let mut newest: BTreeMap<DeviceId, (u64, usize)> = BTreeMap::new();
        for (idx, (_, backend)) in storages.iter().enumerate() {
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

        for (dev, (seq, idx)) in newest {
            if seq <= state.last_seen.get(&dev).copied().unwrap_or(0) {
                continue;
            }
            let key = Manifest::storage_key(&rec.folder_id, &dev, seq);
            let Some(blob) = storages[idx].1.get(&key)? else {
                continue;
            };
            let m = Manifest::open(
                &blob,
                &self.vault.vault_id,
                &rec.folder_id,
                &dev,
                seq,
                &fk.meta,
            )?;
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
        Ok(report)
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
            state.files.insert(remote.path.clone(), remote);
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
                state.files.insert(remote.path.clone(), remote);
                report.files_updated += 1;
            }
            Err(e) => {
                report
                    .files_unavailable
                    .push(format!("{}: {e}", remote.path));
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
                for (spec, backend) in storages {
                    if let Some(ct) = backend.get(&key)? {
                        if ObjectName::from_bytes(&crypto::hash(&ct)) != cref.object {
                            continue; // corrupt copy; try the next storage
                        }
                        got = Some((spec.name().to_string(), ct));
                        break;
                    }
                }
                let Some((storage_name, ct)) = got else {
                    let _ = fs::remove_file(&tmp);
                    bail!(
                        "chunk {} is not available on any readable storage",
                        cref.chunk.short()
                    );
                };
                let plain = crypto::decrypt(
                    &fk.chunk_key(&cref.chunk),
                    &fk.chunk_aad(&self.vault.vault_id, &cref.chunk, cref.size),
                    &ct,
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

    /// pull then push, for every attached folder (or one).
    pub fn sync(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        let names: Vec<String> = match folder {
            Some(f) => vec![f.to_string()],
            None => self
                .folders()
                .into_iter()
                .filter(|(_, m)| m.is_some())
                .map(|(r, _)| r.name)
                .collect(),
        };
        let mut out = Vec::new();
        for name in names {
            let pull = self.pull(&name)?;
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
            });
        }
        Ok(StatusReport {
            vault_id: self.vault.vault_id.to_string(),
            device_id: self.vault.device_id.to_string(),
            device_name: self.vault.device_name.clone(),
            format_version: crate::FORMAT_VERSION,
            storages: self.config.storages.clone(),
            devices: view
                .devices
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
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
        for ((_, _), rec) in view.chunks.iter() {
            let key = chunk_storage_key(&rec.object);
            for storage in rec.storages.keys() {
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
            for ((folder, chunk), object) in &referenced {
                let key = chunk_storage_key(object);
                for (spec, backend) in &storages {
                    if let Some(ct) = backend.get(&key)? {
                        if ObjectName::from_bytes(&crypto::hash(&ct)) == *object {
                            report.objects_verified_now += 1;
                            self.pending.push(Event::ChunkVerified {
                                folder: folder.clone(),
                                chunk: chunk.clone(),
                                object: object.clone(),
                                storage: spec.name().to_string(),
                            });
                        } else {
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
        }
        Ok(report)
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
        let key = self.keys.ledger_key();
        let mut out = Vec::new();
        for s in self.ledger.all()? {
            let b = s.open(&key)?;
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
