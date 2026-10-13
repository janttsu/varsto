// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The trash (`docs/spec/alpha-0-format.md` section 43).
//!
//! A file deleted on a device keeps its last version, with its block list,
//! as a *trash entry* for a number of days (30 unless the vault or the
//! folder says otherwise). Entries live in one *trash record* per device and
//! folder, `vault/trash/<folder>/<device>/<written utc, 20 digits>.enc`,
//! replaced as a whole like the access records (`access_sync`): zstd JSON
//! sealed under a key derived from the folder's metadata key, so every
//! device that holds the folder key, members of a shared folder included,
//! can list and restore what any other device deleted. A device writes only
//! the deletions it made itself and the entries it restored or purged
//! (removals); the trash of a folder is the union of the newest record of
//! every device, less the removals of any device, less what has expired.
//!
//! Why records rather than the tombstones in manifests: a tombstone carries
//! no blocks and is replaced as soon as a new file takes the path, and the
//! trash must keep a deleted version also when the path is used again.
//!
//! The blocks of an entry count as used until it expires or is purged: data
//! moves of a whole folder take them along, a storage is not removed while
//! they would lose their last copy, and `fsck` counts them as referenced.
//! Once an entry has gone, its blocks that no current file, no other entry
//! and no other folder (backups included) uses are dropped
//! (`Event::ChunkDropped`, sealed and pushed before anything is deleted)
//! from this device's storages, except from a cold storage before its
//! minimum storage duration has passed; those wait in a local queue.
//!
//! A vault may name a *trash storage* (vault-wide setting, published as
//! `vault/trash-settings/<device>/<utc>.enc` under the folder-record key):
//! blocks only trash entries use are copied there, checked, and dropped from
//! this device's other warm storages, so warm storage is not paid for
//! deleted data. The trash storage takes no other blocks. Restoring from a
//! cold trash storage needs a confirmed cold read.

use super::verify::storage_identity;
use super::*;

const DAY: i64 = 86_400;
/// Days an entry stays in the trash unless the vault or folder says otherwise.
pub const DEFAULT_TRASH_DAYS: u32 = 30;
/// Longest retention that can be set (ten years).
pub const MAX_TRASH_DAYS: u32 = 3650;
const RECORD_PREFIX: &str = "vault/trash/";
const SETTINGS_PREFIX: &str = "vault/trash-settings/";
/// A record keeps an entry (and a removal) this long after the entry
/// expired, so every device sees it go and drops its blocks.
const KEEP_LISTED_SECS: i64 = 7 * DAY;
/// Least time between two readings of the other devices' records started
/// by a sync (listing the trash reads them at once).
const READ_EVERY_SECS: i64 = 600;
/// How often the background service runs the trash upkeep.
pub const TRASH_UPKEEP_EVERY_SECS: i64 = DAY;
/// Blocks per ledger batch when moving to the trash storage.
const MOVE_GROUP: usize = 64;

/// One deleted file version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrashEntry {
    /// Hex, derived from the folder, path, deleting device and its clock.
    pub id: String,
    pub path: String,
    pub size: u64,
    /// Modification time of the deleted version (nanoseconds).
    pub mtime: i64,
    pub content_hash: String,
    pub chunks: Vec<ChunkRef>,
    pub deleted_utc: i64,
    pub deleted_by: DeviceId,
    /// Lamport clock of the deletion.
    pub clock: u64,
}

/// An entry taken out of the trash by restoring or purging it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrashRemoval {
    pub utc: i64,
    pub by: DeviceId,
    pub restored: bool,
    /// When the entry was deleted (decides when the removal can be forgotten).
    pub deleted_utc: i64,
}

#[derive(Serialize, Deserialize)]
struct TrashBody {
    device: DeviceId,
    folder: FolderId,
    written_utc: i64,
    entries: Vec<TrashEntry>,
    #[serde(default)]
    removed: BTreeMap<String, TrashRemoval>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RemoteTrash {
    written_utc: i64,
    entries: Vec<TrashEntry>,
    #[serde(default)]
    removed: BTreeMap<String, TrashRemoval>,
}

/// `state/trash/<folder>.json`: this device's own entries and removals,
/// what it published last and the newest record of every other device.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct TrashCache {
    #[serde(default)]
    own: Vec<TrashEntry>,
    #[serde(default)]
    own_removed: BTreeMap<String, TrashRemoval>,
    #[serde(default)]
    published_utc: i64,
    #[serde(default)]
    published_hash: String,
    #[serde(default)]
    read_utc: i64,
    #[serde(default)]
    remote: BTreeMap<DeviceId, RemoteTrash>,
    /// Entries that left the trash and whose blocks were queued for dropping.
    #[serde(default)]
    queued: BTreeSet<String>,
}

/// Vault-wide trash settings (newest wins).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrashSettings {
    pub days: u32,
    /// Folders kept for another number of days.
    #[serde(default)]
    pub folder_days: BTreeMap<FolderId, u32>,
    /// Name of the trash storage on the device that set it.
    #[serde(default)]
    pub storage: Option<String>,
    /// Its identity (`vault/storage-id.json`), so devices that name it
    /// differently find it.
    #[serde(default)]
    pub storage_id: Option<String>,
    #[serde(default)]
    pub updated_utc: i64,
    #[serde(default)]
    pub device: Option<DeviceId>,
}

impl Default for TrashSettings {
    fn default() -> Self {
        TrashSettings {
            days: DEFAULT_TRASH_DAYS,
            folder_days: BTreeMap::new(),
            storage: None,
            storage_id: None,
            updated_utc: 0,
            device: None,
        }
    }
}

/// `state/trash/settings.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SettingsCache {
    #[serde(default)]
    settings: Option<TrashSettings>,
    /// The trash storage's name on this device, when it has it.
    #[serde(default)]
    local_storage: Option<String>,
    #[serde(default)]
    read_utc: i64,
    #[serde(default)]
    upkeep_utc: i64,
}

/// A block whose trash entry has gone, waiting to be dropped.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DropItem {
    folder: FolderId,
    chunk: ChunkId,
    object: ObjectName,
}

/// One entry as listed.
#[derive(Clone, Debug, Serialize)]
pub struct TrashItem {
    pub folder: String,
    pub folder_id: String,
    pub id: String,
    pub path: String,
    pub size: u64,
    pub deleted_utc: i64,
    pub deleted_by: String,
    pub deleted_by_id: String,
    pub expires_utc: i64,
    /// A copy is in this device's local trash (restored without downloading).
    pub local_copy: bool,
    /// Storages holding blocks of it.
    pub storages: Vec<String>,
    /// Its blocks are on cold storage only: restoring needs a confirmed cold read.
    pub cold_only: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TrashStatus {
    pub days: u32,
    pub folder_days: BTreeMap<String, u32>,
    pub storage: Option<String>,
    /// The trash storage's name here; `None` when this device lacks it.
    pub storage_here: Option<String>,
    pub storage_cold: bool,
    pub notes: Vec<String>,
    pub entries: u64,
    pub bytes: u64,
    /// Bytes of trash blocks per storage (a block on two storages counts twice).
    pub by_storage: BTreeMap<String, u64>,
    pub local_copies: u64,
    pub local_copy_bytes: u64,
    pub last_upkeep_utc: Option<i64>,
    pub next_expiry_utc: Option<i64>,
    /// Blocks waiting to be dropped (cold minimum duration, unreachable storage).
    pub drops_waiting: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TrashRestorePlan {
    pub folder: String,
    pub files: u64,
    pub bytes: u64,
    /// Files restored from this device's local trash.
    pub from_local_copies: u64,
    /// Cold storages that must be read, and how much.
    pub cold_storages: Vec<String>,
    pub cold_bytes: u64,
    pub read_cost: Option<String>,
    /// Entry path -> path it is restored to.
    pub targets: Vec<(String, String)>,
    /// Files no readable copy is known of.
    pub unavailable: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct RestoredFile {
    pub from: String,
    pub to: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TrashRestoreReport {
    pub folder: String,
    pub restored: Vec<RestoredFile>,
    pub bytes: u64,
    pub from_local_copies: u64,
    pub from_storages: u64,
    pub cold_read: bool,
    pub unavailable: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TrashPurgeReport {
    pub entries: u64,
    pub bytes: u64,
    pub blocks_dropped: u64,
    pub bytes_dropped: u64,
    /// Blocks kept for now (a cold storage's minimum duration).
    pub blocks_waiting: u64,
    pub local_copies_removed: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TrashUpkeepReport {
    pub expired: u64,
    pub blocks_dropped: u64,
    pub bytes_dropped: u64,
    pub blocks_waiting: u64,
    pub blocks_moved: u64,
    pub bytes_moved: u64,
    pub local_copies_removed: u64,
    pub notes: Vec<String>,
}

#[derive(Default)]
struct DropCounts {
    dropped: u64,
    bytes: u64,
    waiting: u64,
}

fn record_key(meta: &SecretKey, folder: &FolderId) -> SecretKey {
    meta.derive("trash-record", &[folder.as_str().as_bytes()])
}

fn record_aad(vault: &VaultId, folder: &FolderId, device: &DeviceId, written: i64) -> Vec<u8> {
    crypto::aad(
        "trash-record",
        &[
            vault.as_str().as_bytes(),
            folder.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &written.to_le_bytes(),
        ],
    )
}

fn record_storage_key(folder: &FolderId, device: &DeviceId, written: i64) -> String {
    format!("{RECORD_PREFIX}{folder}/{device}/{written:020}.enc")
}

/// Every trash record of a folder (removing a folder deletes them).
pub(super) fn record_prefix(folder: &FolderId) -> String {
    format!("{RECORD_PREFIX}{folder}/")
}

fn settings_key(base: &SecretKey) -> SecretKey {
    base.derive("trash-settings", &[])
}

fn settings_aad(vault: &VaultId, device: &DeviceId, written: i64) -> Vec<u8> {
    crypto::aad(
        "trash-settings",
        &[
            vault.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &written.to_le_bytes(),
        ],
    )
}

fn entry_id(folder: &FolderId, path: &str, device: &DeviceId, clock: u64) -> String {
    let h = crypto::hash(
        &[
            b"varsto-trash-entry".as_slice(),
            folder.as_str().as_bytes(),
            &[0],
            path.as_bytes(),
            &[0],
            device.as_str().as_bytes(),
            &clock.to_le_bytes(),
        ]
        .concat(),
    );
    hex::encode(&h[..16])
}

/// An entry from another device's record that could have come from an
/// honest device: its own deletion, a path inside the folder, sizes that
/// add up.
fn entry_valid(e: &TrashEntry, folder: &FolderId, writer: &DeviceId) -> bool {
    if &e.deleted_by != writer || e.id != entry_id(folder, &e.path, writer, e.clock) {
        return false;
    }
    if util::check_rel_path(&e.path).is_err() {
        return false;
    }
    let mut total: u64 = 0;
    for c in &e.chunks {
        if c.size == 0 || c.size > manifest::MAX_CHUNK_SIZE {
            return false;
        }
        total = match total.checked_add(c.size) {
            Some(t) => t,
            None => return false,
        };
    }
    total == e.size
}

/// Whether `path` is `sel` or lies under the directory `sel`.
fn under(path: &str, sel: &str) -> bool {
    let sel = sel.trim_matches('/');
    sel.is_empty() || path == sel || path.strip_prefix(sel).is_some_and(|r| r.starts_with('/'))
}

/// `report.txt` -> `report (restored).txt`, `report (restored 2).txt`, ...
pub fn restored_name(path: &str, n: u32) -> String {
    let (dir, name) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let tag = if n <= 1 {
        " (restored)".to_string()
    } else {
        format!(" (restored {n})")
    };
    let new_name = match name.rfind('.') {
        Some(i) if i > 0 => format!("{}{}{}", &name[..i], tag, &name[i..]),
        _ => format!("{name}{tag}"),
    };
    format!("{dir}{new_name}")
}

/// Entries to restore: the entry, its target path, a local copy to use.
type RestoreWork = Vec<(TrashEntry, String, Option<PathBuf>)>;

/// What is in a folder's trash at some time.
struct TrashSets {
    /// In the trash now (newest deletion first).
    visible: Vec<TrashEntry>,
    /// Expired or purged, still listed in some record: their blocks may go.
    gone: Vec<TrashEntry>,
    /// Restored: their blocks are the restored files' blocks.
    restored: Vec<TrashEntry>,
}

impl Engine {
    // ----- local files -------------------------------------------------------

    fn trash_state_dir(&self) -> PathBuf {
        self.home.join("state").join("trash")
    }

    fn trash_cache_path(&self, folder: &FolderId) -> PathBuf {
        self.trash_state_dir().join(format!("{folder}.json"))
    }

    fn load_trash_cache(&self, folder: &FolderId) -> TrashCache {
        util::read_json_or_default(&self.trash_cache_path(folder)).unwrap_or_default()
    }

    fn save_trash_cache(&self, folder: &FolderId, cache: &TrashCache) -> Result<()> {
        util::write_json(&self.trash_cache_path(folder), cache)
    }

    fn settings_cache_path(&self) -> PathBuf {
        self.trash_state_dir().join("settings.json")
    }

    fn load_settings_cache(&self) -> SettingsCache {
        util::read_json_or_default(&self.settings_cache_path()).unwrap_or_default()
    }

    fn save_settings_cache(&self, c: &SettingsCache) -> Result<()> {
        util::write_json(&self.settings_cache_path(), c)
    }

    fn drops_path(&self) -> PathBuf {
        self.trash_state_dir().join("drops.json")
    }

    /// The vault's trash settings as this device knows them.
    pub fn trash_settings(&self) -> TrashSettings {
        self.load_settings_cache().settings.unwrap_or_default()
    }

    /// Days a folder's entries are kept.
    pub fn trash_days_for(&self, folder: &FolderId) -> u32 {
        let s = self.trash_settings();
        s.folder_days.get(folder).copied().unwrap_or(s.days).max(1)
    }

    /// The trash storage's name on this device, if it has it.
    pub(super) fn trash_storage_here(&self) -> Option<String> {
        let c = self.load_settings_cache();
        c.settings.as_ref()?.storage.as_ref()?;
        c.local_storage
            .filter(|n| self.config.storages.iter().any(|s| s.name() == n))
    }

    /// Find the trash storage among this device's storages: by identity,
    /// else by name.
    fn resolve_trash_storage(&self, s: &TrashSettings) -> Option<String> {
        let name = s.storage.as_ref()?;
        if let Some(id) = &s.storage_id {
            for spec in self
                .config
                .storages
                .iter()
                .filter(|x| !x.is_carrier() && !x.is_data_only())
            {
                let found = self
                    .open_spec(spec)
                    .ok()
                    .and_then(|b| storage_identity(b.as_ref()).ok());
                if found.as_deref() == Some(id.as_str()) {
                    return Some(spec.name().to_string());
                }
            }
        }
        self.config
            .storages
            .iter()
            .find(|x| x.name() == name && !x.is_carrier())
            .map(|x| x.name().to_string())
    }

    /// The local trash directory of a folder (`<home>/trash/<folder>`).
    fn local_trash_dir(&self, folder: &FolderId) -> PathBuf {
        self.home.join("trash").join(folder.as_str())
    }

    /// Copies of `entry` in this device's local trash: files named
    /// `<path>.<time>` with its size and content, written under the local
    /// form of that name (`crate::names`, as a pull writes them).
    fn local_copies(&self, fk: &FolderKeys, entry: &TrashEntry) -> Vec<PathBuf> {
        let trash_root = self.local_trash_dir(&fk.folder);
        let rules = self.local_rules(&trash_root);
        let Ok(base) = util::safe_join(&trash_root, &rules.default_local(&entry.path)) else {
            return Vec::new();
        };
        let Some(dir) = base.parent() else {
            return Vec::new();
        };
        let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
        let prefix = format!("{name}.");
        let Ok(list) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in list.flatten() {
            let local = e.file_name().to_string_lossy().to_string();
            let n = rules.default_vault(&local);
            let Some(stamp) = n.strip_prefix(&prefix) else {
                continue;
            };
            if stamp.is_empty() || !stamp.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let p = e.path();
            if !fs::metadata(&p).is_ok_and(|m| m.is_file() && m.len() == entry.size) {
                continue;
            }
            if Self::file_content_hash(fk, &p).as_deref() == Some(entry.content_hash.as_str()) {
                out.push(p);
            }
        }
        out
    }

    fn file_content_hash(fk: &FolderKeys, path: &Path) -> Option<String> {
        use std::io::Read;
        let mut f = fs::File::open(path).ok()?;
        let mut h = KeyedHasher::new(&fk.hash);
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Some(hex::encode(h.finalize()))
    }

    // ----- recording deletions -------------------------------------------------

    /// Record deletions this device's scan found: `gone` holds the last live
    /// version of each and the clock of its deletion. A file whose content
    /// is still in the folder under another path (a rename) is not trashed.
    pub(super) fn trash_record_deletions(
        &self,
        rec: &FolderRecord,
        state: &FolderState,
        gone: Vec<(FileState, u64)>,
    ) -> Result<()> {
        if gone.is_empty() || rec.is_backup() {
            return Ok(());
        }
        let live: HashSet<&str> = state
            .files
            .values()
            .filter(|f| !f.deleted)
            .map(|f| f.content_hash.as_str())
            .collect();
        let me = self.vault.device_id.clone();
        let now = util::now_utc();
        let mut cache = self.load_trash_cache(&rec.folder_id);
        let mut added = false;
        for (prev, clock) in gone {
            if prev.deleted || live.contains(prev.content_hash.as_str()) {
                continue;
            }
            cache.own.push(TrashEntry {
                id: entry_id(&rec.folder_id, &prev.path, &me, clock),
                path: prev.path,
                size: prev.size,
                mtime: prev.mtime,
                content_hash: prev.content_hash,
                chunks: prev.chunks,
                deleted_utc: now,
                deleted_by: me.clone(),
                clock,
            });
            added = true;
        }
        if added {
            self.save_trash_cache(&rec.folder_id, &cache)?;
        }
        Ok(())
    }

    // ----- records on the storages -----------------------------------------------

    /// Publish this device's trash record of a folder when it changed,
    /// forgetting entries long expired (their blocks are queued for
    /// dropping first). Returns whether a record was written.
    pub(super) fn trash_publish(&mut self, rec: &FolderRecord, now: i64) -> Result<bool> {
        if rec.is_backup() {
            return Ok(false);
        }
        let mut cache = self.load_trash_cache(&rec.folder_id);
        let keep = self.trash_days_for(&rec.folder_id) as i64 * DAY + KEEP_LISTED_SECS;
        let (old, own): (Vec<TrashEntry>, Vec<TrashEntry>) = std::mem::take(&mut cache.own)
            .into_iter()
            .partition(|e| now >= e.deleted_utc + keep);
        cache.own = own;
        cache.own_removed.retain(|_, r| now < r.deleted_utc + keep);
        if !old.is_empty() {
            self.trash_enqueue(&rec.folder_id, &old)?;
        }
        let json = serde_json::to_vec(&(&cache.own, &cache.own_removed))?;
        let hash = hex::encode(crypto::hash(&json));
        if hash == cache.published_hash
            || (cache.published_hash.is_empty()
                && cache.own.is_empty()
                && cache.own_removed.is_empty())
        {
            self.save_trash_cache(&rec.folder_id, &cache)?;
            return Ok(false);
        }
        let storages = self.metadata_storages(true)?;
        let storages: OpenStorages = storages
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        if storages.is_empty() {
            self.save_trash_cache(&rec.folder_id, &cache)?;
            return Ok(false);
        }
        let fk = self.folder_keys(rec)?;
        let me = self.vault.device_id.clone();
        let written = now.max(cache.published_utc + 1);
        let body = TrashBody {
            device: me.clone(),
            folder: rec.folder_id.clone(),
            written_utc: written,
            entries: cache.own.clone(),
            removed: cache.own_removed.clone(),
        };
        let packed = zstd::bulk::compress(&serde_json::to_vec(&body)?, 3)?;
        let blob = crypto::encrypt(
            &record_key(&fk.meta, &rec.folder_id),
            &record_aad(&self.vault.vault_id, &rec.folder_id, &me, written),
            &packed,
        )?;
        let key = record_storage_key(&rec.folder_id, &me, written);
        let own = format!("{}{me}/", record_prefix(&rec.folder_id));
        for (_, b) in &storages {
            b.put_if_absent(&key, &blob)?;
            // Only the newest record of a device is read.
            for old in b.list(&own)? {
                if old != key {
                    b.delete(&old)?;
                }
            }
        }
        cache.published_utc = written;
        cache.published_hash = hash;
        self.save_trash_cache(&rec.folder_id, &cache)?;
        Ok(true)
    }

    /// Read the newest trash record of every other device of a folder.
    fn trash_read(
        &self,
        storages: &OpenStorages,
        fk: &FolderKeys,
        cache: &mut TrashCache,
    ) -> Result<usize> {
        let prefix = record_prefix(&fk.folder);
        let mut newest: BTreeMap<DeviceId, (i64, usize, String)> = BTreeMap::new();
        for (i, (_, b)) in storages.iter().enumerate() {
            for key in b.list(&prefix)? {
                let Some((dev, file)) = key.strip_prefix(&prefix).and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Some(t)) = (
                    DeviceId::from_hex(dev),
                    file.strip_suffix(".enc")
                        .and_then(|t| t.parse::<i64>().ok()),
                ) else {
                    continue;
                };
                if newest.get(&dev).is_none_or(|(n, _, _)| t > *n) {
                    newest.insert(dev, (t, i, key));
                }
            }
        }
        let metas = fk.meta_keys();
        let mut read = 0;
        for (dev, (t, i, key)) in newest {
            let known =
                self.devices.devices.contains_key(&dev) || self.devices.members.contains_key(&dev);
            if dev == self.vault.device_id || !known || self.is_revoked(&dev) {
                continue;
            }
            if cache.remote.get(&dev).is_some_and(|r| r.written_utc >= t) {
                continue;
            }
            let Some(blob) = storages[i].1.get(&key)? else {
                continue;
            };
            let a = record_aad(&self.vault.vault_id, &fk.folder, &dev, t);
            let Some(packed) = metas
                .iter()
                .find_map(|m| crypto::decrypt(&record_key(m, &fk.folder), &a, &blob).ok())
            else {
                continue;
            };
            let Ok(json) = zstd::bulk::decompress(&packed, 256 << 20) else {
                continue;
            };
            let Ok(body) = serde_json::from_slice::<TrashBody>(&json) else {
                continue;
            };
            if body.device != dev || body.folder != fk.folder || body.written_utc != t {
                continue;
            }
            let entries = body
                .entries
                .into_iter()
                .filter(|e| entry_valid(e, &fk.folder, &dev))
                .collect();
            cache.remote.insert(
                dev,
                RemoteTrash {
                    written_utc: t,
                    entries,
                    removed: body.removed,
                },
            );
            read += 1;
        }
        Ok(read)
    }

    /// Read the other devices' trash records (every folder whose key is at
    /// hand) and the vault's trash settings, when the last reading is older
    /// than a few minutes or `force`.
    pub(super) fn trash_refresh(&mut self, force: bool) -> Result<()> {
        if self.removal.is_some() {
            return Ok(());
        }
        let now = util::now_utc();
        let storages: OpenStorages = self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        if storages.is_empty() {
            return Ok(());
        }
        self.trash_read_settings(&storages, force, now)?;
        let folders: Vec<FolderRecord> = self.folders().into_iter().map(|(r, _)| r).collect();
        for rec in folders {
            let Ok(rec) = self.with_key(&rec) else {
                continue; // a locked Strongroom
            };
            let mut cache = self.load_trash_cache(&rec.folder_id);
            if !force && now - cache.read_utc < READ_EVERY_SECS {
                continue;
            }
            let fk = self.folder_keys(&rec)?;
            self.trash_read(&storages, &fk, &mut cache)?;
            cache.read_utc = now;
            self.save_trash_cache(&rec.folder_id, &cache)?;
        }
        Ok(())
    }

    fn trash_read_settings(
        &mut self,
        storages: &OpenStorages,
        force: bool,
        now: i64,
    ) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        let mut cache = self.load_settings_cache();
        if !force && now - cache.read_utc < READ_EVERY_SECS {
            return Ok(());
        }
        let known = cache.settings.as_ref().map(|s| s.updated_utc).unwrap_or(0);
        let mut best: Option<(i64, DeviceId, usize, String)> = None;
        for (i, (_, b)) in storages.iter().enumerate() {
            for key in b.list(SETTINGS_PREFIX)? {
                let Some((dev, file)) = key
                    .strip_prefix(SETTINGS_PREFIX)
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Some(t)) = (
                    DeviceId::from_hex(dev),
                    file.strip_suffix(".enc")
                        .and_then(|t| t.parse::<i64>().ok()),
                ) else {
                    continue;
                };
                if t <= known || !self.trusted(&dev) {
                    continue;
                }
                if best.as_ref().is_none_or(|(n, d, _, _)| (t, &dev) > (*n, d)) {
                    best = Some((t, dev, i, key));
                }
            }
        }
        if let Some((t, dev, i, key)) = best {
            if let Some(blob) = storages[i].1.get(&key)? {
                let a = settings_aad(&self.vault.vault_id, &dev, t);
                let opened = self
                    .folder_record_keys()
                    .iter()
                    .find_map(|k| crypto::decrypt(&settings_key(k), &a, &blob).ok())
                    .and_then(|j| serde_json::from_slice::<TrashSettings>(&j).ok())
                    .filter(|s| s.updated_utc == t && s.device.as_ref() == Some(&dev));
                if let Some(mut s) = opened {
                    s.days = s.days.clamp(1, MAX_TRASH_DAYS);
                    cache.local_storage = self.resolve_trash_storage(&s);
                    cache.settings = Some(s);
                }
            }
        }
        cache.read_utc = now;
        self.save_settings_cache(&cache)
    }

    /// What is in a folder's trash at `now`.
    fn trash_sets(&self, folder: &FolderId, now: i64) -> TrashSets {
        let cache = self.load_trash_cache(folder);
        let days = self.trash_days_for(folder) as i64;
        let mut removed: HashMap<String, bool> = cache
            .own_removed
            .iter()
            .map(|(id, r)| (id.clone(), r.restored))
            .collect();
        let mut all: BTreeMap<String, TrashEntry> = BTreeMap::new();
        for e in &cache.own {
            all.insert(e.id.clone(), e.clone());
        }
        for (dev, r) in &cache.remote {
            if self.is_revoked(dev) {
                continue;
            }
            // A member of a shared folder (another person) cannot take
            // entries out of the owner's trash: on the owner's devices its
            // removals do not count (its deletions do).
            let member = !self.vault.member && self.devices.members.contains_key(dev);
            for (id, x) in r.removed.iter().filter(|_| !member) {
                // Purged anywhere counts as purged.
                let e = removed.entry(id.clone()).or_insert(x.restored);
                *e = *e && x.restored;
            }
            for e in &r.entries {
                all.entry(e.id.clone()).or_insert_with(|| e.clone());
            }
        }
        let mut sets = TrashSets {
            visible: Vec::new(),
            gone: Vec::new(),
            restored: Vec::new(),
        };
        for (id, e) in all {
            match removed.get(&id) {
                Some(true) => sets.restored.push(e),
                Some(false) => sets.gone.push(e),
                None if now >= e.deleted_utc + days * DAY => sets.gone.push(e),
                None => sets.visible.push(e),
            }
        }
        sets.visible
            .sort_by(|a, b| b.deleted_utc.cmp(&a.deleted_utc).then(a.path.cmp(&b.path)));
        sets
    }

    /// Blocks of the entries in a folder's trash now (they count as used).
    pub(super) fn trash_chunks(&self, folder: &FolderId) -> Vec<ChunkRef> {
        self.trash_sets(folder, util::now_utc())
            .visible
            .into_iter()
            .flat_map(|e| e.chunks)
            .collect()
    }

    /// Chunks of a folder that must stay: current files (and versions still
    /// to download) and entries in the trash.
    fn chunks_in_use(&self, folder: &FolderId, state: &FolderState, now: i64) -> HashSet<ChunkId> {
        let mut out: HashSet<ChunkId> = state
            .files
            .values()
            .chain(state.pending_remote.values())
            .filter(|f| !f.deleted)
            .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
            .collect();
        for e in self.trash_sets(folder, now).visible {
            out.extend(e.chunks.into_iter().map(|c| c.chunk));
        }
        out
    }

    // ----- dropping blocks ------------------------------------------------------

    fn trash_enqueue(&self, folder: &FolderId, entries: &[TrashEntry]) -> Result<()> {
        let mut queue: Vec<DropItem> =
            util::read_json_or_default(&self.drops_path()).unwrap_or_default();
        let mut have: HashSet<(FolderId, ChunkId)> = queue
            .iter()
            .map(|d| (d.folder.clone(), d.chunk.clone()))
            .collect();
        for e in entries {
            for c in &e.chunks {
                if have.insert((folder.clone(), c.chunk.clone())) {
                    queue.push(DropItem {
                        folder: folder.clone(),
                        chunk: c.chunk.clone(),
                        object: c.object.clone(),
                    });
                }
            }
        }
        util::write_json(&self.drops_path(), &queue)
    }

    /// Seal and push the pending events now, also inside a sync.
    fn commit_now(&mut self) -> Result<()> {
        let cycle = self.cycle.take();
        let committed = self.commit_batch();
        self.cycle = cycle;
        committed.map(|_| ())
    }

    /// The minimum storage duration of a storage, in seconds, if known.
    fn minimum_secs(&self, storage: &str) -> Option<i64> {
        self.storage_price(storage)
            .and_then(|p| p.minimum_storage_days)
            .map(|d| d as i64 * DAY)
    }

    /// Drop the queued blocks that nothing uses any more from this device's
    /// storages: the drops are sealed and pushed before anything is deleted.
    fn trash_drop_queued(
        &mut self,
        now: i64,
        stale: &BTreeSet<FolderId>,
        counts: &mut DropCounts,
    ) -> Result<()> {
        if self.vault.member || self.forked_self {
            return Ok(());
        }
        let mut queue: Vec<DropItem> =
            util::read_json_or_default(&self.drops_path()).unwrap_or_default();
        if queue.is_empty() {
            return Ok(());
        }
        let view = self.view()?;
        let mut in_use: BTreeMap<FolderId, Option<HashSet<ChunkId>>> = BTreeMap::new();
        let mut keep: Vec<DropItem> = Vec::new();
        let mut deletes: Vec<(String, ObjectName, u64)> = Vec::new();
        let local: BTreeMap<&str, &StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| (s.name(), s))
            .collect();
        // Objects other folders (backups too) name: never dropped here.
        let mut elsewhere: HashMap<&ObjectName, BTreeSet<&FolderId>> = HashMap::new();
        for ((f, _), r) in &view.chunks {
            elsewhere.entry(&r.object).or_default().insert(f);
        }
        for item in std::mem::take(&mut queue) {
            if stale.contains(&item.folder) {
                // Its state could not be brought up to date: judged later.
                keep.push(item);
                continue;
            }
            let used = in_use.entry(item.folder.clone()).or_insert_with(|| {
                let attached = self
                    .config
                    .folders
                    .iter()
                    .any(|m| m.folder_id == item.folder);
                let removed = self
                    .keyring
                    .folders
                    .get(&item.folder)
                    .is_none_or(|r| r.is_removed());
                if !attached || removed || !self.state_path(&item.folder).exists() {
                    return None;
                }
                self.load_state(&item.folder)
                    .ok()
                    .map(|st| self.chunks_in_use(&item.folder, &st, now))
            });
            // Not judged here (folder not attached): left alone.
            let Some(used) = used else { continue };
            if used.contains(&item.chunk) {
                continue;
            }
            if elsewhere
                .get(&item.object)
                .is_some_and(|fs| fs.iter().any(|f| *f != &item.folder))
            {
                continue;
            }
            let Some(r) = view
                .locate(&item.folder, &item.chunk)
                .filter(|r| r.object == item.object)
            else {
                continue;
            };
            let mut waiting = false;
            for (storage, loc) in &r.storages {
                let Some(spec) = local.get(storage.as_str()) else {
                    continue;
                };
                if spec.is_cold() {
                    if let Some(min) = self.minimum_secs(storage) {
                        if now < loc.claimed_utc + min {
                            waiting = true;
                            counts.waiting += 1;
                            continue;
                        }
                    }
                }
                self.pending.push(Event::ChunkDropped {
                    folder: item.folder.clone(),
                    chunk: item.chunk.clone(),
                    object: item.object.clone(),
                    storage: storage.clone(),
                });
                deletes.push((storage.clone(), item.object.clone(), r.size));
            }
            if waiting {
                keep.push(item);
            }
        }
        self.commit_now()?;
        let mut claimed: BTreeMap<String, HashSet<ObjectName>> = BTreeMap::new();
        let mut opened: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for (storage, object, size) in deletes {
            if !claimed.contains_key(&storage) {
                claimed.insert(storage.clone(), self.objects_claimed_on(&storage)?);
            }
            if claimed[&storage].contains(&object) {
                continue;
            }
            if !opened.contains_key(&storage) {
                match self.open_storage(&storage) {
                    Ok(b) => {
                        opened.insert(storage.clone(), b);
                    }
                    Err(_) => continue,
                }
            }
            let b = &opened[&storage];
            let key = chunk_storage_key(&object);
            if b.exists(&key).unwrap_or(false) && b.delete(&key).is_ok() {
                counts.dropped += 1;
                counts.bytes += size;
            }
        }
        util::write_json(&self.drops_path(), &keep)
    }

    // ----- the trash storage -------------------------------------------------------

    /// Move the blocks only trash entries of `rec` use to the trash storage:
    /// copy, check, record, drop from this device's other warm storages.
    fn trash_to_storage(
        &mut self,
        rec: &FolderRecord,
        now: i64,
        report: &mut TrashUpkeepReport,
    ) -> Result<()> {
        let Some(ts_name) = self.trash_storage_here() else {
            return Ok(());
        };
        // A trash storage being drained takes nothing new (`drain`).
        if self.closed_storages().contains(&ts_name) {
            return Ok(());
        }
        if self.vault.member || !self.state_path(&rec.folder_id).exists() {
            return Ok(());
        }
        let Some(ts_spec) = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == ts_name)
            .cloned()
        else {
            return Ok(());
        };
        let state = self.load_state(&rec.folder_id)?;
        let live: HashSet<ChunkId> = state
            .files
            .values()
            .chain(state.pending_remote.values())
            .filter(|f| !f.deleted)
            .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
            .collect();
        let view = self.view()?;
        let warm: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier() && !s.is_cold() && s.name() != ts_name)
            .map(|s| s.name().to_string())
            .collect();
        let mut items: Vec<(ChunkRef, bool)> = Vec::new();
        let mut seen: HashSet<ChunkId> = HashSet::new();
        for e in self.trash_sets(&rec.folder_id, now).visible {
            for c in e.chunks {
                if live.contains(&c.chunk) || !seen.insert(c.chunk.clone()) {
                    continue;
                }
                let Some(r) = view
                    .locate(&rec.folder_id, &c.chunk)
                    .filter(|r| r.object == c.object)
                else {
                    continue;
                };
                // Another folder naming the object keeps it where it is.
                if view
                    .chunks
                    .iter()
                    .any(|((f, _), o)| f != &rec.folder_id && o.object == c.object)
                {
                    continue;
                }
                let on_ts = r.storages.contains_key(&ts_name);
                let on_warm = r.storages.keys().any(|n| warm.contains(n));
                if on_ts && !on_warm {
                    continue;
                }
                items.push((c, on_ts));
            }
        }
        if items.is_empty() {
            return Ok(());
        }
        let ts = self.open_spec(&ts_spec)?;
        let sources: OpenStorages = self
            .open_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier() && s.name() != ts_name)
            .collect();
        let read_back = !ts_spec.is_cold();
        let task = activity::start(
            activity::TRASH_MOVE,
            &rec.name,
            items.iter().map(|(c, _)| c.size).sum(),
            activity::Unit::Bytes,
        );
        // A trash storage with a quota takes what fits; the rest stays where
        // it is (`quotas`).
        let gate = self.quota_gate(&view);
        let mut failed = 0u64;
        for group in items.chunks(MOVE_GROUP) {
            task.advance(group.iter().map(|(c, _)| c.size).sum());
            let mut deletes: Vec<(String, ObjectName, u64)> = Vec::new();
            for (c, on_ts) in group {
                let key = chunk_storage_key(&c.object);
                let good = |ct: &Vec<u8>| ObjectName::from_bytes(&crypto::hash(ct)) == c.object;
                if !on_ts {
                    if !gate.take(&ts_name, c.size) {
                        continue;
                    }
                    let ct = self.cached_object(&c.object).or_else(|| {
                        match fetch::fetch_object(
                            self.peers.as_deref(),
                            &c.object,
                            &sources,
                            &self.fetch_stats,
                        ) {
                            Fetched::Got { bytes, .. } if good(&bytes) => Some(bytes),
                            _ => None,
                        }
                    });
                    let Some(ct) = ct else {
                        failed += 1;
                        continue;
                    };
                    if ts.put_if_absent(&key, &ct).is_err() {
                        failed += 1;
                        continue;
                    }
                    let checked = if read_back {
                        matches!(ts.get(&key), Ok(Some(b)) if good(&b))
                    } else {
                        ts.exists(&key).unwrap_or(false)
                    };
                    if !checked {
                        failed += 1;
                        continue;
                    }
                    self.pending.push(Event::ChunkStored {
                        folder: rec.folder_id.clone(),
                        chunk: c.chunk.clone(),
                        object: c.object.clone(),
                        storage: ts_name.clone(),
                        size: ct.len() as u64,
                    });
                    if read_back {
                        self.pending.push(Event::ChunkVerified {
                            folder: rec.folder_id.clone(),
                            chunk: c.chunk.clone(),
                            object: c.object.clone(),
                            storage: ts_name.clone(),
                        });
                    }
                    report.blocks_moved += 1;
                    report.bytes_moved += c.size;
                }
                let Some(r) = view.locate(&rec.folder_id, &c.chunk) else {
                    continue;
                };
                for n in r.storages.keys().filter(|n| warm.contains(*n)) {
                    self.pending.push(Event::ChunkDropped {
                        folder: rec.folder_id.clone(),
                        chunk: c.chunk.clone(),
                        object: c.object.clone(),
                        storage: n.clone(),
                    });
                    deletes.push((n.clone(), c.object.clone(), c.size));
                }
            }
            // The copies and drops are sealed and pushed before anything is deleted.
            self.commit_now()?;
            let mut claimed: BTreeMap<String, HashSet<ObjectName>> = BTreeMap::new();
            for (storage, object, _) in deletes {
                if !claimed.contains_key(&storage) {
                    claimed.insert(storage.clone(), self.objects_claimed_on(&storage)?);
                }
                if claimed[&storage].contains(&object) {
                    continue;
                }
                if let Ok(b) = self.open_storage(&storage) {
                    let _ = b.delete(&chunk_storage_key(&object));
                }
            }
        }
        if failed > 0 {
            report.notes.push(format!(
                "{failed} block{} of folder {} could not be copied to the trash storage {ts_name}; they stay where they are and are tried again",
                if failed == 1 { "" } else { "s" },
                rec.name
            ));
        }
        report.notes.extend(gate.refusals());
        if ts_spec.is_cold() {
            if let Some(d) = self.minimum_secs(&ts_name) {
                report.notes.push(format!(
                    "{ts_name} bills every block for at least {} days: blocks are not deleted from it earlier, even when the trash is emptied",
                    d / DAY
                ));
            }
        }
        Ok(())
    }

    // ----- what the user sees and does ----------------------------------------------

    fn trash_folders(&self, folder: Option<&str>) -> Result<Vec<FolderRecord>> {
        match folder {
            Some(f) => {
                let rec = self
                    .keyring
                    .find(f)
                    .filter(|r| !r.is_removed() && !r.is_backup())
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown folder {f}"))?;
                Ok(vec![self.with_key(&rec)?])
            }
            None => Ok(self
                .folders()
                .into_iter()
                .filter_map(|(r, _)| self.with_key(&r).ok())
                .collect()),
        }
    }

    /// The trash of one folder or of every folder, newest deletion first.
    pub fn trash_list(&mut self, folder: Option<&str>) -> Result<Vec<TrashItem>> {
        self.trash_refresh(true)?;
        let now = util::now_utc();
        let view = self.view()?;
        let mut out = Vec::new();
        for rec in self.trash_folders(folder)? {
            let fk = self.folder_keys(&rec)?;
            let days = self.trash_days_for(&rec.folder_id) as i64;
            for e in self.trash_sets(&rec.folder_id, now).visible {
                let local_copy = !self.local_copies(&fk, &e).is_empty();
                let (storages, cold_only) = self.entry_storages(&view, &rec.folder_id, &e);
                out.push(TrashItem {
                    folder: rec.name.clone(),
                    folder_id: rec.folder_id.to_string(),
                    id: e.id.clone(),
                    path: e.path.clone(),
                    size: e.size,
                    deleted_utc: e.deleted_utc,
                    deleted_by: self.device_name(&e.deleted_by),
                    deleted_by_id: e.deleted_by.to_string(),
                    expires_utc: e.deleted_utc + days * DAY,
                    local_copy,
                    storages,
                    cold_only: cold_only && !local_copy,
                });
            }
        }
        out.sort_by(|a, b| {
            b.deleted_utc
                .cmp(&a.deleted_utc)
                .then(a.folder.cmp(&b.folder))
                .then(a.path.cmp(&b.path))
        });
        Ok(out)
    }

    /// Storages holding blocks of an entry, and whether a block can be read
    /// only from cold storage.
    fn entry_storages(
        &self,
        view: &LedgerView,
        folder: &FolderId,
        e: &TrashEntry,
    ) -> (Vec<String>, bool) {
        let mut names = BTreeSet::new();
        let mut cold_only = false;
        for c in &e.chunks {
            let Some(r) = view
                .locate(folder, &c.chunk)
                .filter(|r| r.object == c.object)
            else {
                continue;
            };
            names.extend(r.storages.keys().cloned());
            if self.needs_cold_read(r, c) {
                cold_only = true;
            }
        }
        (names.into_iter().collect(), cold_only)
    }

    /// A block that no warm storage of this device and no cache holds, but a
    /// cold one does.
    fn needs_cold_read(&self, r: &crate::ledger::ChunkRecord, c: &ChunkRef) -> bool {
        let spec = |n: &str| self.config.storages.iter().find(|s| s.name() == n);
        let warm = r
            .storages
            .keys()
            .any(|n| spec(n).is_some_and(|s| !s.is_cold() && !s.is_carrier()));
        let cold = r
            .storages
            .keys()
            .any(|n| spec(n).is_some_and(|s| s.is_cold()));
        !warm && cold && self.cached_object(&c.object).is_none()
    }

    /// Settings, totals and where the trash's blocks are.
    pub fn trash_status(&mut self) -> Result<TrashStatus> {
        self.trash_refresh(true)?;
        self.trash_status_cached()
    }

    /// `trash_status` from what this device read last, without asking the
    /// storages (for the Help page).
    pub fn trash_status_cached(&self) -> Result<TrashStatus> {
        let now = util::now_utc();
        let settings = self.trash_settings();
        let cache = self.load_settings_cache();
        let view = self.view()?;
        let mut st = TrashStatus {
            days: settings.days,
            storage: settings.storage.clone(),
            storage_here: self.trash_storage_here(),
            last_upkeep_utc: (cache.upkeep_utc > 0).then_some(cache.upkeep_utc),
            ..Default::default()
        };
        for (fid, d) in &settings.folder_days {
            if let Some(r) = self.keyring.folders.get(fid).filter(|r| !r.is_removed()) {
                st.folder_days.insert(r.name.clone(), *d);
            }
        }
        if let Some(n) = &st.storage_here {
            st.storage_cold = self
                .config
                .storages
                .iter()
                .any(|s| s.name() == n && s.is_cold());
        } else if let Some(n) = &settings.storage {
            st.notes.push(format!(
                "the trash storage {n} is not a storage of this device: this device keeps trashed blocks where they are"
            ));
        }
        for rec in self.trash_folders(None)? {
            let fk = self.folder_keys(&rec)?;
            let days = self.trash_days_for(&rec.folder_id) as i64;
            let mut seen: HashSet<ChunkId> = HashSet::new();
            for e in self.trash_sets(&rec.folder_id, now).visible {
                st.entries += 1;
                st.bytes += e.size;
                let exp = e.deleted_utc + days * DAY;
                if st.next_expiry_utc.is_none_or(|t| exp < t) {
                    st.next_expiry_utc = Some(exp);
                }
                for c in &e.chunks {
                    if !seen.insert(c.chunk.clone()) {
                        continue;
                    }
                    if let Some(r) = view.locate(&rec.folder_id, &c.chunk) {
                        for n in r.storages.keys() {
                            *st.by_storage.entry(n.clone()).or_default() += c.size;
                        }
                    }
                }
            }
            let dir = self.local_trash_dir(&fk.folder);
            for e in walkdir::WalkDir::new(&dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                st.local_copies += 1;
                st.local_copy_bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        let queue: Vec<DropItem> =
            util::read_json_or_default(&self.drops_path()).unwrap_or_default();
        st.drops_waiting = queue.len() as u64;
        Ok(st)
    }

    /// Change the vault's trash settings: the days entries are kept (for
    /// the vault, or with `folder` for one folder; 0 there returns the
    /// folder to the vault's days), and the trash storage (`Some(None)`
    /// clears it). Published so every device keeps the same.
    pub fn trash_set(
        &mut self,
        days: Option<u32>,
        folder: Option<&str>,
        storage: Option<Option<String>>,
    ) -> Result<TrashStatus> {
        if self.vault.member {
            bail!("a member device cannot change the owner's trash settings");
        }
        self.org_allows(|p| p.members_may_set_policies, "change the trash settings")?;
        let storages: OpenStorages = self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        // Start from the newest settings any device published.
        self.trash_read_settings(&storages, true, util::now_utc())?;
        let mut s = self.trash_settings();
        match (folder, days) {
            (Some(f), Some(d)) => {
                if d > MAX_TRASH_DAYS {
                    bail!("the trash keeps files at most {MAX_TRASH_DAYS} days");
                }
                let rec = self
                    .keyring
                    .find(f)
                    .filter(|r| !r.is_removed() && !r.is_backup())
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown folder {f}"))?;
                if d == 0 {
                    s.folder_days.remove(&rec.folder_id);
                } else {
                    s.folder_days.insert(rec.folder_id.clone(), d);
                }
            }
            (Some(_), None) => bail!("give --days with --folder"),
            (None, Some(d)) => {
                if d == 0 || d > MAX_TRASH_DAYS {
                    bail!("the trash keeps files from 1 to {MAX_TRASH_DAYS} days");
                }
                s.days = d;
            }
            (None, None) => {}
        }
        if let Some(choice) = storage {
            match choice {
                None => {
                    s.storage = None;
                    s.storage_id = None;
                }
                Some(name) => {
                    let spec = self
                        .config
                        .storages
                        .iter()
                        .find(|x| x.name() == name)
                        .cloned()
                        .ok_or_else(|| anyhow!("unknown storage {name}"))?;
                    if spec.is_carrier() {
                        bail!("{name} is a transferrer: it carries blocks between devices and cannot keep the trash");
                    }
                    let others = self
                        .config
                        .storages
                        .iter()
                        .filter(|x| x.name() != name && !x.is_carrier())
                        .count();
                    if others == 0 {
                        bail!("{name} is the only storage of this vault: the trash storage must be another one");
                    }
                    s.storage_id = (!spec.is_data_only())
                        .then(|| {
                            self.open_spec(&spec)
                                .ok()
                                .and_then(|b| storage_identity(b.as_ref()).ok())
                        })
                        .flatten();
                    s.storage = Some(name);
                }
            }
        }
        let me = self.vault.device_id.clone();
        let now = util::now_utc().max(s.updated_utc + 1);
        s.updated_utc = now;
        s.device = Some(me.clone());
        let json = serde_json::to_vec(&s)?;
        let blob = crypto::encrypt(
            &settings_key(&self.folder_record_key_now()),
            &settings_aad(&self.vault.vault_id, &me, now),
            &json,
        )?;
        let key = format!("{SETTINGS_PREFIX}{me}/{now:020}.enc");
        let own = format!("{SETTINGS_PREFIX}{me}/");
        for (_, b) in self.metadata_storages(true)? {
            b.put_if_absent(&key, &blob)?;
            for old in b.list(&own)? {
                if old != key {
                    b.delete(&old)?;
                }
            }
        }
        let mut cache = self.load_settings_cache();
        cache.local_storage = self.resolve_trash_storage(&s);
        cache.settings = Some(s);
        cache.read_utc = util::now_utc();
        self.save_settings_cache(&cache)?;
        self.trash_status()
    }

    /// Entries of a folder's trash selected by paths (a file, or every
    /// entry under a directory); per path only its newest deletion.
    fn select_entries(
        &self,
        folder: &FolderId,
        paths: &[String],
        now: i64,
    ) -> Vec<(TrashEntry, String)> {
        let mut out: Vec<(TrashEntry, String)> = Vec::new();
        let mut taken: HashSet<String> = HashSet::new();
        for e in self.trash_sets(folder, now).visible {
            let Some(sel) = paths.iter().find(|p| under(&e.path, p)) else {
                continue;
            };
            // Newest first: a path deleted twice restores its last version.
            if taken.insert(e.path.clone()) {
                out.push((e, sel.trim_matches('/').to_string()));
            }
        }
        out
    }

    /// Where each selected entry is restored to: its own path when free,
    /// otherwise `name (restored).ext`; with `to`, under that directory of
    /// the folder (keeping the part below the selected path's parent).
    fn restore_targets(
        &self,
        rec: &FolderRecord,
        root: &Path,
        picked: &[(TrashEntry, String)],
        to: Option<&str>,
    ) -> Result<Vec<String>> {
        let state = self.load_state(&rec.folder_id)?;
        let encrypted = self.mount_is_encrypted(&rec.folder_id);
        let to = to.map(|t| t.trim_matches('/')).filter(|t| !t.is_empty());
        if let Some(t) = to {
            util::check_rel_path(t)?;
        }
        let mut chosen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for (e, sel) in picked {
            let base = match to {
                None => e.path.clone(),
                Some(t) => {
                    let parent = sel.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    let rel = if parent.is_empty() {
                        e.path.as_str()
                    } else {
                        e.path
                            .strip_prefix(parent)
                            .map(|r| r.trim_start_matches('/'))
                            .unwrap_or(e.path.as_str())
                    };
                    format!("{t}/{rel}")
                }
            };
            let taken = |p: &str| -> bool {
                if chosen.contains(p)
                    || state.files.get(p).is_some_and(|f| !f.deleted)
                    || state.pending_remote.get(p).is_some_and(|f| !f.deleted)
                {
                    return true;
                }
                if encrypted {
                    return false;
                }
                let d = self.disk_of(root, &state, p);
                d.exists() || placeholder_path(&d).exists()
            };
            let mut target = base.clone();
            let mut n = 1;
            while taken(&target) {
                target = restored_name(&base, n);
                n += 1;
                if n > 1000 {
                    bail!("no free name to restore {} to", e.path);
                }
            }
            util::check_rel_path(&target)?;
            chosen.insert(target.clone());
            out.push(target);
        }
        Ok(out)
    }

    /// What restoring `paths` of a folder's trash takes: where each file
    /// goes, what is read from cold storage and what that costs.
    pub fn trash_restore_plan(
        &mut self,
        folder: &str,
        paths: &[String],
        to: Option<&str>,
    ) -> Result<TrashRestorePlan> {
        self.trash_refresh(true)?;
        let (rec, root) = self.resolve_folder(folder)?;
        self.restore_plan_for(&rec, &root, paths, to, util::now_utc())
            .map(|(p, _)| p)
    }

    fn restore_plan_for(
        &self,
        rec: &FolderRecord,
        root: &Path,
        paths: &[String],
        to: Option<&str>,
        now: i64,
    ) -> Result<(TrashRestorePlan, RestoreWork)> {
        if paths.is_empty() {
            bail!("name the files or directories to restore");
        }
        let picked = self.select_entries(&rec.folder_id, paths, now);
        if picked.is_empty() {
            bail!(
                "nothing in the trash of {} matches {}",
                rec.name,
                paths.join(", ")
            );
        }
        let targets = self.restore_targets(rec, root, &picked, to)?;
        let fk = self.folder_keys(rec)?;
        let view = self.view()?;
        let mut plan = TrashRestorePlan {
            folder: rec.name.clone(),
            ..Default::default()
        };
        let mut cold: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for ((e, _), target) in picked.into_iter().zip(targets) {
            plan.files += 1;
            plan.bytes += e.size;
            plan.targets.push((e.path.clone(), target.clone()));
            let local = self.local_copies(&fk, &e).into_iter().next();
            if local.is_some() {
                plan.from_local_copies += 1;
            } else {
                for c in &e.chunks {
                    match view
                        .locate(&rec.folder_id, &c.chunk)
                        .filter(|r| r.object == c.object)
                    {
                        Some(r) if self.needs_cold_read(r, c) => {
                            plan.cold_bytes += c.size;
                            cold.extend(
                                r.storages
                                    .keys()
                                    .filter(|n| {
                                        self.config
                                            .storages
                                            .iter()
                                            .any(|s| s.name() == n.as_str() && s.is_cold())
                                    })
                                    .cloned(),
                            );
                        }
                        Some(r) if !r.storages.is_empty() || !r.devices.is_empty() => {}
                        _ => {
                            if self.cached_object(&c.object).is_none()
                                && !plan.unavailable.contains(&e.path)
                            {
                                plan.unavailable.push(e.path.clone());
                            }
                        }
                    }
                }
            }
            out.push((e, target, local));
        }
        plan.cold_storages = cold.into_iter().collect();
        let mut costs: Vec<String> = Vec::new();
        for n in &plan.cold_storages {
            if let Some(p) = self.storage_price(n) {
                if let Some(c) = p.read_cost(plan.cold_bytes) {
                    costs.push(format!("{c:.2} {}", p.currency));
                }
            }
        }
        plan.read_cost = (!costs.is_empty()).then(|| costs.join(" or "));
        Ok((plan, out))
    }

    /// Restore entries of a folder's trash (files, or every entry under a
    /// directory) to their paths, or to `name (restored).ext` when the path
    /// is taken, or under the folder directory `to`. Nothing is overwritten.
    /// The restored files are new versions and sync like any change. Blocks
    /// only a cold storage holds are read only with `confirm_cold_read`.
    pub fn trash_restore(
        &mut self,
        folder: &str,
        paths: &[String],
        to: Option<&str>,
        confirm_cold_read: bool,
    ) -> Result<TrashRestoreReport> {
        self.ensure_active()?;
        self.trash_refresh(true)?;
        let (rec, root) = self.resolve_for_write(folder)?;
        let now = util::now_utc();
        let (plan, work) = self.restore_plan_for(&rec, &root, paths, to, now)?;
        if !plan.cold_storages.is_empty() && !confirm_cold_read {
            let mut msg = format!(
                "restoring needs a cold read: {} of it is kept only on cold storage {}",
                util::human_bytes(plan.cold_bytes),
                plan.cold_storages.join(", ")
            );
            if let Some(c) = &plan.read_cost {
                msg += &format!(" (reading it back costs about {c}; cold storage may also take hours to make it readable)");
            }
            msg += "; confirm the cold read to restore it";
            bail!("{msg}");
        }
        let fk = self.folder_keys(&rec)?;
        let encrypted = self.mount_is_encrypted(&rec.folder_id);
        let storages = self.open_storages(confirm_cold_read)?;
        let mut report = TrashRestoreReport {
            folder: rec.name.clone(),
            cold_read: !plan.cold_storages.is_empty(),
            ..Default::default()
        };
        let task = activity::start(
            activity::TRASH_RESTORE,
            &rec.name,
            plan.bytes,
            activity::Unit::Bytes,
        );
        let tmp_dir = self.home.join("trash").join(".restore");
        fs::create_dir_all(&tmp_dir)?;
        let mut restored_ids: Vec<(String, i64)> = Vec::new();
        let mut cache_writes: Vec<(String, PathBuf, u64)> = Vec::new();
        for (e, target, local) in work {
            task.advance(e.size);
            let tmp = tmp_dir.join(format!("{}-{}", std::process::id(), e.id));
            let got = match &local {
                Some(p) => fs::copy(p, &tmp).map(|_| true).map_err(anyhow::Error::from),
                None => self.restore_from_blocks(&rec, &fk, &e, &tmp, &storages),
            };
            match got {
                Ok(from_local) => {
                    if Self::file_content_hash(&fk, &tmp).as_deref()
                        != Some(e.content_hash.as_str())
                    {
                        let _ = fs::remove_file(&tmp);
                        report
                            .unavailable
                            .push(format!("{}: the restored content did not match", e.path));
                        continue;
                    }
                    if from_local {
                        report.from_local_copies += 1;
                    } else {
                        report.from_storages += 1;
                    }
                }
                Err(err) => {
                    let _ = fs::remove_file(&tmp);
                    report.unavailable.push(format!("{}: {err:#}", e.path));
                    continue;
                }
            }
            // The local copy is the file again now.
            if let Some(p) = &local {
                let _ = fs::remove_file(p);
            }
            if encrypted {
                cache_writes.push((target.clone(), tmp, e.size));
            } else {
                // The local name (mapped where this filesystem needs it) is
                // recorded before the push's scan finds the file.
                let mut state = self.load_state(&rec.folder_id)?;
                let disk = self.place(&root, &mut state, &target, None)?;
                self.save_state(&rec.folder_id, &state)?;
                if disk.exists() || placeholder_path(&disk).exists() {
                    let _ = fs::remove_file(&tmp);
                    report
                        .unavailable
                        .push(format!("{}: {target} appeared meanwhile", e.path));
                    continue;
                }
                if let Some(parent) = disk.parent() {
                    fs::create_dir_all(parent)?;
                }
                if fs::rename(&tmp, &disk).is_err() {
                    fs::copy(&tmp, &disk)?;
                    let _ = fs::remove_file(&tmp);
                }
                if e.mtime > 0 {
                    let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(e.mtime as u64);
                    if let Ok(f) = fs::File::options().write(true).open(&disk) {
                        let _ = f.set_modified(t);
                    }
                }
            }
            report.bytes += e.size;
            report.restored.push(RestoredFile {
                from: e.path.clone(),
                to: target,
                size: e.size,
            });
            restored_ids.push((e.id.clone(), e.deleted_utc));
        }
        // The entries leave the trash on every device.
        let mut cache = self.load_trash_cache(&rec.folder_id);
        let me = self.vault.device_id.clone();
        for (id, deleted_utc) in &restored_ids {
            cache.own_removed.insert(
                id.clone(),
                TrashRemoval {
                    utc: now,
                    by: me.clone(),
                    restored: true,
                    deleted_utc: *deleted_utc,
                },
            );
            cache.queued.insert(id.clone());
        }
        self.save_trash_cache(&rec.folder_id, &cache)?;
        for (target, tmp, size) in cache_writes {
            let written = fs::File::open(&tmp)
                .map_err(anyhow::Error::from)
                .and_then(|f| {
                    self.write_from_reader_sized(rec.folder_id.as_str(), &target, f, Some(size))
                });
            let _ = fs::remove_file(&tmp);
            written?;
        }
        // A new version of each file; their blocks go back to the folder's
        // storages if they had left them.
        self.push(rec.folder_id.as_str())?;
        Ok(report)
    }

    /// Fetch, check and decrypt an entry's blocks into `out`. Returns false
    /// (not from a local copy).
    fn restore_from_blocks(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        e: &TrashEntry,
        out: &Path,
        storages: &OpenStorages,
    ) -> Result<bool> {
        let mut file = fs::File::create(out)?;
        for c in &e.chunks {
            let good = |ct: &Vec<u8>| ObjectName::from_bytes(&crypto::hash(ct)) == c.object;
            let (ct, source) = match self.cached_object(&c.object) {
                Some(ct) => (ct, None),
                None => match fetch::fetch_object(
                    self.peers.as_deref(),
                    &c.object,
                    storages,
                    &self.fetch_stats,
                ) {
                    Fetched::Got { bytes, source, .. } if good(&bytes) => (bytes, Some(source)),
                    Fetched::Got { .. } => bail!("block {} failed its check", c.chunk.short()),
                    Fetched::Failed(err) => return Err(err),
                    Fetched::Missing(Some(nd)) => return Err(anyhow::Error::new(nd)),
                    Fetched::Missing(None) => bail!(
                        "block {} is not available on any readable storage",
                        c.chunk.short()
                    ),
                },
            };
            let plain = crate::pack::unpack(
                &crypto::decrypt(
                    &fk.chunk_key(c.epoch, &c.chunk)?,
                    &fk.chunk_aad(&self.vault.vault_id, &c.chunk, c.size),
                    &ct,
                )?,
                c.size,
            )?;
            if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain)) != c.chunk {
                bail!("block {} failed its content check", c.chunk.short());
            }
            file.write_all(&plain)?;
            if let Some(s) = source.filter(|s| !s.starts_with("peer:")) {
                self.pending.push(Event::ChunkVerified {
                    folder: rec.folder_id.clone(),
                    chunk: c.chunk.clone(),
                    object: c.object.clone(),
                    storage: s,
                });
            }
        }
        file.sync_all()?;
        Ok(false)
    }

    /// Delete entries from the trash for good: those of `paths` in `folder`,
    /// or with `all` everything (of `folder`, or of every folder). Their
    /// blocks that nothing else uses are dropped from this device's
    /// storages; other devices drop theirs at their next upkeep.
    pub fn trash_purge(
        &mut self,
        folder: Option<&str>,
        paths: &[String],
        all: bool,
    ) -> Result<TrashPurgeReport> {
        self.ensure_active()?;
        if !all && (folder.is_none() || paths.is_empty()) {
            bail!("name a folder and the files to delete for good, or empty the whole trash");
        }
        self.trash_refresh(true)?;
        let now = util::now_utc();
        let me = self.vault.device_id.clone();
        let mut report = TrashPurgeReport::default();
        let task = activity::start(
            activity::TRASH_PURGE,
            folder.unwrap_or(""),
            0,
            activity::Unit::Items,
        );
        let mut touched: Vec<(FolderRecord, Vec<TrashEntry>)> = Vec::new();
        for rec in self.trash_folders(folder)? {
            let picked: Vec<TrashEntry> = if all {
                self.trash_sets(&rec.folder_id, now).visible
            } else {
                self.trash_sets(&rec.folder_id, now)
                    .visible
                    .into_iter()
                    .filter(|e| paths.iter().any(|p| under(&e.path, p)))
                    .collect()
            };
            if picked.is_empty() {
                continue;
            }
            let mut cache = self.load_trash_cache(&rec.folder_id);
            for e in &picked {
                cache.own_removed.insert(
                    e.id.clone(),
                    TrashRemoval {
                        utc: now,
                        by: me.clone(),
                        restored: false,
                        deleted_utc: e.deleted_utc,
                    },
                );
                cache.queued.insert(e.id.clone());
                report.entries += 1;
                report.bytes += e.size;
            }
            self.save_trash_cache(&rec.folder_id, &cache)?;
            touched.push((rec, picked));
        }
        if touched.is_empty() && !all {
            bail!("nothing in the trash matches {}", paths.join(", "));
        }
        task.step("drop", report.entries, activity::Unit::Items);
        let stale = if self.vault.member {
            BTreeSet::new()
        } else {
            self.trash_pull_folders()
        };
        for (rec, picked) in &touched {
            self.trash_publish(rec, now)?;
            self.trash_enqueue(&rec.folder_id, picked)?;
            let fk = self.folder_keys(rec)?;
            for e in picked {
                for p in self.local_copies(&fk, e) {
                    if fs::remove_file(&p).is_ok() {
                        report.local_copies_removed += 1;
                    }
                }
            }
            task.advance(picked.len() as u64);
        }
        let mut counts = DropCounts::default();
        self.trash_drop_queued(now, &stale, &mut counts)?;
        report.blocks_dropped = counts.dropped;
        report.bytes_dropped = counts.bytes;
        report.blocks_waiting = counts.waiting;
        Ok(report)
    }

    /// Bring the attached folders' file lists up to date before blocks are
    /// judged unused (a file restored or created again elsewhere uses them).
    /// Returns the folders that could not be pulled.
    fn trash_pull_folders(&mut self) -> BTreeSet<FolderId> {
        let mut stale = BTreeSet::new();
        let attached: Vec<FolderId> = self
            .config
            .folders
            .iter()
            .map(|m| m.folder_id.clone())
            .collect();
        for fid in attached {
            let Some(rec) = self.keyring.folders.get(&fid).cloned() else {
                continue;
            };
            if rec.is_removed() || rec.is_backup() {
                continue;
            }
            let ok = self.with_key(&rec).is_ok()
                && !self.is_held(&fid)
                && self.pull(fid.as_str()).is_ok();
            if !ok {
                stale.insert(fid);
            }
        }
        stale
    }

    /// Whether the daily trash upkeep is due.
    pub fn trash_upkeep_due(&self, now: i64) -> bool {
        now - self.load_settings_cache().upkeep_utc >= TRASH_UPKEEP_EVERY_SECS
    }

    /// The daily upkeep: expire entries, move trashed blocks to the trash
    /// storage, drop blocks nothing uses any more and clear old local trash.
    pub fn trash_upkeep(&mut self) -> Result<TrashUpkeepReport> {
        self.trash_upkeep_at(util::now_utc())
    }

    /// `trash_upkeep` as if it were `now` (tests).
    pub fn trash_upkeep_at(&mut self, now: i64) -> Result<TrashUpkeepReport> {
        self.ensure_active()?;
        let mut report = TrashUpkeepReport::default();
        self.trash_refresh(true)?;
        let stale = if self.vault.member || self.forked_self {
            BTreeSet::new()
        } else {
            self.trash_pull_folders()
        };
        for rec in self.trash_folders(None)? {
            let sets = self.trash_sets(&rec.folder_id, now);
            let mut cache = self.load_trash_cache(&rec.folder_id);
            let days = self.trash_days_for(&rec.folder_id) as i64;
            let newly: Vec<TrashEntry> = sets
                .gone
                .iter()
                .filter(|e| !cache.queued.contains(&e.id))
                .cloned()
                .collect();
            report.expired += newly
                .iter()
                .filter(|e| now >= e.deleted_utc + days * DAY)
                .count() as u64;
            if !newly.is_empty() {
                self.trash_enqueue(&rec.folder_id, &newly)?;
                cache.queued.extend(newly.iter().map(|e| e.id.clone()));
            }
            // Forget queued ids no record lists any more.
            let listed: HashSet<&str> = sets
                .gone
                .iter()
                .chain(sets.visible.iter())
                .chain(sets.restored.iter())
                .map(|e| e.id.as_str())
                .collect();
            cache.queued.retain(|id| listed.contains(id.as_str()));
            self.save_trash_cache(&rec.folder_id, &cache)?;
            self.trash_publish(&rec, now)?;
            if !self.forked_self {
                self.trash_to_storage(&rec, now, &mut report)?;
            }
            report.local_copies_removed += self.clear_local_trash(&rec.folder_id, days, now);
        }
        let mut counts = DropCounts::default();
        self.trash_drop_queued(now, &stale, &mut counts)?;
        report.blocks_dropped = counts.dropped;
        report.bytes_dropped = counts.bytes;
        report.blocks_waiting = counts.waiting;
        if counts.waiting > 0 {
            report.notes.push(format!(
                "{} block cop{} on cold storage stay until the storage's minimum duration has passed",
                counts.waiting,
                if counts.waiting == 1 { "y" } else { "ies" }
            ));
        }
        let mut c = self.load_settings_cache();
        c.upkeep_utc = now;
        self.save_settings_cache(&c)?;
        Ok(report)
    }

    /// Remove local trash copies (`<path>.<time>`) older than the folder's
    /// trash days. Returns how many.
    fn clear_local_trash(&self, folder: &FolderId, days: i64, now: i64) -> u64 {
        let dir = self.local_trash_dir(folder);
        if !dir.is_dir() {
            return 0;
        }
        let mut removed = 0;
        for e in walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(stamp) = name
                .rsplit_once('.')
                .and_then(|(_, s)| s.parse::<i64>().ok())
            else {
                continue;
            };
            if now >= stamp + days * DAY && fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
        // Empty directories left behind.
        let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(&dir)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir())
            .map(|e| e.into_path())
            .collect();
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            let _ = fs::remove_dir(d);
        }
        removed
    }

    /// Forget a folder's trash here (the folder was removed).
    pub(super) fn forget_trash(&self, folder: &FolderId) {
        let _ = fs::remove_file(self.trash_cache_path(folder));
        let _ = fs::remove_dir_all(self.local_trash_dir(folder));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_names_never_collide_with_the_original() {
        assert_eq!(restored_name("docs/a.txt", 1), "docs/a (restored).txt");
        assert_eq!(restored_name("docs/a.txt", 2), "docs/a (restored 2).txt");
        assert_eq!(restored_name("Makefile", 1), "Makefile (restored)");
        assert_eq!(restored_name(".bashrc", 1), ".bashrc (restored)");
    }

    #[test]
    fn selections_match_files_and_directories() {
        assert!(under("docs/a.txt", "docs"));
        assert!(under("docs/a.txt", "docs/"));
        assert!(under("docs/a.txt", "docs/a.txt"));
        assert!(!under("docs2/a.txt", "docs"));
        assert!(!under("docs", "docs/a.txt"));
    }

    #[test]
    fn entries_from_other_devices_are_checked() {
        let folder = FolderId::from_bytes(&[1; 16]);
        let dev = DeviceId::from_bytes(&[2; 16]);
        let other = DeviceId::from_bytes(&[3; 16]);
        let e = TrashEntry {
            id: entry_id(&folder, "a.txt", &dev, 7),
            path: "a.txt".into(),
            size: 10,
            mtime: 0,
            content_hash: String::new(),
            chunks: vec![ChunkRef {
                chunk: ChunkId::from_bytes(&[4; 16]),
                object: ObjectName::from_bytes(&[5; 32]),
                size: 10,
                epoch: 0,
            }],
            deleted_utc: 1,
            deleted_by: dev.clone(),
            clock: 7,
        };
        assert!(entry_valid(&e, &folder, &dev));
        // Only a device's own deletions count.
        assert!(!entry_valid(&e, &folder, &other));
        let mut escape = e.clone();
        escape.path = "../x".into();
        escape.id = entry_id(&folder, "../x", &dev, 7);
        assert!(!entry_valid(&escape, &folder, &dev));
        let mut wrong = e.clone();
        wrong.size = 11;
        assert!(!entry_valid(&wrong, &folder, &dev));
    }
}
