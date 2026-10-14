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

use crate::activity;
use crate::chunking::{Chunker, ChunkerParams};
use crate::crypto::{self, KeyedHasher, SecretKey};
use crate::fsmeta;
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName, VaultId};
use crate::ignore_rules::{self, Matcher as IgnoreMatcher};
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
use fetch::{fetch_in_order, FetchStats, Fetched, PREFETCH_FILES, PREFETCH_OBJECTS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

mod access_sync;
mod backups;
mod block_cache;
mod changes_ops;
mod data_moves;
mod devinfo;
mod disk_fetch;
mod disk_groups;
mod disk_insert;
mod disk_suggest;
mod drain;
mod fetch;
mod folder_rules;
mod folder_safety;
mod guide;
mod help;
mod history;
mod imports;
mod ledger_recovery;
mod ledger_upkeep;
mod local_names;
mod manifest_upkeep;
mod membership;
mod notes;
mod org_ops;
mod placement;
mod quotas;
mod repair;
mod restic_mirror;
mod scrub;
mod share_ops;
mod share_roles;
mod staged_moves;
mod strongroom_ops;
mod trash;
mod verify;
mod view;
mod where_data;
pub use access_sync::AccessExchangeReport;
pub use backups::{
    BackupOptions, BackupSummary, ExpireReport, RestoreReport, SnapshotInfo, SnapshotPick,
    SnapshotReport,
};
pub use block_cache::{BlockWriter, StagedFile, BLOCK_CACHE_DIR, EXPORT_DIR};
pub use changes_ops::{ChangeView, ChangesQuery, ChangesReport};
pub use devinfo::DeviceDetails;
pub use disk_fetch::{
    DiskFetchSettings, DiskStep, FetchPlan, FetchPlanReport, InsertAnswer, PlanDriver, PlanFile,
    RemoteOption, StepOutcome,
};
pub use disk_groups::DiskGroupStatus;
pub use disk_insert::{DiskInsertReport, DiskProgress, FillOutcome, InsertOptions};
pub use drain::{DrainOptions, DrainPlan, DrainRunLimits, DrainRunReport, DrainStatus};
pub use folder_rules::IgnoreInfo;
pub use folder_safety::{
    paused_error, ChangeKind, DiscardReport, FolderChanges, FolderPaused, HeldDeletions,
    HeldSummary, PauseKind, RevertReport, FOLDER_MARKER,
};
pub use help::{help_without_vault, HelpObserved};
pub use history::{
    history_kept, parse_utc, FolderHistory, HistoryItem, HistoryList, HistoryRestoreReport,
    HistoryStatus, HistoryTarget, DEFAULT_HISTORY_DAYS, MAX_HISTORY_DAYS,
};
pub use imports::{
    CleanupFile, ImportCleanupReport, ImportOptions, ImportReport, ImportStatus, ImportVerify,
    MissingFile,
};
pub use ledger_recovery::{
    JunkReport, LedgerBehind, LedgerDeviceStatus, LedgerHealth, LedgerHolding, LedgerProblem,
    LedgerRebuildOptions, LedgerRebuildReport, LedgerStatus, StorageRebuildReport,
};
pub use manifest_upkeep::ManifestPolicy;
pub use membership::{
    removal_notice, DeviceInfo, DeviceRemoved, EpochForks, EpochRecord, Grant, KemRecord, Removal,
    Revocation, RevokeReport, Revoked, SignedEpoch, SignedRevocation,
};
pub use notes::{
    check_analysis, AnalysisHit, FileAnalysis, NotesExchangeReport, ANALYSIS_MAX_BYTES,
    LISTING_CHARS, TAGS_MAX, TAG_MAX_CHARS,
};
pub use org_ops::{
    LogView, OrgApproved, OrgBrief, OrgCreated, OrgDevice, OrgRemoveReport, OrgSummary, OrgUser,
    UnlistedDevice,
};
pub use quotas::QuotaStatus;
pub use repair::{
    Damage, DamageKind, RepairOptions, RepairReport, RepairStatus, RepairedCopy, Unrepairable,
};
pub use restic_mirror::{CheckOptions, SetupReport};
pub use scrub::ScrubOptions;
pub use share_ops::{ShareMember, ShareMembers, ShareRevokeReport};
pub use share_roles::{ShareRoleReport, KEPT_ASIDE_DIR};
pub use staged_moves::{JobRunLimits, MoveJobRequest, MoveJobRun, SERVICE_RUN_GROUPS};
pub use strongroom_ops::{CleanupReport, ConvertReport, StrongroomKeySummary};
pub use trash::{
    restored_name, RestoredFile, TrashItem, TrashPurgeReport, TrashRestorePlan, TrashRestoreReport,
    TrashSettings, TrashStatus, TrashUpkeepReport, DEFAULT_TRASH_DAYS, MAX_TRASH_DAYS,
    TRASH_UPKEEP_EVERY_SECS,
};
pub use where_data::{CopyStats, DataLocations, DeviceShare, FolderShare, StorageShare};

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
struct LocalIndexEntry {
    size: u64,
    mtime: i64,
    content_hash: String,
    /// The metadata this device last saw on disk (`fsmeta::observe`): a
    /// property is published only when what is seen changes from this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    meta_seen: Option<crate::fsmeta::FileMeta>,
}

/// Per-folder state on this device: `home/state/<folder>.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FolderState {
    /// Merged view as applied to disk (including tombstones).
    files: BTreeMap<String, FileState>,
    /// What is on disk, keyed by manifest path. In a folder kept encrypted
    /// on this device (`block_cache`): the files whose blocks are all in the
    /// block cache, with the size, time and hash of the version cached.
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
    /// 2 once videos marked done by older versions (which gave up when
    /// ffmpeg was not found) were let go, so that they are tried again.
    #[serde(default)]
    thumbs_rev: u32,
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
    /// The local index describes the block cache (see `engine::block_cache`).
    /// False in states written before folders kept encrypted on a device
    /// used it: their index described plain files in the folder directory.
    #[serde(default)]
    block_cache: bool,
    /// A backup's source: files the last scan could not read (left out of
    /// the snapshot and named in it).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    unreadable: BTreeSet<String>,
    /// Vault paths written under another local name on this device (the
    /// Windows mapping, a case collision): see `crate::names`.
    #[serde(default, skip_serializing_if = "crate::names::LocalNames::is_empty")]
    local_names: crate::names::LocalNames,
    /// Deletions the mass-deletion guard holds until the user decides
    /// (`folder_safety`); the folder is paused meanwhile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held: Option<folder_safety::HeldDeletions>,
    /// Send-only: other devices' newer states not applied here, by path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    not_applied: BTreeMap<String, FileState>,
    /// Receive-only: this device's changes that are not published, by path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    local_changes: BTreeMap<String, folder_safety::ChangeKind>,
    /// Remote versions not written here because this device's ignore rules
    /// cover the path, or symbolic links while links are off here: reported
    /// once each, and applied once the rule or setting no longer stops them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ignored_remote: BTreeMap<String, FileState>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `clock.json`: the end of this device's current reservation of logical
/// clock values (every value up to `lamport` is taken or reserved). Ticks
/// are handed out from memory; the file is written once per
/// `CLOCK_RESERVE` values (see `Engine::tick`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Clock {
    lamport: u64,
}

/// Logical clock values reserved in `clock.json` at a time. A crash or a
/// process exit wastes at most the unused rest of the reservation, which is
/// harmless: Lamport values only need to grow and never repeat.
const CLOCK_RESERVE: u64 = 1000;

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
    /// Read-only members of shared folders, with the last ledger batch of
    /// each that still counts (written while it was an editor; `share_roles`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    share_viewers: BTreeMap<DeviceId, u64>,
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
    /// Storages skipped because they are at their quota, one sentence
    /// each ("storage X is at its quota (Y of Z)"); blocks that had no
    /// other storage wait on this device for the next push.
    #[serde(default)]
    pub storages_full: Vec<String>,
    /// Entries the folder's ignore rules left out of the scan (directories
    /// count once).
    #[serde(default)]
    pub files_ignored: u64,
    /// Of the changed files, those whose metadata alone changed (no blocks).
    #[serde(default)]
    pub metadata_changed: u64,
    /// This device may only read the folder: nothing was published.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    /// Read-only folder: local changes moved to `kept-aside/` or undone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept_aside: Vec<String>,
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
    /// Files written under another local name because this device's
    /// filesystem already has a file whose name differs only in case:
    /// "vault path -> local path".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renamed_locally: Vec<String>,
    /// The folder is paused on this device (`folder_safety`): nothing was
    /// synced; this says why and what to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<FolderPaused>,
    /// Incoming changes not written because this device's ignore rules
    /// cover the path (each version reported once).
    #[serde(default)]
    pub files_ignored: Vec<String>,
    /// Symbolic links this system would not create: a note
    /// (`<path>.varsto-link`) stands in their place.
    #[serde(default)]
    pub links_as_notes: Vec<String>,
    /// Incoming links not created because symbolic links are off here.
    #[serde(default)]
    pub links_skipped: Vec<String>,
    /// Metadata that could not be applied: "path: problem".
    #[serde(default)]
    pub metadata_problems: Vec<String>,
    /// Files left for later because the disk would keep less free space
    /// than its limit (`freespace`), and why (one line per place).
    #[serde(default)]
    pub files_waiting_for_space: u64,
    #[serde(default)]
    pub low_space: Vec<String>,
    /// Read-only members whose changes to the folder were not taken (names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes_refused: Vec<String>,
    /// This device may only read the folder: local changes moved to
    /// `kept-aside/` or undone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept_aside: Vec<String>,
}

impl PullReport {
    /// A download refused for lack of space: the file waits for the next
    /// sync (kept pending by the caller); the reason is listed once.
    pub(crate) fn waiting_for_space(&mut self, low: &crate::freespace::LowSpace) {
        self.files_waiting_for_space += 1;
        if !self.low_space.contains(&low.text) {
            self.low_space.push(low.text.clone());
        }
    }
}

/// Blocks of a folder by where they are: on a storage (verified by another
/// device or not) or only on this device, and whether this device holds them.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BlockCounts {
    pub verified_here: u64,
    pub verified_away: u64,
    pub stored_here: u64,
    pub stored_away: u64,
    /// On this device and on no storage yet.
    pub local_only: u64,
    /// Neither on this device nor on a storage.
    pub missing: u64,
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
    /// Shared with this device read-only (a viewer): nothing is published.
    #[serde(default)]
    pub read_only: bool,
    pub selective: bool,
    /// Plain files on this device (false: "encrypted on this device", see `FolderMount::encrypted`).
    #[serde(default)]
    pub plain: bool,
    pub placeholders: u64,
    pub pinned: u64,
    /// Exact block counts for the data map.
    pub blocks: BlockCounts,
    /// Durability policy, if one is set (human-readable).
    #[serde(default)]
    pub policy: Option<String>,
    /// Strongroom state: "locked" or "unlocked until <utc>".
    #[serde(default)]
    pub strongroom: Option<String>,
    /// This device's sync mode for the folder.
    pub mode: crate::vault::FolderMode,
    /// The mass-deletion guard, in words.
    pub deletion_guard: String,
    /// Why the folder is paused on this device, if it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<FolderPaused>,
    /// Deletions held until the user decides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held_deletions: Option<HeldSummary>,
    /// Send-only: other devices' changes not applied here.
    pub remote_not_applied: u64,
    /// Receive-only: this device's changes not published.
    pub local_changes: u64,
    /// The free space kept on the folder's disk here, as set ("10%",
    /// bytes) or `None` for the default; and as text ("5 %").
    #[serde(default)]
    pub min_free: Option<String>,
    #[serde(default)]
    pub min_free_text: String,
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
    /// Destination devices of transferrers, by storage name.
    #[serde(default)]
    pub carrier_for: BTreeMap<String, Vec<String>>,
    /// The organization the vault belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgBrief>,
    /// Whether this device's ledger needs a rebuild (`ledger_recovery`).
    pub ledger_health: LedgerHealth,
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
    /// Damaged copies on this device's storages put in the repair queue.
    #[serde(default)]
    pub repairs_queued: u64,
    /// Whether this device's ledger needs a rebuild (`ledger_recovery`).
    #[serde(default)]
    pub ledger_health: LedgerHealth,
}

/// What `disk add` did.
#[derive(Clone, Debug, Serialize)]
pub struct DiskAddReport {
    pub pool: String,
    pub disk: PoolDisk,
    pub objects_added: u64,
    pub bytes_added: u64,
    /// Why nothing (or less than expected) went to the disk, when the
    /// reason is the disk itself: smaller than the space the pool keeps free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
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
    /// Disk group rule of the pool (copies on disks in different places)
    /// and the objects still short of it after this check.
    pub group_copies: u32,
    pub group_short: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
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
    /// What the file contains, as recorded by an assistant or the user
    /// (`notes`): the first `LISTING_CHARS` characters in a listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<String>,
    /// The analysis is longer than shown (`Engine::analysis` has it all).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub analysis_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_utc: Option<i64>,
    /// The file changed since it was analysed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub analysis_stale: bool,
    /// The model or tool that wrote the analysis, as it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_by: Option<String>,
    /// The device the analysis was written on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_author: Option<String>,
    /// Permission bits as published (`fsmeta`), and as `rwxr-xr-x`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode_text: Option<String>,
    /// The entry is a symbolic link to this target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink: Option<String>,
    /// The link's target is absolute (it may point elsewhere on each device).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub symlink_absolute: bool,
    /// "user:group" (names, or ids where a name is not known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Names of the extended attributes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub xattrs: Vec<String>,
}

impl FileEntry {
    /// Fill the metadata fields from a file's state.
    fn with_meta(mut self, f: &FileState) -> FileEntry {
        if let Some(m) = &f.meta {
            self.mode = m.mode;
            self.mode_text = m.mode_text();
            self.symlink = m.symlink.clone();
            self.symlink_absolute = m.symlink.as_deref().is_some_and(fsmeta::target_is_absolute);
            self.owner = m.owner.as_ref().map(|o| {
                format!(
                    "{}:{}",
                    o.user.clone().unwrap_or_else(|| o.uid.to_string()),
                    o.group.clone().unwrap_or_else(|| o.gid.to_string())
                )
            });
            self.xattrs = m
                .xattrs
                .as_ref()
                .map(|x| x.keys().cloned().collect())
                .unwrap_or_default();
        }
        self
    }
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
    /// Where the peer-to-peer server takes what it serves from: refreshed
    /// as soon as a push has published new files, before their upload.
    snapshot_sink: Option<SnapshotSink>,
    /// What this device knows of the packs on each storage.
    pack_caches: crate::packs::Caches,
    /// Objects of small files fetched ahead during a pull (see `prefetch_small`).
    prefetched: HashMap<ObjectName, Fetched>,
    /// How fast peers and storages answered during recent downloads.
    fetch_stats: std::sync::Arc<FetchStats>,
    /// Strongroom folder keys held in memory until the expiry time (UTC seconds).
    unlocked: BTreeMap<FolderId, (SecretKey, i64)>,
    home: PathBuf,
    vault: LocalVault,
    keys: Keys,
    config: Config,
    keyring: Keyring,
    ledger: LedgerStore,
    /// The current logical clock value (in memory, see `tick`).
    clock: Clock,
    /// The end of the reservation written to `clock.json`: values up to it
    /// are this process's to hand out without touching the file.
    clock_reserved: u64,
    /// How many times `clock.json` was written by this engine (tests).
    clock_writes: u64,
    devices: DeviceCache,
    pending: Vec<Event>,
    forked_self: bool,
    /// What is known to be wrong with this device's ledger (`ledger_recovery`).
    ledger_alarm: ledger_recovery::Alarm,
    /// Vault keys per epoch (they change when a device is revoked).
    epochs: membership::VaultEpochs,
    /// Set once this device has seen its own revocation: it no longer syncs.
    removal: Option<Removal>,
    /// The organization this vault belongs to, if any (`org_ops`).
    org: Option<crate::org::OrgState>,
    pub chunker: ChunkerParams,
    /// Counts the calls made to every storage this engine opens (measurements).
    storage_calls: Option<std::sync::Arc<crate::storage::StorageCalls>>,
    /// The storages opened during the current operation, by name, with the
    /// spec they were opened from: every phase of a sync shares one backend
    /// (one connection pool, one view of the packs) instead of opening the
    /// storage again (`open_spec`, `finish_storages`).
    storages_open: std::sync::Mutex<OpenedStorages>,
    /// The location view, kept up to date as batches arrive.
    view_cache: std::sync::Mutex<ledger_upkeep::ViewSlot>,
    /// Set while one action runs whose ledger events go into one batch.
    cycle: Option<ledger_upkeep::Cycle>,
    /// When to write checkpoints and how many batches to keep before them.
    ledger_policy: ledger_upkeep::LedgerPolicy,
    /// When manifests are listed in full and whether old ones are pruned.
    manifest_policy: manifest_upkeep::ManifestPolicy,
    /// The token of the restic hold this engine works under (its own run's
    /// completeness check), which the hold does not stop (`restic_mirror`).
    hold_exempt: Option<String>,
    /// The filesystem rules to assume for every folder instead of probing
    /// them (tests simulate Windows or a case-insensitive disk with it).
    local_rules: Option<crate::names::LocalRules>,
    /// Tests: the paths of the files downloaded, in order (`record_downloads`).
    download_log: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
    /// Which file metadata this system can represent (`fsmeta::Caps`).
    meta_caps: crate::fsmeta::Caps,
    /// Of the last scan: entries ignored, files whose metadata alone changed.
    scan_extra: (u64, u64),
    /// The scan a pull just made, for the push that follows it in a sync.
    last_scan: Option<ScanOutcome>,
    /// Tests: behave like a modified client that ignores a read-only role
    /// (`share_roles`).
    role_guard_off: bool,
    /// Tests: the platform and version this device says it runs (`devinfo`).
    platform_override: Option<String>,
    version_override: Option<String>,
}

/// What the peer-to-peer server serves from (see `Engine::set_snapshot_sink`).
pub type SnapshotSink =
    std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::p2p::Snapshot>>>>;

/// Open storages with their specs.
type OpenStorages = Vec<(StorageSpec, Box<dyn Storage>)>;

/// The backends opened during an operation, by storage name, each with the
/// spec it was opened from (`Engine::storages_open`).
type OpenedStorages = HashMap<String, (StorageSpec, std::sync::Arc<dyn Storage>)>;

/// Threads that write objects during a push, and how many encrypted
/// blocks may wait for them.
const UPLOADERS: usize = 8;
const UPLOAD_QUEUE: usize = 16;
/// At most this much encrypted data waits for or is with the uploaders:
/// with the large blocks of big files (up to 16 MiB) the queue alone would
/// otherwise hold hundreds of megabytes, too much for a phone.
const UPLOAD_BYTES: u64 = 128 << 20;

/// Count one finished write in the report and the ledger.
fn apply_upload(
    me: &mut Engine,
    folder_id: &FolderId,
    d: UploadDone,
    report: &mut PushReport,
    first_error: &mut Option<anyhow::Error>,
) {
    match d.outcome {
        Ok(written) => {
            if written {
                report.chunks_uploaded += 1;
                report.bytes_uploaded += d.size;
            }
            me.pending.push(Event::ChunkStored {
                folder: folder_id.clone(),
                chunk: d.chunk,
                object: d.object,
                storage: d.storage,
                size: d.size,
            });
        }
        // A pool with no disk attached (or no room) is left out for the rest
        // of this push and tried again next time.
        Err(e)
            if matches!(
                pool::pool_error(&e),
                Some(PoolError::NoDiskAttached { .. } | PoolError::NoRoom { .. })
            ) || crate::freespace::low_space(&e).is_some() =>
        {
            if !report.storages_unavailable.contains(&d.storage) {
                report.storages_unavailable.push(d.storage);
            }
        }
        Err(e) => {
            first_error.get_or_insert(e);
        }
    }
}

/// One object to write to some storages during a push.
struct UploadJob {
    targets: Vec<String>,
    chunk: ChunkId,
    object: ObjectName,
    ct: Vec<u8>,
}

/// A batch of objects on its way to the storages: one work item per
/// storage shares it, and its bytes leave the upload budget when the last
/// of them is done.
struct UploadBatch {
    jobs: Vec<UploadJob>,
    /// Storages still to write it.
    left: std::sync::atomic::AtomicUsize,
    /// Encrypted bytes it holds (counted once, however many storages).
    held: u64,
}

/// What a folder scan found, kept from a sync's pull for its push so the
/// folder is walked once per sync (`Engine::last_scan`).
struct ScanOutcome {
    folder: FolderId,
    scanned: u64,
    changed: u64,
    /// Entries ignored, files whose metadata alone changed (`scan_extra`).
    extra: (u64, u64),
}

/// How one write went.
struct UploadDone {
    storage: String,
    chunk: ChunkId,
    object: ObjectName,
    size: u64,
    outcome: Result<bool>,
}

/// What a policy evaluation knows about this device's storages
/// (`Engine::policy_ctx`).
pub(crate) struct PolicyCtx {
    places: BTreeMap<String, (String, bool)>,
    carriers: BTreeSet<String>,
    unknown: Vec<String>,
    unreadable_places: BTreeMap<String, Vec<String>>,
    pools: BTreeMap<String, PoolStorage>,
}

/// Suffix of placeholder files in selective folders (plan 6.34, Resilio-style).
pub const PLACEHOLDER_SUFFIX: &str = ".varsto-placeholder";

/// Whether anything (a file, a directory, a link, even a dangling one) is at `p`.
fn present(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn mtime_ns_of(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Names Varsto keeps for itself inside folders (`.varsto*`), except the
/// synced ignore file.
fn reserved_name(name: &str) -> bool {
    name.starts_with(".varsto") && name != ignore_rules::IGNORE_FILE
}

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
        crate::logged_op_plain!("init", device_name, {
            Self::init_inner(home, device_name, passphrase)
        })
    }

    fn init_inner(home: &Path, device_name: &str, passphrase: &str) -> Result<(Engine, String)> {
        ensure_no_vault(home)?;
        util::private_home(home)?;
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
        crate::logging::register_key(keys.master.as_bytes());
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
        crate::logged_op_plain!("join with secret", device_name, {
            Self::join_with_secret_inner(
                home,
                device_name,
                passphrase,
                vault_key_hex,
                storage,
                secret,
            )
        })
    }

    fn join_with_secret_inner(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        crate::logging::register_secret(vault_key_hex);
        Self::join_with_signer(
            home,
            device_name,
            passphrase,
            vault_key_hex,
            storage,
            secret,
            None,
        )
    }

    /// Like `join_with_secret`, with the signing key the device already made
    /// (an organization request): its device id is then the one the admin
    /// approved. Without one a fresh key is generated.
    pub(crate) fn join_with_signer(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
        secret: Option<String>,
        signer: Option<crypto::SigningKey>,
    ) -> Result<Engine> {
        ensure_no_vault(home)?;
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
        util::private_home(home)?;
        let keys = Keys {
            master,
            signer: signer.unwrap_or_else(crypto::SigningKey::generate),
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
        engine.add_storage_internal(storage, secret)?;
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
        crate::logged_op_plain!("join paired", device_name, {
            Self::join_paired_inner(home, device_name, passphrase, bundle)
        })
    }

    fn join_paired_inner(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
    ) -> Result<(Engine, Vec<String>)> {
        Self::join_paired_with(home, device_name, passphrase, bundle, None)
    }

    pub(crate) fn join_paired_with(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
        signer: Option<crypto::SigningKey>,
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
        let mut engine = Self::join_with_signer(
            home,
            device_name,
            passphrase,
            &bundle.vault_key,
            chosen.spec.clone(),
            chosen.secret.clone(),
            signer,
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
                .and_then(|()| engine.add_storage_internal(s.spec.clone(), s.secret.clone()));
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
        self.org_allows(|p| p.members_may_add_devices, "add devices")?;
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
            snapshot_sink: None,
            pack_caches: Default::default(),
            prefetched: HashMap::new(),
            local_rules: None,
            fetch_stats: Default::default(),
            unlocked: BTreeMap::new(),
            home: home.to_path_buf(),
            vault,
            keys,
            config: Config::default(),
            keyring: Keyring::default(),
            ledger: LedgerStore::open(&home.join("ledger"))?,
            clock: Clock::default(),
            clock_reserved: 0,
            clock_writes: 0,
            devices: DeviceCache::default(),
            pending: Vec::new(),
            forked_self: false,
            ledger_alarm: Default::default(),
            epochs,
            removal: None,
            org: crate::org::OrgState::load(home),
            chunker: ChunkerParams::DEFAULT,
            storage_calls: None,
            storages_open: Default::default(),
            view_cache: Default::default(),
            cycle: None,
            ledger_policy: Default::default(),
            manifest_policy: Default::default(),
            hold_exempt: None,
            download_log: None,
            meta_caps: crate::fsmeta::Caps::here(),
            scan_extra: (0, 0),
            last_scan: None,
            role_guard_off: false,
            platform_override: None,
            version_override: None,
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
        Self::accept_share_with_secret(home, device_name, passphrase, token, storage, None)
    }

    /// Like `accept_share`, through a storage that needs a secret (an S3
    /// bucket both users can reach); the secret goes into this device's
    /// encrypted secret store.
    pub fn accept_share_with_secret(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        token: &ShareToken,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        crate::logged_op_plain!("accept share with secret", device_name, {
            Self::accept_share_with_secret_inner(
                home,
                device_name,
                passphrase,
                token,
                storage,
                secret,
            )
        })
    }

    fn accept_share_with_secret_inner(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        token: &ShareToken,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        ensure_no_vault(home)?;
        let backend = storage.open_with(&|_| secret.clone())?;
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
        util::private_home(home)?;
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
            placement: None,
            placement_updated_utc: 0,
            strongroom: None,
            removed_utc: 0,
            epoch_keys: token.epoch_keys.clone(),
            backup: None,
            share_join: (!token.join_secret_hex.is_empty()).then(|| crate::vault::ShareJoin {
                invite: token.invite.clone(),
                secret_hex: token.join_secret_hex.clone(),
                role: token.role,
            }),
        };
        engine.keyring.folders.insert(rec.folder_id.clone(), rec);
        // The request key stays as this member's KEM key: grants of later
        // share epochs are sealed to it.
        engine.adopt_member_kem()?;
        engine.remember_share_owners(&token.folder_id, &token.owners)?;
        engine.keyring.save(
            home,
            &engine.keys,
            &engine.vault.vault_id,
            &engine.vault.device_id,
        )?;
        engine.add_storage_internal(storage, secret)?;
        engine.pending.push(Event::DeviceEnrolled {
            name: engine.vault.device_name.clone(),
        });
        engine.commit_batch()?;
        engine.pull_registry()?;
        Ok(engine)
    }

    /// Owner: share a folder with another user. The token carries the folder
    /// key (and the keys of later epochs); seal it to the recipient's request
    /// code with `ShareToken::seal` (see `share_ops::share_create_for`).
    pub fn share_create(&mut self, folder: &str) -> Result<ShareToken> {
        crate::logged_op_plain!("share create", folder, { self.share_create_inner(folder) })
    }

    fn share_create_inner(&mut self, folder: &str) -> Result<ShareToken> {
        self.share_prepare(folder)
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
                let (fid, epoch) = crate::share::parse_ledger_key_id(other)?;
                let rec = self.keyring.folders.get(&fid)?;
                Some(vault::share_ledger_key(
                    &self.share_epoch_key(rec, epoch)?,
                    &rec.folder_id,
                ))
            }
        }
    }

    /// Unlock an existing device directory.
    pub fn open(home: &Path, passphrase: &str) -> Result<Engine> {
        crate::logged_op_plain!("open", home.display(), {
            Self::open_inner(home, passphrase)
        })
    }

    fn open_inner(home: &Path, passphrase: &str) -> Result<Engine> {
        let vault: LocalVault = util::read_json(&home.join("vault.json"))
            .with_context(|| format!("no vault in {}", home.display()))?;
        if vault.format_version != crate::FORMAT_VERSION {
            bail!(
                "local vault format {} is not readable by this version",
                vault.format_version
            );
        }
        util::private_home(home)?;
        let keys = Keys::load(home, passphrase, &vault.vault_id, &vault.device_id)?;
        let keyring = Keyring::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let epochs = membership::VaultEpochs::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let removal = util::read_json(&home.join("removed.json")).ok();
        let clock: Clock = util::read_json_or_default(&home.join("clock.json"))?;
        let mut engine = Engine {
            peers: None,
            snapshot_sink: None,
            pack_caches: Default::default(),
            prefetched: HashMap::new(),
            local_rules: None,
            fetch_stats: Default::default(),
            unlocked: BTreeMap::new(),
            config: Config::load(home)?,
            ledger: LedgerStore::open(&home.join("ledger"))?,
            clock: clock.clone(),
            // The file holds the end of the last reservation: the values
            // below it may have been handed out before the last exit.
            clock_reserved: clock.lamport,
            clock_writes: 0,
            devices: util::read_json_or_default(&home.join("devices.json"))?,
            home: home.to_path_buf(),
            vault,
            keys,
            keyring,
            pending: Vec::new(),
            forked_self: false,
            ledger_alarm: Default::default(),
            epochs,
            removal,
            org: crate::org::OrgState::load(home),
            chunker: ChunkerParams::DEFAULT,
            storage_calls: None,
            storages_open: Default::default(),
            view_cache: Default::default(),
            cycle: None,
            ledger_policy: Default::default(),
            manifest_policy: Default::default(),
            hold_exempt: None,
            download_log: None,
            meta_caps: crate::fsmeta::Caps::here(),
            scan_extra: (0, 0),
            last_scan: None,
            role_guard_off: false,
            platform_override: None,
            version_override: None,
        };
        let (pending, pending_lost) = ledger_upkeep::load_deferred(home);
        engine.pending = pending;
        engine.ledger_alarm = ledger_recovery::Alarm::at_open(&engine, pending_lost);
        if engine.ledger_alarm.fork_marked() {
            // A real fork was found earlier: this identity signs nothing more.
            engine.forked_self = true;
        }
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

    /// The next logical clock value. The clock lives in memory; `clock.json`
    /// holds the end of a reservation of `CLOCK_RESERVE` values and is
    /// written (and fsynced) only when the reservation is used up, not on
    /// every tick. A restart continues after the reserved end, so no value
    /// is handed out twice; the unused rest of a reservation is wasted,
    /// which Lamport ordering does not mind.
    fn tick(&mut self) -> Result<u64> {
        if self.clock.lamport >= self.clock_reserved {
            self.reserve_clock()?;
        }
        self.clock.lamport = self
            .clock
            .lamport
            .checked_add(1)
            .ok_or_else(|| anyhow!("the logical clock of this vault is exhausted"))?;
        Ok(self.clock.lamport)
    }

    /// Reserve the next `CLOCK_RESERVE` values in `clock.json`. Another
    /// process on this device (the command line beside the background
    /// service) may have reserved values meanwhile: the new reservation
    /// starts after the higher of its end and our own value, so the two
    /// processes never hand out the same value.
    fn reserve_clock(&mut self) -> Result<()> {
        let path = self.home.join("clock.json");
        if let Ok(disk) = util::read_json::<Clock>(&path) {
            self.clock.lamport = self.clock.lamport.max(disk.lamport);
        }
        let end = self
            .clock
            .lamport
            .checked_add(CLOCK_RESERVE)
            .ok_or_else(|| anyhow!("the logical clock of this vault is exhausted"))?;
        util::write_json(&path, &Clock { lamport: end })?;
        self.clock_reserved = end;
        self.clock_writes += 1;
        Ok(())
    }

    /// Tests: one tick of the logical clock.
    #[doc(hidden)]
    pub fn tick_clock(&mut self) -> Result<u64> {
        self.tick()
    }

    /// Tests: how many times this engine wrote `clock.json`.
    #[doc(hidden)]
    pub fn clock_writes(&self) -> u64 {
        self.clock_writes
    }

    /// Most a clock seen elsewhere may be ahead of ours: a device cannot
    /// have made more events than this since we last heard from the vault.
    /// Larger values are a damaged or hostile batch and are not adopted, so
    /// one bad value cannot push everyone's clock to the end and win every
    /// later ordering.
    const CLOCK_LEAP: u64 = 1 << 40;

    fn observe_clock(&mut self, seen: u64) -> Result<()> {
        if seen > self.clock.lamport && seen <= self.clock.lamport.saturating_add(Self::CLOCK_LEAP)
        {
            self.clock.lamport = seen;
            if seen >= self.clock_reserved {
                // Beyond what the file reserves: the next ticks must not be
                // reused by another process or after a restart.
                self.reserve_clock()?;
            }
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

    /// Open a storage, or hand out the one opened earlier in this operation.
    /// Disk pools are opened anew every time: their disks come and go.
    fn open_spec(&self, spec: &StorageSpec) -> Result<Box<dyn Storage>> {
        if let StorageSpec::Pool { .. } = spec {
            return self.open_spec_fresh(spec);
        }
        let mut open = self.storages_open.lock().unwrap();
        if let Some((cached, backend)) = open.get(spec.name()) {
            if cached == spec {
                return Ok(Box::new(crate::storage::SharedStorage(backend.clone())));
            }
        }
        let backend: std::sync::Arc<dyn Storage> =
            std::sync::Arc::from(self.open_spec_fresh(spec)?);
        open.insert(spec.name().to_string(), (spec.clone(), backend.clone()));
        Ok(Box::new(crate::storage::SharedStorage(backend)))
    }

    /// Drop the storages opened so far: the list, a spec or a secret changed.
    fn forget_storages(&self) {
        self.storages_open.lock().unwrap().clear();
    }

    /// The end of a user-level operation (a sync, a push, a pull): what the
    /// storages learned is kept and the opened backends are dropped, so the
    /// next operation sees a changed bucket or secret. Inside a sync's cycle
    /// the storages stay open for its remaining phases.
    fn finish_storages(&mut self) {
        if self.cycle.is_some() {
            return;
        }
        self.learn_conditional_writes();
        self.forget_storages();
    }

    /// Remember in `config.json` what the S3 storages found out about
    /// `If-None-Match: *` (`Storage::conditional_writes`), so the probe is
    /// not repeated by the next process.
    fn learn_conditional_writes(&mut self) {
        let learned: Vec<(String, bool)> = self
            .storages_open
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(name, (_, backend))| {
                backend.conditional_writes().map(|c| (name.clone(), c))
            })
            .filter(|(name, c)| self.config.conditional_writes.get(name) != Some(c))
            .collect();
        if learned.is_empty() {
            return;
        }
        for (name, c) in learned {
            self.config.conditional_writes.insert(name, c);
        }
        if let Err(e) = self.config.save(&self.home) {
            log::warn!("config.json not saved after probing conditional writes: {e:#}");
        }
    }

    /// Whether an S3 storage honours conditional writes (`If-None-Match:
    /// *`), when its first write has probed it (`crate::s3`).
    pub fn conditional_writes(&self, storage: &str) -> Option<bool> {
        self.config.conditional_writes.get(storage).copied()
    }

    fn open_spec_fresh(&self, spec: &StorageSpec) -> Result<Box<dyn Storage>> {
        let kind = match spec {
            StorageSpec::LocalDir { .. } => "local",
            StorageSpec::S3 { .. } => "s3",
            StorageSpec::Rclone { .. } => "rclone",
            StorageSpec::Pool { .. } => "pool",
        };
        let backend: Box<dyn Storage> = if let StorageSpec::Pool { .. } = spec {
            Box::new(self.open_pool(spec)?)
        } else {
            let store = self.secret_store()?;
            let options = crate::storage::OpenOptions {
                conditional_writes: self.config.conditional_writes.get(spec.name()).copied(),
            };
            let inner = spec.open_with_options(&|r| store.secrets.get(r).cloned(), &options)?;
            // Small blocks go into packs on hot storages; cold storage and
            // transferrers keep one object per block (restores and removals
            // work per object there). Packs are read wherever they are.
            let packing = !spec.is_cold() && !spec.is_carrier();
            Box::new(crate::packs::PackAware::new(
                inner,
                &self.pack_caches,
                packing,
            ))
        };
        let backend: Box<dyn Storage> = Box::new(crate::storage::LoggedStorage::new(backend, kind));
        Ok(match &self.storage_calls {
            Some(calls) => Box::new(crate::storage::CountingStorage::new(backend, calls.clone())),
            None => backend,
        })
    }

    /// Count every call this engine makes to its storages from now on
    /// (measurements and tests).
    #[doc(hidden)]
    pub fn count_storage_calls(&mut self, calls: std::sync::Arc<crate::storage::StorageCalls>) {
        self.storage_calls = Some(calls);
        self.forget_storages();
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
        Ok(
            PoolStorage::open(spec, &self.home, self.pool_identity(spec.name()))?
                .with_verify_parallelism(self.verify_setting(spec.name())),
        )
    }

    /// The device's verification setting for a storage, pool, `folder:<name>`
    /// or `block-cache` (`config.json`, `verify_parallelism`; `*` for the rest).
    pub(crate) fn verify_setting(&self, name: &str) -> crate::parverify::Parallelism {
        let p = &self.config.verify_parallelism;
        p.get(name)
            .or_else(|| p.get("*"))
            .copied()
            .unwrap_or_default()
    }

    /// How verification reads a storage: S3 and rclone are network
    /// storages; a directory is on whatever medium its path is.
    pub(crate) fn storage_lane(&self, spec: &StorageSpec) -> crate::parverify::LanePlan {
        use crate::media::{storage_media, Media};
        let media = match spec {
            StorageSpec::S3 { .. } | StorageSpec::Rclone { .. } => Media::Network,
            StorageSpec::LocalDir { path, .. } => storage_media(path),
            // The disks attached now (their marker is where they were last
            // mounted), read as one: `get` takes whichever holds a copy.
            StorageSpec::Pool { disks, .. } => Media::combined(
                &disks
                    .iter()
                    .filter_map(|d| d.last_mount.as_ref())
                    .filter(|m| crate::pool::DiskMarker::path(m).is_file())
                    .map(|m| storage_media(m))
                    .collect::<Vec<_>>(),
            ),
        };
        crate::parverify::lane_plan(media, self.verify_setting(spec.name()))
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
        crate::logged_op_plain!("add storage with secret", spec.name().to_string(), {
            self.add_storage_with_secret_inner(spec, secret)
        })
    }

    fn add_storage_with_secret_inner(
        &mut self,
        spec: StorageSpec,
        secret: Option<String>,
    ) -> Result<()> {
        self.org_allows(|p| p.members_may_add_storages, "add storages")?;
        self.add_storage_internal(spec, secret)
    }

    /// `add_storage_with_secret` without the organization's policy check:
    /// for joining, where the storages come from the device that approved
    /// or paired this one.
    fn add_storage_internal(&mut self, spec: StorageSpec, secret: Option<String>) -> Result<()> {
        if self.config.storages.iter().any(|s| s.name() == spec.name()) {
            bail!("a storage named {} already exists", spec.name());
        }
        if spec.is_cold() && spec.is_carrier() {
            bail!("a storage is either a transferrer or cold storage, not both");
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
            self.forget_storages();
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
        // Storages being drained are leaving too: they neither count nor
        // receive copies.
        let closed = self.closed_storages();
        let others: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != name && !s.is_carrier() && !closed.contains(s.name()))
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
        let gate = self.quota_gate(&view);
        let mut targets_used = BTreeSet::new();
        // Backups count too: their blocks are on storages only.
        let records: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed())
            .cloned()
            .collect();
        for rec in records {
            let policy = rec.effective_policy().unwrap_or_default();
            let required = policy.min_copies.max(1) as usize;
            // Blocks no file refers to any more need no copies; a folder never
            // pulled here has no state, so then every block counts. A backup:
            // the blocks of the snapshots this device has seen.
            let referenced: HashSet<ChunkId> = if rec.is_backup() {
                self.backup_blocks_known(&rec.folder_id)
                    .into_iter()
                    .map(|(c, _)| c)
                    .collect()
            } else {
                self.load_state(&rec.folder_id)
                    .map(|st| {
                        st.files
                            .values()
                            .filter(|f| !f.deleted)
                            .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            // Blocks of the folder's trash keep one copy (`trash`); the
            // folder's copy rules are for its current files.
            let trashed: HashSet<ChunkId> = if rec.is_backup() {
                HashSet::new()
            } else {
                self.trash_chunks(&rec.folder_id)
                    .into_iter()
                    .map(|c| c.chunk)
                    .filter(|c| !referenced.contains(c))
                    .collect()
            };
            for ((folder, chunk), cr) in &view.chunks {
                if folder != &rec.folder_id || !cr.storages.contains_key(name) {
                    continue;
                }
                let trash_only = trashed.contains(chunk);
                if !referenced.is_empty() && !referenced.contains(chunk) && !trash_only {
                    continue;
                }
                let (policy, required) = if trash_only {
                    (crate::policy::Policy::default(), 1)
                } else {
                    (policy.clone(), required)
                };
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
                    !holders.iter().any(|h| h.as_str() == s.name())
                        && !targets.contains(&s.name())
                        && gate.fits(s.name(), cr.size)
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
                    gate.take(t, cr.size);
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
        crate::logged_op_plain!("remove storage", name, {
            self.remove_storage_inner(name, delete_data)
        })
    }

    fn remove_storage_inner(
        &mut self,
        name: &str,
        delete_data: bool,
    ) -> Result<StorageRemovalReport> {
        self.org_allows(|p| p.members_may_add_storages, "remove storages")?;
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
            let task = activity::start(
                activity::STORAGE_REMOVAL,
                name,
                plan.copies.len() as u64,
                activity::Unit::Items,
            );
            task.set_phase("copy");
            for c in &plan.copies {
                task.advance(1);
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
                let keys = source.list("")?;
                task.step("delete", keys.len() as u64, activity::Unit::Items);
                for key in keys {
                    task.advance(1);
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
        self.config.storage_settings.remove(name);
        self.config.conditional_writes.remove(name);
        self.config.save(&self.home)?;
        self.forget_storages();
        self.forget_drain_state(name);
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
        // A drained storage holds nothing Varsto needs any more (`drain`).
        let drained = self.drained_storages();
        Ok(self
            .open_storages(include_cold)?
            .into_iter()
            .filter(|(s, _)| !s.is_data_only() && !drained.contains(s.name()))
            .collect())
    }

    /// Create a folder in the vault and mount it at `path` on this device.
    pub fn add_folder(&mut self, name: &str, path: &Path) -> Result<FolderId> {
        crate::logged_op_plain!("add folder", name, { self.add_folder_inner(name, path) })
    }

    fn add_folder_inner(&mut self, name: &str, path: &Path) -> Result<FolderId> {
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
            placement: None,
            placement_updated_utc: 0,
            strongroom: None,
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
            backup: None,
            share_join: None,
        };
        let id = rec.folder_id.clone();
        folder_safety::write_marker(path, &rec)?;
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
            mode: Default::default(),
            deletion_guard: None,
            ignore_local: Vec::new(),
            meta: Default::default(),
            min_free: None,
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
        crate::logged_op_plain!("attach folder", name_or_id, {
            self.attach_folder_inner(name_or_id, path, selective)
        })
    }

    fn attach_folder_inner(
        &mut self,
        name_or_id: &str,
        path: &Path,
        selective: bool,
    ) -> Result<FolderId> {
        if let Some(b) = self.keyring.find_backup(name_or_id) {
            bail!(
                "{} is a backup: backups are never attached; restore it into a directory instead (varsto backup restore)",
                b.name
            );
        }
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
            mode: Default::default(),
            deletion_guard: None,
            ignore_local: Vec::new(),
            meta: Default::default(),
            min_free: None,
        });
        self.config.save(&self.home)?;
        folder_safety::write_marker(path, &rec)?;
        Ok(rec.folder_id.clone())
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
        crate::logged_op_plain!("detach folder", name, { self.detach_folder_inner(name) })
    }

    fn detach_folder_inner(&mut self, name: &str) -> Result<()> {
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
        self.forget_marker_flag(folder);
        Ok(())
    }

    fn forget_folder(&mut self, folder: &FolderId, removed_utc: i64) -> Result<()> {
        self.detach_mount(folder)?;
        self.forget_notes(folder);
        if self.config.backups.iter().any(|b| &b.folder_id == folder) {
            self.config.backups.retain(|b| &b.folder_id != folder);
            self.config.save(&self.home)?;
        }
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
        crate::logged_op!("remove folder", name, {
            self.remove_folder_inner(name, purge)
        })
    }

    fn remove_folder_inner(&mut self, name: &str, purge: bool) -> Result<u64> {
        if self.vault.member {
            bail!("a member device cannot remove the owner's folders");
        }
        let rec = self
            .keyring
            .find(name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {name}"))?;
        self.remove_record(&rec, purge)
    }

    /// Publish the removal of a folder or backup, delete its data when
    /// `purge`, and forget it here.
    fn remove_record(&mut self, rec: &FolderRecord, purge: bool) -> Result<u64> {
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
            let storages = self.open_storages(true)?;
            let task = activity::start(
                activity::FOLDER_PURGE,
                &rec.name,
                (objects.len() * storages.len()) as u64,
                activity::Unit::Items,
            );
            for (_, backend) in storages {
                for key in &objects {
                    if backend.exists(key).unwrap_or(false) {
                        backend.delete(key)?;
                        deleted += 1;
                    }
                    task.advance(1);
                }
                for prefix in [
                    format!("manifests/{}/", rec.folder_id),
                    format!("thumbs/{}/", rec.folder_id),
                    format!("vault/access/{}/", rec.folder_id),
                    notes::folder_prefix(&rec.folder_id),
                    trash::record_prefix(&rec.folder_id),
                    crate::snapshot::Snapshot::backup_prefix(&rec.folder_id),
                ] {
                    for key in backend.list(&prefix)? {
                        backend.delete(&key)?;
                        deleted += 1;
                    }
                }
            }
        }
        self.forget_folder(&rec.folder_id, removal.removed_utc)?;
        if purge {
            self.forget_trash(&rec.folder_id);
        }
        Ok(deleted)
    }

    /// The vault's folders (backups are listed by `backups`).
    pub fn folders(&self) -> Vec<(FolderRecord, Option<PathBuf>)> {
        self.keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_backup())
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

    /// The free space a folder's disk keeps here (`folder set --min-free`).
    pub fn folder_min_free(&self, folder: &FolderId) -> crate::freespace::MinFree {
        self.config
            .folders
            .iter()
            .find(|m| &m.folder_id == folder)
            .and_then(|m| m.min_free)
            .unwrap_or(crate::freespace::DEFAULT)
    }

    /// Set (or, with `None`, reset to the default) the free space kept on
    /// the disk holding a folder attached here.
    pub fn set_folder_min_free(
        &mut self,
        name_or_id: &str,
        min: Option<crate::freespace::MinFree>,
    ) -> Result<()> {
        let (rec, _) = self.resolve_folder(name_or_id)?;
        let m = self
            .config
            .folders
            .iter_mut()
            .find(|m| m.folder_id == rec.folder_id)
            .ok_or_else(|| anyhow!("folder {} is not attached on this device", rec.name))?;
        m.min_free = min;
        self.config.save(&self.home)?;
        crate::freespace::forget(&crate::freespace::Place::folder(&rec.name).key);
        Ok(())
    }

    /// Set (or reset) the free space kept on a local-directory storage's disk.
    pub fn set_storage_min_free(
        &mut self,
        name: &str,
        min: Option<crate::freespace::MinFree>,
    ) -> Result<()> {
        let spec = self
            .config
            .storages
            .iter_mut()
            .find(|s| s.name() == name)
            .ok_or_else(|| anyhow!("no storage named {name}"))?;
        match spec {
            StorageSpec::LocalDir { min_free, .. } => *min_free = min,
            StorageSpec::Pool { .. } => bail!(
                "{name} is a disk pool: it keeps its own reserve on every disk (set when the pool is added)"
            ),
            _ => bail!("{name} is not on a disk of this device; a minimum free space applies to local directories only"),
        }
        self.config.save(&self.home)?;
        crate::freespace::forget(&crate::freespace::Place::storage(name).key);
        Ok(())
    }

    /// May `needed` bytes be written at `disk` for `rec`? Within the
    /// folder's root the folder's limit applies, elsewhere (a restore
    /// target) the default one.
    pub(crate) fn space_for(&self, rec: &FolderRecord, disk: &Path, needed: u64) -> Result<()> {
        use crate::freespace::{check, Place, DEFAULT};
        let mount = self
            .config
            .folders
            .iter()
            .find(|m| m.folder_id == rec.folder_id && disk.starts_with(&m.path));
        match mount {
            Some(m) => check(
                &Place::folder(&rec.name),
                disk,
                m.min_free.unwrap_or(DEFAULT),
                needed,
            ),
            None => {
                let dir = disk.parent().unwrap_or(disk);
                check(&Place::path(dir), disk, DEFAULT, needed)
            }
        }
    }

    fn mount_is_selective(&self, folder: &FolderId) -> bool {
        self.config
            .folders
            .iter()
            .any(|m| &m.folder_id == folder && m.selective)
    }

    /// Switch selective sync on or off for an attached folder.
    pub fn set_selective(&mut self, name_or_id: &str, selective: bool) -> Result<()> {
        crate::logged_op_plain!("set selective", name_or_id, {
            self.set_selective_inner(name_or_id, selective)
        })
    }

    fn set_selective_inner(&mut self, name_or_id: &str, selective: bool) -> Result<()> {
        let (rec, _) = self.resolve_folder(name_or_id)?;
        self.ensure_not_held(&rec)?;
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

    /// Mark an attached folder as "encrypted on this device" (phones): its
    /// files are kept as encrypted blocks and read through the app only (see
    /// `engine::block_cache`); selective sync chooses which files are kept,
    /// as in any folder. Plain files already in its directory are converted
    /// on the next sync. Switching back is refused once the folder has
    /// files: detach it and attach it again with plain files instead.
    pub fn set_encrypted_here(&mut self, name_or_id: &str, encrypted: bool) -> Result<()> {
        crate::logged_op_plain!("set encrypted here", name_or_id, {
            self.set_encrypted_here_inner(name_or_id, encrypted)
        })
    }

    fn set_encrypted_here_inner(&mut self, name_or_id: &str, encrypted: bool) -> Result<()> {
        let (rec, _) = self.resolve_folder(name_or_id)?;
        if !encrypted
            && self.mount_is_encrypted(&rec.folder_id)
            && self
                .load_state(&rec.folder_id)?
                .files
                .values()
                .any(|f| !f.deleted)
        {
            bail!(
                "{} keeps its files encrypted on this device; detach it and attach it again to keep plain files",
                rec.name
            );
        }
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.encrypted = encrypted;
        }
        self.config.save(&self.home)?;
        // Only folders with plain files carry a marker (`folder_safety`).
        let (_, root) = self.resolve_folder(name_or_id)?;
        if encrypted {
            let _ = fs::remove_file(root.join(FOLDER_MARKER));
        } else if root.is_dir() {
            folder_safety::write_marker(&root, &rec)?;
        }
        Ok(())
    }

    /// Replace every local copy in a folder with a placeholder where the
    /// storages hold the content. Returns (freed, kept): files not yet stored
    /// elsewhere are kept.
    pub fn free_folder(&mut self, folder: &str) -> Result<(u64, u64)> {
        crate::logged_op!("free folder", folder, { self.free_folder_inner(folder) })
    }

    fn free_folder_inner(&mut self, folder: &str) -> Result<(u64, u64)> {
        let (rec, root) = self.resolve_for_write(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        if self.mount_is_encrypted(&rec.folder_id) {
            let paths: Vec<String> = state.local_index.keys().cloned().collect();
            let kept = self.free_cached(&rec, &paths)?.len() as u64;
            return Ok((paths.len() as u64 - kept, kept));
        }
        let paths: Vec<String> = state
            .files
            .values()
            .filter(|f| !f.deleted && self.disk_of(&root, &state, &f.path).exists())
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

    /// Folders kept "encrypted on this device" that still hold plain copies
    /// from before the block cache (when such folders were decrypted while
    /// unlocked), handled without the keys (the vault is locked at service
    /// start): only files whose on-disk content is exactly what the ledger
    /// already holds (local index matches the manifest and the file is
    /// unchanged since) are replaced by placeholders; anything else is kept
    /// for the conversion on the next sync while unlocked. Returns the number
    /// of files removed.
    pub fn wipe_encrypted_folders_locked(home: &Path) -> Result<u64> {
        let config = Config::load(home)?;
        let mut freed = 0u64;
        for m in config.folders.iter().filter(|m| m.encrypted) {
            let state_path = home.join("state").join(format!("{}.json", m.folder_id));
            let mut state: FolderState = util::read_json_or_default(&state_path)?;
            if state.block_cache {
                continue; // nothing plain is kept any more
            }
            let mut changed = false;
            let files: Vec<_> = state
                .files
                .values()
                .filter(|f| !f.deleted)
                .cloned()
                .collect();
            for f in files {
                let disk = state.local_names.disk(
                    &m.path,
                    crate::names::LocalRules::detect(&m.path),
                    &f.path,
                );
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

    /// `resolve_folder` for what writes into the folder's directory: refused
    /// while a restic run holds the folder (`restic_mirror`).
    /// The folder's directory must also carry its marker (`folder_safety`).
    fn resolve_for_write(&self, name_or_id: &str) -> Result<(FolderRecord, PathBuf)> {
        let found = self.resolve_folder(name_or_id)?;
        self.ensure_not_held(&found.0)?;
        self.ensure_marker(&found.0, &found.1)?;
        Ok(found)
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
            self.publish_share_records(backend.as_ref(), &rec)?;
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
                let Ok(id) = DeviceId::from_hex(id) else {
                    continue;
                };
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
                let Ok(id) = DeviceId::from_hex(id) else {
                    continue;
                };
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
                let (Ok(dev), Ok(fid)) = (DeviceId::from_hex(dev), FolderId::from_hex(fid)) else {
                    continue;
                };
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
                    // `vault/policies/<folder>/<device>/<utc>.enc`: the name
                    // says who wrote it, the envelope proves it.
                    let Some(named) = key
                        .strip_prefix(vault::PolicyRecord::PREFIX)
                        .and_then(|r| r.split('/').nth(1))
                        .and_then(|d| DeviceId::from_hex(d).ok())
                    else {
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
                        let verify = |d: &DeviceId| self.device_key(d);
                        if let Ok(rec) = vault::PolicyRecord::open_any(
                            &blob,
                            &self.vault.vault_id,
                            &fid,
                            &named,
                            &fr_keys,
                            &verify,
                            self.org.is_none(),
                        ) {
                            if !self.trusted(&rec.device)
                                || !self.org_accepts_policy_from(&rec.device)
                            {
                                continue;
                            }
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
        // Member records, epochs and grants of shared folders.
        let (devs, folders) = self.pull_share_state()?;
        changed_devices |= devs;
        changed_folders |= folders;
        // Placement records: newest per folder wins, as for policies.
        changed_folders |= self.pull_placement_records()?;
        // Quotas and drains of the storages (`quotas`): newest per storage wins.
        self.pull_storage_settings()?;
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
            self.clear_deferred();
            return self.ensure_active().map(|_| None);
        }
        if let Err(e) = self.ensure_ledger_writable() {
            // Nothing is signed until the ledger is restored; the events
            // wait for it in `ledger/pending.json`.
            let _ = self.defer_events();
            return Err(e);
        }
        if self.cycle.is_some() {
            // One batch at the end of the action (see `one_batch`).
            self.defer_events()?;
            return Ok(None);
        }
        // A storage holding newer batches of this identity than this device
        // has (a copy restored from an old backup): signing now would sign a
        // number that exists already. One short listing, usually empty.
        if let Err(e) = self.check_storage_before_signing() {
            let _ = self.defer_events();
            return Err(e);
        }
        let lamport = self.tick()?;
        let events = std::mem::take(&mut self.pending);
        let n_events = events.len();
        if !self.vault.member {
            let (key_id, ledger_key) = self.ledger_key_now();
            let signed = self.ledger.append_own_seen(
                &self.vault.device_id,
                events,
                self.seen_heads(),
                lamport,
                &ledger_key,
                &key_id,
                &self.keys.signer,
            )?;
            log::debug!(seq = signed.seq, events = n_events, lamport = lamport, key_id = key_id.as_str(); "ledger batch sealed");
            // The events are in a local batch now.
            self.clear_deferred();
            let t = crate::logging::Timer::start();
            self.push_own_batches()?;
            log::debug!(seq = signed.seq, ms = t.ms(); "ledger batches pushed");
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
                | Event::ChunkDropped { folder, .. }
                | Event::FolderAdded { folder } => Some(folder.clone()),
                Event::SnapshotTaken { backup, .. }
                | Event::SnapshotExpired { backup, .. }
                | Event::BackupStopped { backup } => Some(backup.clone()),
                Event::DeviceEnrolled { .. } | Event::StorageRetired { .. } | Event::Unknown => {
                    None
                }
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
            let (key_id, key) = self.share_ledger_key_now(rec)?;
            let signed = self.ledger.append_own_with(
                &self.vault.device_id,
                evs,
                lamport,
                &key,
                &key_id,
                &self.keys.signer,
            )?;
            log::debug!(seq = signed.seq, folder:% = fid, lamport = lamport; "ledger batch sealed for a shared folder");
            last = Some(signed.seq);
        }
        self.clear_deferred();
        self.push_own_batches()?;
        Ok(last)
    }

    fn mark_forked(&mut self, _device: &DeviceId) -> Result<()> {
        // Another copy of this device identity has published batches we never
        // wrote (restored from an old backup, or cloned). Refuse to sign more.
        self.forked_self = true;
        Ok(())
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
        let _task = activity::start(activity::SYNC_SCAN, &rec.name, 0, activity::Unit::Items);
        if self.mount_is_encrypted(&rec.folder_id) {
            return self.scan_cached(rec, root, state);
        }
        let fk = self.folder_keys(rec)?;
        let me = self.vault.device_id.clone();
        // Chunks this folder already references keep their object (and key
        // epoch): after a key change, unchanged content is not re-uploaded.
        // Built when the first changed file needs it: a scan that finds
        // nothing changed never copies the folder's chunk list.
        let mut known: Option<std::collections::HashMap<ChunkId, ChunkRef>> = None;
        let mut seen = BTreeSet::new();
        let mut placeholders: BTreeSet<String> = BTreeSet::new();
        // Entries left as they are in the vault: links while links are off
        // here (or whose target is not text), and notes standing for links.
        let mut kept: BTreeSet<String> = BTreeSet::new();
        let mut scanned = 0u64;
        let mut changed = 0u64;
        let mut ignored = 0u64;
        let mut meta_changed = 0u64;
        let mut new_index = BTreeMap::new();
        let rules = self.local_rules(root);
        let mut replaced: Vec<(FileState, u64)> = Vec::new();
        // A backup takes what it can read; the rest is named in its snapshot.
        let backup = rec.is_backup();
        state.unreadable.clear();
        // Receive-only: local changes are noted, never made versions.
        let receive_only =
            !backup && self.mount_mode(&rec.folder_id) == crate::vault::FolderMode::ReceiveOnly;
        if !receive_only && !state.local_changes.is_empty() {
            // No longer receive-only: the changes are scanned again as
            // ordinary changes and published.
            for p in std::mem::take(&mut state.local_changes).keys() {
                state.local_index.remove(p);
            }
        }
        let (local_rules, settings) = self
            .config
            .folders
            .iter()
            .find(|m| m.folder_id == rec.folder_id)
            .map(|m| (m.ignore_local.clone(), m.meta))
            .unwrap_or_default();
        let caps = self.meta_caps;
        // Ignore rules (`ignore_rules`); a backup has its own selection.
        let mut ignore = (!backup).then(|| IgnoreMatcher::new(Some(root), &local_rules));
        let mut names = fsmeta::Names::default();
        let mut walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !reserved_name(&e.file_name().to_string_lossy()));
        while let Some(entry) = walker.next() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) if backup => {
                    if let Some(p) = e
                        .path()
                        .and_then(|p| p.strip_prefix(root).ok())
                        .and_then(util::manifest_path)
                    {
                        let p = state.local_names.vault_of(rules, &p);
                        state.unreadable.insert(p);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if entry.depth() == 0 {
                continue;
            }
            let ft = entry.file_type();
            if !(ft.is_file() || ft.is_dir() || ft.is_symlink()) {
                continue;
            }
            let rel = entry.path().strip_prefix(root)?;
            let Some(local) = util::manifest_path(rel) else {
                continue;
            };
            // Local names map back to vault paths (`crate::names`).
            let path = state.local_names.vault_of(rules, &local);
            if let Some(m) = ignore.as_mut() {
                if m.walk_ignored(&path, ft.is_dir()) {
                    ignored += 1;
                    if ft.is_dir() {
                        walker.skip_current_dir();
                    }
                    continue;
                }
            }
            if ft.is_dir() {
                continue;
            }
            if let Some(real) = local.strip_suffix(PLACEHOLDER_SUFFIX) {
                placeholders.insert(state.local_names.vault_of(rules, real));
                continue;
            }
            let path = state.local_names.vault_of(rules, &local);
            let md = entry.metadata()?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            if ft.is_symlink() {
                // A link is recorded with its target and never followed.
                let target = if settings.symlinks && caps.symlinks {
                    fsmeta::read_link(entry.path())
                } else {
                    None
                };
                let Some(target) = target else {
                    kept.insert(path);
                    continue;
                };
                scanned += 1;
                activity::advance_current(1);
                seen.insert(path.clone());
                let obs = fsmeta::observe(entry.path(), &md, &caps, &settings, &mut names);
                let prev = state.files.get(&path).filter(|f| !f.deleted);
                let seen_meta = state
                    .local_index
                    .get(&path)
                    .and_then(|e| e.meta_seen.as_ref());
                let mut meta =
                    fsmeta::combine(&obs, seen_meta, prev.and_then(|p| p.meta.as_ref()), &caps)
                        .unwrap_or_default();
                meta.v = fsmeta::META_VERSION;
                meta.mode = None;
                meta.xattrs = None;
                meta.symlink = Some(target.clone());
                let content_hash = fsmeta::link_hash(&fk.hash, &target);
                let same = prev.is_some_and(|p| {
                    p.content_hash == content_hash && p.meta.as_ref() == Some(&meta)
                });
                if !same && receive_only {
                    // Noted, not published (`folder_safety`).
                    let kind = if prev.is_some() {
                        folder_safety::ChangeKind::Modified
                    } else {
                        folder_safety::ChangeKind::Added
                    };
                    state.local_changes.insert(path.clone(), kind);
                } else if !same {
                    let clock = self.tick()?;
                    let mut version = state
                        .files
                        .get(&path)
                        .map(|p| p.version.clone())
                        .unwrap_or_default();
                    version.insert(me.clone(), clock);
                    state.files.insert(
                        path.clone(),
                        FileState {
                            path: path.clone(),
                            version,
                            deleted: false,
                            size: 0,
                            mtime,
                            content_hash: content_hash.clone(),
                            chunks: vec![],
                            modified_by: me.clone(),
                            modified_clock: clock,
                            meta: Some(meta),
                        },
                    );
                    changed += 1;
                }
                new_index.insert(
                    path,
                    LocalIndexEntry {
                        size: 0,
                        mtime,
                        content_hash,
                        meta_seen: Some(obs),
                    },
                );
                continue;
            }
            if let Some(real) = path.strip_suffix(PLACEHOLDER_SUFFIX) {
                placeholders.insert(real.to_string());
                continue;
            }
            if let Some(real) = path.strip_suffix(fsmeta::LINK_NOTE_SUFFIX) {
                if state.files.get(real).is_some_and(|f| f.is_symlink()) {
                    kept.insert(real.to_string());
                    continue;
                }
            }
            let size = md.len();
            scanned += 1;
            activity::advance_current(1);
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
            let obs = fsmeta::observe(entry.path(), &md, &caps, &settings, &mut names);
            let seen_meta = state
                .local_index
                .get(&path)
                .and_then(|e| e.meta_seen.clone());
            let unchanged = matches!(state.local_index.get(&path), Some(e) if e.size == size && e.mtime == mtime)
                && (matches!(state.files.get(&path), Some(f) if !f.deleted && !f.is_symlink())
                    || (receive_only && state.local_changes.contains_key(&path)));
            if unchanged {
                let mut ix = state.local_index[&path].clone();
                ix.meta_seen = Some(obs.clone());
                new_index.insert(path.clone(), ix);
                if !receive_only
                    && self.metadata_only_change(state, &path, &obs, seen_meta.as_ref(), &caps)?
                {
                    changed += 1;
                    meta_changed += 1;
                }
                continue;
            }
            // Changed or new: chunk, hash, (upload).
            let file = match fs::File::open(entry.path()) {
                Ok(f) => f,
                Err(_) if backup => {
                    state.unreadable.insert(path.clone());
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let mut hasher = KeyedHasher::new(&fk.hash);
            let mut chunks = Vec::new();
            let params = self.chunker_for(size);
            let events_before = self.pending.len();
            let mut read_failed = false;
            for chunk in Chunker::new(std::io::BufReader::new(file), params)? {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(_) if backup => {
                        read_failed = true;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                hasher.update(&chunk);
                let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &chunk));
                let known = known.get_or_insert_with(|| {
                    state
                        .files
                        .values()
                        .chain(state.pending_remote.values())
                        .flat_map(|f| f.chunks.iter())
                        .map(|c| (c.chunk.clone(), c.clone()))
                        .collect()
                });
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
                // A backup's blocks are kept on storages only: no device
                // offers them (`engine::backups`).
                if !rec.is_backup() {
                    self.pending.push(Event::ChunkOnDevice {
                        folder: rec.folder_id.clone(),
                        chunk: chunk_id.clone(),
                        object: object.clone(),
                        size: chunk.len() as u64,
                    });
                }
                chunks.push(ChunkRef {
                    chunk: chunk_id,
                    object,
                    size: chunk.len() as u64,
                    epoch,
                });
            }
            if read_failed {
                state.unreadable.insert(path.clone());
                continue;
            }
            let content_hash = hex::encode(hasher.finalize());
            let previous = state.files.get(&path);
            let was = previous.filter(|p| !p.deleted && !p.is_symlink()).cloned();
            if let Some(prev) = previous {
                if !prev.deleted && !prev.is_symlink() && prev.content_hash == content_hash {
                    // Touched but identical: keep the version, refresh the index.
                    state.local_changes.remove(&path);
                    new_index.insert(
                        path.clone(),
                        LocalIndexEntry {
                            size,
                            mtime,
                            content_hash,
                            meta_seen: Some(obs.clone()),
                        },
                    );
                    if !receive_only
                        && self.metadata_only_change(
                            state,
                            &path,
                            &obs,
                            seen_meta.as_ref(),
                            &caps,
                        )?
                    {
                        changed += 1;
                        meta_changed += 1;
                    }
                    continue;
                }
            }
            if receive_only {
                // Noted, not published: the blocks are not offered either.
                let kind = if previous.is_some_and(|p| !p.deleted) {
                    folder_safety::ChangeKind::Modified
                } else {
                    folder_safety::ChangeKind::Added
                };
                state.local_changes.insert(path.clone(), kind);
                self.pending.truncate(events_before);
                new_index.insert(
                    path,
                    LocalIndexEntry {
                        size,
                        mtime,
                        content_hash,
                        meta_seen: Some(obs),
                    },
                );
                continue;
            }
            let meta = fsmeta::combine(
                &obs,
                seen_meta.as_ref(),
                previous
                    .filter(|p| !p.deleted)
                    .and_then(|p| p.meta.as_ref()),
                &caps,
            );
            let mut version = previous.map(|p| p.version.clone()).unwrap_or_default();
            let clock = self.tick()?;
            version.insert(me.clone(), clock);
            if let Some(prev) = was {
                // Replaced: the previous version goes to the history
                // (`history`), with the clock of the new one.
                replaced.push((prev, clock));
            }
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
                    meta,
                },
            );
            new_index.insert(
                path,
                LocalIndexEntry {
                    size,
                    mtime,
                    content_hash,
                    meta_seen: Some(obs),
                },
            );
            changed += 1;
        }
        // Deletions. Paths the ignore rules cover are left as the vault has
        // them: an ignored file that disappears here is not deleted elsewhere.
        let gone: Vec<String> = state
            .files
            .iter()
            .filter(|(p, f)| {
                !f.deleted && !seen.contains(*p) && !placeholders.contains(*p) && !kept.contains(*p)
            })
            .map(|(p, _)| p.clone())
            .filter(|p| !ignore.as_mut().is_some_and(|m| m.is_ignored(p, false)))
            .collect();
        self.scan_extra = (ignored, meta_changed);
        // Index entries of ignored files go; those of kept links stay.
        for p in &kept {
            if let Some(e) = state.local_index.get(p) {
                new_index.insert(p.clone(), e.clone());
            }
        }
        if receive_only {
            for path in gone {
                state
                    .local_changes
                    .insert(path, folder_safety::ChangeKind::Deleted);
            }
            // Files added here and removed again are no change any more.
            state
                .local_changes
                .retain(|p, k| *k != folder_safety::ChangeKind::Added || seen.contains(p));
            state.local_index = new_index;
            return Ok((scanned, changed));
        }
        // Too many files gone at once: held until the user decides.
        if let Some(pause) = self.hold_local_deletions(rec, root, state, &gone) {
            // The versions this scan made are kept; their predecessors go
            // to the history as usual.
            self.history_record_replacements(rec, replaced)?;
            state.local_index = new_index;
            self.save_state(&rec.folder_id, state)?;
            return Err(pause.into());
        }
        let mut trashed: Vec<(FileState, u64)> = Vec::new();
        for path in gone {
            state.local_names.forget(rules, &path);
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
                    meta: None,
                },
            );
            trashed.push((prev, clock));
            changed += 1;
        }
        state.local_index = new_index;
        // The deleted versions go to the trash (`trash`), the replaced ones
        // to the history (`history`).
        self.trash_record_deletions(rec, state, trashed)?;
        self.history_record_replacements(rec, replaced)?;
        Ok((scanned, changed))
    }

    /// A file whose content did not change: publish a new version when its
    /// metadata did (the chunks stay; nothing is uploaded). True if it did.
    fn metadata_only_change(
        &mut self,
        state: &mut FolderState,
        path: &str,
        obs: &fsmeta::FileMeta,
        seen: Option<&fsmeta::FileMeta>,
        caps: &fsmeta::Caps,
    ) -> Result<bool> {
        let Some(prev) = state.files.get(path).filter(|f| !f.deleted) else {
            return Ok(false);
        };
        let meta = fsmeta::combine(obs, seen, prev.meta.as_ref(), caps);
        if meta == prev.meta {
            return Ok(false);
        }
        let me = self.vault.device_id.clone();
        let clock = self.tick()?;
        let mut next = prev.clone();
        next.version.insert(me.clone(), clock);
        next.modified_by = me;
        next.modified_clock = clock;
        next.meta = meta;
        state.files.insert(path.to_string(), next);
        Ok(true)
    }

    // ----- push ---------------------------------------------------------------

    pub fn push(&mut self, folder: &str) -> Result<PushReport> {
        self.push_with_scan(folder, None)
    }

    /// `push` with the scan a pull of the same folder just made, so a sync
    /// walks the folder once (`sync_folders`).
    fn push_with_scan(&mut self, folder: &str, scan: Option<ScanOutcome>) -> Result<PushReport> {
        let out = crate::logged_op!("push", folder, { self.push_inner(folder, scan) });
        self.finish_storages();
        out
    }

    fn push_inner(&mut self, folder: &str, scan: Option<ScanOutcome>) -> Result<PushReport> {
        self.ensure_active()?;
        self.ensure_ledger_writable()?;
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let (rec, root) = self.resolve_for_write(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        self.check_held(&rec, &root, &mut state)?;
        let mut report = PushReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        if self.share_read_only(&rec) {
            // A viewer publishes nothing for the folder; local changes are
            // kept aside and the shared version comes back on the next pull.
            report.read_only = true;
            report.kept_aside = self.read_only_guard(&rec, &root, &mut state)?;
            report.batch_seq = self.commit_batch()?;
            self.save_state(&rec.folder_id, &state)?;
            return Ok(report);
        }
        let (scanned, changed) = match scan.filter(|s| s.folder == rec.folder_id) {
            // The pull of this sync scanned the folder moments ago, and the
            // state it saved carries what it found.
            Some(s) => {
                self.scan_extra = s.extra;
                (s.scanned, s.changed)
            }
            None => self.scan(&rec, &root, &mut state)?,
        };
        report.files_scanned = scanned;
        report.files_changed = changed;
        (report.files_ignored, report.metadata_changed) = self.scan_extra;
        // Unpublished changes (this scan's, or ones a pull's scan recorded
        // before it): publish them first.
        // Only with peers: without them nobody can fetch from this device
        // before the upload, and the sync keeps to one ledger batch.
        let has_peers = self.peers.as_ref().is_some_and(|p| !p.is_empty());
        if has_peers && Manifest::files_hash(&state.files) != state.published_hash {
            // Tell the other devices about the new files before uploading
            // them: they fetch the blocks from this device peer to peer while
            // the storages receive their copies (a large file would otherwise
            // reach them only once its whole upload is done). A device that
            // cannot reach this one finds the blocks on the storages later.
            report.manifest_seq = self.publish_manifest(&rec, &mut state)?;
            self.ensure_manifest_everywhere(&rec, &state)?;
            // Now, not at the end of the sync: the other devices learn of the
            // new manifest from this batch.
            let cycle = self.cycle.take();
            let committed = self.commit_batch();
            self.cycle = cycle;
            committed?;
            self.save_state(&rec.folder_id, &state)?;
            self.refresh_snapshot();
            self.notify_peers_changed();
            log::debug!("push {}: file list published before the upload", rec.name);
        }
        self.upload_missing(&rec, &root, &state, &mut report)?;
        report.thumbnails = self.make_thumbnails(&rec, &root, &mut state)?;
        if let Some(seq) = self.publish_manifest(&rec, &mut state)? {
            report.manifest_seq = Some(seq);
        }
        self.ensure_manifest_everywhere(&rec, &state)?;
        // Deletions found by this scan, restores and purges reach the
        // other devices' trash.
        self.trash_publish(&rec, util::now_utc())?;
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
        let carrier_need = self.carrier_destinations(&view, &folder_id);
        let targets = self.write_targets(rec);
        // Storages with a quota take what fits; the rest goes to the other
        // storages, or waits here for the next push.
        let gate = self.quota_gate(&view);
        // A backup goes to its storages only (never a transferrer), and
        // blocks dropped by an expiry are written again when a new snapshot
        // uses them.
        let backup = rec.is_backup();
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
                // The folder's placement, and blocks moved away stay away.
                .filter(|(spec, _)| {
                    if backup {
                        !spec.is_carrier() && targets.wants(spec.name(), None)
                    } else {
                        targets.wants(spec.name(), known)
                    }
                })
                // A carrier only takes what no other device has yet (F-048),
                // or, with destinations, what one of them still lacks.
                .filter(|(spec, _)| {
                    if !spec.is_carrier() {
                        return true;
                    }
                    match carrier_need.get(spec.name()) {
                        Some(targets) => {
                            !targets.is_empty()
                                && known
                                    .map(|r| targets.iter().any(|t| !r.devices.contains(t)))
                                    .unwrap_or(true)
                        }
                        None => !held_elsewhere,
                    }
                })
                .map(|(spec, _)| spec.name().to_string())
                .collect()
        };
        let encrypted_here = self.mount_is_encrypted(&folder_id);
        // Counted by the files' transfers (`progress`) on this thread.
        let to_upload: u64 = state
            .files
            .values()
            .filter(|f| !f.deleted && !f.chunks.iter().all(|c| missing_on(c).is_empty()))
            .map(|f| f.size)
            .sum();
        let _task = (to_upload > 0).then(|| {
            activity::start(
                activity::UPLOAD,
                &rec.name,
                to_upload,
                activity::Unit::Bytes,
            )
        });
        // Reading, chunking and encrypting stay on this thread; the writes go
        // to a few uploader threads, so that many small objects do not each
        // wait for the previous one's round trip to the storage. A batch (one
        // block, or small blocks that storages keeping packs write as one
        // pack, crate::packs) becomes one work item per storage it goes to,
        // so the storages are written side by side rather than one after the
        // other. The queue is bounded: at most UPLOAD_QUEUE items wait.
        let (job_tx, job_rx) =
            std::sync::mpsc::sync_channel::<(usize, std::sync::Arc<UploadBatch>)>(UPLOAD_QUEUE);
        let job_rx = std::sync::Mutex::new(job_rx);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<UploadDone>();
        let storages_ref = &storages;
        let mut first_error: Option<anyhow::Error> = None;
        let budget = (std::sync::Mutex::new(0u64), std::sync::Condvar::new());
        let budget_ref = &budget;
        std::thread::scope(|s| -> Result<()> {
            // Owned by this closure: however it returns (an error reading a
            // file included), the sender goes and the uploaders stop.
            let job_tx = job_tx;
            for _ in 0..UPLOADERS.max(storages.len()) {
                let (job_rx, done_tx) = (&job_rx, done_tx.clone());
                s.spawn(move || loop {
                    let (i, batch) = match job_rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => break,
                    };
                    let (spec, backend) = &storages_ref[i];
                    let mine: Vec<&UploadJob> = batch
                        .jobs
                        .iter()
                        .filter(|j| j.targets.iter().any(|t| t == spec.name()))
                        .collect();
                    if !mine.is_empty() {
                        // One object, or a storage without packs: written
                        // one by one, each with its own outcome (a pool's
                        // "no room" stays a pool error). Several small ones
                        // on a storage keeping packs: one pack.
                        let outcomes: Vec<Result<bool>> =
                            if mine.len() == 1 || !backend.packs_small_objects() {
                                mine.iter()
                                    .map(|j| {
                                        backend.put_if_absent(&chunk_storage_key(&j.object), &j.ct)
                                    })
                                    .collect()
                            } else {
                                let members: Vec<(String, &[u8])> = mine
                                    .iter()
                                    .map(|j| (j.object.as_str().to_string(), j.ct.as_slice()))
                                    .collect();
                                match backend.put_pack(&members) {
                                    Ok(flags) => flags.into_iter().map(Ok).collect(),
                                    Err(e) => {
                                        // A full disk stays that error (the
                                        // storage is left out, not the push).
                                        let low = crate::freespace::low_space(&e).cloned();
                                        let msg = format!("{e:#}");
                                        mine.iter()
                                            .map(|_| match &low {
                                                Some(l) => Err(anyhow::Error::new(l.clone())),
                                                None => Err(anyhow!("{msg}")),
                                            })
                                            .collect()
                                    }
                                }
                            };
                        for (job, outcome) in mine.iter().zip(outcomes) {
                            let _ = done_tx.send(UploadDone {
                                storage: spec.name().to_string(),
                                chunk: job.chunk.clone(),
                                object: job.object.clone(),
                                size: job.ct.len() as u64,
                                outcome,
                            });
                        }
                    }
                    // The last storage of the batch done: its bytes are free.
                    if batch.left.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
                        *budget_ref.0.lock().unwrap() -= batch.held;
                        budget_ref.1.notify_all();
                    }
                });
            }
            drop(done_tx);
            // Small blocks wait here until a pack's worth is together.
            let mut small: Vec<UploadJob> = Vec::new();
            let mut send_batch =
                |me: &mut Self, report: &mut PushReport, batch: Vec<UploadJob>| -> bool {
                    while let Ok(d) = done_rx.try_recv() {
                        apply_upload(me, &folder_id, d, report, &mut first_error);
                    }
                    if first_error.is_some() {
                        return false;
                    }
                    // One item per storage any object of the batch goes to.
                    let to: Vec<usize> = storages_ref
                        .iter()
                        .enumerate()
                        .filter(|(_, (spec, _))| {
                            batch
                                .iter()
                                .any(|j| j.targets.iter().any(|t| t == spec.name()))
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if to.is_empty() {
                        return true;
                    }
                    let held: u64 = batch.iter().map(|j| j.ct.len() as u64).sum();
                    {
                        let mut used = budget_ref.0.lock().unwrap();
                        while *used > 0 && *used + held > UPLOAD_BYTES {
                            used = budget_ref.1.wait(used).unwrap();
                        }
                        *used += held;
                    }
                    let item = std::sync::Arc::new(UploadBatch {
                        jobs: batch,
                        left: std::sync::atomic::AtomicUsize::new(to.len()),
                        held,
                    });
                    to.into_iter()
                        .all(|i| job_tx.send((i, item.clone())).is_ok())
                };
            // `None` sends what is still waiting (at the end).
            let mut send =
                |me: &mut Self, report: &mut PushReport, job: Option<UploadJob>| -> bool {
                    match job {
                        Some(job) if job.ct.len() <= crate::packs::MAX_MEMBER => {
                            small.push(job);
                            let bytes: usize = small.iter().map(|j| j.ct.len()).sum();
                            if bytes >= crate::packs::TARGET_BYTES
                                || small.len() >= crate::packs::MAX_MEMBERS
                            {
                                let batch = std::mem::take(&mut small);
                                return send_batch(me, report, batch);
                            }
                            true
                        }
                        Some(job) => send_batch(me, report, vec![job]),
                        None if small.is_empty() => true,
                        None => {
                            let batch = std::mem::take(&mut small);
                            send_batch(me, report, batch)
                        }
                    }
                };
            'files: for file in state.files.values().filter(|f| !f.deleted) {
                if file.chunks.iter().all(|c| missing_on(c).is_empty()) {
                    continue;
                }
                if encrypted_here {
                    // Kept encrypted here: the objects come from the block cache.
                    let progress =
                        crate::progress::Transfer::upload(&rec.name, &file.path, file.size);
                    for expected in &file.chunks {
                        progress.advance(expected.size);
                        let targets: Vec<String> = missing_on(expected)
                            .into_iter()
                            .filter(|t| !report.storages_unavailable.iter().any(|u| u == t))
                            .collect();
                        if targets.is_empty() {
                            continue;
                        }
                        let Some(ct) = self.cached_object(&expected.object) else {
                            continue;
                        };
                        let targets: Vec<String> = targets
                            .into_iter()
                            .filter(|t| gate.take(t, ct.len() as u64))
                            .collect();
                        if targets.is_empty() {
                            continue;
                        }
                        let job = UploadJob {
                            targets,
                            chunk: expected.chunk.clone(),
                            object: expected.object.clone(),
                            ct,
                        };
                        if !send(self, report, Some(job)) {
                            break 'files;
                        }
                    }
                    continue;
                }
                let disk = self.disk_of(root, state, &file.path);
                let Ok(handle) = fs::File::open(&disk) else {
                    continue;
                };
                let progress = crate::progress::Transfer::upload(&rec.name, &file.path, file.size);
                for (index, chunk) in
                    Chunker::new(std::io::BufReader::new(handle), self.chunker_for(file.size))?
                        .enumerate()
                {
                    let chunk = chunk?;
                    progress.advance(chunk.len() as u64);
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
                    let targets: Vec<String> = targets
                        .into_iter()
                        .filter(|t| gate.take(t, ct.len() as u64))
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    let job = UploadJob {
                        targets,
                        chunk: chunk_id,
                        object,
                        ct,
                    };
                    if !send(self, report, Some(job)) {
                        break 'files;
                    }
                }
            }
            send(self, report, None);
            drop(send);
            drop(job_tx);
            for d in done_rx.iter() {
                apply_upload(self, &folder_id, d, report, &mut first_error);
            }
            Ok(())
        })?;
        for msg in gate.refusals() {
            if !report.storages_full.contains(&msg) {
                report.storages_full.push(msg);
            }
        }
        if let Some(e) = first_error {
            return Err(e);
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
        if state.thumbs_rev < 2 {
            let videos: Vec<String> = state
                .files
                .values()
                .filter(|f| thumbs::is_video(&f.path))
                .map(|f| f.content_hash.clone())
                .collect();
            for h in videos {
                state.thumbs_done.remove(&h);
            }
            state.thumbs_rev = 2;
        }
        let videos_here = thumbs::video_tool_available();
        let candidates: Vec<(String, String)> = state
            .files
            .values()
            .filter(|f| {
                !f.deleted
                    && !f.is_symlink()
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
        let fk = self.folder_keys(rec)?;
        let meta = fk.meta.clone();
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        let mut made = 0u64;
        for (path, hash) in candidates {
            // Without a tool for videos (a phone, a computer without ffmpeg)
            // they wait: the app around the service may hand in a frame
            // (`store_thumbnail`), or ffmpeg is installed later.
            if thumbs::is_video(&path) && !encrypted_here && !videos_here {
                continue;
            }
            let key = thumbs::storage_key(&rec.folder_id, &hash);
            if storages
                .iter()
                .any(|(_, b)| b.exists(&key).unwrap_or(false))
            {
                state.thumbs_done.insert(hash);
                continue;
            }
            let made_here = if encrypted_here {
                // Pictures are decoded in memory from their cached blocks;
                // videos would need a plain file, so none is made here.
                if thumbs::is_video(&path) {
                    state.thumbs_done.insert(hash);
                    continue;
                }
                if !state.local_index.contains_key(&path) {
                    continue;
                }
                self.thumbnail_from_cache(&fk, state, &path)
            } else {
                let disk = self.disk_of(root, state, &path);
                if !disk.exists() {
                    continue;
                }
                thumbs::make_with(&disk, &path, &self.config.thumbnails)
            };
            let Some(bytes) = made_here else {
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

    /// Videos in plain folders on this device that have no thumbnail yet,
    /// for an app that makes frames itself (a phone): (folder, path, file).
    pub fn videos_without_thumbnails(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, PathBuf)>> {
        let mut out = Vec::new();
        for (rec, root) in self.folders() {
            let Some(root) = root else { continue };
            if self.mount_is_encrypted(&rec.folder_id) {
                continue;
            }
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| {
                !f.deleted
                    && thumbs::is_video(&f.path)
                    && !f.content_hash.is_empty()
                    && !state.thumbs_done.contains(&f.content_hash)
            }) {
                let disk = self.disk_of(&root, &state, &f.path);
                if disk.is_file() {
                    out.push((rec.name.clone(), f.path.clone(), disk));
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Store a thumbnail made outside the engine (a video frame from the
    /// phone's media framework) for the current version of a file: it is
    /// decoded and encoded again, encrypted and written like any other.
    pub fn store_thumbnail(&mut self, folder: &str, path: &str, picture: &[u8]) -> Result<()> {
        let (rec, _) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .filter(|f| !f.deleted && !f.content_hash.is_empty())
            .ok_or_else(|| anyhow!("{path} is not a file of {folder}"))?;
        let hash = file.content_hash.clone();
        let jpeg = thumbs::normalize(picture).ok_or_else(|| anyhow!("not a picture"))?;
        let fk = self.folder_keys(&rec)?;
        let blob = thumbs::seal(&jpeg, &self.vault.vault_id, &rec.folder_id, &hash, &fk.meta)?;
        let key = thumbs::storage_key(&rec.folder_id, &hash);
        for (spec, backend) in self.metadata_storages(false)? {
            if !spec.is_carrier() {
                backend.put_if_absent(&key, &blob)?;
            }
        }
        state.thumbs_done.insert(hash);
        self.save_state(&rec.folder_id, &state)
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
        let mut holder: Option<usize> = None;
        for (i, (_, backend)) in storages.iter().enumerate() {
            if backend.exists(&key)? {
                holder.get_or_insert(i);
                continue;
            }
            // Read the published copy only when a storage lacks it.
            if blob.is_none() {
                if let Some(h) = holder {
                    blob = storages[h].1.get(&key)?;
                }
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
        let created_utc = util::now_utc();
        let m = Manifest {
            format_version: crate::FORMAT_VERSION,
            folder: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            seq,
            lamport,
            created_utc,
            files: state.files.clone(),
        };
        let blob = m.seal(&self.vault.vault_id, &self.folder_keys(rec)?.meta)?;
        let key = Manifest::storage_key(&rec.folder_id, &self.vault.device_id, seq);
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&key, &blob)?;
        }
        log::debug!(
            folder = rec.name.as_str(),
            seq = seq,
            files = state.files.values().filter(|f| !f.deleted).count(),
            deleted = state.files.values().filter(|f| f.deleted).count(),
            bytes = blob.len();
            "manifest published"
        );
        self.pending.push(Event::ManifestPublished {
            folder: rec.folder_id.clone(),
            seq,
            manifest_hash: hex::encode(crypto::hash(&blob)),
            files: state.files.values().filter(|f| !f.deleted).count() as u64,
        });
        state.published_seq = seq;
        state.published_hash = hash;
        // This device's own versions enter its change history as published.
        let _ = self.history_from_own(rec, state, created_utc);
        Ok(Some(seq))
    }

    // ----- pull ---------------------------------------------------------------

    pub fn pull(&mut self, folder: &str) -> Result<PullReport> {
        let out = crate::logged_op!("pull", folder, { self.pull_inner(folder) });
        self.finish_storages();
        out
    }

    fn pull_inner(&mut self, folder: &str) -> Result<PullReport> {
        self.ensure_active()?;
        let (rec, root) = self.resolve_for_write(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        self.check_held(&rec, &root, &mut state)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        self.last_scan = None;
        if self.share_read_only(&rec) {
            report.kept_aside = self.read_only_guard(&rec, &root, &mut state)?;
        } else {
            let (scanned, changed) = self.scan(&rec, &root, &mut state)?;
            self.last_scan = Some(ScanOutcome {
                folder: rec.folder_id.clone(),
                scanned,
                changed,
                extra: self.scan_extra,
            });
        }
        let forks = self.pull_ledger_once()?;
        report.forked_devices = forks.iter().map(|d| d.to_string()).collect();
        if !self.keyring.folders.contains_key(&rec.folder_id) {
            // Converted into a Strongroom by another device just now.
            return Ok(report);
        }
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(false)?;
        // Counted by the files' downloads (`progress`); the total is not known.
        let _task = activity::start(activity::DOWNLOAD, &rec.name, 0, activity::Unit::Bytes);
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        // Send-only: other devices' changes are noted, never applied here.
        // A read-only shared folder takes every change (`share_roles`).
        let send_only = self.mount_mode(&rec.folder_id) == crate::vault::FolderMode::SendOnly
            && !self.share_read_only(&rec);

        // Files whose copies were unreachable last time: a storage or a peer
        // may have them now. Newest first, like every download.
        // This device's ignore rules: incoming changes to paths they cover
        // are not written here (`ignore_rules`).
        let mut ignore = (!self.mount_is_encrypted(&rec.folder_id))
            .then(|| IgnoreMatcher::new(Some(&root), &self.ignore_local(&rec.folder_id)));
        let mut pending: Vec<FileState> = state.pending_remote.values().cloned().collect();
        pending.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
        for remote in pending {
            if send_only {
                state.pending_remote.remove(&remote.path);
                state.not_applied.insert(remote.path.clone(), remote);
                continue;
            }
            if Self::skip_ignored(&mut ignore, &mut state, &remote, &mut report) {
                continue;
            }
            self.apply_remote(&rec, &fk, &root, &mut state, remote, &storages, &mut report)?;
        }
        if send_only {
            // Caught up by this device's own changes (or an override).
            let files = &state.files;
            state
                .not_applied
                .retain(|p, r| !matches!(manifest::merge(files.get(p), r), Merge::KeepLocal));
        } else if !state.not_applied.is_empty() {
            // No longer send-only: what was not applied is applied now.
            let mut waiting: Vec<FileState> = std::mem::take(&mut state.not_applied)
                .into_values()
                .collect();
            waiting.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
            for remote in waiting {
                if Self::skip_ignored(&mut ignore, &mut state, &remote, &mut report) {
                    continue;
                }
                let path = remote.path.clone();
                self.merge_one(
                    &rec,
                    &fk,
                    &root,
                    &mut state,
                    &path,
                    &remote,
                    &storages,
                    &mut report,
                )?;
            }
        }
        // Versions held back by a rule or setting that no longer applies.
        let links_on = self.meta_settings(&rec.folder_id).symlinks && self.meta_caps.symlinks;
        let released: Vec<FileState> = state
            .ignored_remote
            .values()
            // Send-only: nothing is applied here (`folder_safety`).
            .filter(|_| !send_only)
            .filter(|f| links_on || !f.is_symlink())
            .filter(|f| {
                !ignore
                    .as_mut()
                    .is_some_and(|m| m.is_ignored(&f.path, false))
            })
            .cloned()
            .collect();
        for remote in released {
            state.ignored_remote.remove(&remote.path);
            // Only a version newer than this device's is applied; a local
            // file made meanwhile stays and the other devices resolve the
            // conflict when they see it.
            if matches!(
                manifest::merge(state.files.get(&remote.path), &remote),
                Merge::TakeRemote
            ) {
                self.apply_remote(&rec, &fk, &root, &mut state, remote, &storages, &mut report)?;
            }
        }

        // Newest manifest per other device, across storages: only what the
        // ledger announced since the last applied one (`manifest_upkeep`).
        let newest = self.newest_manifests(&rec.folder_id, &state.last_seen, &storages)?;

        // A revoked device's manifests count only up to the last one its
        // accepted ledger batches announced.
        let capped = if self.devices.revoked.is_empty() {
            BTreeMap::new()
        } else {
            self.view()?.manifests
        };
        let metas = fk.meta_keys();
        // Changes made by read-only members (after they stopped being
        // editors) are not taken, even when another device relays them.
        let viewer_clocks = self.share_viewer_clocks(&rec);
        let refused = |f: &FileState| {
            viewer_clocks
                .get(&f.modified_by)
                .is_some_and(|c| f.modified_clock > *c)
        };
        // Change history (`changes_ops`): started once from what is held,
        // then fed by every manifest taken. Never in the way of syncing.
        let mut hist = self.open_history(&rec.folder_id);
        let _ = self.history_backfill(&mut hist, &rec, &state, &storages);
        for (dev, (seq, idx)) in newest {
            if !self.share_manifest_source_ok(&rec, &dev) {
                // A device that is not a participant of the shared folder.
                continue;
            }
            if self.devices.devices.contains_key(&dev)
                && !self.is_revoked(&dev)
                && !self.trusted(&dev)
            {
                // A device of the vault that is not trusted: not in the
                // organization's roster, on a platform its policy refuses,
                // or enrolled with an old key. What it writes is not taken
                // (its manifest stays unread until it is trusted again).
                continue;
            }
            if !self.share_writer_ok(&rec, &dev) {
                // A read-only member: what it publishes is not taken. Its
                // manifest stays unread (`last_seen` does not move), so a
                // later role as editor takes its newest one.
                if seq > state.last_seen.get(&dev).copied().unwrap_or(0) {
                    report.writes_refused.push(self.member_name(&dev));
                }
                continue;
            }
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
            let Some(m) = metas.iter().find_map(|meta| {
                Manifest::open(&blob, &self.vault.vault_id, &rec.folder_id, &dev, seq, meta).ok()
            }) else {
                if self.share_access_lost(&rec.folder_id) {
                    // Removed from the shared folder: newer manifests are
                    // under a key this device will not get.
                    continue;
                }
                if !self.trusted(&dev) {
                    // Not a trusted full device (a member, a replica, a
                    // removed device, or a name planted on the storage):
                    // what does not open is skipped, so nobody but a
                    // trusted device can stop this folder's pull.
                    log::warn!(folder:% = rec.folder_id, device:% = dev, seq = seq; "manifest does not open: skipped");
                    continue;
                }
                bail!(
                    "manifest {seq} of device {} does not open with any key this device holds (a newer vault key has not arrived yet?)",
                    dev.short()
                );
            };
            self.observe_clock(m.lamport)?;
            // The newest files first (by their modification time), so that
            // what was just made arrives first on a large pull.
            let mut entries: Vec<(&String, &FileState)> = m.files.iter().collect();
            entries.sort_by(|a, b| b.1.mtime.cmp(&a.1.mtime).then(a.0.cmp(b.0)));
            if send_only {
                for (path, remote) in &entries {
                    if !refused(remote)
                        && !matches!(
                            manifest::merge(state.files.get(*path), remote),
                            Merge::KeepLocal
                        )
                    {
                        state.not_applied.insert((*path).clone(), (*remote).clone());
                    }
                }
                let _ = self.history_from_manifest(&mut hist, &m, &blob, &refused);
                report.manifests_applied += 1;
                state.last_seen.insert(dev, seq);
                continue;
            }
            // Too many deletions at once: held (this manifest stays unread
            // until the user decides, so nothing of it is lost).
            if let Some(pause) = self.hold_remote_deletions(&rec, &root, &mut state, &dev, &entries)
            {
                self.prefetched.clear();
                self.commit_batch()?;
                self.save_state(&rec.folder_id, &state)?;
                return Err(pause.into());
            }
            report.manifests_applied += 1;
            let fetch_ahead = !encrypted_here && !self.mount_is_selective(&rec.folder_id);
            let mut ahead_from = 0;
            for (i, (path, remote)) in entries.iter().enumerate() {
                if fetch_ahead && i >= ahead_from {
                    ahead_from = self.prefetch_small(&entries, i, &state, &storages);
                }
                if Self::skip_ignored(&mut ignore, &mut state, remote, &mut report) {
                    continue;
                }
                if refused(remote) {
                    continue;
                }
                self.merge_one(
                    &rec,
                    &fk,
                    &root,
                    &mut state,
                    path,
                    remote,
                    &storages,
                    &mut report,
                )?;
            }
            let _ = self.history_from_manifest(&mut hist, &m, &blob, &refused);
            state.last_seen.insert(dev, seq);
            // Whatever was fetched ahead and not used (a file that failed
            // earlier in its batch) is not kept past its manifest.
            self.prefetched.clear();
        }
        let _ = hist.save();
        if encrypted_here {
            self.cache_wanted(&rec, &fk, &mut state, &storages, &mut report)?;
        }
        self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
        self.prune_carriers(&rec)?;
        Ok(report)
    }

    /// Combine one remote state of `path` with this device's (`manifest::merge`).
    #[allow(clippy::too_many_arguments)]
    fn merge_one(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        root: &Path,
        state: &mut FolderState,
        path: &str,
        remote: &FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let me = self.vault.device_id.clone();
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        match manifest::merge(state.files.get(path), remote) {
            Merge::KeepLocal => {}
            Merge::TakeRemote => {
                self.apply_remote(rec, fk, root, state, remote.clone(), storages, report)?;
            }
            Merge::Conflict { winner, loser } => {
                report.conflicts += 1;
                // Receive-only: a local change of the file is not one of
                // the versions; it goes to the trash.
                self.drop_local_change(rec, root, state, path)?;
                if let (true, Some(loser)) = (encrypted_here, &loser) {
                    self.conflict_copy_cached(rec, fk, state, path, loser, storages, report)?;
                } else if let Some(loser) = loser {
                    let cpath = manifest::conflict_path(path, &loser);
                    let local_is_loser = state
                        .files
                        .get(path)
                        .map(|l| l.content_hash == loser.content_hash)
                        .unwrap_or(false);
                    let disk =
                        self.place(root, state, &cpath, Some(&mut report.renamed_locally))?;
                    if let Some(parent) = disk.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let local = self.disk_of(root, state, path);
                    if local_is_loser && present(&local) {
                        fs::rename(&local, &disk)?;
                    } else if let Some(target) = loser.symlink() {
                        fsmeta::write_link(&disk, target)?;
                    } else {
                        self.download_to(rec, fk, &disk, &loser, storages, report)?;
                    }
                    // The conflict copy is a new local file: it gets its own version.
                    let clock = self.tick()?;
                    let mut cstate = loser.clone();
                    cstate.path = cpath.clone();
                    cstate.version = BTreeMap::from([(me.clone(), clock)]);
                    cstate.modified_by = me.clone();
                    cstate.modified_clock = clock;
                    let seen = self.settle_meta(
                        &rec.folder_id,
                        &disk,
                        &cstate,
                        &mut report.metadata_problems,
                    );
                    let md = fs::symlink_metadata(&disk)?;
                    state.local_index.insert(
                        cpath.clone(),
                        LocalIndexEntry {
                            size: md.len(),
                            mtime: mtime_ns_of(&md),
                            content_hash: cstate.content_hash.clone(),
                            meta_seen: seen,
                        },
                    );
                    state.files.insert(cpath, cstate);
                }
                let local_has_winner = state
                    .files
                    .get(path)
                    .map(|l| l.content_hash == winner.content_hash && l.deleted == winner.deleted)
                    .unwrap_or(false)
                    && (winner.deleted
                        || if encrypted_here {
                            state.local_index.contains_key(path)
                        } else {
                            present(&self.disk_of(root, state, path))
                        });
                if local_has_winner {
                    // The content is here; the winner's metadata may differ
                    // from this device's (a concurrent chmod).
                    if !encrypted_here && !winner.deleted {
                        let disk = self.disk_of(root, state, path);
                        let seen = self.settle_meta(
                            &rec.folder_id,
                            &disk,
                            &winner,
                            &mut report.metadata_problems,
                        );
                        if let Some(ix) = state.local_index.get_mut(path) {
                            ix.meta_seen = seen;
                        }
                    }
                    state.files.insert(path.to_string(), winner);
                } else {
                    self.apply_remote(rec, fk, root, state, winner, storages, report)?;
                }
            }
        }
        Ok(())
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
        let need = self.carrier_destinations(&view, &rec.folder_id);
        for ((folder, _chunk), r) in view.chunks.iter() {
            if folder != &rec.folder_id {
                continue;
            }
            let held_by_other = r.devices.iter().any(|d| d != &me);
            for (spec, backend) in &carriers {
                if !r.storages.contains_key(spec.name()) {
                    continue;
                }
                let delivered = match need.get(spec.name()) {
                    // Emptied as soon as every destination that uses the folder holds it.
                    Some(targets) => targets.iter().all(|t| r.devices.contains(t)),
                    None => held_by_other && r.devices.contains(&me),
                };
                if delivered {
                    backend.delete(&chunk_storage_key(&r.object))?;
                }
            }
        }
        Ok(())
    }

    /// Per transferrer with destinations: those of them that use `folder`
    /// (they published its file list or hold some of its blocks). Transferrers
    /// without destinations are absent (any device that lacks a block).
    fn carrier_destinations(
        &self,
        view: &LedgerView,
        folder: &FolderId,
    ) -> HashMap<String, Vec<DeviceId>> {
        let uses = |d: &DeviceId| {
            view.manifests.contains_key(&(folder.clone(), d.clone()))
                || view
                    .chunks
                    .iter()
                    .any(|((f, _), r)| f == folder && r.devices.contains(d))
        };
        self.config
            .carrier_for
            .iter()
            .filter(|(_, ts)| !ts.is_empty())
            .map(|(name, ts)| {
                (
                    name.clone(),
                    ts.iter().filter(|t| uses(t)).cloned().collect(),
                )
            })
            .collect()
    }

    /// Set (or with an empty list clear) the destination devices of a
    /// transferrer, by device name or id.
    pub fn set_carrier_for(&mut self, storage: &str, devices: &[String]) -> Result<Vec<String>> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == storage)
            .ok_or_else(|| anyhow!("unknown storage {storage}"))?;
        if !spec.is_carrier() {
            bail!("{storage} is not a transferrer");
        }
        let mut ids = Vec::new();
        let mut names = Vec::new();
        for want in devices.iter().map(|d| d.trim()).filter(|d| !d.is_empty()) {
            let found = self
                .devices
                .devices
                .iter()
                .find(|(id, r)| {
                    r.name.eq_ignore_ascii_case(want)
                        || (want.len() >= 8 && id.as_str().starts_with(want))
                })
                .map(|(id, r)| (id.clone(), r.name.clone()))
                .ok_or_else(|| anyhow!("no device named {want} in this vault"))?;
            if !ids.contains(&found.0) {
                ids.push(found.0);
                names.push(found.1);
            }
        }
        if ids.is_empty() {
            self.config.carrier_for.remove(storage);
        } else {
            self.config.carrier_for.insert(storage.to_string(), ids);
        }
        self.config.save(&self.home)?;
        Ok(names)
    }

    /// Destination device names of each transferrer that has some.
    pub fn carrier_destination_names(&self) -> BTreeMap<String, Vec<String>> {
        self.config
            .carrier_for
            .iter()
            .map(|(s, ids)| {
                let names = ids
                    .iter()
                    .map(|id| {
                        self.devices
                            .devices
                            .get(id)
                            .map(|r| r.name.clone())
                            .unwrap_or_else(|| id.short().to_string())
                    })
                    .collect();
                (s.clone(), names)
            })
            .collect()
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
        if self.mount_is_encrypted(&rec.folder_id) {
            return self.apply_remote_cached(rec, fk, state, remote, storages, report);
        }
        // Manifests are validated when opened; this is the last line of
        // defence before a path from another device touches the disk: no
        // directory above the entry may be a link (the entry itself may be
        // one: it is replaced or removed, never followed).
        util::check_rel_path(&remote.path)?;
        let rules = self.local_rules(root);
        self.check_no_link_above(root, state, &remote.path)?;
        let was_link = state
            .files
            .get(&remote.path)
            .is_some_and(|f| f.is_symlink());
        // Receive-only: a local change of this file goes to the trash
        // before the vault's version replaces it.
        self.drop_local_change(rec, root, state, &remote.path)?;
        if remote.deleted {
            let local = state
                .local_names
                .local_rel(rules, &remote.path)
                .into_owned();
            let disk = util::safe_join(root, &local)?;
            let _ = fs::remove_file(placeholder_path(&disk));
            if was_link {
                let _ = fs::remove_file(fsmeta::note_path(&disk));
            }
            if present(&disk) {
                self.move_to_trash(&rec.folder_id, &disk, &remote.path)?;
                report.files_deleted += 1;
            }
            state.local_names.forget(rules, &remote.path);
            state.local_index.remove(&remote.path);
            state.pending_remote.remove(&remote.path);
            state.files.insert(remote.path.clone(), remote);
            return Ok(());
        }
        let disk = self.place(root, state, &remote.path, Some(&mut report.renamed_locally))?;
        let settings = self.meta_settings(&rec.folder_id);
        if let Some(target) = remote.symlink() {
            if !(settings.symlinks && self.meta_caps.symlinks) {
                // Links are off here: the vault keeps it, this disk does not.
                if Self::hold_back(state, &remote) {
                    report.links_skipped.push(remote.path.clone());
                }
                state.pending_remote.remove(&remote.path);
                return Ok(());
            }
            let _ = fs::remove_file(placeholder_path(&disk));
            match fsmeta::write_link(&disk, target) {
                Ok(fsmeta::LinkOutcome::Link) => {
                    let seen = self.settle_meta(
                        &rec.folder_id,
                        &disk,
                        &remote,
                        &mut report.metadata_problems,
                    );
                    let md = fs::symlink_metadata(&disk)?;
                    state.local_index.insert(
                        remote.path.clone(),
                        LocalIndexEntry {
                            size: 0,
                            mtime: mtime_ns_of(&md),
                            content_hash: remote.content_hash.clone(),
                            meta_seen: seen,
                        },
                    );
                }
                Ok(fsmeta::LinkOutcome::Note) => {
                    report.links_as_notes.push(remote.path.clone());
                    state.local_index.remove(&remote.path);
                }
                Err(e) => {
                    report
                        .files_unavailable
                        .push(format!("{}: {e}", remote.path));
                    return Ok(());
                }
            }
            state.pending_remote.remove(&remote.path);
            state.files.insert(remote.path.clone(), remote);
            report.files_updated += 1;
            return Ok(());
        }
        if was_link {
            let _ = fs::remove_file(fsmeta::note_path(&disk));
        }
        let selective = self.mount_is_selective(&rec.folder_id);
        if selective && !state.pinned.contains(&remote.path) && !present(&disk) {
            // Selective sync: show the file as a placeholder; fetch on demand.
            Self::write_placeholder(&disk, &remote)?;
            state.local_index.remove(&remote.path);
            state.pending_remote.remove(&remote.path);
            state.files.insert(remote.path.clone(), remote);
            report.files_updated += 1;
            return Ok(());
        }
        // The content here is the remote content (only the metadata
        // changed): nothing to download.
        let same_content_here = state.local_index.get(&remote.path).is_some_and(|ix| {
            ix.content_hash == remote.content_hash
                && fs::symlink_metadata(&disk).is_ok_and(|md| {
                    md.file_type().is_file() && md.len() == ix.size && mtime_ns_of(&md) == ix.mtime
                })
        }) && state
            .files
            .get(&remote.path)
            .is_some_and(|f| !f.deleted && !f.is_symlink());
        let fetched = if same_content_here {
            Ok(())
        } else {
            self.download_to(rec, fk, &disk, &remote, storages, report)
        };
        match fetched {
            Ok(()) => {
                let seen = self.settle_meta(
                    &rec.folder_id,
                    &disk,
                    &remote,
                    &mut report.metadata_problems,
                );
                let md = fs::metadata(&disk)?;
                state.local_index.insert(
                    remote.path.clone(),
                    LocalIndexEntry {
                        size: md.len(),
                        mtime: mtime_ns_of(&md),
                        content_hash: remote.content_hash.clone(),
                        meta_seen: seen,
                    },
                );
                state.pending_remote.remove(&remote.path);
                state.files.insert(remote.path.clone(), remote);
                report.files_updated += 1;
            }
            Err(e) => {
                if let Some(low) = crate::freespace::low_space(&e) {
                    report.waiting_for_space(low);
                    state.pending_remote.insert(remote.path.clone(), remote);
                    return Ok(());
                }
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

    /// Write what this device can of `file`'s metadata onto `disk` and
    /// return what the disk shows afterwards (the index's `meta_seen`).
    fn settle_meta(
        &self,
        folder: &FolderId,
        disk: &Path,
        file: &FileState,
        problems: &mut Vec<String>,
    ) -> Option<fsmeta::FileMeta> {
        let settings = self.meta_settings(folder);
        if let Some(m) = &file.meta {
            for p in fsmeta::apply(disk, m, &self.meta_caps, &settings) {
                problems.push(format!("{}: {p}", file.path));
            }
        }
        let md = fs::symlink_metadata(disk).ok()?;
        Some(fsmeta::observe(
            disk,
            &md,
            &self.meta_caps,
            &settings,
            &mut fsmeta::Names::default(),
        ))
    }

    /// An incoming version of a path this device's ignore rules cover: not
    /// written here, reported once per version. True when skipped.
    fn skip_ignored(
        ignore: &mut Option<IgnoreMatcher>,
        state: &mut FolderState,
        remote: &FileState,
        report: &mut PullReport,
    ) -> bool {
        let Some(m) = ignore.as_mut() else {
            return false;
        };
        if !m.is_ignored(&remote.path, false) {
            return false;
        }
        if Self::hold_back(state, remote) {
            report.files_ignored.push(remote.path.clone());
        }
        state.pending_remote.remove(&remote.path);
        true
    }

    /// Keep a remote version that is not written here for later; true when
    /// it is newer than the one kept (to be reported).
    fn hold_back(state: &mut FolderState, remote: &FileState) -> bool {
        let newer = match state.ignored_remote.get(&remote.path) {
            None => true,
            Some(kept) => !matches!(
                manifest::compare(&kept.version, &remote.version),
                manifest::Order::Equal | manifest::Order::LocalNewer
            ),
        };
        if newer {
            state
                .ignored_remote
                .insert(remote.path.clone(), remote.clone());
        }
        newer
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
        // Nothing new is written where the disk would keep less free space
        // than its limit; the caller keeps the file for a later sync.
        self.space_for(rec, disk, file.size)?;
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
            if fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!(
                    "{} is a symbolic link; files are not written through links",
                    parent.display()
                );
            }
        }
        let tmp = disk.with_file_name(format!(".varsto-tmp-{}", std::process::id()));
        if let Some(log) = &self.download_log {
            log.lock().unwrap().push(file.path.clone());
        }
        let progress = crate::progress::Download::begin(&rec.name, &file.path, file.size);
        {
            let mut out = fs::File::create(&tmp)?;
            // No device holds a backup's blocks: storages only.
            let peers = if rec.is_backup() {
                None
            } else {
                self.peers.clone()
            };
            let stats = self.fetch_stats.clone();
            // Blocks copied from pool disks for a disk fetch plan are read
            // from the staging area instead (`disk_fetch`).
            let staging = self.staging_roots();
            // Every object is one round trip to a peer or a storage. Fetched
            // one after another, a link with any latency idles most of the
            // time, so a window of chunks of the file (`fetch::fetch_in_order`) is in flight at
            // once; they are still checked, decrypted and written in order.
            // Small files may have been fetched ahead together (`prefetch_small`).
            // (A file that repeats a block takes the normal way: each cached
            // object is handed out once.)
            let distinct = file
                .chunks
                .iter()
                .map(|c| &c.object)
                .collect::<HashSet<_>>()
                .len();
            let ahead: Option<Vec<Fetched>> = if !file.chunks.is_empty()
                && distinct == file.chunks.len()
                && file
                    .chunks
                    .iter()
                    .all(|c| self.prefetched.contains_key(&c.object))
            {
                Some(
                    file.chunks
                        .iter()
                        .filter_map(|c| self.prefetched.remove(&c.object))
                        .collect(),
                )
            } else {
                None
            };
            let mut write_chunk = |cref: &ChunkRef, fetched: Fetched| -> Result<()> {
                let (storage_name, ct) = match fetched {
                    Fetched::Got {
                        source,
                        bytes,
                        from_peer,
                    } => {
                        if from_peer {
                            report.chunks_from_peers += 1;
                        }
                        (source, bytes)
                    }
                    Fetched::Failed(e) => return Err(e),
                    Fetched::Missing(needs_disk) => {
                        let _ = fs::remove_file(&tmp);
                        if let Some(nd) = needs_disk {
                            return Err(anyhow::Error::new(nd));
                        }
                        bail!(
                            "chunk {} is not available on any readable storage",
                            cref.chunk.short()
                        );
                    }
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
                progress.advance(plain.len() as u64);
                report.chunks_downloaded += 1;
                report.bytes_downloaded += plain.len() as u64;
                self.pending.push(Event::ChunkVerified {
                    folder: rec.folder_id.clone(),
                    chunk: cref.chunk.clone(),
                    object: cref.object.clone(),
                    storage: storage_name,
                });
                if !rec.is_backup() {
                    self.pending.push(Event::ChunkOnDevice {
                        folder: rec.folder_id.clone(),
                        chunk: cref.chunk.clone(),
                        object: cref.object.clone(),
                        size: cref.size,
                    });
                }
                Ok(())
            };
            match ahead {
                Some(got) => {
                    for (cref, fetched) in file.chunks.iter().zip(got) {
                        write_chunk(cref, fetched)?;
                    }
                }
                None if staging.is_empty() => fetch_in_order(
                    peers.as_deref(),
                    &file.chunks,
                    storages,
                    &stats,
                    &mut write_chunk,
                )?,
                None => {
                    // Runs of staged blocks are read from the staging area,
                    // the runs between them fetched as usual, in order.
                    let staged = |c: &ChunkRef| disk_fetch::staged_object(&staging, &c.object);
                    let mut i = 0;
                    while i < file.chunks.len() {
                        let here = staged(&file.chunks[i]).is_some();
                        let mut j = i;
                        while j < file.chunks.len() && staged(&file.chunks[j]).is_some() == here {
                            j += 1;
                        }
                        if here {
                            for c in &file.chunks[i..j] {
                                let Some((path, pool)) = staged(c) else {
                                    continue;
                                };
                                let bytes = fs::read(&path)?;
                                let fetched =
                                    if ObjectName::from_bytes(&crypto::hash(&bytes)) == c.object {
                                        Fetched::Got {
                                            source: pool,
                                            bytes,
                                            from_peer: false,
                                        }
                                    } else {
                                        let _ = fs::remove_file(&path);
                                        fetch::fetch_object(
                                            peers.as_deref(),
                                            &c.object,
                                            storages,
                                            &stats,
                                        )
                                    };
                                write_chunk(c, fetched)?;
                            }
                        } else {
                            fetch_in_order(
                                peers.as_deref(),
                                &file.chunks[i..j],
                                storages,
                                &stats,
                                &mut write_chunk,
                            )?;
                        }
                        i = j;
                    }
                }
            }
            out.sync_all()?;
        }
        fsmeta::make_replaceable(disk);
        fs::rename(&tmp, disk)?;
        if self.share_read_only(rec) {
            share_roles::set_read_only(disk, true);
        }
        Ok(())
    }

    /// Fetch the blocks of the single-block files that the pull is about to
    /// take from `m`, starting at file `from`, together into `prefetched`:
    /// fetched one file after another, a folder of many small files waits a
    /// full round trip per file. Returns the index of the first file not
    /// looked at.
    fn prefetch_small(
        &mut self,
        entries: &[(&String, &FileState)],
        from: usize,
        state: &FolderState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
    ) -> usize {
        let mut wanted: Vec<ChunkRef> = Vec::new();
        let mut seen: HashSet<ObjectName> = HashSet::new();
        let mut next = from;
        for (path, remote) in entries.iter().skip(from) {
            if wanted.len() >= PREFETCH_OBJECTS || next >= from + PREFETCH_FILES {
                break;
            }
            next += 1;
            // Single-block files only: a file of several blocks has its own
            // window (`download_to`).
            if remote.deleted
                || remote.chunks.len() != 1
                || !matches!(
                    manifest::merge(state.files.get(*path), remote),
                    Merge::TakeRemote
                )
            {
                continue;
            }
            for c in &remote.chunks {
                if !self.prefetched.contains_key(&c.object) && seen.insert(c.object.clone()) {
                    wanted.push(c.clone());
                }
            }
        }
        if wanted.len() > 1 {
            let peers = self.peers.clone();
            let stats = self.fetch_stats.clone();
            let cache = &mut self.prefetched;
            let _ = fetch_in_order(peers.as_deref(), &wanted, storages, &stats, |c, f| {
                if matches!(f, Fetched::Got { .. }) {
                    cache.insert(c.object.clone(), f);
                }
                Ok(())
            });
        }
        next
    }

    fn write_placeholder(disk: &Path, file: &FileState) -> Result<()> {
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
            if fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!(
                    "{} is a symbolic link; files are not written through links",
                    parent.display()
                );
            }
        }
        let info = serde_json::json!({ "varsto": "placeholder", "size": file.size, "mtime_ns": file.mtime, "hint": "run `varsto folder fetch` or use the app to download this file" });
        util::write_atomic(&placeholder_path(disk), &serde_json::to_vec(&info)?)
    }

    /// In a folder that is not selective (any more), download every file
    /// that is still a placeholder here. Files that cannot be fetched now
    /// are listed and stay placeholders until the next sync. Returns how
    /// many were downloaded.
    fn fill_placeholders(&mut self, folder: &str, unavailable: &mut Vec<String>) -> Result<u64> {
        let (rec, root) = self.resolve_for_write(folder)?;
        if self.mount_is_selective(&rec.folder_id) || self.mount_is_encrypted(&rec.folder_id) {
            return Ok(0);
        }
        let state = self.load_state(&rec.folder_id)?;
        let mut wanted: Vec<&FileState> = state
            .files
            .values()
            .filter(|f| {
                let disk = self.disk_of(&root, &state, &f.path);
                !f.deleted && !disk.exists() && placeholder_path(&disk).exists()
            })
            .collect();
        // Newest first.
        wanted.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
        let wanted: Vec<String> = wanted.into_iter().map(|f| f.path.clone()).collect();
        let mut done = 0;
        for path in wanted {
            match self.fetch_file(folder, &path) {
                Ok(_) => done += 1,
                Err(_) => unavailable.push(path),
            }
        }
        Ok(done)
    }

    /// Download a placeholder file of a selective folder and keep it here.
    pub fn fetch_file(&mut self, folder: &str, path: &str) -> Result<PullReport> {
        crate::logged_op!("fetch file", format!("{folder}/{path}"), {
            self.fetch_file_inner(folder, path)
        })
    }

    fn fetch_file_inner(&mut self, folder: &str, path: &str) -> Result<PullReport> {
        self.ensure_active()?;
        let (rec, root) = self.resolve_for_write(folder)?;
        if self.mount_is_encrypted(&rec.folder_id) {
            return self.fetch_cached(&rec, path);
        }
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("unknown file {path}"))?;
        if file.deleted {
            bail!("{path} is deleted");
        }
        // One file, which can be large: a task of its own (the transfer
        // feeds it), shown with the file's name.
        let task = activity::start(
            activity::DOWNLOAD,
            &rec.name,
            file.size,
            activity::Unit::Bytes,
        );
        task.set_phase("file");
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(false)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        let disk = self.place(&root, &mut state, path, Some(&mut report.renamed_locally))?;
        self.check_no_link_above(&root, &state, path)?;
        match file.symlink() {
            Some(target) => {
                fsmeta::write_link(&disk, target)?;
            }
            None => self.download_to(&rec, &fk, &disk, &file, &storages, &mut report)?,
        }
        state.accessed.insert(path.to_string(), now_secs());
        let _ = fs::remove_file(placeholder_path(&disk));
        let seen = self.settle_meta(&rec.folder_id, &disk, &file, &mut report.metadata_problems);
        let md = fs::symlink_metadata(&disk)?;
        state.local_index.insert(
            path.to_string(),
            LocalIndexEntry {
                size: md.len(),
                mtime: mtime_ns_of(&md),
                content_hash: file.content_hash.clone(),
                meta_seen: seen,
            },
        );
        state.pinned.insert(path.to_string());
        report.files_updated += 1;
        // What was fetched and checked is recorded with the next batch:
        // nobody needs it published at once.
        self.defer_events()?;
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
                // The local name maps back to the vault path.
                let local = rel.join("/");
                let path = match self.load_state(&rec.folder_id) {
                    Ok(state) => state
                        .local_names
                        .vault_of_local(self.local_rules(&root), &local),
                    Err(_) => local,
                };
                return Ok((rec.folder_id.to_string(), path));
            }
        }
        bail!("{} is not in a Varsto folder on this device", abs.display())
    }

    /// Replace a local file of a selective folder with a placeholder. Refused
    /// unless every chunk is on at least one storage that is not a carrier,
    /// and unless the file on disk is the version that was synced.
    pub fn free_file(&mut self, folder: &str, path: &str) -> Result<()> {
        crate::logged_op_plain!("free file", format!("{folder}/{path}"), {
            self.free_file_inner(folder, path)
        })
    }

    fn free_file_inner(&mut self, folder: &str, path: &str) -> Result<()> {
        let (rec, root) = self.resolve_for_write(folder)?;
        if self.mount_is_encrypted(&rec.folder_id) {
            // Its cached blocks go, except those other cached files use.
            return match self.free_cached(&rec, &[path.to_string()])?.pop() {
                Some((_, why)) => Err(anyhow!(why)),
                None => Ok(()),
            };
        }
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
        let disk = self.disk_of(&root, &state, path);
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
        // A freed file turns a folder selective.
        if !self.mount_is_selective(&rec.folder_id) {
            self.set_selective(folder, true)?;
        }
        Ok(())
    }

    /// Files of a folder with their local state (for the interface and CLI).
    /// Set (or clear) the durability policy of a folder and publish it so
    /// every device evaluates the same rule.
    pub fn set_policy(&mut self, folder: &str, policy: Option<Policy>) -> Result<()> {
        crate::logged_op_plain!("set policy", folder, {
            self.set_policy_inner(folder, policy)
        })
    }

    fn set_policy_inner(&mut self, folder: &str, policy: Option<Policy>) -> Result<()> {
        if self.vault.member {
            bail!("a member device cannot set policies on the owner's folders");
        }
        self.org_allows(|p| p.members_may_set_policies, "set policies")?;
        let (rec, _) = self.resolve_folder(folder)?;
        let now = util::now_utc();
        let f = self
            .keyring
            .folders
            .get_mut(&rec.folder_id)
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        // Cleared: an empty policy, so the default does not come back.
        let policy = Some(policy.unwrap_or_default());
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
        // Signed in an organization (where only some devices may set
        // policies, and every device runs a version that reads signatures);
        // the older, unsigned form otherwise, so devices still on alpha.9
        // keep reading it. Without an organization any device may set a
        // policy, so a signature would prove nothing more.
        let blob = if self.org.is_some() {
            prec.seal_signed(&self.vault.vault_id, &fr_key, &self.keys.signer)?
        } else {
            prec.seal(&self.vault.vault_id, &fr_key)?
        };
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
        crate::logged_op!("policy check at", "", {
            self.policy_check_at_inner(now_utc)
        })
    }

    fn policy_check_at_inner(&self, now_utc: i64) -> Result<Vec<PolicyReport>> {
        let view = self.view()?;
        let mut ctx = self.policy_ctx();
        let mut reports = Vec::new();
        for (rec, _) in self.folders() {
            let Some(policy) = rec.effective_policy() else {
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
                    facts.push(self.chunk_facts(&mut ctx, &view, &rec.folder_id, &cr.chunk));
                }
            }
            let mut report = crate::policy::evaluate(
                &rec.name,
                &policy,
                &facts,
                &ctx.unreadable_places,
                &ctx.unknown,
                now_utc,
            );
            self.disk_group_findings(&rec, &state, &view, &ctx.pools, &mut report);
            reports.push(report);
        }
        // Why a policy may not be met: a storage at its quota or leaving.
        let notes = self.storage_notes(&view);
        for r in reports.iter_mut().filter(|r| {
            matches!(
                r.state,
                crate::policy::PolicyState::AtRisk | crate::policy::PolicyState::Violated
            )
        }) {
            r.reasons.extend(notes.iter().cloned());
        }
        Ok(reports)
    }

    /// What a policy evaluation needs to know about this device's storages.
    pub(crate) fn policy_ctx(&self) -> PolicyCtx {
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
        PolicyCtx {
            places,
            carriers,
            unknown,
            unreadable_places,
            pools,
        }
    }

    /// The copies of one chunk as a policy counts them.
    pub(crate) fn chunk_facts(
        &self,
        ctx: &mut PolicyCtx,
        view: &LedgerView,
        folder: &FolderId,
        chunk: &ChunkId,
    ) -> crate::policy::ChunkFacts {
        let mut copies = Vec::new();
        if let Some(record) = view.locate(folder, chunk) {
            for (name, loc) in &record.storages {
                if loc.claimed_by.is_empty() || ctx.carriers.contains(name) {
                    continue;
                }
                let place = if name.starts_with("replica:") {
                    "replica".to_string()
                } else {
                    ctx.places
                        .get(name)
                        .map(|(p, _)| p.clone())
                        .unwrap_or_else(|| "other".to_string())
                };
                let verified = loc.independently_verified(name);
                let verified_utc = loc.verified_utc;
                if let Some(pool) = ctx.pools.get(name) {
                    // One copy per disk that holds the object (disk
                    // groups keep several), each at its disk's place.
                    for (copy, at, v, v_utc, readable) in
                        Self::pool_copies(name, pool, &record.object, verified, verified_utc)
                    {
                        if !readable {
                            let list = ctx.unreadable_places.entry(at.clone()).or_default();
                            if !list.contains(&copy) {
                                list.push(copy.clone());
                            }
                        }
                        copies.push((copy, at, v, v_utc));
                    }
                    continue;
                }
                copies.push((name.clone(), place, verified, verified_utc));
            }
        }
        crate::policy::ChunkFacts { copies }
    }

    /// The vault key (hex) for the recovery kit. Only an unlocked owner
    /// device can produce it; members hold no vault key.
    pub fn export_vault_key(&self) -> Result<String> {
        if self.vault.member {
            bail!("a member device holds folder keys only, not the vault key");
        }
        self.org_allows(
            |p| p.members_may_add_devices,
            "print the recovery kit or export the vault key",
        )?;
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
        crate::logged_op_plain!("create strongroom", name, {
            self.create_strongroom_inner(name, path, method, key, unlock_minutes)
        })
    }

    fn create_strongroom_inner(
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
        let info =
            crate::strongroom::enroll(key, method, &self.vault.vault_id, &folder_id, &folder_key)?;
        let rec = FolderRecord {
            folder_id: folder_id.clone(),
            name: name.to_string(),
            key_hex: String::new(),
            created_by: self.vault.device_id.clone(),
            created_utc: util::now_utc(),
            shared: false,
            policy: None,
            policy_updated_utc: 0,
            placement: None,
            placement_updated_utc: 0,
            strongroom: Some(info),
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
            backup: None,
            share_join: None,
        };
        folder_safety::write_marker(path, &rec)?;
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
            mode: Default::default(),
            deletion_guard: None,
            ignore_local: Vec::new(),
            meta: Default::default(),
            min_free: None,
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
        let fk = crate::strongroom::unlock(key, &self.vault.vault_id, &rec.folder_id, info)?;
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
        crate::logged_op_plain!("unlock strongroom with key", folder, {
            self.unlock_strongroom_with_key_inner(folder, key_hex, minutes)
        })
    }

    fn unlock_strongroom_with_key_inner(
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
        crate::logged_op_plain!("lock strongroom", folder, {
            self.lock_strongroom_inner(folder)
        })
    }

    fn lock_strongroom_inner(&mut self, folder: &str) -> Result<()> {
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

    /// Block sizes for a file of `size` bytes: the same everywhere, so the
    /// same content gives the same blocks. Tests that set their own sizes
    /// keep them.
    pub(crate) fn chunker_for(&self, size: u64) -> ChunkerParams {
        if self.chunker == ChunkerParams::DEFAULT {
            ChunkerParams::for_size(size)
        } else {
            self.chunker
        }
    }

    /// Read the local configuration and keyring again: another process on
    /// this device (the command line) changed them while this engine was
    /// open. Keys stay as they are; nothing is written. True when what this
    /// device syncs (folders, where they are, storages) is now different.
    pub fn reload_local(&mut self) -> Result<bool> {
        crate::logged_op!("reload local", "", { self.reload_local_inner() })
    }

    fn reload_local_inner(&mut self) -> Result<bool> {
        let signature = |e: &Engine| -> String {
            let folders: Vec<_> = e
                .folders()
                .into_iter()
                .map(|(r, m)| (r.folder_id.clone(), r.name.clone(), m))
                .collect();
            format!(
                "{}|{}",
                serde_json::to_string(&e.config).unwrap_or_default(),
                serde_json::to_string(&folders).unwrap_or_default()
            )
        };
        let before = signature(self);
        self.config = Config::load(&self.home)?;
        self.forget_storages();
        self.keyring = Keyring::load(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.view_cache = Default::default();
        Ok(signature(self) != before)
    }

    /// Hand the peer-to-peer server (the background service's) the place it
    /// reads its snapshot from, so a push can refresh it early.
    pub fn set_snapshot_sink(&mut self, sink: Option<SnapshotSink>) {
        self.snapshot_sink = sink;
    }

    fn refresh_snapshot(&self) {
        let Some(sink) = &self.snapshot_sink else {
            return;
        };
        match self.peer_snapshot() {
            Ok(s) => *sink.lock().unwrap() = Some(std::sync::Arc::new(s)),
            Err(e) => eprintln!("p2p snapshot after publishing failed: {e:#}"),
        }
    }

    /// Tell the other devices over peer-to-peer that something new was
    /// published; on a thread of its own, so a slow peer holds nothing up.
    pub fn notify_peers_changed(&self) {
        if let Some(peers) = self.peers.clone() {
            std::thread::spawn(move || peers.notify_changed());
        }
    }

    /// Peers to try before storages (None disables).
    /// Tests: record the path of every file downloaded, in order.
    #[doc(hidden)]
    pub fn record_downloads(&mut self, log: std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        self.download_log = Some(log);
    }

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
    /// file present on disk, plus objects in local-directory storages and in
    /// the block cache (folders kept encrypted here), served verbatim.
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
            let plain_here = !self.mount_is_encrypted(&rec.folder_id);
            for f in state.files.values().filter(|f| plain_here && !f.deleted) {
                let disk = self.disk_of(&root, &state, &f.path);
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
        let mut local_roots: Vec<PathBuf> = self
            .config
            .storages
            .iter()
            .filter_map(|s| match s {
                StorageSpec::LocalDir { path, .. } if !s.is_cold() => Some(path.clone()),
                _ => None,
            })
            .collect();
        if self.block_cache_root().is_dir() {
            local_roots.push(self.block_cache_root());
        }
        Ok(crate::p2p::Snapshot {
            vault_id: self.vault.vault_id.clone(),
            device_id: self.vault.device_id.clone(),
            peer_key: self.peer_key(),
            folder_keys,
            pieces,
            local_roots,
            // Refused at the door: revoked devices, and in an organization
            // every device the roster does not list.
            revoked: self
                .devices
                .revoked
                .keys()
                .chain(self.devices.devices.keys().filter(|d| !self.trusted(d)))
                .cloned()
                .collect(),
            activity_audience: self.activity_audience(),
        })
    }

    /// The devices this one tells what it is doing (`/p2p/activity`) and
    /// asks the same of: in an organization, the devices the roster gives to
    /// the same user, as for the other details of one's own devices; `None`
    /// (every device of the vault) otherwise.
    pub fn activity_audience(&self) -> Option<BTreeSet<DeviceId>> {
        let org = self.org.as_ref()?;
        let roster = org.roster.as_ref()?;
        let me = &self.vault.device_id;
        let Some(user) = org.user_of(me) else {
            // Not in the roster (yet): nobody.
            return Some(BTreeSet::new());
        };
        Some(
            roster
                .members
                .iter()
                .filter(|m| m.user == user && &m.device != me)
                .map(|m| m.device.clone())
                .collect(),
        )
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
            mapped_tcp: Vec::new(),
            mapped_udp: Vec::new(),
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
        self.write_from_reader_sized(folder, path, bytes, Some(bytes.len() as u64))
    }

    /// `write_file` with the content streamed from `reader`. In a folder kept
    /// encrypted here it goes straight into the block cache (no plain file);
    /// elsewhere into a temporary file next to the target, renamed into place
    /// once complete. An error while reading leaves the folder unchanged.
    pub fn write_from_reader(
        &mut self,
        folder: &str,
        path: &str,
        reader: impl std::io::Read,
    ) -> Result<PushReport> {
        self.write_from_reader_sized(folder, path, reader, None)
    }

    /// `write_from_reader` when the size is known beforehand (an upload with
    /// a Content-Length): the block sizes then follow the file size.
    pub fn write_from_reader_sized(
        &mut self,
        folder: &str,
        path: &str,
        reader: impl std::io::Read,
        size: Option<u64>,
    ) -> Result<PushReport> {
        crate::logged_op_plain!("write from reader sized", format!("{folder}/{path}"), {
            self.write_from_reader_sized_inner(folder, path, reader, size)
        })
    }

    fn write_from_reader_sized_inner(
        &mut self,
        folder: &str,
        path: &str,
        reader: impl std::io::Read,
        size: Option<u64>,
    ) -> Result<PushReport> {
        block_cache::check_rel_path(path)?;
        if let Some(writer) = self.block_writer(folder)? {
            let staged = writer.write_sized(reader, size)?;
            return self.commit_staged(folder, path, staged);
        }
        let (rec, root) = self.resolve_for_write(folder)?;
        // The file's local name (mapped where this filesystem needs it) is
        // recorded before the scan of the push finds it.
        self.ensure_share_writable(&rec)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let disk = self.place(&root, &mut state, path, None)?;
        self.save_state(&rec.folder_id, &state)?;
        if placeholder_path(&disk).exists() {
            bail!("{path} is a placeholder here; fetch it before overwriting");
        }
        if let Some(parent) = disk.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = disk.with_file_name(format!(".varsto-upload-{}", std::process::id()));
        let written = (|| -> Result<()> {
            let mut out = fs::File::create(&tmp)?;
            std::io::copy(&mut { reader }, &mut out)?;
            out.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e.context(format!("write {}", disk.display())));
        }
        fs::rename(&tmp, &disk).with_context(|| format!("write {}", disk.display()))?;
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
        let state = self.load_state(&rec.folder_id)?;
        let disk = self.disk_of(&root, &state, path);
        let known = state.files.get(path).is_some_and(|f| !f.deleted);
        if known || disk.exists() || placeholder_path(&disk).exists() {
            bail!("{path} already exists; files are never replaced, choose another name");
        }
        Ok(())
    }

    /// Create a directory inside a folder. Folder lists name files only; in a
    /// folder kept encrypted here a directory exists once a file is in it.
    pub fn mkdir(&mut self, folder: &str, path: &str) -> Result<()> {
        crate::logged_op_plain!("mkdir", format!("{folder}/{path}"), {
            self.mkdir_inner(folder, path)
        })
    }

    fn mkdir_inner(&mut self, folder: &str, path: &str) -> Result<()> {
        let (rec, root) = self.resolve_for_write(folder)?;
        self.ensure_share_writable(&rec)?;
        block_cache::check_rel_path(path)?;
        if self.mount_is_encrypted(&rec.folder_id) {
            return Ok(());
        }
        let local = self.local_rules(&root).default_local(path).into_owned();
        fs::create_dir_all(util::safe_join(&root, &local)?)?;
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
        crate::logged_op_plain!("read file", format!("{folder}/{path}"), {
            self.read_file_inner(folder, path)
        })
    }

    fn read_file_inner(&mut self, folder: &str, path: &str) -> Result<Vec<u8>> {
        self.ensure_active()?;
        let (rec, root) = self.resolve_folder(folder)?;
        if self.mount_is_encrypted(&rec.folder_id) {
            // Decrypted in memory, from the block cache where it can.
            let size = self.view_size(folder, path)?;
            let bytes = self.view_range(folder, path, 0, size)?;
            self.touch_access(folder, path)?;
            return Ok(bytes);
        }
        block_cache::check_rel_path(path)?;
        let state = self.load_state(&rec.folder_id)?;
        if !state.files.contains_key(path) {
            bail!("unknown file {path} in {folder}");
        }
        // Never through a link: one may point anywhere.
        let local = state.local_names.local_rel(self.local_rules(&root), path);
        fsmeta::check_no_link(&root, &local)?;
        let disk = self.disk_of(&root, &state, path);
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
        crate::logged_op!("move file", format!("{folder}/{from} -> {to}"), {
            self.move_file_inner(folder, from, to)
        })
    }

    fn move_file_inner(&mut self, folder: &str, from: &str, to: &str) -> Result<PushReport> {
        let report = self.move_file_only(folder, from, to)?;
        // The file's analysis goes along (`notes`).
        let rec = self.resolve_folder(folder)?.0;
        self.notes_follow_move(&rec.folder_id, from, to)?;
        Ok(report)
    }

    fn move_file_only(&mut self, folder: &str, from: &str, to: &str) -> Result<PushReport> {
        let (rec, root) = self.resolve_for_write(folder)?;
        self.ensure_share_writable(&rec)?;
        for p in [from, to] {
            util::check_rel_path(p)?;
        }
        // Moving never replaces a file, also not one only another device has.
        self.ensure_path_free(folder, to)?;
        let rec = self.resolve_folder(folder)?.0;
        if self.mount_is_encrypted(&rec.folder_id) {
            return self.move_cached(&rec, folder, from, to);
        }
        // Where the file is, and where its new name goes on this disk; the
        // new local name is recorded before the push's scan finds it.
        let mut state = self.load_state(&rec.folder_id)?;
        let src = self.disk_of(&root, &state, from);
        // (The old name's record goes when the push's scan finds it gone.)
        let dst = self.place(&root, &mut state, to, None)?;
        self.save_state(&rec.folder_id, &state)?;
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
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        // Newest use on any device of the folder (`access_sync`).
        let accessed = self.merged_access(&rec.folder_id, &state);
        let analyses = self.analyses_for_listing(&rec.folder_id, &state);
        let mut out = Vec::new();
        for f in state.files.values().filter(|f| !f.deleted) {
            let disk = self.disk_of(&root, &state, &f.path);
            let state_str = if encrypted_here {
                // Blocks in the cache, or not (yet) on this device.
                if state.local_index.contains_key(&f.path) {
                    "local"
                } else if state.pending_remote.contains_key(&f.path) {
                    "missing"
                } else {
                    "placeholder"
                }
            } else if present(&disk) || (f.is_symlink() && fsmeta::note_path(&disk).exists()) {
                "local"
            } else if placeholder_path(&disk).exists() {
                "placeholder"
            } else {
                "missing"
            };
            out.push(
                FileEntry {
                    path: f.path.clone(),
                    size: f.size,
                    state: state_str.to_string(),
                    pinned: state.pinned.contains(&f.path),
                    content_hash: f.content_hash.clone(),
                    selective,
                    disk: disk.clone(),
                    media: thumbs::is_image(&f.path) || thumbs::is_video(&f.path),
                    modified_utc: f.mtime / 1_000_000_000,
                    last_accessed_utc: accessed.get(&f.path).copied(),
                    analysis: None,
                    analysis_truncated: false,
                    analysis_tags: Vec::new(),
                    analysis_utc: None,
                    analysis_stale: false,
                    analysis_by: None,
                    analysis_author: None,
                    ..Default::default()
                }
                .with_meta(f),
            );
            if let (Some(a), Some(e)) = (analyses.get(&f.path), out.last_mut()) {
                let shown: String = a.analysis.chars().take(LISTING_CHARS).collect();
                e.analysis_truncated = shown.len() < a.analysis.len();
                e.analysis = Some(shown);
                e.analysis_tags = a.tags.clone();
                e.analysis_utc = Some(a.analysed_utc);
                e.analysis_stale = a.stale;
                e.analysis_by = a.by.clone();
                e.analysis_author = Some(a.author.clone());
            }
        }
        Ok(out)
    }

    /// pull then push, for every attached folder (or one).
    pub fn sync(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        crate::logged_op!("sync", folder.unwrap_or("all folders"), {
            self.sync_inner(folder)
        })
    }

    fn sync_inner(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        // Every folder's pull and push record into one ledger batch, and the
        // ledger is pulled once.
        let (mut out, seq) = self.one_batch_seq(|e| e.sync_folders(folder))?;
        for (_, push) in out.iter_mut() {
            push.batch_seq = push.batch_seq.or(seq);
        }
        // System, version and platform, signed (an organization's platform
        // policy is checked against them); republished only when changed.
        let _ = self.refresh_device_details();
        // Checkpoints, acknowledgements and pruning; anything left undone
        // (an unreachable storage) is retried after the next sync.
        let _ = self.ledger_upkeep();
        // Last-accessed records of every device, when due (`access_sync`).
        let _ = self.access_upkeep(false);
        // File analyses: follow renames, publish and read (`notes`).
        let _ = self.notes_upkeep(false);
        let _ = self.manifest_upkeep();
        // No claims at all while manifests name blocks: the ledger is gone
        // everywhere (checked at most hourly, and only without claims).
        let _ = self.ledger_lost_everywhere(false);
        // The other devices' trash records, when due (`trash`).
        let _ = self.trash_refresh(false);
        self.finish_storages();
        Ok(out)
    }

    fn sync_folders(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        if self.org_platform_block().is_some() {
            // Locked out by the organization's platform policy: read a
            // policy that allows this device again before giving up.
            let _ = self.pull_registry();
            let _ = self.sync_membership();
        }
        self.ensure_active()?;
        // A lost or damaged local ledger is restored before anything else.
        self.ensure_ledger_writable()?;
        // A folder another device converted into a Strongroom must be
        // adopted before it is synced under its old key.
        self.pull_registry()?;
        self.finish_strongroom_conversions();
        // The restic device keeps every folder: new ones are attached in
        // its mirror as soon as their record is here.
        self.restic_auto_attach();
        let names: Vec<String> = match folder {
            Some(f) => vec![f.to_string()],
            None => self
                .folders()
                .into_iter()
                .filter(|(r, m)| {
                    m.is_some()
                        && (!r.is_strongroom() || self.is_unlocked(&r.folder_id))
                        && !self.is_held(&r.folder_id)
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
            // A paused folder (`folder_safety`) is reported and skipped; the
            // other folders sync as usual.
            let paused =
                |e: anyhow::Error, mut pull: PullReport| -> Result<(PullReport, PushReport)> {
                    let p = folder_safety::paused_error(&e).ok_or(e)?;
                    pull.folder = p.folder.clone();
                    let push = PushReport {
                        folder: p.folder.clone(),
                        ..Default::default()
                    };
                    pull.paused = Some(p);
                    Ok((pull, push))
                };
            let mut pull = match self.pull(&name) {
                Ok(p) => p,
                Err(e) => {
                    self.last_scan = None;
                    out.push(paused(e, PullReport::default())?);
                    continue;
                }
            };
            // The pull scanned the folder; the push need not walk it again.
            let scan = self.last_scan.take();
            if self.keyring.find(&name).is_none() {
                continue; // converted while pulling
            }
            // Selective sync turned off: the placeholders become files.
            pull.files_updated += self.fill_placeholders(&name, &mut pull.files_unavailable)?;
            match self.push_with_scan(&name, scan) {
                Ok(push) => out.push((pull, push)),
                Err(e) => out.push(paused(e, pull)?),
            }
        }
        if self.block_cache_root().is_dir() {
            // Blocks no cached file needs any more (a newer version arrived,
            // a file was deleted) leave the block cache once stored elsewhere.
            let view = self.view()?;
            self.gc_block_cache(&view)?;
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
            // Blocks of files that are on this device (not placeholders).
            let here: HashSet<&ChunkId> = match &mount {
                Some(_) => state
                    .files
                    .values()
                    .filter(|f| !f.deleted && state.local_index.contains_key(&f.path))
                    .flat_map(|f| f.chunks.iter().map(|c| &c.chunk))
                    .collect(),
                None => HashSet::new(),
            };
            // Transferrers empty themselves: a copy there is not kept.
            let carriers: HashSet<&str> = self
                .config
                .storages
                .iter()
                .filter(|s| s.is_carrier())
                .map(|s| s.name())
                .collect();
            let mut without = 0u64;
            let mut verified = 0u64;
            let mut blocks = BlockCounts::default();
            for c in &chunks {
                let rec_c = view.locate(&rec.folder_id, c);
                let kept: Vec<(&String, &ledger::Location)> = rec_c
                    .map(|r| {
                        r.storages
                            .iter()
                            .filter(|(n, _)| !carriers.contains(n.as_str()))
                            .collect()
                    })
                    .unwrap_or_default();
                let is_here = here.contains(c);
                if kept.is_empty() {
                    without += 1;
                    if is_here {
                        blocks.local_only += 1;
                    } else {
                        blocks.missing += 1;
                    }
                    continue;
                }
                let checked = kept.iter().any(|(n, l)| l.independently_verified(n));
                if checked {
                    verified += 1;
                }
                match (checked, is_here) {
                    (true, true) => blocks.verified_here += 1,
                    (true, false) => blocks.verified_away += 1,
                    (false, true) => blocks.stored_here += 1,
                    (false, false) => blocks.stored_away += 1,
                }
            }
            let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
            let placeholders_here = mount
                .as_ref()
                .map(|m| {
                    state
                        .files
                        .values()
                        .filter(|f| {
                            !f.deleted
                                && if encrypted_here {
                                    !state.local_index.contains_key(&f.path)
                                } else {
                                    placeholder_path(&self.disk_of(m, &state, &f.path)).exists()
                                }
                        })
                        .count() as u64
                })
                .unwrap_or(0);
            folders.push(FolderStatus {
                folder_id: rec.folder_id.to_string(),
                name: rec.name.clone(),
                path: mount.clone(),
                files,
                bytes,
                chunks: chunks.len() as u64,
                chunks_without_storage_copy: without,
                chunks_verified_elsewhere: verified,
                published_seq: state.published_seq,
                shared: rec.shared,
                read_only: self.share_read_only(&rec),
                policy: rec.effective_policy().map(|p| p.describe()),
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
                blocks,
                mode: self.mount_mode(&rec.folder_id),
                deletion_guard: self.deletion_guard(&rec.folder_id).describe(),
                paused: mount
                    .as_ref()
                    .and_then(|root| self.pause_of(&rec, root, &state)),
                held_deletions: self.held_summary(&state),
                remote_not_applied: state.not_applied.len() as u64,
                local_changes: state.local_changes.len() as u64,
                min_free: self
                    .config
                    .folders
                    .iter()
                    .find(|m| m.folder_id == rec.folder_id)
                    .and_then(|m| m.min_free)
                    .map(|m| m.setting()),
                min_free_text: self.folder_min_free(&rec.folder_id).describe(),
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
                // Members removed from a shared folder are listed per folder.
                .filter(|k| !self.devices.members.contains_key(*k))
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
            carrier_for: self.carrier_destination_names(),
            org: self.org_brief(),
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
            ledger_health: self.ledger_health(),
        })
    }

    /// Compare the ledger with what the storages actually hold. With
    /// `verify_content`, every referenced object is downloaded and hashed.
    /// Compare the ledger with the hot storages (and with `verify_content`
    /// download and hash every referenced object). What is missing or
    /// corrupt is queued for automatic repair (`engine::repair`).
    pub fn fsck(&mut self, verify_content: bool) -> Result<FsckReport> {
        crate::logged_op!("fsck", if verify_content { "with content" } else { "" }, {
            self.fsck_inner(verify_content)
        })
    }

    fn fsck_inner(&mut self, verify_content: bool) -> Result<FsckReport> {
        let (mut report, found) = self.fsck_scan(verify_content)?;
        let mut damage = Vec::new();
        repair::merge_damage(&mut damage, found);
        report.repairs_queued = damage.len() as u64;
        self.queue_damage(damage)?;
        let _ = self.ledger_lost_everywhere(false);
        report.ledger_health = self.ledger_health();
        Ok(report)
    }

    /// `fsck` without touching the repair queue: the report and every
    /// damaged copy on a storage of this device that repair could rewrite.
    fn fsck_scan(&mut self, verify_content: bool) -> Result<(FsckReport, Vec<Damage>)> {
        let task = activity::start(activity::FSCK, "", 0, activity::Unit::Items);
        task.set_phase("scan");
        let _ = self.pull_ledger()?;
        let view = self.view()?;
        let mut report = FsckReport {
            forked_devices: view.forked.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        };
        let now = util::now_utc();
        let mut damage: Vec<Damage> = Vec::new();
        let damaged = |folder: &FolderId,
                       chunk: &ChunkId,
                       object: &ObjectName,
                       storage: &str,
                       kind: DamageKind| Damage {
            folder: folder.clone(),
            chunk: chunk.clone(),
            object: object.clone(),
            storage: storage.to_string(),
            kind,
            found_by: "fsck".to_string(),
            found_utc: now,
            retry_utc: 0,
            reason: None,
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
        // Referenced chunks from every attached folder's current files and
        // its trash.
        let mut referenced: BTreeMap<(FolderId, ChunkId), ObjectName> = BTreeMap::new();
        for (rec, _) in self.folders() {
            let state = self.load_state(&rec.folder_id)?;
            for f in state.files.values().filter(|f| !f.deleted) {
                for c in &f.chunks {
                    referenced.insert((rec.folder_id.clone(), c.chunk.clone()), c.object.clone());
                }
            }
            for c in self.trash_chunks(&rec.folder_id) {
                referenced.insert((rec.folder_id.clone(), c.chunk), c.object);
            }
        }
        // Storages not listed (cold ones): a claim there counts as a copy.
        let unlisted: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_cold())
            .map(|s| s.name())
            .collect();
        // Blocks of backup snapshots this device has read or written.
        let backups: Vec<FolderId> = self
            .keyring
            .folders
            .values()
            .filter(|r| r.is_backup() && !r.is_removed())
            .map(|r| r.folder_id.clone())
            .collect();
        for b in backups {
            for (chunk, object) in self.backup_blocks_known(&b) {
                referenced.insert((b.clone(), chunk), object);
            }
        }
        report.chunks_referenced = referenced.len() as u64;
        let mut referenced_objects = HashSet::new();
        for ((folder, chunk), object) in &referenced {
            let key = chunk_storage_key(object);
            referenced_objects.insert(key.clone());
            let present_somewhere = listings.values().any(|l| l.contains(&key))
                || view.locate(folder, chunk).is_some_and(|r| {
                    r.object == *object
                        && r.storages
                            .iter()
                            .any(|(n, l)| unlisted.contains(n.as_str()) && !l.claimed_by.is_empty())
                });
            if present_somewhere {
                report.chunks_with_storage_copy += 1;
            } else {
                report
                    .chunks_missing
                    .push(format!("{}/{}", folder.short(), chunk.short()));
                // On no storage at all: every hot storage that takes every
                // block should get it back.
                for (spec, _) in &storages {
                    if !spec.is_carrier() && !spec.is_data_only() {
                        damage.push(damaged(
                            folder,
                            chunk,
                            object,
                            spec.name(),
                            DamageKind::Missing,
                        ));
                    }
                }
            }
            match view.locate(folder, chunk) {
                Some(r) if r.verified_storages() > 0 => report.chunks_verified_elsewhere += 1,
                Some(r) if r.claimed_storages() > 0 => report.chunks_claimed_only += 1,
                _ => {}
            }
        }
        for ((folder, chunk), rec) in view.chunks.iter() {
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
                        // Storage names are local: another device's "box"
                        // may be another place. Rewrite our own claims and
                        // blocks of current files (every storage takes those).
                        let ours = rec.storages[storage]
                            .claimed_by
                            .contains(&self.vault.device_id);
                        if !ours && !referenced.contains_key(&(folder.clone(), chunk.clone())) {
                            continue;
                        }
                        damage.push(damaged(
                            folder,
                            chunk,
                            &rec.object,
                            storage,
                            DamageKind::Missing,
                        ));
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
            task.step("verify", referenced.len() as u64, activity::Unit::Items);
            // Every referenced object on every storage, read ahead on each
            // storage's own readers (parallel where its medium allows); the
            // results come back here in the order of the plain loop.
            let refs: Vec<(&(FolderId, ChunkId), &ObjectName)> = referenced.iter().collect();
            let plans: Vec<crate::parverify::LanePlan> = storages
                .iter()
                .map(|(spec, _)| self.storage_lane(spec))
                .collect();
            let mut jobs: Vec<crate::parverify::Job<(usize, usize)>> = Vec::new();
            for (r, ((folder, chunk), _)) in refs.iter().enumerate() {
                let size = view.locate(folder, chunk).map_or(0, |c| c.size);
                for s in 0..storages.len() {
                    jobs.push(crate::parverify::Job {
                        item: (r, s),
                        lane: s,
                        size,
                    });
                }
            }
            if storages.is_empty() {
                task.advance(refs.len() as u64);
            }
            let mut failed: Option<anyhow::Error> = None;
            let storages_ref = &storages;
            let refs_ref = &refs;
            crate::parverify::run_ordered(
                &jobs,
                &plans,
                |&(r, s)| storages_ref[s].1.get(&chunk_storage_key(refs_ref[r].1)),
                |_, got| got.map(|ct| ct.map(|ct| crypto::hash(&ct))),
                |_, &(r, s), got| {
                    if s == 0 {
                        task.advance(1);
                    }
                    let ((folder, chunk), object) = refs[r];
                    let spec = &storages[s].0;
                    let hash = match got {
                        Ok(h) => h,
                        Err(e)
                            if matches!(
                                pool::pool_error(&e),
                                Some(PoolError::NeedsDisk { .. })
                            ) =>
                        {
                            report.objects_offline += 1;
                            return true;
                        }
                        Err(e) => {
                            failed = Some(e);
                            return false;
                        }
                    };
                    if let Some(hash) = hash {
                        if ObjectName::from_bytes(&hash) == *object {
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
                            if !spec.is_carrier() {
                                damage.push(damaged(
                                    folder,
                                    chunk,
                                    object,
                                    spec.name(),
                                    DamageKind::Corrupt,
                                ));
                            }
                        }
                    }
                    true
                },
            );
            if let Some(e) = failed {
                return Err(e);
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
        Ok((report, damage))
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

    /// Every disk of every pool with its attached state and the bookkeeping
    /// the pool index has (refreshes the registry, adopting disks other
    /// devices filled). `disk_report` adds what needs the ledger.
    pub fn disks(&mut self) -> Result<Vec<DiskStatus>> {
        let mut out = Vec::new();
        for spec in self.pool_specs() {
            let pool = self.open_pool(&spec)?;
            out.extend(pool.statuses());
            let disks = pool.disks();
            drop(pool);
            self.save_pool_disks(spec.name(), disks)?;
        }
        self.add_fsck_facts(&mut out);
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
        self.disk_add_at(mount, pool_name, label, "")
    }

    /// Reattach routine: verify the marker and the objects (sizes; hashes with
    /// `full`), apply queued deletions, then fill the disk with new objects.
    pub fn disk_check(&mut self, label: &str, full: bool) -> Result<DiskCheckReport> {
        crate::logged_op!("disk check", label, { self.disk_check_inner(label, full) })
    }

    fn disk_check_inner(&mut self, label: &str, full: bool) -> Result<DiskCheckReport> {
        let (spec, pool, disk) = self.find_disk(label)?;
        let mount = pool
            .mount_of(&disk.id)
            .ok_or_else(|| anyhow!("disk {} is not attached", disk.label))?;
        let task = activity::start(activity::DISK_CHECK, &disk.label, 0, activity::Unit::Bytes);
        let (objects_removed, bytes_removed) = pool.apply_pending_deletes(&disk.id)?;
        task.set_phase("verify");
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
            task.step("fill", 0, activity::Unit::Bytes);
            self.fill_disk(&spec, &pool, &disk.id)?
        };
        drop(task);
        self.commit_batch()?;
        pool.flush()?;
        let disks = pool.disks();
        let (group_copies, group_short) = (pool.copies(), pool.group_shortfall().0);
        drop(pool);
        self.save_pool_disks(spec.name(), disks)?;
        Ok(DiskCheckReport {
            group_copies,
            group_short,
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
        crate::logged_op!("disk eject", label, { self.disk_eject_inner(label) })
    }

    fn disk_eject_inner(&mut self, label: &str) -> Result<PathBuf> {
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
        crate::logged_op!("disk retire", label, { self.disk_retire_inner(label) })
    }

    fn disk_retire_inner(&mut self, label: &str) -> Result<u64> {
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
        let size = fs::metadata(path)?.len();
        for params in [self.chunker_for(size)] {
            let file = fs::File::open(path)?;
            for piece in Chunker::new(std::io::BufReader::new(file), params)? {
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
        }
        bail!("chunk {} is not in {}", chunk.short(), path.display())
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
/// ledger, state, configuration, secrets, grants, the block cache and
/// exported copies) so it can start over. The user's files in attached
/// folders are left untouched; the storages are not changed either, so other
/// devices keep working.
/// Refuse to set up a vault where one already is, saying which one and
/// how to start over.
pub fn ensure_no_vault(home: &Path) -> Result<()> {
    let p = home.join("vault.json");
    if !p.exists() {
        return Ok(());
    }
    let what = util::read_json::<LocalVault>(&p)
        .map(|v| {
            format!(
                "vault {} as device \"{}\"",
                v.vault_id.short(),
                v.device_name
            )
        })
        .unwrap_or_else(|_| "a vault".to_string());
    bail!(
        "this device already holds {what} ({}). To start over here, run `varsto reset --yes` first: it removes this device's keys and settings; files in folders stay, and the vault's other devices and storages are not touched",
        home.display()
    )
}

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
        org_ops::RESET_ORG[0],
        org_ops::RESET_ORG[1],
    ] {
        let p = home.join(name);
        if p.exists() {
            fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(name.to_string());
        }
    }
    for dir in ["state", "ledger", "trash", BLOCK_CACHE_DIR, EXPORT_DIR] {
        let p = home.join(dir);
        if p.exists() {
            fs::remove_dir_all(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(format!("{dir}/"));
        }
    }
    Ok(removed)
}
