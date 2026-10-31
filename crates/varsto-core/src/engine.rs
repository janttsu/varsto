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
//!
//! Storage format 3 (`docs/spec/format-3-design.md`): the ledger is
//! `ledger3` (`ledger3_ops`), membership and folder keys come from signed
//! records and grants (`members3`), block places from the folder block map
//! and manifests are base + delta records (`folder3`). The location view
//! of `crate::ledger` (`Engine::view`) is kept in memory only: no batch of
//! it is stored, so it holds this device's events not sealed yet, which
//! placement, `where`, protection and history read during an action.

use crate::activity;
use crate::chunking::{Chunker, ChunkerParams};
use crate::crypto::{self, KeyedHasher, SecretKey};
use crate::fsmeta;
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName, VaultId};
use crate::ignore_rules::{self, Matcher as IgnoreMatcher};
use crate::ledger::{self, Event, Ingest, LedgerStore, LedgerView, KEY_LEDGER, KEY_REPLICA};
use crate::manifest::{self, ChunkRef, FileState, Manifest, Merge};
use crate::policy::{Policy, PolicyReport};
use crate::pool::{self, DiskStatus, PoolDisk, PoolError, PoolIdentity, PoolStorage};
use crate::replica::{self, ReplicaToken};
use crate::storage::{Storage, StorageSpec};
use crate::thumbs;
use crate::util;
use crate::vault::SecretStore;
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
mod folder3;
mod folder_rules;
mod folder_safety;
mod forward;
mod fsck3_ops;
mod guide;
mod health;
mod help;
mod history;
mod home_lock;
mod imports;
mod ledger3_ops;
mod ledger_heads;
mod ledger_recovery;
mod ledger_upkeep;
mod local_names;
mod mailbox;
mod manifest_upkeep;
mod members3;
mod membership;
mod membership3_ops;
mod notes;
mod org_ops;
mod p2p3;
mod pack_upkeep;
mod placement;
mod protection;
mod quotas;
mod records3_io;
mod repair;
mod restic_mirror;
mod scrub;
mod share_ops;
mod share_roles;
mod staged_moves;
mod storage_directory;
mod storages3_ops;
mod strongroom_ops;
mod thumbs3;
mod torrent;
mod trash;
mod trash3_io;
mod verify;
mod view;
mod viz;
mod where_data;
mod youtube;
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
pub use forward::{
    ForwardFolder, ForwardOptions, ForwardReport, ForwardSettings, ForwardStatus, LEASE_SLOT_SECS,
    LEASE_WORK_SECS,
};
pub use health::{is_network_error, StorageDown, StorageHealth};
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
pub use mailbox::MailboxOptions;
pub use manifest_upkeep::ManifestPolicy;
pub use membership::{
    removal_notice, DeviceInfo, DeviceRemoved, EpochForks, Removal, RevokeReport, Revoked,
};
pub use membership3_ops::{
    parse_role as parse_folder_role, FolderMember, FolderMembers, FolderRemoval, FolderRequest,
    MissingRecoveryCopy,
};
pub use notes::{
    check_analysis, AnalysisHit, FileAnalysis, NotesExchangeReport, ANALYSIS_MAX_BYTES,
    LISTING_CHARS, TAGS_MAX, TAG_MAX_CHARS,
};
pub use org_ops::{
    LogView, OrgApproved, OrgBrief, OrgCreated, OrgDevice, OrgRemoveReport, OrgSummary, OrgUser,
    UnlistedDevice,
};
pub use p2p3::{DirectoryRead, SAVED_PEERS};
pub use protection::{ClassCoverage, Protection};
pub use quotas::QuotaStatus;
pub use repair::{
    Damage, DamageKind, RepairOptions, RepairReport, RepairStatus, RepairedCopy, Unrepairable,
};
pub use restic_mirror::{CheckOptions, SetupReport};
pub use scrub::ScrubOptions;
pub use share_ops::{ShareMember, ShareMembers, ShareRevokeReport};
pub use share_roles::{ShareRoleReport, KEPT_ASIDE_DIR};
pub use staged_moves::{JobRunLimits, MoveJobRequest, MoveJobRun, SERVICE_RUN_GROUPS};
pub use storage_directory::KnownStorage;
pub use strongroom_ops::{CleanupReport, ConvertReport, StrongroomKeySummary};
pub use torrent::{
    find_job, plan_batch, torrent_jobs_at, BatchPlan, Candidate, CompletedFiles, FileOutcome,
    JobFile, JobState, SystemEnv, TorrentAddOptions, TorrentEnv, TorrentJob, CHEAPEST,
    DEFAULT_FREE_MIN,
};
pub use trash::{
    restored_name, RestoredFile, TrashItem, TrashPurgeReport, TrashRestorePlan, TrashRestoreReport,
    TrashSettings, TrashStatus, TrashUpkeepReport, DEFAULT_TRASH_DAYS, MAX_TRASH_DAYS,
    TRASH_UPKEEP_EVERY_SECS,
};
pub use where_data::{CopyStats, DataLocations, DeviceShare, FolderShare, StorageShare};
pub use youtube::{
    find_youtube_job, task_args as youtube_task_args, youtube_jobs_at, BlockingYoutubeEnv,
    ServiceYoutubeEnv, TaskKind as YoutubeTaskKind, Video as YoutubeVideo, VideoCounts,
    VideoStatus, YoutubeAddOptions, YoutubeEnv, YoutubeJob, YoutubeScanReport, YtState,
    DEFAULT_REFRESH_HOURS, DEFAULT_YT_FREE_MIN,
};

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
    /// Storages that were given every thumbnail already stored elsewhere (a
    /// storage added later would otherwise only get thumbnails made after it).
    #[serde(default)]
    thumbs_replicated: BTreeSet<String>,
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
    /// The change is saved here but its upload failed (a storage cannot be
    /// reached): why. The next sync or push uploads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_pending: Option<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct PullReport {
    /// Chunks fetched from peers instead of storages.
    #[serde(default)]
    pub chunks_from_peers: u64,
    /// Of `bytes_downloaded`, the bytes of the chunks that came from peers
    /// (the rest came from storages).
    #[serde(default)]
    pub bytes_from_peers: u64,
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
    /// The folder was not synced this time: why (a sync reports it and
    /// goes on with the other folders).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Storages this sync could not reach and left out (`storage_health`
    /// says more).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storages_down: Vec<String>,
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
    /// Newest modification time of a current file (UTC seconds), if any.
    pub last_change_utc: Option<i64>,
    pub chunks: u64,
    /// Chunks of current files that no storage claims to hold.
    pub chunks_without_storage_copy: u64,
    /// Chunks that at least one device other than the writer has verified on a storage.
    pub chunks_verified_elsewhere: u64,
    /// How well the folder is protected (see `Engine::protection`).
    pub protection: Protection,
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

/// One pack copied whole to another storage before the storage goes.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedCopy {
    /// The pack id (hex).
    pub pack: String,
    pub target: String,
    /// Its size class.
    pub bytes: u64,
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
    /// Storages that could not be reached and rest before the next try
    /// (`Engine::storage_health`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storages_down: Vec<StorageHealth>,
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
    /// The format-3 report the counters above are taken from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format3: Option<crate::fsck3::Fsck3Report>,
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
    /// How often a long push with peers publishes what it stored so far
    /// (`EarlyPublish`).
    early_publish: EarlyPublish,
    /// Tests: the pack size of hot storages instead of `packs::HOT_TARGET`.
    pack_target_for_tests: Option<usize>,
    /// Tests: called before every pack write of this engine's storages.
    pack_write_hook: Option<crate::storage::PackWriteHook>,
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
    /// The store behind the in-memory location view (`Engine::view`); it
    /// holds no batch in a format-3 vault (`state/f2-ledger`).
    ledger: LedgerStore,
    /// The format-3 ledger, membership and folder records (`ledger3_ops`).
    f3: ledger3_ops::Core3,
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
    /// Storages that failed with a network error in this run, and those
    /// resting after failures (`health`).
    health: health::Health,
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
    /// Set while this engine holds the device directory's lock (`home_lock`).
    home_held: bool,
    /// The write counter of the device directory as of this engine's last
    /// read of it (`home_lock`).
    home_generation: u64,
}

/// What the peer-to-peer server serves from (see `Engine::set_snapshot_sink`).
pub type SnapshotSink =
    std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::p2p::Snapshot>>>>;

/// A push with peers publishes its file list before the upload, so peers
/// fetch the new files from this device while the storages receive them,
/// and then, while the upload runs, the map record of the packs stored so
/// far with their claims, whenever `bytes` more were handed to the
/// storages or `secs` passed since the last time, and something new was
/// stored (spec section 77.23).
#[derive(Clone, Copy, Debug)]
pub struct EarlyPublish {
    pub bytes: u64,
    pub secs: u64,
}

impl Default for EarlyPublish {
    fn default() -> Self {
        EarlyPublish {
            bytes: 64 << 20,
            secs: 30,
        }
    }
}

/// Open storages with their specs.
type OpenStorages = Vec<(StorageSpec, Box<dyn Storage>)>;

/// The backends opened during an operation, by storage name, each with the
/// spec it was opened from (`Engine::storages_open`).
type OpenedStorages = HashMap<String, (StorageSpec, std::sync::Arc<dyn Storage>)>;

/// Threads that write objects during a push, and how many encrypted
/// blocks may wait for them.
/// The thumbnail pass of one sync stops after this many pictures or this
/// much time, whichever comes first; the next sync continues (the made ones
/// are remembered in the folder state). A folder added with thousands of
/// pictures then neither holds the service nor the UI for minutes.
const THUMBS_PER_PASS: usize = 200;
const THUMBS_PASS_TIME: std::time::Duration = std::time::Duration::from_secs(20);
/// The early pass, before the upload of a big folder: a first screenful.
const THUMBS_EARLY_PER_PASS: usize = 48;
const THUMBS_EARLY_TIME: std::time::Duration = std::time::Duration::from_secs(8);

const UPLOADERS: usize = 8;
const UPLOAD_QUEUE: usize = 16;
/// At least this much encrypted data may wait for or be with the uploaders
/// (counted once per storage it goes to); the budget grows with the pack
/// sizes of the storages written (`upload_budget`), up to `UPLOAD_BYTES_MAX`.
const UPLOAD_BYTES: u64 = 128 << 20;
const UPLOAD_BYTES_MAX: u64 = 768 << 20;

/// Bytes a push may hold for `targets` (pack sizes of the storages it
/// writes): a pack's worth for each, and some to fill the next.
/// Take from `jobs` the blocks of one pack of at most `target` bytes, first
/// fit decreasing (`packs::first_fit_decreasing`: its first bin, the one
/// filled with the largest blocks first), in their original order; the
/// others stay.
fn take_full_pack(
    jobs: &mut Vec<std::sync::Arc<UploadJob>>,
    target: u64,
) -> Vec<std::sync::Arc<UploadJob>> {
    let sizes: Vec<usize> = jobs.iter().map(|j| j.ct.len()).collect();
    let limit = usize::try_from(target).unwrap_or(usize::MAX);
    let mut take = vec![false; jobs.len()];
    if let Some(bin) = crate::packs::first_fit_decreasing(&sizes, limit)
        .into_iter()
        .next()
    {
        for i in bin {
            take[i] = true;
        }
    }
    let mut picked = Vec::new();
    let mut rest = Vec::new();
    for (j, t) in jobs.drain(..).zip(take) {
        if t {
            picked.push(j);
        } else {
            rest.push(j);
        }
    }
    *jobs = rest;
    picked
}

/// Write the blocks of one batch to every storage of its target set: built
/// once into packs of the set's size classes (`packs::build`) and the same
/// bytes written everywhere, so a pack has one id on every storage of the
/// set (`docs/spec/format-3-design.md` section 2). A storage that does not
/// take a built pack (one that holds a member already, or keeps no packs)
/// gets the members through its own `put_pack`. One outcome list per
/// storage of the set, one entry per job: written now, or why not.
fn write_to_set(
    backends: &[&dyn Storage],
    jobs: &[std::sync::Arc<UploadJob>],
) -> Vec<Vec<Result<bool>>> {
    let failed_all = |e: &anyhow::Error, storage: &str| -> Vec<Result<bool>> {
        // A full disk stays that error (the storage is left out, not the
        // push), and so do a pool's "no disk" and a storage that cannot be
        // reached (`health`).
        let low = crate::freespace::low_space(e).cloned();
        let pool = pool::pool_error(e).cloned();
        let down = health::is_network_error(e).then(|| health::StorageDown {
            storage: storage.to_string(),
            reason: format!("{e:#}"),
        });
        let msg = format!("{e:#}");
        jobs.iter()
            .map(|_| match (&low, &pool, &down) {
                (Some(l), _, _) => Err(anyhow::Error::new(l.clone())),
                (None, Some(p), _) => Err(anyhow::Error::new(p.clone())),
                (None, None, Some(d)) => Err(anyhow::Error::new(d.clone())),
                _ => Err(anyhow!("{msg}")),
            })
            .collect()
    };
    let members: Vec<(String, &[u8])> = jobs
        .iter()
        .map(|j| (j.object.as_str().to_string(), j.ct.as_slice()))
        .collect();
    if backends.len() == 1 {
        return vec![match backends[0].put_pack(&members) {
            Ok(flags) => flags.into_iter().map(Ok).collect(),
            Err(e) => failed_all(&e, backends[0].name()),
        }];
    }
    // One copy of each object (two files of the push may share a block);
    // a repeat is "not written now", as `put_pack` says of it.
    let mut seen: HashSet<&str> = HashSet::new();
    let unique: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, (o, _))| seen.insert(o.as_str()))
        .map(|(i, _)| i)
        .collect();
    let target = backends[0].pack_target().max(1);
    let limit = target.min(crate::packs::top_class(target));
    let sizes: Vec<usize> = unique.iter().map(|&i| members[i].1.len()).collect();
    let mut bins: Vec<Vec<usize>> = crate::packs::first_fit_decreasing(&sizes, limit)
        .into_iter()
        .map(|bin| {
            let mut idx: Vec<usize> = bin.into_iter().map(|b| unique[b]).collect();
            // The order of the push inside a pack (blocks of a file together).
            idx.sort_unstable();
            idx
        })
        .collect();
    bins.sort_by_key(|b| b.first().copied());
    let built: Vec<crate::packs::BuiltPack> = bins
        .iter()
        .map(|idx| {
            let group: Vec<(String, &[u8])> = idx.iter().map(|&i| members[i].clone()).collect();
            crate::packs::build(&group, target)
        })
        .collect();
    // One thread per storage of the set: a slow storage does not hold back
    // the fast ones, and one that fails leaves the others' writes as they
    // are.
    let write_one = |backend: &dyn Storage| -> Vec<Result<bool>> {
        let mut flags: Vec<Option<Result<bool>>> = (0..jobs.len()).map(|_| None).collect();
        let mut error = None;
        for (idx, (id, data, locs)) in bins.iter().zip(&built) {
            let taken = match backend.put_built_pack(id, data, locs) {
                Ok(Some(f)) => Ok(f),
                Ok(None) => {
                    let own: Vec<(String, &[u8])> =
                        idx.iter().map(|&i| members[i].clone()).collect();
                    backend.put_pack(&own)
                }
                Err(e) => Err(e),
            };
            match taken {
                Ok(f) => {
                    for (&i, w) in idx.iter().zip(f) {
                        flags[i] = Some(Ok(w));
                    }
                }
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        match error {
            // The whole batch counts as not written on this storage; its
            // blocks are tried there again at the next push (a pack that
            // did go is found then and not written twice).
            Some(e) => failed_all(&e, backend.name()),
            None => flags.into_iter().map(|f| f.unwrap_or(Ok(false))).collect(),
        }
    };
    let write_one = &write_one;
    std::thread::scope(|s| {
        let handles: Vec<_> = backends
            .iter()
            .map(|&backend| s.spawn(move || write_one(backend)))
            .collect();
        handles
            .into_iter()
            .zip(backends)
            .map(|(h, backend)| {
                h.join().unwrap_or_else(|_| {
                    let e = anyhow!("the writer of storage {} stopped", backend.name());
                    failed_all(&e, backend.name())
                })
            })
            .collect()
    })
}

/// The target sets of one block: the storages it goes to (by index),
/// grouped by the pack size they are written with, so that a pack's class
/// fits every storage of its set (hot, local, pool and transferrer
/// storages up to 64 MiB; cold ones, which go on to 256 MiB, apart).
fn target_sets(to: &[usize], pack_target: impl Fn(usize) -> usize) -> Vec<Vec<usize>> {
    let mut by_target: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &i in to {
        by_target.entry(pack_target(i)).or_default().push(i);
    }
    by_target.into_values().collect()
}

fn upload_budget(targets: impl Iterator<Item = usize>) -> u64 {
    let sum: u64 = targets.map(|t| t as u64).sum();
    // A pack being written and the buffer the next one is filled from.
    (sum * 2 + (64 << 20)).clamp(UPLOAD_BYTES, UPLOAD_BYTES_MAX)
}

/// Count one finished write in the report and the ledger. The quota room
/// taken for a block that was not written now (the storage failed, or held
/// it already) is given back to `gate` for the rest of the push.
fn apply_upload(
    me: &mut Engine,
    folder_id: &FolderId,
    d: UploadDone,
    report: &mut PushReport,
    first_error: &mut Option<anyhow::Error>,
    gate: &quotas::QuotaGate,
) {
    if !matches!(d.outcome, Ok(true)) {
        gate.give_back(&d.storage, d.size);
    }
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
                pack: None,
            });
        }
        // A pool with no disk attached (or no room), and a storage that
        // cannot be reached, are left out for the rest of this push and
        // tried again next time: the others' packs are published.
        Err(e)
            if matches!(
                pool::pool_error(&e),
                Some(PoolError::NoDiskAttached { .. } | PoolError::NoRoom { .. })
            ) || crate::freespace::low_space(&e).is_some()
                || health::is_network_error(&e) =>
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

/// The packs `storages` wrote since they were last asked, by storage, for
/// the map record of a push. Packs written in this process by anything
/// but this push (whose blocks are `info`) are left out: their writers
/// make their own map records.
fn stored_packs(
    storages: &OpenStorages,
    info: &HashMap<crate::ledger3::ObjectBin, crate::blockmap::ChunkInfo>,
) -> Vec<(String, Vec<crate::packs::NewPack>)> {
    let mut per_storage = Vec::new();
    for (spec, backend) in storages {
        let new: Vec<crate::packs::NewPack> = backend
            .take_new_packs()
            .into_iter()
            .filter(|p| {
                p.members.iter().all(|(o, _)| {
                    crate::storages3::object_bin(&ObjectName::from_hex(o).unwrap_or_default())
                        .is_ok_and(|b| info.contains_key(&b))
                })
            })
            .collect();
        if !new.is_empty() {
            per_storage.push((spec.name().to_string(), new));
        }
    }
    per_storage
}

/// When a push publishes the packs it stored so far (`EarlyPublish`).
struct Cadence {
    every: EarlyPublish,
    /// Encrypted bytes handed to the uploaders since the last publish.
    bytes: u64,
    since: std::time::Instant,
}

impl Cadence {
    fn new(every: EarlyPublish) -> Cadence {
        Cadence {
            every,
            bytes: 0,
            since: std::time::Instant::now(),
        }
    }

    /// Count `bytes` more handed over; true when a publish is due.
    fn add(&mut self, bytes: u64) -> bool {
        self.bytes += bytes;
        self.bytes >= self.every.bytes || self.since.elapsed().as_secs() >= self.every.secs
    }

    fn published(&mut self) {
        self.bytes = 0;
        self.since = std::time::Instant::now();
    }
}

/// One object to write to some storages during a push.
struct UploadJob {
    targets: Vec<String>,
    chunk: ChunkId,
    object: ObjectName,
    ct: Vec<u8>,
}

/// The blocks of one pack on their way to one storage; their bytes leave
/// the upload budget when it is written.
struct UploadBatch {
    jobs: Vec<std::sync::Arc<UploadJob>>,
    /// Encrypted bytes it holds.
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

/// How long joining waits for the bundled storages to answer, all together.
const REACHABLE_WITHIN: std::time::Duration = std::time::Duration::from_secs(8);

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
        crypto::check_passphrase(passphrase)?;
        crate::names::check_display_name(device_name)?;
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
        let mut engine = Self::write_new(home, vault, keys, passphrase, epochs)?;
        // The recovery key (K1) is made now and shown once with the kit
        // (`recovery_kit_text`); folders added in this session are escrowed
        // under it at once.
        engine.f3.recovery = Some(crate::membership3::RecoveryKey::generate());
        Ok((engine, vault_key_hex))
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
            None,
        )
    }

    /// Like `join_with_secret`, with the signing key (K6) the device already
    /// made (an organization request, or the hello of a pairing): its device
    /// id is then the one the other side saw; likewise its KEM key (K8),
    /// which a pairing sealed the vault key and the folder grants to.
    /// Without them fresh keys are generated.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn join_with_signer(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        vault_key_hex: &str,
        storage: StorageSpec,
        secret: Option<String>,
        signer: Option<crypto::SigningKey>,
        kem: Option<crate::kem::DecapsKey>,
    ) -> Result<Engine> {
        crypto::check_passphrase(passphrase)?;
        crate::names::check_display_name(device_name)?;
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
            bail!("{}", crate::format_mismatch(meta.format_version));
        }
        let given = SecretKey::from_hex(vault_key_hex)?;
        let signer = signer.unwrap_or_else(crypto::SigningKey::generate);
        let kem = kem.unwrap_or_else(crate::kem::DecapsKey::generate);
        // The vault words are the newest vault key: its epoch is found on
        // the storage and the chain of vault epoch records gives the older
        // keys down to K3₀ (an out-of-date key is refused).
        let vault_keys = {
            let refs: Vec<&dyn Storage> = vec![backend.as_ref()];
            let m = crate::membership3::Membership::join(
                members3::bin(&meta.vault_id)?,
                &refs,
                &signer,
                &kem,
                given,
            )?;
            if m.devices.devices.is_empty() {
                bail!(
                    "this vault key does not open the records on storage {}: check the vault words",
                    storage.name()
                );
            }
            m.vault_keys.clone()
        };
        let master = vault_keys
            .k3_0()
            .cloned()
            .ok_or_else(|| anyhow!("the vault key of epoch 0 is not reached from these words"))?;
        let mut epochs = membership::VaultEpochs::genesis(&master);
        epochs.keys = vault_keys.keys.clone();
        epochs.kem = Some(kem);
        util::private_home(home)?;
        let keys = Keys { master, signer };
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

    /// Join without reaching any storage: the vault keys come from the
    /// pairing (`Bundle::vault_epochs`), the storages are only written to
    /// the settings, and `state/pending-join.json` makes the next sync
    /// finish what needs a storage (`finish_pending_join`): check the vault
    /// and the keys, enrol this device and read the vault's records.
    #[allow(clippy::too_many_arguments)]
    fn join_deferred(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
        epochs: &[crate::pair::BundleEpoch],
        storages: &[&crate::pair::BundleStorage],
        signer: Option<crypto::SigningKey>,
        kem: Option<crate::kem::DecapsKey>,
        mut notes: Vec<String>,
    ) -> Result<(Engine, Vec<String>)> {
        crypto::check_passphrase(passphrase)?;
        ensure_no_vault(home)?;
        let mut by_epoch = BTreeMap::new();
        for e in epochs {
            by_epoch.insert(e.epoch, SecretKey::from_hex(&e.key)?);
        }
        let master = by_epoch
            .get(&0)
            .cloned()
            .ok_or_else(|| anyhow!("the pairing did not carry the vault key of epoch 0"))?;
        let vault_id = VaultId::from_hex(&bundle.vault_id)?;
        let mut vault_epochs = membership::VaultEpochs::genesis(&master);
        vault_epochs.keys = by_epoch;
        vault_epochs.kem = Some(kem.unwrap_or_else(crate::kem::DecapsKey::generate));
        util::private_home(home)?;
        let keys = Keys {
            master,
            signer: signer.unwrap_or_else(crypto::SigningKey::generate),
        };
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id,
            device_id: ledger::device_id_for(&keys.signer.public()),
            device_name: device_name.to_string(),
            // The vault's own date is read from its storage later.
            created_utc: util::now_utc(),
            member: false,
        };
        let mut engine = Self::write_new(home, vault, keys, passphrase, vault_epochs)?;
        for s in storages {
            engine.add_storage_deferred(s.spec.clone(), s.secret.clone())?;
        }
        std::fs::create_dir_all(engine.home.join("state"))?;
        util::write_json(
            &engine.pending_join_path(),
            &PendingJoin {
                storages: storages.iter().map(|s| s.spec.name().to_string()).collect(),
                since_utc: util::now_utc(),
            },
        )?;
        notes.push(
            "joined without reaching a storage: this device is set up with the vault's keys; the next sync (the background service does it) finishes joining as soon as a storage can be reached".into(),
        );
        Ok((engine, notes))
    }

    /// Keep a storage's settings and secret without contacting it (a join
    /// that is finished later).
    fn add_storage_deferred(&mut self, spec: StorageSpec, secret: Option<String>) -> Result<()> {
        if self.config.storages.iter().any(|s| s.name() == spec.name()) {
            bail!("a storage named {} already exists", spec.name());
        }
        if let Some(secret) = secret {
            let reference = match &spec {
                StorageSpec::S3 { secret_ref, .. } if !secret_ref.is_empty() => secret_ref.clone(),
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
        self.config.storages.push(spec);
        self.config.save(&self.home)
    }

    fn pending_join_path(&self) -> PathBuf {
        self.home.join("state").join("pending-join.json")
    }

    /// The storages a join without storage access is still waiting for
    /// (`None`: joining is complete).
    pub fn join_pending(&self) -> Option<Vec<String>> {
        util::read_json::<PendingJoin>(&self.pending_join_path())
            .ok()
            .map(|p| p.storages)
    }

    /// Finish a join that was made without reaching a storage: the first
    /// storage that answers must hold this vault (same id and format) and
    /// open with this device's vault key (not one from before a removal);
    /// then the storages are added as usual, the registry and ledger are
    /// read and this device's enrolment is published. Without a pending
    /// join it does nothing; while no storage answers it fails and the
    /// next sync tries again.
    fn finish_pending_join(&mut self) -> Result<()> {
        let path = self.pending_join_path();
        let Ok(pending) = util::read_json::<PendingJoin>(&path) else {
            return Ok(());
        };
        // Until joining is finished nothing else works here: every sync
        // asks the storages again, also one resting after failures (storage
        // health, spec 79.1).
        self.retry_storages_now();
        let mut notes = Vec::new();
        let mut found: Option<(StorageSpec, VaultMeta)> = None;
        for name in &pending.storages {
            let Some(spec) = self
                .config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .cloned()
            else {
                continue;
            };
            let got = self
                .open_spec(&spec)
                .and_then(|b| b.get(VaultMeta::STORAGE_KEY))
                .and_then(|m| match m {
                    Some(bytes) => Ok(serde_json::from_slice::<VaultMeta>(&bytes)?),
                    None => Err(anyhow!("holds no vault")),
                });
            match got {
                Ok(meta) => {
                    found = Some((spec, meta));
                    break;
                }
                Err(e) => notes.push(format!("{name}: {e:#}")),
            }
        }
        let Some((first, meta)) = found else {
            bail!(
                "joining is not finished: no storage of the vault can be reached yet ({}); it finishes by itself when one can",
                notes.join("; ")
            );
        };
        if meta.format_version != crate::FORMAT_VERSION {
            bail!("{}", crate::format_mismatch(meta.format_version));
        }
        if meta.vault_id != self.vault.vault_id {
            bail!(
                "storage {} holds another vault than the one paired with: run `varsto reset --yes` and pair again",
                first.name()
            );
        }
        {
            let backend = self.open_spec(&first)?;
            let refs: Vec<&dyn Storage> = vec![backend.as_ref()];
            let kem = self
                .epochs
                .kem
                .as_ref()
                .ok_or_else(|| anyhow!("this device has no K8"))?;
            let newest = self
                .epochs
                .keys
                .values()
                .next_back()
                .cloned()
                .ok_or_else(|| anyhow!("this device holds no vault key"))?;
            let m = crate::membership3::Membership::join(
                members3::bin(&meta.vault_id)?,
                &refs,
                &self.keys.signer,
                kem,
                newest,
            )?;
            if m.devices.devices.is_empty() {
                bail!(
                    "this vault key does not open the records on storage {}: run `varsto reset --yes` and pair again",
                    first.name()
                );
            }
        }
        self.vault.created_utc = meta.created_utc;
        util::write_json(&self.home.join("vault.json"), &self.vault)?;
        let order = std::iter::once(first.name().to_string()).chain(
            pending
                .storages
                .iter()
                .filter(|n| n.as_str() != first.name())
                .cloned(),
        );
        for name in order {
            let Some(spec) = self
                .config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .cloned()
            else {
                continue;
            };
            self.config.storages.retain(|s| s.name() != name);
            if let Err(e) = self.add_storage_internal(spec.clone(), None) {
                // Kept as it was: the other storages are added when they answer.
                self.config.storages.retain(|s| s.name() != name);
                self.config.storages.push(spec);
                self.config.save(&self.home)?;
                if name == first.name() {
                    return Err(e);
                }
                log::warn!("storage {name} is not reachable yet: {e:#}");
            }
        }
        self.pull_registry()?;
        self.pull_ledger()?;
        self.push_own_batches()?;
        let _ = std::fs::remove_file(&path);
        log::info!("joining finished through storage {}", first.name());
        Ok(())
    }

    /// Join with what a paired device sent (`pair::Bundle`, with the vault
    /// key the pairing opened in `vault_key`) and the keys of this device's
    /// hello (`keys`: the folder grants the other device wrote are sealed
    /// to its K8): through the first of its storages that this device can
    /// reach, then add the other reachable ones. Returns the engine and one
    /// note per storage.
    pub fn join_paired(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
        keys: crate::pair::v3::PairingKeys,
    ) -> Result<(Engine, Vec<String>)> {
        crate::logged_op_plain!("join paired", device_name, {
            Self::join_paired_with(
                home,
                device_name,
                passphrase,
                bundle,
                Some(keys.signer),
                Some(keys.kem),
            )
        })
    }

    pub(crate) fn join_paired_with(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        bundle: &crate::pair::Bundle,
        signer: Option<crypto::SigningKey>,
        kem: Option<crate::kem::DecapsKey>,
    ) -> Result<(Engine, Vec<String>)> {
        crate::names::check_display_name(device_name)?;
        let mut notes = Vec::new();
        let mut first = None;
        // All storages are asked at once with a short budget: a dead one
        // costs that budget once, not once each in turn.
        let mut answers = Self::reachable_all(&bundle.storages, REACHABLE_WITHIN);
        for (i, s) in bundle.storages.iter().enumerate() {
            match answers[i].take().unwrap_or_else(|| Ok(())) {
                Ok(()) => {
                    first = Some(i);
                    break;
                }
                Err(e) => notes.push(format!("{}: not reachable here ({e:#})", s.spec.name())),
            }
        }
        let Some(first) = first else {
            // No storage answers, but the sender gave every vault key and
            // the settings of a network storage: set this device up now and
            // finish joining when one can be reached.
            if let Some(epochs) = &bundle.vault_epochs {
                let network: Vec<&crate::pair::BundleStorage> = bundle
                    .storages
                    .iter()
                    .filter(|s| {
                        matches!(s.spec, StorageSpec::S3 { .. } | StorageSpec::Rclone { .. })
                    })
                    .collect();
                if !network.is_empty() {
                    return Self::join_deferred(
                        home,
                        device_name,
                        passphrase,
                        bundle,
                        epochs,
                        &network,
                        signer,
                        kem,
                        notes,
                    );
                }
            }
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
            kem,
        )?;
        if engine.vault.vault_id.to_string() != bundle.vault_id {
            bail!(
                "storage {} holds another vault than the one paired with",
                chosen.spec.name()
            );
        }
        notes.push(format!("{}: joined through it", chosen.spec.name()));
        for (i, s) in bundle.storages.iter().enumerate().skip(first + 1) {
            let r = answers[i]
                .take()
                .unwrap_or_else(|| Ok(()))
                .and_then(|()| engine.add_storage_internal(s.spec.clone(), s.secret.clone()));
            notes.push(match r {
                Ok(()) => format!("{}: added", s.spec.name()),
                Err(e) => format!("{}: not reachable here ({e:#})", s.spec.name()),
            });
        }
        Ok((engine, notes))
    }

    /// `reachable` for every storage at once, each on its own thread, waiting
    /// at most `within` in all. One answer per storage; a storage that has
    /// not answered by then is a network error (its thread is left to end by
    /// itself: every network call has its own limits).
    fn reachable_all(
        storages: &[crate::pair::BundleStorage],
        within: std::time::Duration,
    ) -> Vec<Option<Result<()>>> {
        let (tx, rx) = std::sync::mpsc::channel();
        for (i, s) in storages.iter().enumerate() {
            let (tx, s) = (tx.clone(), s.clone());
            std::thread::spawn(move || {
                let _ = tx.send((i, Self::reachable(&s)));
            });
        }
        drop(tx);
        let deadline = std::time::Instant::now() + within;
        let mut out: Vec<Option<Result<()>>> = storages.iter().map(|_| None).collect();
        let mut got = 0;
        while got < storages.len() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok((i, r)) => {
                    out[i] = Some(r);
                    got += 1;
                }
                Err(_) => break,
            }
        }
        for (i, slot) in out.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Err(crate::storage::network_unavailable(
                    storages[i].spec.name().to_string(),
                    format!("no answer within {} s", within.as_secs()),
                )));
            }
        }
        out
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
            vault_epochs: Some(
                self.epochs
                    .keys
                    .iter()
                    .map(|(e, k)| crate::pair::BundleEpoch {
                        epoch: *e,
                        key: k.to_hex(),
                    })
                    .collect(),
            ),
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
        let f3 = ledger3_ops::Core3::open(home, &vault.vault_id)?;
        let home_generation = home_lock::read_generation(home);
        let mut engine = Engine {
            peers: None,
            snapshot_sink: None,
            early_publish: EarlyPublish::default(),
            pack_target_for_tests: None,
            pack_write_hook: None,
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
            ledger: LedgerStore::open(&home.join("state").join("f2-ledger"))?,
            f3,
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
            health: health::Health::new(home),
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
            home_held: false,
            home_generation,
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

    pub fn is_member(&self) -> bool {
        self.vault.member
    }

    /// Which key opens a batch of the location view's store with this key
    /// id (`Engine::view`; the store holds none in a format-3 vault).
    fn key_for_id(&self, id: &str) -> Option<SecretKey> {
        match id {
            KEY_REPLICA if !self.vault.member => {
                Some(replica::replica_key(self.root_key(), &self.vault.vault_id))
            }
            id if !self.vault.member && id.starts_with(KEY_LEDGER) => self.ledger_key_for(id),
            _ => None,
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
            bail!("{}", crate::format_mismatch(vault.format_version));
        }
        util::private_home(home)?;
        // Read before the state: a writer that comes after is noticed.
        let home_generation = home_lock::read_generation(home);
        let keys = Keys::load(home, passphrase, &vault.vault_id, &vault.device_id)?;
        let keyring = Keyring::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let epochs = membership::VaultEpochs::load(home, &keys, &vault.vault_id, &vault.device_id)?;
        let removal = util::read_json(&home.join("removed.json")).ok();
        let clock: Clock = util::read_json_or_default(&home.join("clock.json"))?;
        let mut engine = Engine {
            peers: None,
            snapshot_sink: None,
            early_publish: EarlyPublish::default(),
            pack_target_for_tests: None,
            pack_write_hook: None,
            pack_caches: Default::default(),
            prefetched: HashMap::new(),
            local_rules: None,
            fetch_stats: Default::default(),
            unlocked: BTreeMap::new(),
            config: Config::load(home)?,
            ledger: LedgerStore::open(&home.join("state").join("f2-ledger"))?,
            f3: ledger3_ops::Core3::open(home, &vault.vault_id)?,
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
            health: health::Health::new(home),
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
            home_held: false,
            home_generation,
        };
        // The membership as this device last read it (no storage is read).
        if let Err(e) = engine.load_members3_local() {
            log::warn!("membership records kept here could not be read: {e:#}");
        }
        let (pending, pending_lost) = ledger_upkeep::load_deferred(home);
        engine.pending = pending;
        let (pending3, pending3_lost) = ledger_upkeep::load_pending3(home);
        if !pending3.is_empty() && engine.pending3_already_sealed(&pending3) {
            // The batch was sealed and the process died before the file went.
            let _ = ledger_upkeep::write_pending3(home, &[]);
        } else {
            engine.f3.pending = pending3;
        }
        engine.ledger_alarm =
            ledger_recovery::Alarm::at_open(&engine, pending_lost || pending3_lost);
        if engine.ledger_alarm.fork_marked() {
            // A real fork was found earlier: this identity signs nothing more.
            engine.forked_self = true;
        }
        // Command-line runs use the peers of the directory saved here
        // (accepted peer records; no storage is asked while opening), over
        // TLS on TCP only; a sync reads the storages' records first. The
        // service adds LAN peers and the QUIC node.
        if engine.config.p2p.enabled {
            if let Some(p) = engine.p2p_peers_local() {
                engine.set_peers(Some(std::sync::Arc::new(p)));
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
        // A storage marked down is tried again by the next operation
        // (unless it rests: `health`).
        self.health.end_run();
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

    /// `inner` with its block objects in packs (format 2, `crate::packs`):
    /// 64 MiB on hot, local, pool and transferrer storages, 256 MiB on cold
    /// ones.
    pub(crate) fn pack_store(
        &self,
        spec: &StorageSpec,
        inner: Box<dyn Storage>,
    ) -> crate::packs::PackStore {
        // Reads find blocks at the places the folders' block maps give
        // (format 3: no pack indexes, no tombstone lists).
        self.ensure_tables();
        let target = if spec.is_cold() {
            crate::packs::COLD_TARGET
        } else {
            self.pack_target_for_tests
                .unwrap_or(crate::packs::HOT_TARGET)
        };
        crate::packs::PackStore::new(inner, &self.pack_caches, target)
    }

    fn open_spec_fresh(&self, spec: &StorageSpec) -> Result<Box<dyn Storage>> {
        let kind = match spec {
            StorageSpec::LocalDir { .. } => "local",
            StorageSpec::S3 { .. } => "s3",
            StorageSpec::Rclone { .. } => "rclone",
            StorageSpec::Pool { .. } => "pool",
        };
        let inner: Box<dyn Storage> = if let StorageSpec::Pool { .. } = spec {
            Box::new(self.open_pool(spec)?)
        } else {
            let store = self.secret_store()?;
            let options = crate::storage::OpenOptions {
                conditional_writes: self.config.conditional_writes.get(spec.name()).copied(),
            };
            spec.open_with_options(&|r| store.secrets.get(r).cloned(), &options)?
        };
        let backend: Box<dyn Storage> = Box::new(self.pack_store(spec, inner));
        let backend: Box<dyn Storage> = match &self.pack_write_hook {
            Some(hook) => Box::new(crate::storage::HookedStorage::new(backend, hook.clone())),
            None => backend,
        };
        let backend: Box<dyn Storage> = Box::new(crate::storage::LoggedStorage::new(backend, kind));
        let backend: Box<dyn Storage> = match &self.storage_calls {
            Some(calls) => Box::new(crate::storage::CountingStorage::new(backend, calls.clone())),
            None => backend,
        };
        // Outermost: a storage marked down answers at once, uncounted.
        Ok(Box::new(health::HealthStorage::new(
            backend,
            self.health.clone(),
        )))
    }

    /// Tests: write packs of `bytes` on hot storages instead of 64 MiB
    /// (`None`: the default), so a test pushes several packs with little
    /// data.
    #[doc(hidden)]
    pub fn set_pack_target_for_tests(&mut self, bytes: Option<usize>) {
        self.pack_target_for_tests = bytes;
        self.forget_storages();
    }

    /// Tests: run `hook` with the storage's name before every pack this
    /// engine writes (a slow or failing storage); an error fails the write.
    #[doc(hidden)]
    pub fn set_pack_write_hook(&mut self, hook: Option<crate::storage::PackWriteHook>) {
        self.pack_write_hook = hook;
        self.forget_storages();
    }

    /// How often a long push with peers publishes what it stored so far.
    pub fn set_early_publish(&mut self, every: EarlyPublish) {
        self.early_publish = every;
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
            marker_key: self.root_key().derive("disk-pool-marker", &[]),
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
        self.add_storage_checked(spec, secret, true)
    }

    /// `add_storage_with_secret` without the organization's policy check:
    /// for joining, where the storages come from the device that approved
    /// or paired this one.
    fn add_storage_internal(&mut self, spec: StorageSpec, secret: Option<String>) -> Result<()> {
        self.add_storage_checked(spec, secret, false)
    }

    fn add_storage_checked(
        &mut self,
        spec: StorageSpec,
        secret: Option<String>,
        refuse_duplicates: bool,
    ) -> Result<()> {
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
        let mut stored_secret: Option<String> = None;
        if let Some(secret) = secret {
            let reference = match &spec {
                StorageSpec::S3 {
                    secret_ref, name, ..
                } if !secret_ref.is_empty() => secret_ref.clone(),
                _ => spec.name().to_string(),
            };
            let mut store = self.secret_store()?;
            stored_secret = Some(reference.clone());
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
        if refuse_duplicates {
            if let Err(e) = self.refuse_duplicate_storage(&spec, backend.as_ref()) {
                self.forget_storages();
                // The credentials given with it are not kept.
                if let (Some(r), Ok(mut store)) = (stored_secret, self.secret_store()) {
                    store.secrets.remove(&r);
                    let _ = store.save(
                        &self.home,
                        &self.keys,
                        &self.vault.vault_id,
                        &self.vault.device_id,
                    );
                }
                return Err(e);
            }
        }
        let meta = VaultMeta {
            format_version: crate::FORMAT_VERSION,
            vault_id: self.vault.vault_id.clone(),
            created_utc: self.vault.created_utc,
        };
        if let Some(existing) = backend.get(VaultMeta::STORAGE_KEY)? {
            let existing: VaultMeta = serde_json::from_slice(&existing)?;
            if existing.format_version != crate::FORMAT_VERSION {
                self.forget_storages();
                bail!(
                    "{}",
                    crate::storage_holds_other_format(spec.name(), existing.format_version)
                );
            }
            if existing.vault_id != meta.vault_id {
                bail!("storage {} belongs to another vault", spec.name());
            }
        } else {
            backend.put_if_absent(VaultMeta::STORAGE_KEY, &serde_json::to_vec_pretty(&meta)?)?;
        }
        let name = spec.name().to_string();
        let carrier = spec.is_carrier();
        self.config.storages.push(spec);
        self.config.save(&self.home)?;
        // The membership records read so far go to the new storage too: a
        // device that reaches the vault only through it finds them there.
        if !carrier {
            self.copy_records(backend.as_ref())?;
        }
        // This device's record and the batches signed before the first
        // storage existed (its enrolment) go out now.
        self.publish_registry()?;
        if !self.vault.member {
            self.push_own_batches()?;
        }
        // The vault's records reach the new storage too (a device that
        // reads only it finds them), and the other devices learn its name
        // and identity (a `storage-names` record).
        if let Err(e) = self.copy_records_to(&name) {
            log::warn!(storage = name.as_str(); "records not copied to the new storage: {e:#}");
        }
        self.publish_storage_names();
        Ok(())
    }

    pub fn storages(&self) -> &[StorageSpec] {
        &self.config.storages
    }

    /// What removing a storage takes: every block on it must keep enough
    /// copies on the other storages (at least one, or the folder policy's
    /// minimum and per-place rules), so the packs whose blocks fall short
    /// of that are copied whole first (`storages3::drain`, as a drain
    /// works them out).
    pub fn plan_storage_removal(&self, name: &str) -> Result<StorageRemovalPlan> {
        if !self.config.storages.iter().any(|s| s.name() == name) {
            bail!("unknown storage {name}");
        }
        let mut plan = StorageRemovalPlan {
            storage: name.to_string(),
            ..Default::default()
        };
        // Storages being drained are leaving too: they do not receive copies.
        let closed = self.closed_storages();
        if !self
            .config
            .storages
            .iter()
            .any(|s| s.name() != name && !s.is_carrier() && !closed.contains(s.name()))
        {
            plan.blocked = Some(format!(
                "{name} is the last storage of this vault: add another storage first"
            ));
            return Ok(plan);
        }
        let view = self.view3()?;
        let gate = self.quota_gate(&view);
        let work = self.drain_work_for_removal(name, &gate)?;
        let mut targets_used = BTreeSet::new();
        for item in &work.items {
            plan.blocks += item.needed_blocks;
            if let Some(why) = &item.shortfall {
                plan.blocked.get_or_insert_with(|| why.clone());
                continue;
            }
            if item.copy_to.is_empty() {
                plan.blocks_ok += item.needed_blocks;
            }
            let bytes = crate::ledger3::events::class_bytes(item.class).unwrap_or(0);
            for t in &item.copy_to {
                targets_used.insert(t.clone());
                plan.bytes_to_copy += bytes;
                plan.copies.push(PlannedCopy {
                    pack: hex::encode(item.pack),
                    target: t.clone(),
                    bytes,
                });
            }
        }
        plan.targets = targets_used.into_iter().collect();
        Ok(plan)
    }

    /// Remove a storage: copy what the plan says (whole packs, checked
    /// against their ids), check again, record the retirement in the ledger
    /// so no device counts it as a copy any more, and drop it from this
    /// device. With `delete_data` everything Varsto wrote there is deleted
    /// afterwards.
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
        if !plan.copies.is_empty() {
            let copied = self.copy_off_for_removal(name)?;
            report.blocks_copied = copied.0;
            report.bytes_copied = copied.1;
            let again = self.plan_storage_removal(name)?;
            if again.blocked.is_some() || !again.copies.is_empty() {
                bail!("{name} still holds blocks without enough copies elsewhere; nothing was removed");
            }
        }
        self.pending.push(Event::StorageRetired {
            storage: name.to_string(),
        });
        self.commit_batch()?;
        if delete_data {
            let source = self.open_storage(name).with_context(|| {
                format!("{name} must be reachable to delete what Varsto wrote there")
            })?;
            // Everything Varsto wrote there (block names are virtual).
            let keys: Vec<String> = source
                .list("")?
                .into_iter()
                .filter(|k| !k.starts_with("chunks/"))
                .collect();
            let task = activity::start(
                activity::STORAGE_REMOVAL,
                name,
                keys.len() as u64,
                activity::Unit::Items,
            );
            task.set_phase("delete");
            for key in keys {
                task.advance(1);
                source.delete(&key)?;
                report.objects_deleted += 1;
            }
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
            // Down in this run (`health`): left out, not waited for again.
            if self.storage_down(spec.name()) {
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
        // The name is checked against the folders this device knows, and
        // below against the records as read now (the storages when they
        // answer): adding a folder does not wait for a storage.
        self.ensure_unique_folder_name_known(name)?;
        crate::names::check_display_name(name)?;
        fs::create_dir_all(path)?;
        // Format 3: the folder record (this device the owner), a random K9₀
        // granted to this device, and the escrow under the recovery key when
        // this session holds it (else `status` warns until it is written).
        // They are kept on this device first; a storage that does not
        // answer gets them from the outbox later.
        let k1 = self.f3.recovery.clone();
        let wanted = name.trim().to_lowercase();
        let id = self
            .with_enrolled_at(members3::Reach::StoragesOrLocal, |m| {
                if let Some(st) = m
                    .registry
                    .folders
                    .values()
                    .find(|s| !s.is_removed() && s.name.to_lowercase() == wanted)
                {
                    bail!(
                        "the vault already has a folder named {}: attach that one, or choose another name",
                        st.name
                    );
                }
                m.create_folder(name, BTreeMap::new(), k1.as_ref())
            })?
            .ok_or_else(|| {
                anyhow!("add a storage first: a folder's records live on the vault's storages")
            })?;
        let granted = self
            .f3
            .members
            .granted
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("the grant of the new folder did not open here"))?;
        let k9_0 = granted
            .epochs
            .get(&0)
            .ok_or_else(|| anyhow!("the grant of the new folder has no first epoch"))?;
        let rec = FolderRecord {
            folder_id: FolderId::from_bytes(&id),
            name: name.to_string(),
            key_hex: k9_0.to_hex(),
            k11_hex: granted.k11.to_hex(),
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
            self.exclusive(|e| e.attach_folder_inner(name_or_id, path, selective))
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
        // A grant may have arrived since the membership was read here (an
        // owner approved this device's request a moment ago).
        let keyless = |e: &Engine| {
            e.keyring.find(name_or_id).is_none_or(|r| {
                !r.is_strongroom() && r.key_hex.is_empty() && r.epoch_keys.is_empty()
            })
        };
        if keyless(self) && !self.vault.member {
            // This device's copy of the records first (a grant the last
            // sync brought); the storages only when that has no key.
            if let Err(e) = self.load_members3_local() {
                log::debug!("membership not read from this device's copy: {e:#}");
            }
            if keyless(self) {
                let _ = self.refresh_members();
            }
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
        // Format 3: a folder opens only with a grant to this device.
        if !rec.is_strongroom() {
            self.folder_keys3(&rec)?;
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
        self.ensure_unique_folder_name_known(name)
    }

    /// `ensure_unique_folder_name` against the folders this device knows,
    /// without reading the storages.
    fn ensure_unique_folder_name_known(&self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("a folder needs a name");
        }
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

    /// Stop syncing a folder on this device. Its files stay where they are;
    /// the sync state goes, so attaching it again later starts clean instead
    /// of reading missing files as deletions.
    pub fn detach_folder(&mut self, name: &str) -> Result<()> {
        crate::logged_op_plain!("detach folder", name, {
            self.exclusive(|e| e.detach_folder_inner(name))
        })
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
    /// Format 3: an owner's folder record with the `removed` stamp (every
    /// device stops syncing the folder when it reads it); with `purge` the
    /// folder's packs are dropped in one batch and deleted, then its
    /// records.
    fn remove_record(&mut self, rec: &FolderRecord, purge: bool) -> Result<u64> {
        let id = members3::bin(&rec.folder_id)?;
        let removed_utc = util::now_utc();
        self.with_enrolled(|m| m.remove_folder(&id))?
            .ok_or_else(|| anyhow!("this device has no storage to publish the removal to"))?;
        let mut deleted = 0u64;
        if purge {
            let (packs, records) = self.purge_folder(&id, &rec.name)?;
            deleted = packs + records;
        }
        self.forget_folder(&rec.folder_id, removed_utc)?;
        if purge {
            self.forget_trash(&rec.folder_id);
        }
        Ok(deleted)
    }

    /// Delete what a removed folder left on this device's storages: its
    /// packs (dropped in one batch first) and its records (manifests, maps,
    /// trash, access, notes, thumbnails, snapshots, Strongroom key wraps).
    /// Returns (pack objects deleted, records deleted).
    pub(super) fn purge_folder(
        &mut self,
        id: &crate::record::Id16,
        name: &str,
    ) -> Result<(u64, u64)> {
        let view = self.view3()?;
        let packs: Vec<[u8; 32]> = view
            .packs
            .keys()
            .filter(|p| view.pack_folder(p) == Some(*id))
            .copied()
            .collect();
        let storages = self.open_storages(true)?;
        // The folder's records on each storage, listed first so that the
        // task counts them too.
        let hex_id = hex::encode(id);
        let mut record_keys: Vec<(usize, String)> = Vec::new();
        for (i, (spec, backend)) in storages.iter().enumerate() {
            if spec.is_data_only() {
                continue;
            }
            for prefix in [
                "manifests",
                "maps",
                "trash",
                "access",
                "notes",
                "thumbs",
                "snapshots",
                "vault/strongroom",
            ] {
                for key in backend.list(&format!("{prefix}/{hex_id}/"))? {
                    record_keys.push((i, key));
                }
            }
        }
        let task = activity::start(
            activity::FOLDER_PURGE,
            name,
            (packs.len() * storages.len() + record_keys.len()) as u64,
            activity::Unit::Items,
        );
        // The drops are recorded and pushed before anything is deleted.
        let mut gone = Vec::new();
        for (spec, backend) in &storages {
            for p in &packs {
                let key = crate::packs::pack_key(&hex::encode(p));
                if backend.exists(&key).unwrap_or(false) {
                    self.f3
                        .pending
                        .push(crate::ledger3::events::Event::PackDropped(
                            crate::ledger3::events::PackOn {
                                storage: spec.name().to_string(),
                                pack: *p,
                            },
                        ));
                    gone.push((spec.name().to_string(), key));
                }
            }
        }
        self.commit3()?;
        let (mut objects, mut records) = (0u64, 0u64);
        for (name, key) in gone {
            if let Some((_, backend)) = storages.iter().find(|(s, _)| s.name() == name) {
                backend.delete(&key)?;
                objects += 1;
            }
            task.advance(1);
        }
        for (i, key) in record_keys {
            storages[i].1.delete(&key)?;
            records += 1;
            task.advance(1);
        }
        Ok((objects, records))
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
            // Format 3: a folder this device has no grant for is known by
            // name only.
            if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
                self.folder_keys3(rec)?;
            }
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

    /// Publish this device's device record when the registry lacks it, and
    /// read the membership (format 3, `members3`).
    fn publish_registry(&mut self) -> Result<()> {
        self.refresh_members()
    }

    /// Look for the device records other devices published since (a device
    /// that just joined), without a sync: one listing per storage. True when
    /// the vault's device list changed. The service asks every few seconds
    /// after something that may have added a device and backs off.
    pub fn refresh_devices(&mut self) -> Result<bool> {
        let before = self.devices.devices.len();
        self.pull_registry()?;
        Ok(self.devices.devices.len() != before)
    }

    /// Read the membership records: devices, folders, grants to this
    /// device, policies, placement, storage settings, Strongroom records
    /// and device details (format 3, `members3`).
    fn pull_registry(&mut self) -> Result<()> {
        self.refresh_members()
    }

    // ----- ledger mailbox ----------------------------------------------------

    /// Seal the events recorded since the last batch into this device's
    /// next format-3 batch and push it (`ledger3_ops::commit3`).
    fn commit_batch(&mut self) -> Result<Option<u64>> {
        self.commit3()
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
                            chunking: 0,
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
            let params = self.chunker_for(size, &fk);
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
                        let ct = crate::chunk_seal::seal_chunk(
                            &fk,
                            &self.vault.vault_id,
                            &chunk_id,
                            fk.epoch,
                            &chunk,
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
                    chunking: self.chunking_mark(),
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
                    chunking: 0,
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

    /// `push` after a change that is already saved on this device. When the
    /// upload fails (a storage is down, no network), the change stays and the
    /// report says "upload pending"; the next sync or push uploads it.
    /// Errors that mean nothing could be published at all (removed device,
    /// forked ledger, paused folder) are still returned.
    fn push_after_local(&mut self, folder: &str) -> Result<PushReport> {
        match self.push(folder) {
            Ok(r) => Ok(r),
            Err(e) => {
                if self.ensure_active().is_err()
                    || self.ensure_ledger_writable().is_err()
                    || self.forked_self
                    || folder_safety::paused_error(&e).is_some()
                {
                    return Err(e);
                }
                log::warn!("{folder}: saved here, upload pending: {e:#}");
                Ok(PushReport {
                    folder: folder.to_string(),
                    upload_pending: Some(format!("{e:#}")),
                    ..Default::default()
                })
            }
        }
    }

    /// `push` with the scan a pull of the same folder just made, so a sync
    /// walks the folder once (`sync_folders`).
    fn push_with_scan(&mut self, folder: &str, scan: Option<ScanOutcome>) -> Result<PushReport> {
        let out = crate::logged_op!("push", folder, {
            self.exclusive(|e| e.push_inner(folder, scan))
        });
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
        let folder = members3::bin(&rec.folder_id)?;
        let epoch = self.folder_keys(&rec)?.epoch;
        // Unpublished changes, with peers: the file list goes out before
        // the upload (spec section 77.23). The other devices fetch the new
        // files from this device peer to peer (it holds them: `held`) while
        // the storages receive their copies; a large file would otherwise
        // reach them only once its whole upload is done. A device that
        // cannot reach this one finds the blocks on the storages later.
        // Without peers nobody could fetch from here before the upload, and
        // the push keeps to one map record and one batch.
        if self.has_peers() && Manifest::files_hash(&state.files) != state.published_hash {
            if let Some(seq) = self.publish_manifest(&folder, epoch, &state)? {
                report.manifest_seq = Some(seq);
                state.published_seq = seq;
                state.published_hash = Manifest::files_hash(&state.files);
                let _ = self.history_from_own(&rec, &state, util::now_utc());
                // Now, not at the end of the push: the other devices learn
                // of the new record from this batch.
                self.flush_pending()?;
                self.save_state(&rec.folder_id, &state)?;
                self.refresh_snapshot();
                self.notify_peers_changed();
                log::debug!("push {}: file list published before the upload", rec.name);
            }
        }
        // A folder added with many pictures shows its first thumbnails
        // before the (possibly hours long) upload, not only after it. Best
        // effort: a storage that cannot take the thumbnail record never
        // holds back the upload (the pictures are tried again next push).
        report.thumbnails = self
            .make_thumbnails(
                &rec,
                &root,
                &mut state,
                THUMBS_EARLY_PER_PASS,
                THUMBS_EARLY_TIME,
            )
            .unwrap_or_else(|e| {
                log::warn!("push {}: thumbnails not published: {e:#}", rec.name);
                0
            });
        // One action (design section 3, "Writer"): packs, then one map
        // delta listing their members, then the manifest delta and the trash
        // record, then one batch with `pack_stored` for every (pack,
        // storage) and `record_published` for every record. A long upload
        // with peers publishes the packs stored so far on the way
        // (`EarlyPublish`); `written` is what is left.
        let written = self.upload_missing(&rec, &root, &state, &mut report)?;
        let view3 = self.view3()?;
        self.publish_map3(&folder, epoch, &written, &view3)?;
        report.thumbnails += self
            .make_thumbnails(&rec, &root, &mut state, THUMBS_PER_PASS, THUMBS_PASS_TIME)
            .unwrap_or_else(|e| {
                log::warn!("push {}: thumbnails not published: {e:#}", rec.name);
                0
            });
        if let Some(seq) = self.publish_manifest(&folder, epoch, &state)? {
            report.manifest_seq = Some(seq);
            state.published_seq = seq;
            state.published_hash = Manifest::files_hash(&state.files);
            // This device's own versions enter its change history as published.
            let _ = self.history_from_own(&rec, &state, util::now_utc());
        }
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
    /// Write the blocks of the current files that a target storage lacks
    /// (no live place of the block's object on it, design section 3,
    /// "Dedup for a writer") into packs, one per target set, and return the
    /// packs written for the map record of the push. Files whose blocks are
    /// all held are skipped without reading them; the others are chunked
    /// again (chunking and encryption are deterministic, so the objects are
    /// identical).
    fn upload_missing(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &FolderState,
        report: &mut PushReport,
    ) -> Result<Vec<crate::blockmap::WrittenPack>> {
        let storages: OpenStorages = self.open_storages(true)?;
        if storages.is_empty() {
            return Ok(Vec::new());
        }
        let view3 = self.view3()?;
        let folder3 = members3::bin(&rec.folder_id)?;
        let table = self.table3(&folder3)?;
        // Transferrers (F-048) take what no other device holds yet, or with
        // destinations what one of them still lacks: "holds" is the `held`
        // flag of the devices' manifests (design section 4).
        let held = self.load_manifests(&folder3).held_index();
        let me3 = self.me3();
        let configured: BTreeMap<String, Vec<crate::record::Id16>> = self
            .config
            .carrier_for
            .iter()
            .map(|(n, ds)| {
                (
                    n.clone(),
                    ds.iter().filter_map(|d| members3::bin(d).ok()).collect(),
                )
            })
            .collect();
        let destinations = crate::storages3::carrier_destinations_held(&configured, &held);
        let is_backup = rec.is_backup();
        let fk = self.folder_keys(rec)?;
        let folder_id = rec.folder_id.clone();
        let targets = self.write_targets(rec);
        // Storages with a quota take what fits (the size classes of the
        // packs claimed there count); the rest goes to the other storages,
        // or waits here for the next push.
        let gate = self.quota_gate(&view3);
        // (chunk id, plaintext length, epoch) of every object written.
        let mut info: HashMap<crate::ledger3::ObjectBin, crate::blockmap::ChunkInfo> =
            HashMap::new();
        let missing_on = |cref: &ChunkRef| -> Vec<String> {
            let standing = {
                let t = table.read().unwrap_or_else(|e| e.into_inner());
                data_moves::BlockStanding::of(&view3, &t, &cref.object)
            };
            let object = crate::storages3::object_bin(&cref.object).unwrap_or_default();
            storages
                .iter()
                .filter(|(spec, _)| !standing.copies.contains(spec.name()))
                // A backup's blocks never go to a transferrer (no device
                // takes them from there).
                .filter(|(spec, _)| {
                    !spec.is_carrier()
                        || !is_backup
                            && crate::storages3::carrier_wants(
                                &held,
                                &object,
                                &me3,
                                destinations.get(spec.name()).map(|v| v.as_slice()),
                            )
                })
                // The folder's placement; blocks moved away stay away.
                .filter(|(spec, _)| targets.wants(spec.name(), Some(&standing)))
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
        // to a few uploader threads. Every block goes into a pack
        // (`crate::packs`): each storage collects the blocks it needs until
        // a pack's worth (64 MiB, 256 MiB on cold storages) is together and
        // then writes them as one work item, so storages are written side by
        // side and a storage sees pack sizes only. The queue is bounded, and
        // so are the bytes held (`upload_budget`): when the budget is used
        // up, what each storage collected goes out as it is.
        let (job_tx, job_rx) =
            std::sync::mpsc::sync_channel::<(Vec<usize>, UploadBatch)>(UPLOAD_QUEUE);
        let job_rx = std::sync::Mutex::new(job_rx);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<UploadDone>();
        let storages_ref = &storages;
        let mut first_error: Option<anyhow::Error> = None;
        let budget = (std::sync::Mutex::new(0u64), std::sync::Condvar::new());
        let budget_ref = &budget;
        let limit = upload_budget(storages.iter().map(|(_, b)| b.pack_target().max(1 << 20)));
        // With peers, the packs stored so far are published on the way.
        let mut early = self.has_peers().then(|| Cadence::new(self.early_publish));
        std::thread::scope(|s| -> Result<()> {
            // Owned by this closure: however it returns (an error reading a
            // file included), the sender goes and the uploaders stop.
            let job_tx = job_tx;
            for _ in 0..UPLOADERS.max(storages.len()) {
                let (job_rx, done_tx) = (&job_rx, done_tx.clone());
                s.spawn(move || loop {
                    let (set, batch) = match job_rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => break,
                    };
                    let backends: Vec<&dyn Storage> =
                        set.iter().map(|&i| storages_ref[i].1.as_ref()).collect();
                    let outcomes = write_to_set(&backends, &batch.jobs);
                    for (&i, outcomes) in set.iter().zip(outcomes) {
                        let spec = &storages_ref[i].0;
                        for (job, outcome) in batch.jobs.iter().zip(outcomes) {
                            let _ = done_tx.send(UploadDone {
                                storage: spec.name().to_string(),
                                chunk: job.chunk.clone(),
                                object: job.object.clone(),
                                size: job.ct.len() as u64,
                                outcome,
                            });
                        }
                    }
                    *budget_ref.0.lock().unwrap() -= batch.held;
                    budget_ref.1.notify_all();
                });
            }
            drop(done_tx);
            // What each target set (the storages of one size-class range a
            // block goes to, `target_sets`) collected for its next pack: its
            // blocks and their bytes. One pack is built per set and written
            // to all of its storages under one id.
            type Collected = BTreeMap<Vec<usize>, (Vec<std::sync::Arc<UploadJob>>, u64)>;
            let mut collected: Collected = BTreeMap::new();
            let send_to = |collected: &mut Collected, set: &Vec<usize>| -> bool {
                let Some((jobs, bytes)) = collected.remove(set) else {
                    return true;
                };
                let held = bytes * set.len() as u64;
                jobs.is_empty()
                    || job_tx
                        .send((set.clone(), UploadBatch { jobs, held }))
                        .is_ok()
            };
            let send_full = |collected: &mut Collected, set: &Vec<usize>, target: u64| -> bool {
                let Some((jobs, bytes)) = collected.get_mut(set) else {
                    return true;
                };
                let picked = take_full_pack(jobs, target);
                let sent: u64 = picked.iter().map(|j| j.ct.len() as u64).sum();
                *bytes -= sent;
                picked.is_empty()
                    || job_tx
                        .send((
                            set.clone(),
                            UploadBatch {
                                jobs: picked,
                                held: sent * set.len() as u64,
                            },
                        ))
                        .is_ok()
            };
            let send_all = |collected: &mut Collected| -> bool {
                let sets: Vec<Vec<usize>> = collected.keys().cloned().collect();
                sets.iter().all(|set| send_to(collected, set))
            };
            // `None` sends everything collected (at the end).
            let mut send =
                |me: &mut Self, report: &mut PushReport, job: Option<UploadJob>| -> bool {
                    while let Ok(d) = done_rx.try_recv() {
                        apply_upload(me, &folder_id, d, report, &mut first_error, &gate);
                    }
                    if first_error.is_some() {
                        return false;
                    }
                    let Some(job) = job else {
                        return send_all(&mut collected);
                    };
                    let to: Vec<usize> = storages_ref
                        .iter()
                        .enumerate()
                        .filter(|(_, (spec, _))| job.targets.iter().any(|t| t == spec.name()))
                        .map(|(i, _)| i)
                        .collect();
                    if to.is_empty() {
                        return true;
                    }
                    let need = job.ct.len() as u64 * to.len() as u64;
                    let over = {
                        let used = budget_ref.0.lock().unwrap();
                        *used > 0 && *used + need > limit
                    };
                    if over {
                        // Hand over what is collected, then wait for room.
                        if !send_all(&mut collected) {
                            return false;
                        }
                        let mut used = budget_ref.0.lock().unwrap();
                        while *used > 0 && *used + need > limit {
                            used = budget_ref.1.wait(used).unwrap();
                        }
                    }
                    *budget_ref.0.lock().unwrap() += need;
                    let job = std::sync::Arc::new(job);
                    let size = job.ct.len() as u64;
                    for set in target_sets(&to, |i| storages_ref[i].1.pack_target()) {
                        let target = storages_ref[set[0]].1.pack_target().max(1) as u64;
                        let e = collected.entry(set.clone()).or_default();
                        e.0.push(job.clone());
                        e.1 += size;
                        // Once a pack's worth and one more block are
                        // collected, a pack is filled from the buffer
                        // (first fit decreasing) and sent; the rest waits
                        // for the next one. Only the last pack of the push
                        // is not full. (A block larger than the pack size
                        // gets a pack of its own.)
                        if e.1 >= target + crate::packs::MAX_OBJECT.min(target)
                            && !send_full(&mut collected, &set, target)
                        {
                            return false;
                        }
                    }
                    true
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
                        if let (Ok(o), Ok(c)) = (
                            crate::storages3::object_bin(&expected.object),
                            crate::storages3::object_bin(&expected.chunk),
                        ) {
                            info.insert(o, (c, expected.size as u32, expected.epoch));
                        }
                        let sent = ct.len() as u64;
                        let job = UploadJob {
                            targets,
                            chunk: expected.chunk.clone(),
                            object: expected.object.clone(),
                            ct,
                        };
                        if !send(self, report, Some(job)) {
                            break 'files;
                        }
                        if let Some(c) = early.as_mut() {
                            if c.add(sent) {
                                self.publish_stored_so_far(
                                    &rec.name, &folder3, fk.epoch, &storages, &info, c,
                                );
                            }
                        }
                    }
                    continue;
                }
                let disk = self.disk_of(root, state, &file.path);
                let Ok(handle) = fs::File::open(&disk) else {
                    continue;
                };
                let progress = crate::progress::Transfer::upload(&rec.name, &file.path, file.size);
                for (index, chunk) in Chunker::new(
                    std::io::BufReader::new(handle),
                    self.chunker_for(file.size, &fk),
                )?
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
                    let ct = crate::chunk_seal::seal_chunk(
                        &fk,
                        &self.vault.vault_id,
                        &chunk_id,
                        expected.epoch,
                        &chunk,
                    )?;
                    let object = ObjectName::from_bytes(&crypto::hash(&ct));
                    let targets: Vec<String> = targets
                        .into_iter()
                        .filter(|t| gate.take(t, ct.len() as u64))
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    if let (Ok(o), Ok(c)) = (
                        crate::storages3::object_bin(&object),
                        crate::storages3::object_bin(&chunk_id),
                    ) {
                        info.insert(o, (c, expected.size as u32, expected.epoch));
                    }
                    let sent = ct.len() as u64;
                    let job = UploadJob {
                        targets,
                        chunk: chunk_id,
                        object,
                        ct,
                    };
                    if !send(self, report, Some(job)) {
                        break 'files;
                    }
                    if let Some(c) = early.as_mut() {
                        if c.add(sent) {
                            self.publish_stored_so_far(
                                &rec.name, &folder3, fk.epoch, &storages, &info, c,
                            );
                        }
                    }
                }
            }
            send(self, report, None);
            drop(send);
            // A push that stopped (a write failed) leaves blocks it took
            // room for and never handed over: that room is given back.
            for (set, (jobs, _)) in &collected {
                for j in jobs {
                    for &i in set {
                        gate.give_back(storages_ref[i].0.name(), j.ct.len() as u64);
                    }
                }
            }
            drop(job_tx);
            // The uploaders finish what they hold (up to the budget, which
            // can take long on a slow storage): the packs they store are
            // published on the way as well.
            loop {
                match done_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                    Ok(d) => apply_upload(self, &folder_id, d, report, &mut first_error, &gate),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if let Some(c) = early.as_mut() {
                    if c.add(0) {
                        self.publish_stored_so_far(
                            &rec.name, &folder3, fk.epoch, &storages, &info, c,
                        );
                    }
                }
            }
            Ok(())
        })?;
        for msg in gate.refusals() {
            if !report.storages_full.contains(&msg) {
                report.storages_full.push(msg);
            }
        }
        // The packs written (and not published on the way), for the map
        // record of this push.
        let per_storage = stored_packs(&storages, &info);
        if let Some(e) = first_error {
            // Packs written before the failure are claimed by nobody: the
            // next push writes their blocks again and garbage collection
            // takes the orphans after 7 days (design section 3).
            return Err(e);
        }
        crate::blockmap::written_packs(&per_storage, &|o| info.get(o).copied())
    }

    // ----- pull ---------------------------------------------------------------

    pub fn pull(&mut self, folder: &str) -> Result<PullReport> {
        let out = crate::logged_op!("pull", folder, { self.exclusive(|e| e.pull_inner(folder)) });
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

        // Format 3: the map and manifest records the ledger announced past
        // what was applied, accepted by the record rule (a viewer's or an
        // untrusted device's manifests never count); the paths each writer
        // changed are merged.
        let folder3 = members3::bin(&rec.folder_id)?;
        let view3 = self.view3()?;
        let (manifests, mut changed) = self.pull_folder_records(&folder3, &view3)?;
        let me3 = self.me3();
        // A writer whose view is past what this folder state applied (a
        // state that starts clean after `folder detach`, while the views
        // read before stay; a pull stopped before its state was saved)
        // counts with every path of its view, not only the paths its last
        // records changed.
        for (dev3, v) in &manifests.views {
            if *dev3 == me3 {
                continue;
            }
            let applied = state.last_seen.get(&DeviceId::from_bytes(dev3)).copied();
            if applied.is_none_or(|seq| seq < v.seq) {
                changed
                    .entry(*dev3)
                    .or_default()
                    .extend(v.files.keys().cloned());
            }
        }
        // Change history (`changes_ops`): started once from what is held,
        // then fed by the paths every writer's records changed. Never in
        // the way of syncing.
        {
            let mut hist = self.open_history(&rec.folder_id);
            let _ = self.history_backfill(&mut hist, &state, &manifests);
            for (dev3, paths) in &changed {
                if *dev3 == me3 {
                    continue;
                }
                if let Some(v) = manifests.views.get(dev3) {
                    let _ = self.history_from_view(&mut hist, dev3, v, Some(paths));
                }
            }
            let _ = hist.save();
        }
        for (dev3, paths) in changed {
            if dev3 == me3 {
                continue;
            }
            let Some(v) = manifests.views.get(&dev3) else {
                continue;
            };
            let dev = DeviceId::from_bytes(&dev3);
            let states: Vec<(String, FileState)> = paths
                .iter()
                .filter_map(|p| v.files.get(p))
                .map(|e| (e.path.clone(), e.to_state()))
                .collect();
            let mut entries: Vec<(&String, &FileState)> =
                states.iter().map(|(p, f)| (p, f)).collect();
            entries.sort_by(|a, b| b.1.mtime.cmp(&a.1.mtime).then(a.0.cmp(b.0)));
            if send_only {
                for (path, remote) in &entries {
                    if !matches!(
                        manifest::merge(state.files.get(*path), remote),
                        Merge::KeepLocal
                    ) {
                        state.not_applied.insert((*path).clone(), (*remote).clone());
                    }
                }
                report.manifests_applied += 1;
                state.last_seen.insert(dev, v.seq);
                continue;
            }
            // Too many deletions at once: held (the writer's view stays
            // applied in the records, its changes wait for the user).
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
            state.last_seen.insert(dev, v.seq);
            self.prefetched.clear();
        }
        if encrypted_here {
            self.cache_wanted(&rec, &fk, &mut state, &storages, &mut report)?;
        }
        // Transferrers let go of what every device they carry to holds.
        self.prune_carriers(&rec)?;
        self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
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

    /// Empty the transferrers of what they delivered (F-048): a pack of the
    /// folder on a transferrer goes when every live block in it is held
    /// (the `held` flags of the manifests) by every destination that uses
    /// the folder, or, without destinations, by another device as well as
    /// this one. The drops are pushed before the packs are deleted.
    fn prune_carriers(&mut self, rec: &FolderRecord) -> Result<()> {
        let carriers: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .open_storages(true)?
            .into_iter()
            .filter(|(s, _)| s.is_carrier())
            .collect();
        if carriers.is_empty() {
            return Ok(());
        }
        let Some(table) = self.folder_table(rec)? else {
            return Ok(());
        };
        let folder = members3::bin(&rec.folder_id)?;
        let view = self.view3()?;
        let me = self.me3();
        let held = self.load_manifests(&folder).held_index();
        let need = self.carrier_destinations(&held);
        let mut deletes: Vec<(usize, Vec<crate::ledger3::PackId>)> = Vec::new();
        {
            let t = table.read().unwrap_or_else(|e| e.into_inner());
            for (i, (spec, _)) in carriers.iter().enumerate() {
                let packs = crate::storages3::delivered_packs(
                    &view,
                    &t,
                    &folder,
                    spec.name(),
                    &held,
                    &me,
                    need.get(spec.name()).map(|v| v.as_slice()),
                )?;
                if !packs.is_empty() {
                    self.f3
                        .pending
                        .extend(crate::storages3::drop_events(spec.name(), &packs));
                    deletes.push((i, packs));
                }
            }
        }
        if deletes.is_empty() {
            return Ok(());
        }
        self.commit_now()?;
        for (i, packs) in deletes {
            for p in packs {
                let _ = carriers[i]
                    .1
                    .delete(&crate::packs::pack_key(&hex::encode(p)));
            }
        }
        Ok(())
    }

    /// Per transferrer with destinations: those of them that use the
    /// folder (they published its manifest). Transferrers without
    /// destinations are absent (any device that lacks a block).
    fn carrier_destinations(
        &self,
        held: &crate::manifest3::HeldIndex,
    ) -> HashMap<String, Vec<crate::record::Id16>> {
        let configured: BTreeMap<String, Vec<crate::record::Id16>> = self
            .config
            .carrier_for
            .iter()
            .map(|(n, ds)| {
                (
                    n.clone(),
                    ds.iter().filter_map(|d| members3::bin(d).ok()).collect(),
                )
            })
            .collect();
        crate::storages3::carrier_destinations_held(&configured, held)
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
        let (tmp, tmp_file) = util::temp_beside(disk, "tmp")
            .with_context(|| format!("create a temporary file for {}", disk.display()))?;
        if let Some(log) = &self.download_log {
            log.lock().unwrap().push(file.path.clone());
        }
        let progress = crate::progress::Download::begin(&rec.name, &file.path, file.size);
        {
            let mut out = tmp_file;
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
                let (ct, from_peer) = match fetched {
                    Fetched::Got { bytes, from_peer } => {
                        if from_peer {
                            report.chunks_from_peers += 1;
                        }
                        (bytes, from_peer)
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
                let plain = match crate::chunk_seal::open_chunk(
                    fk,
                    &self.vault.vault_id,
                    &cref.chunk,
                    cref.epoch,
                    cref.size,
                    &ct,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = fs::remove_file(&tmp);
                        return Err(e);
                    }
                };
                out.write_all(&plain)?;
                progress.advance(plain.len() as u64);
                report.chunks_downloaded += 1;
                report.bytes_downloaded += plain.len() as u64;
                if from_peer {
                    report.bytes_from_peers += plain.len() as u64;
                }
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
                                let Some((path, _)) = staged(c) else {
                                    continue;
                                };
                                let bytes = fs::read(&path)?;
                                let fetched =
                                    if ObjectName::from_bytes(&crypto::hash(&bytes)) == c.object {
                                        Fetched::Got {
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
            // The mode the folder records, set on the open file before it
            // becomes visible under its name (the metadata step after the
            // rename sets it again and reports a failure).
            util::set_final_mode(&out, file.meta.as_ref().and_then(|m| m.mode));
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
        // Format 3: a live place of every block on a storage that keeps it.
        let view = self.view3()?;
        let durable: HashSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        for c in &file.chunks {
            let ok = self
                .block_copies3(&view, &rec.folder_id, &c.object)
                .iter()
                .any(|k| durable.contains(k) || k.starts_with("replica:"));
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
        // A freed file turns a folder selective, except in a send-only
        // folder (camera upload frees each file it has uploaded): it never
        // applies other devices' files, so what is kept here is not a choice.
        if !self.mount_is_selective(&rec.folder_id)
            && self.mount_mode(&rec.folder_id) != crate::vault::FolderMode::SendOnly
        {
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
        // Strictly newer than what is known (two changes in one second), so
        // other devices adopt it.
        f.policy_updated_utc = now.max(f.policy_updated_utc + 1);
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        let _ = policy;
        // This device's `policy` record (kind 11, `storages3_ops`): every
        // device takes the newest policy of each folder.
        self.publish_policies()
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
        let view = self.view3()?;
        self.policy_reports(&view, now_utc, |id| {
            self.load_state(id).map(std::borrow::Cow::Owned)
        })
    }

    /// The policy check on a view and folder states the caller has. Copies
    /// are counted on the pack-level view through each folder's block map
    /// (design section 4, "Copies of a block").
    fn policy_reports<'s, F>(
        &self,
        view: &crate::ledger3::LedgerView,
        now_utc: i64,
        state_of: F,
    ) -> Result<Vec<PolicyReport>>
    where
        F: Fn(&FolderId) -> Result<std::borrow::Cow<'s, FolderState>>,
    {
        let mut ctx = self.policy_ctx();
        let mut reports = Vec::new();
        for (rec, _) in self.folders() {
            let Some(policy) = rec.effective_policy() else {
                continue;
            };
            let state = state_of(&rec.folder_id)?;
            let mut seen: BTreeMap<ObjectName, u64> = BTreeMap::new();
            let mut facts = Vec::new();
            let table = self.folder_table(&rec)?;
            {
                let t = table
                    .as_ref()
                    .map(|t| t.read().unwrap_or_else(|e| e.into_inner()));
                for file in state.files.values().filter(|f| !f.deleted) {
                    for cr in &file.chunks {
                        if seen.insert(cr.object.clone(), cr.size).is_some() {
                            continue;
                        }
                        facts.push(match &t {
                            Some(t) => self.chunk_facts(&mut ctx, view, t, &cr.object),
                            None => crate::policy::ChunkFacts::default(),
                        });
                    }
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
            if let Some(t) = &table {
                let t = t.read().unwrap_or_else(|e| e.into_inner());
                self.disk_group_findings(&seen, view, &t, &ctx.pools, &mut report);
            }
            // Blocks a mailbox holds for their target: in transit, still short.
            if report.state != crate::policy::PolicyState::Ok {
                if let Some((n, bytes, text)) = self.mailbox_in_transit(&rec.folder_id, &seen) {
                    report.chunks_in_transit = n;
                    report.bytes_in_transit = bytes;
                    report.reasons.push(text);
                }
            }
            reports.push(report);
        }
        // Why a policy may not be met: a storage at its quota or leaving.
        let notes = self.storage_notes(view);
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

    /// The copies of one block as a policy counts them: one per storage
    /// holding a live place of it (one per disk for a pool), transferrers
    /// left out (`storages3::block_facts`).
    pub(crate) fn chunk_facts(
        &self,
        ctx: &mut PolicyCtx,
        view: &crate::ledger3::LedgerView,
        table: &crate::blockmap::MapTable,
        object: &ObjectName,
    ) -> crate::policy::ChunkFacts {
        let Ok(obj) = crate::storages3::object_bin(object) else {
            return crate::policy::ChunkFacts::default();
        };
        let f = {
            let place_of = |n: &str| {
                if ctx.carriers.contains(n) {
                    crate::storages3::Standing::Carrier
                } else {
                    crate::storages3::Standing::Place(
                        ctx.places
                            .get(n)
                            .map(|(p, _)| p.clone())
                            .unwrap_or_else(|| "other".to_string()),
                    )
                }
            };
            let disks_of = |n: &str, pack: &crate::ledger3::PackId| {
                ctx.pools
                    .get(n)
                    .map(|p| crate::storages3::pool_pack_copies(p, pack))
            };
            let env = crate::storages3::CopyEnv {
                place_of: &place_of,
                disks_of: &disks_of,
            };
            crate::storages3::block_facts(view, table, &obj, &env)
        };
        for (place, name) in f.unreadable {
            let list = ctx.unreadable_places.entry(place).or_default();
            if !list.contains(&name) {
                list.push(name);
            }
        }
        f.facts
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
        // Format 3: the id comes from the key (`membership3::strongrooms`),
        // the key wraps travel in a `strongroom` record, the key is never
        // granted.
        let folder_key = SecretKey::random();
        let folder_id = self.strongroom_id_for(&folder_key);
        let info =
            crate::strongroom::enroll(key, method, &self.vault.vault_id, &folder_id, &folder_key)?;
        self.publish_strongroom(name, &folder_key, &info, None, &[], false)?;
        let rec = FolderRecord {
            folder_id: folder_id.clone(),
            name: name.to_string(),
            key_hex: String::new(),
            k11_hex: String::new(),
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
        // Prove the key is right before accepting it: it must match the
        // commitment published with the Strongroom.
        rec.strongroom
            .as_ref()
            .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?
            .verify_key(&rec.folder_id, &fk)?;
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

    /// Block sizes and Gear table for a file of `size` bytes in the folder
    /// of `fk`: the same on every device, so the same content in one folder
    /// gives the same blocks. Tests that set their own sizes keep them (with
    /// the folder's table).
    pub(crate) fn chunker_for(&self, size: u64, fk: &FolderKeys) -> ChunkerParams {
        let seed = fk.chunker_seed();
        if self.chunker == ChunkerParams::DEFAULT {
            ChunkerParams::for_size(size, &seed)
        } else {
            self.chunker.with_seed(&seed)
        }
    }

    /// The `chunking` of a file entry cut by `chunker_for` (format 2), or 0
    /// when tests set their own sizes.
    pub(crate) fn chunking_mark(&self) -> u8 {
        if self.chunker == ChunkerParams::DEFAULT {
            crate::chunking::CHUNKING
        } else {
            0
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

    /// Serve what this device holds now: the peer-to-peer server's snapshot
    /// is built again (a push published new files, or stored packs).
    fn refresh_snapshot(&self) {
        let Some(sink) = &self.snapshot_sink else {
            return;
        };
        match self.peer_snapshot() {
            Ok(s) => *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::sync::Arc::new(s)),
            Err(e) => log::warn!("p2p snapshot after publishing failed: {e:#}"),
        }
    }

    /// Whether this device has peers to serve a push's new files to.
    fn has_peers(&self) -> bool {
        self.peers.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// During a long push (`EarlyPublish`): the packs stored so far go into
    /// a map record and their claims into a batch, pushed now, so other
    /// devices read the blocks from the storages (and peers from the
    /// packs this device serves) before the upload ends; the push's own
    /// map record at the end lists the rest. Nothing stored yet: nothing
    /// is published and the cadence keeps counting. A failure is logged:
    /// the packs it took are claimed by nobody, and the next push writes
    /// their blocks again (orphans go after 7 days).
    fn publish_stored_so_far(
        &mut self,
        name: &str,
        folder: &crate::record::Id16,
        epoch: u32,
        storages: &OpenStorages,
        info: &HashMap<crate::ledger3::ObjectBin, crate::blockmap::ChunkInfo>,
        cadence: &mut Cadence,
    ) {
        let per_storage = stored_packs(storages, info);
        if per_storage.is_empty() {
            return;
        }
        cadence.published();
        let packs: usize = per_storage.iter().map(|(_, p)| p.len()).sum();
        let out = (|| -> Result<()> {
            let written = crate::blockmap::written_packs(&per_storage, &|o| info.get(o).copied())?;
            let view = self.view3()?;
            self.publish_map3(folder, epoch, &written, &view)?;
            self.flush_pending()
        })();
        match out {
            Ok(()) => {
                log::debug!("push {name}: {packs} packs published during the upload");
                self.refresh_snapshot();
                self.notify_peers_changed();
            }
            Err(e) => log::warn!("push {name}: publishing the packs stored so far failed: {e:#}"),
        }
    }

    /// Tell the other devices over peer-to-peer that something new was
    /// published; on a thread of its own, so a slow peer holds nothing up.
    pub fn notify_peers_changed(&self) {
        if let Some(peers) = self.peers.clone() {
            // The message carries this device's head list; the answers
            // carry the peers' lists and proofs, which the next catch-up
            // asks for again (design section 8).
            let heads = self.head_list();
            std::thread::spawn(move || {
                peers.notify_changed(&heads);
            });
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
        // Blocks in packs on local-directory storages, where the ledger
        // places them.
        let dirs: BTreeMap<&str, &PathBuf> = self
            .config
            .storages
            .iter()
            .filter_map(|s| match s {
                StorageSpec::LocalDir { name, path, .. } if !s.is_cold() => {
                    Some((name.as_str(), path))
                }
                _ => None,
            })
            .collect();
        let mut packed = BTreeMap::new();
        if !dirs.is_empty() {
            // Format 3: places from the folders' block maps, packs held
            // there by the pack-level view.
            let view3 = self.view3()?;
            for f in folder_keys.keys() {
                let Ok(id) = members3::bin(f) else { continue };
                let Ok(table) = self.table3(&id) else {
                    continue;
                };
                let t = table.read().unwrap_or_else(|e| e.into_inner());
                for row in t.scan().flatten() {
                    if !crate::blockmap::place_is_live(&t, &row).unwrap_or(false) {
                        continue;
                    }
                    for (storage, root) in &dirs {
                        if view3.is_held(&row.place.pack, storage) {
                            packed.insert(
                                ObjectName::from_bytes(&row.object),
                                (
                                    root.join(crate::packs::pack_key(&hex::encode(row.place.pack))),
                                    u64::from(row.place.offset),
                                    u64::from(row.place.len),
                                ),
                            );
                            break;
                        }
                    }
                }
            }
        }
        let mut local_roots: Vec<PathBuf> = Vec::new();
        if self.block_cache_root().is_dir() {
            local_roots.push(self.block_cache_root());
        }
        // Blocks the mailbox staged (section 78): the device where their
        // target is docked takes them from here.
        let outbox = crate::mailbox::Outbox::new(&self.home);
        if outbox.root().is_dir() {
            local_roots.push(outbox.root().to_path_buf());
        }
        let (heads, ledger_dir) = self.snapshot_heads();
        Ok(crate::p2p::Snapshot {
            vault_id: self.vault.vault_id.clone(),
            device_id: self.vault.device_id.clone(),
            folder_keys,
            pieces,
            local_roots,
            packed,
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
            heads,
            ledger_dir,
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

    /// The device's certificate (TLS over TCP and QUIC), created on first
    /// use (`p2p enable`).
    pub fn p2p_identity(&self) -> Result<crate::p2p::quic::Identity> {
        crate::p2p::quic::Identity::load_or_create(&self.home)
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
        let (tmp, tmp_file) = util::temp_beside(&disk, "upload")
            .with_context(|| format!("write {}", disk.display()))?;
        let written = (|| -> Result<()> {
            let mut out = tmp_file;
            std::io::copy(&mut { reader }, &mut out)?;
            out.sync_all()?;
            util::set_final_mode(&out, None);
            Ok(())
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e.context(format!("write {}", disk.display())));
        }
        fs::rename(&tmp, &disk).with_context(|| format!("write {}", disk.display()))?;
        self.push_after_local(folder)
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
                return self.push_after_local(folder);
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
        self.push_after_local(folder)
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
            self.exclusive(|e| e.sync_inner(folder))
        })
    }

    fn sync_inner(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        // A new run: storages that rest after failures are left out from
        // the start, the others are tried (`health`).
        if self.cycle.is_none() {
            self.health.begin_run();
        }
        // The upkeep steps below reuse the ledger pull of the folders'
        // sync instead of listing every storage again.
        let out = self.sync_round(|e| e.sync_round_inner(folder));
        if out.is_err() {
            self.finish_storages();
        }
        out
    }

    fn sync_round_inner(&mut self, folder: Option<&str>) -> Result<Vec<(PullReport, PushReport)>> {
        // A join made without reaching a storage is finished first.
        self.finish_pending_join()?;
        // Peers opened from the saved directory: read the records now.
        self.refresh_saved_peers();
        // Every folder's pull and push record into one ledger batch, and the
        // ledger is pulled once.
        let (mut out, seq) = self.one_batch_seq(|e| e.sync_folders(folder))?;
        for (_, push) in out.iter_mut() {
            push.batch_seq = push.batch_seq.or(seq);
        }
        // Records and organization objects that reached only some storages
        // go to the others now that they may answer (`health`).
        if let Err(e) = self.heal_partial_writes() {
            log::debug!("partial writes not healed yet: {e:#}");
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
        // The storages this run could not reach, for every folder's report.
        let down: Vec<String> = self
            .storage_health()
            .into_iter()
            .filter(|h| h.down_now)
            .map(|h| h.storage)
            .collect();
        for (pull, _) in out.iter_mut() {
            pull.storages_down = down.clone();
        }
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
        // adopted before it is synced under its old key. With no storage
        // reachable the folders still sync with peers, on the membership
        // known here.
        if let Err(e) = self.pull_registry() {
            if !is_network_error(&e) {
                return Err(e);
            }
            log::warn!("membership not read, no storage answered: {e:#}");
        }
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
            if let Err(e) = self.pull_ledger() {
                if !is_network_error(&e) {
                    return Err(e);
                }
                log::warn!("ledger not pulled, no storage answered: {e:#}");
            }
        }
        // A folder that fails is reported and the others go on; the sync
        // fails only when every folder failed (`first_failure`).
        let mut first_failure: Option<anyhow::Error> = None;
        let mut synced = 0usize;
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
            let failed = |e: anyhow::Error,
                          mut pull: PullReport,
                          first: &mut Option<anyhow::Error>|
             -> (PullReport, PushReport) {
                log::warn!(folder = name.as_str(); "folder not synced: {e:#}");
                if pull.folder.is_empty() {
                    pull.folder = name.clone();
                }
                pull.error = Some(format!("{e:#}"));
                let push = PushReport {
                    folder: pull.folder.clone(),
                    ..Default::default()
                };
                first.get_or_insert(e);
                (pull, push)
            };
            let mut pull = match self.pull(&name) {
                Ok(p) => p,
                Err(e) => {
                    self.last_scan = None;
                    if folder_safety::paused_error(&e).is_some() {
                        out.push(paused(e, PullReport::default())?);
                        synced += 1;
                    } else {
                        out.push(failed(e, PullReport::default(), &mut first_failure));
                    }
                    continue;
                }
            };
            // The pull scanned the folder; the push need not walk it again.
            let scan = self.last_scan.take();
            if self.keyring.find(&name).is_none() {
                synced += 1;
                continue; // converted while pulling
            }
            // Selective sync turned off: the placeholders become files.
            match self.fill_placeholders(&name, &mut pull.files_unavailable) {
                Ok(n) => pull.files_updated += n,
                Err(e) => {
                    out.push(failed(e, pull, &mut first_failure));
                    continue;
                }
            }
            match self.push_with_scan(&name, scan) {
                Ok(push) => {
                    out.push((pull, push));
                    synced += 1;
                }
                Err(e) if folder_safety::paused_error(&e).is_some() => {
                    out.push(paused(e, pull)?);
                    synced += 1;
                }
                Err(e) => out.push(failed(e, pull, &mut first_failure)),
            }
        }
        if synced == 0 {
            if let Some(e) = first_failure {
                return Err(e);
            }
        }
        if self.block_cache_root().is_dir() {
            // Blocks no cached file needs any more (a newer version arrived,
            // a file was deleted) leave the block cache once stored elsewhere.
            self.gc_block_cache()?;
        }
        Ok(out)
    }

    // ----- reporting ----------------------------------------------------------

    pub fn status(&self) -> Result<StatusReport> {
        // One view and one read of each folder's state for the whole report
        // (the protection and the policy check below use them too): on a big
        // vault each costs a good part of a second.
        let view = self.view()?;
        let mut states: BTreeMap<FolderId, FolderState> = BTreeMap::new();
        for (rec, _) in self.folders() {
            let st = self.load_state(&rec.folder_id)?;
            states.insert(rec.folder_id.clone(), st);
        }
        let state_of = |id: &FolderId| -> Result<std::borrow::Cow<'_, FolderState>> {
            Ok(match states.get(id) {
                Some(s) => std::borrow::Cow::Borrowed(s),
                None => std::borrow::Cow::Owned(self.load_state(id)?),
            })
        };
        // Format 3: copies of blocks from the pack-level view and the
        // folders' block maps.
        let view3 = self.view3()?;
        let reports = self.policy_reports(&view3, util::now_utc(), state_of).ok();
        let mut protection = self.protection_with(&view, reports.as_deref(), state_of)?;
        let mut folders = Vec::new();
        for (rec, mount) in self.folders() {
            let state = state_of(&rec.folder_id)?;
            let mut chunks: BTreeMap<ChunkId, ObjectName> = BTreeMap::new();
            let mut bytes = 0u64;
            let mut files = 0u64;
            for f in state.files.values().filter(|f| !f.deleted) {
                files += 1;
                bytes += f.size;
                for c in &f.chunks {
                    chunks.insert(c.chunk.clone(), c.object.clone());
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
            let table = match members3::bin(&rec.folder_id) {
                Ok(f) if !rec.key_hex.is_empty() || !rec.epoch_keys.is_empty() => {
                    Some(self.table3(&f)?)
                }
                _ => None,
            };
            let mut without = 0u64;
            let mut verified = 0u64;
            let mut blocks = BlockCounts::default();
            for (c, object) in &chunks {
                let kept: Vec<crate::storages3::BlockCopy> =
                    match (&table, crate::storages3::object_bin(object)) {
                        (Some(t), Ok(obj)) => {
                            let t = t.read().unwrap_or_else(|e| e.into_inner());
                            crate::storages3::block_copy_details(&view3, &*t, &obj)
                                .into_iter()
                                .filter(|b| !carriers.contains(b.storage.as_str()))
                                .collect()
                        }
                        _ => Vec::new(),
                    };
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
                let checked = kept.iter().any(|b| b.independently_verified);
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
                last_change_utc: state
                    .files
                    .values()
                    .filter(|f| !f.deleted && f.mtime > 0)
                    .map(|f| f.mtime / 1_000_000_000)
                    .max(),
                chunks: chunks.len() as u64,
                chunks_without_storage_copy: without,
                chunks_verified_elsewhere: verified,
                protection: protection
                    .remove(&rec.folder_id.to_string())
                    .unwrap_or_else(Protection::empty),
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
            storages_down: self.storage_health(),
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
                .f3
                .replicas
                .iter()
                .map(|(k, (name, _))| (hex::encode(k), name.clone()))
                .collect(),
            members: self
                .devices
                .members
                .iter()
                .map(|(k, v)| (k.to_string(), v.name.clone()))
                .collect(),
            member: self.vault.member,
            folders,
            ledger_batches: view3.batches,
            lamport: self.clock.lamport,
            forked_devices: view3
                .forked
                .iter()
                .map(hex::encode)
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
            self.exclusive(|e| e.fsck_inner(verify_content))
        })
    }

    fn fsck_inner(&mut self, verify_content: bool) -> Result<FsckReport> {
        // Format 3: `fsck3` over the pack-level view, the block maps and the
        // manifests; the format-2 counters are filled from its report.
        let f = self.fsck3(verify_content)?;
        let view3 = self.view3()?;
        let mut damage = Vec::new();
        for (i, kind) in f
            .missing_copies
            .iter()
            .map(|i| (i, repair::DamageKind::Missing))
            .chain(
                f.corrupt_copies
                    .iter()
                    .chain(&f.wrong_length)
                    .map(|i| (i, repair::DamageKind::Corrupt)),
            )
        {
            // Transferrers empty themselves on purpose: never repaired.
            if self
                .config
                .storages
                .iter()
                .any(|s| s.name() == i.storage && s.is_carrier())
            {
                continue;
            }
            let mut pack = [0u8; 32];
            let _ = hex::decode_to_slice(&i.pack, &mut pack);
            let folder = view3
                .pack_folder(&pack)
                .map(|f| FolderId::from_bytes(&f))
                .unwrap_or_else(|| FolderId::from_bytes(&[0; 16]));
            damage.push(repair::Damage {
                folder,
                chunk: ObjectName::from_bytes(&pack),
                object: ObjectName::from_bytes(&pack),
                storage: i.storage.clone(),
                kind,
                found_by: "fsck".into(),
                found_utc: util::now_utc(),
                retry_utc: 0,
                reason: None,
            });
        }
        let cold: Vec<String> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_cold())
            .map(|s| s.name().to_string())
            .collect();
        let mut report = FsckReport {
            chunks_referenced: f.blocks.referenced,
            chunks_with_storage_copy: f.blocks.live,
            chunks_verified_elsewhere: 0,
            chunks_claimed_only: 0,
            chunks_missing: f
                .damaged_files
                .iter()
                .map(|d| format!("{}/{}", d.folder, d.path))
                .collect(),
            claims_without_object: f.missing_copies.len() as u64,
            objects_unreferenced: f.orphans.len() as u64,
            objects_verified_now: f.copies_verified_now,
            objects_corrupt: f
                .corrupt_copies
                .iter()
                .chain(&f.wrong_length)
                .map(|i| format!("{}@{}", i.pack, i.storage))
                .collect(),
            forked_devices: f.forked_devices.clone(),
            storages_skipped_cold: cold,
            repairs_queued: damage.len() as u64,
            format3: Some(f),
            ..Default::default()
        };
        // Pools: packs whose disks are all away are counted, not failed.
        (report.objects_offline, report.disks_offline) =
            self.pools_offline(&view3, verify_content)?;
        self.queue_damage(damage)?;
        let _ = self.ledger_lost_everywhere(false);
        report.ledger_health = self.ledger_health();
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

    /// Disks that carry a marker of one of this vault's pools but no valid
    /// MAC: (pool, mount, label). They are not used until `varsto disk add`
    /// takes them in.
    pub fn unknown_pool_disks(&self) -> Vec<(String, PathBuf, String)> {
        let mut out = Vec::new();
        for spec in self.pool_specs() {
            if let Ok(pool) = self.open_pool(&spec) {
                for (mount, marker) in pool.unknown_disks() {
                    out.push((spec.name().to_string(), mount, marker.label));
                }
            }
        }
        out
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
        // Packs the disk lost that the pool now holds on no disk are
        // dropped; with `full` every pack on the disk was re-hashed: a
        // verification other devices can rely on (`pack_verified`).
        {
            let view = self.view3()?;
            let good: Vec<String> = if full {
                pool.objects_on(&disk.id)
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect()
            } else {
                Vec::new()
            };
            let gone: Vec<String> = verified
                .bad
                .iter()
                .chain(&verified.missing)
                .cloned()
                .collect();
            let events = crate::storages3::disk_check_events(&pool, &view, &good, &gone);
            self.f3.pending.extend(events);
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
        let view = self.view3()?;
        // A pack the disk holds is elsewhere when another storage holds it.
        let only_here = pool
            .objects_on(&disk.id)
            .iter()
            .filter(|(key, _)| {
                let Some(id) = crate::packs::pack_of_key(key) else {
                    return true;
                };
                let mut pack = [0u8; 32];
                hex::decode_to_slice(id, &mut pack).is_err()
                    || !view.holders(&pack).iter().any(|h| *h != spec.name())
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
        for params in [self.chunker_for(size, fk)] {
            let file = fs::File::open(path)?;
            for piece in Chunker::new(std::io::BufReader::new(file), params)? {
                let piece = piece?;
                if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &piece)) != *chunk {
                    continue;
                }
                return crate::chunk_seal::seal_chunk(
                    fk,
                    &self.vault.vault_id,
                    chunk,
                    epoch,
                    &piece,
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

    /// Every batch held here that opens under a key this device holds
    /// (`varsto ledger`, `/api/ledger`).
    pub fn ledger_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut out = Vec::new();
        for s in self.f3.ledger.all()? {
            let Some(key) = self.key_for3(&s.key_id) else {
                continue;
            };
            let Ok(plain) = crate::ledger3::envelope::open_parts(
                std::slice::from_ref(&s),
                &key,
                crate::ledger3::events::MAX_BATCH_PLAIN,
            ) else {
                continue;
            };
            let Ok(b) = crate::ledger3::events::Batch::from_postcard(&plain) else {
                continue;
            };
            out.push(LedgerEntry {
                device: hex::encode(s.device),
                seq: s.seq,
                lamport: b.lamport,
                created_utc: b.created_utc,
                events: b.events.len(),
                hash: hex::encode(s.body_hash),
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
/// `state/pending-join.json`: a join made without reaching a storage,
/// finished by the next sync that can (`Engine::finish_pending_join`).
#[derive(Serialize, Deserialize)]
struct PendingJoin {
    /// The names of the storages taken over from the pairing.
    storages: Vec<String>,
    since_utc: i64,
}

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
