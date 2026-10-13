// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder safety (spec section 47): the folder marker, the mass-deletion
//! guard and the send-only / receive-only folder modes.
//!
//! * **Marker.** Every folder mounted with plain files on this device has a
//!   small file `.varsto-folder` in its root naming the folder. A root
//!   without it (an unmounted disk leaves an empty mount point) or with
//!   another folder's marker pauses the folder here: nothing is scanned,
//!   so nothing reads as deleted, and nothing is written into it.
//! * **Mass-deletion guard.** A scan that finds more files gone at once
//!   than the folder's `DeletionGuard` allows, or another device's file
//!   list that would delete that many here, is held: nothing is published
//!   or deleted and the folder is paused until the user confirms the
//!   deletions or discards them.
//! * **Modes.** Send-only devices publish their changes but never apply
//!   other devices' ones (listed as "remote changes not applied", which an
//!   override turns into newer versions of this device's state);
//!   receive-only devices apply other devices' changes but never publish
//!   their own (listed as "local changes", which a revert replaces with
//!   the vault's versions, keeping the local copies in the trash).

use super::*;
use crate::vault::{DeletionGuard, FolderMode};

/// The marker file in the root of every folder mounted with plain files.
pub const FOLDER_MARKER: &str = ".varsto-folder";

/// Why a folder is paused on this device.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PauseKind {
    /// The root has no marker (an unmounted disk, a deleted root).
    MarkerMissing,
    /// The root's marker names another folder (or cannot be read).
    MarkerOther,
    /// Deletions wait for the user's confirmation.
    DeletionsHeld,
}

/// A folder that is not synced on this device until the user acts. It is
/// the error `pull`, `push` and anything writing into the folder return;
/// `sync` reports it per folder (`PullReport::paused`) and goes on with
/// the other folders.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderPaused {
    pub folder: String,
    pub kind: PauseKind,
    pub message: String,
    /// The folder's root on this device.
    pub path: PathBuf,
}

impl std::fmt::Display for FolderPaused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FolderPaused {}

/// The pause in an error, if the error is one.
pub fn paused_error(e: &anyhow::Error) -> Option<FolderPaused> {
    e.chain()
        .find_map(|c| c.downcast_ref::<FolderPaused>())
        .cloned()
}

/// What changed about one file.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// Deletions held by the mass-deletion guard (`FolderState::held`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HeldDeletions {
    /// None: this device's scan found the files gone. Some: the device whose
    /// file list would delete them here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_device: Option<DeviceId>,
    pub detected_utc: i64,
    /// Files in the folder when the deletions were held.
    pub of_files: u64,
    pub paths: BTreeSet<String>,
    /// The other device's deletions, applied when confirmed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub remote: BTreeMap<String, FileState>,
}

/// Held deletions as status shows them.
#[derive(Clone, Debug, Serialize)]
pub struct HeldSummary {
    /// "local" (this device's scan) or "remote" (another device's file list).
    pub origin: String,
    /// The other device's name, for remote deletions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    pub files: u64,
    pub of_files: u64,
    pub detected_utc: i64,
    /// The first few paths.
    pub sample: Vec<String>,
}

/// One changed file of `FolderChanges`.
#[derive(Clone, Debug, Serialize)]
pub struct ChangeEntry {
    pub path: String,
    pub kind: ChangeKind,
}

/// What waits for a decision in a folder (`Engine::folder_changes`).
#[derive(Clone, Debug, Serialize)]
pub struct FolderChanges {
    pub folder: String,
    pub mode: FolderMode,
    pub deletion_guard: DeletionGuard,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<FolderPaused>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held: Option<HeldSummary>,
    /// Every held path.
    pub held_paths: Vec<String>,
    /// Receive-only: this device's changes that are not published.
    pub local_changes: Vec<ChangeEntry>,
    /// Send-only: other devices' changes that are not applied here.
    pub remote_not_applied: Vec<ChangeEntry>,
}

/// What discarding held deletions did.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiscardReport {
    pub folder: String,
    /// Files brought back (local deletions) or kept and published again
    /// as the newest version (another device's deletions).
    pub restored: u64,
    /// Files that could not be restored now: still held.
    pub unavailable: Vec<String>,
}

/// What reverting a receive-only folder did.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RevertReport {
    pub folder: String,
    pub reverted: u64,
    /// Local copies moved to the trash.
    pub moved_to_trash: u64,
    /// Files whose vault version could not be fetched now: still local changes.
    pub unavailable: Vec<String>,
}

/// What the marker of a root says about it.
enum Verdict {
    Ours,
    /// No marker, but this is an older mount whose files are here: mark it.
    Adopt,
    Missing,
    Other(String),
}

fn marker_path(root: &Path) -> PathBuf {
    root.join(FOLDER_MARKER)
}

/// Write the marker of `rec` into `root`.
pub(super) fn write_marker(root: &Path, rec: &FolderRecord) -> Result<()> {
    write_marker_for(root, &rec.folder_id, &rec.name)
}

fn write_marker_for(root: &Path, folder: &FolderId, name: &str) -> Result<()> {
    let body = serde_json::json!({
        "varsto": "folder",
        "folder_id": folder.to_string(),
        "name": name,
        "note": "Varsto syncs this directory. Without this file Varsto pauses the folder instead of reading its files as deleted (an unmounted disk looks the same). Do not delete it.",
    });
    util::write_atomic(&marker_path(root), &serde_json::to_vec_pretty(&body)?)
        .with_context(|| format!("writing the folder marker in {}", root.display()))
}

/// The folder id a root's marker names: Ok(None) without a marker,
/// Err(()) for one that cannot be read.
fn read_marker(root: &Path) -> std::result::Result<Option<String>, ()> {
    match fs::read(marker_path(root)) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v["folder_id"].as_str().map(str::to_string))
            .map(Some)
            .ok_or(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

/// A folder converted into a Strongroom keeps its directory under a new id.
pub(super) fn rekey_marker(root: &Path, old: &FolderId, new: &FolderId) {
    if read_marker(root) == Ok(Some(old.to_string())) {
        let name = fs::read(marker_path(root))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["name"].as_str().map(str::to_string))
            .unwrap_or_default();
        let _ = write_marker_for(root, new, &name);
    }
}

/// Whether an unmarked root of an older mount holds the folder's files: no
/// live file is known yet, or at least half of them (or their placeholders)
/// are there.
fn looks_like_folder(root: &Path, rules: crate::names::LocalRules, state: &FolderState) -> bool {
    if !root.is_dir() {
        return false;
    }
    let live: Vec<&FileState> = state.files.values().filter(|f| !f.deleted).collect();
    if live.is_empty() {
        return true;
    }
    let present = live
        .iter()
        .filter(|f| {
            let disk = state.local_names.disk(root, rules, &f.path);
            disk.exists() || placeholder_path(&disk).exists()
        })
        .count();
    present > 0 && present * 2 >= live.len()
}

/// Remove a file into this device's trash (`home/trash/<folder>/<path>.<utc>`),
/// under a name the trash's filesystem allows.
pub(super) fn trash_path(
    home: &Path,
    rules: impl Fn(&Path) -> crate::names::LocalRules,
    folder: &FolderId,
    path: &str,
) -> Result<PathBuf> {
    let trash_root = home.join("trash").join(folder.as_str());
    let name = format!("{}.{}", path, util::now_utc());
    util::safe_join(&trash_root, &rules(&trash_root).default_local(&name))
}

fn index_entry(
    disk: &Path,
    content_hash: &str,
    meta_seen: Option<crate::fsmeta::FileMeta>,
) -> Result<LocalIndexEntry> {
    let md = fs::symlink_metadata(disk)?;
    Ok(LocalIndexEntry {
        size: md.len(),
        mtime: mtime_ns_of(&md),
        content_hash: content_hash.to_string(),
        meta_seen,
    })
}

/// What a remote state would change here.
fn remote_kind(local: Option<&FileState>, remote: &FileState) -> ChangeKind {
    if remote.deleted {
        ChangeKind::Deleted
    } else if local.is_some_and(|l| !l.deleted) {
        ChangeKind::Modified
    } else {
        ChangeKind::Added
    }
}

impl Engine {
    fn marker_flag(&self, folder: &FolderId) -> PathBuf {
        self.home.join("state").join(format!("{folder}.marked"))
    }

    pub(super) fn forget_marker_flag(&self, folder: &FolderId) {
        let _ = fs::remove_file(self.marker_flag(folder));
    }

    fn set_marker_flag(&self, folder: &FolderId) {
        let flag = self.marker_flag(folder);
        if !flag.exists() {
            if let Some(p) = flag.parent() {
                let _ = fs::create_dir_all(p);
            }
            let _ = fs::write(flag, b"");
        }
    }

    /// The mount's sync mode on this device.
    pub(super) fn mount_mode(&self, folder: &FolderId) -> FolderMode {
        self.config
            .folders
            .iter()
            .find(|m| &m.folder_id == folder)
            .map(|m| m.mode)
            .unwrap_or_default()
    }

    pub(super) fn deletion_guard(&self, folder: &FolderId) -> DeletionGuard {
        self.config
            .folders
            .iter()
            .find(|m| &m.folder_id == folder)
            .and_then(|m| m.deletion_guard)
            .unwrap_or_default()
    }

    /// Whether the marker rule applies: plain files in a directory on this
    /// device (a folder kept encrypted here holds its files in the block
    /// cache; a backup's source is only read and never deleted from).
    fn marker_applies(&self, rec: &FolderRecord) -> bool {
        !rec.is_backup() && !self.mount_is_encrypted(&rec.folder_id)
    }

    fn verdict(&self, rec: &FolderRecord, root: &Path) -> Verdict {
        match read_marker(root) {
            Ok(Some(id)) if id == rec.folder_id.as_str() => Verdict::Ours,
            Ok(Some(id)) => Verdict::Other(id),
            Err(()) => Verdict::Other(String::new()),
            Ok(None) => {
                if self.marker_flag(&rec.folder_id).exists() {
                    return Verdict::Missing;
                }
                match self.load_state(&rec.folder_id) {
                    Ok(state) if looks_like_folder(root, self.local_rules(root), &state) => {
                        Verdict::Adopt
                    }
                    _ => Verdict::Missing,
                }
            }
        }
    }

    fn marker_pause(&self, rec: &FolderRecord, root: &Path, verdict: &Verdict) -> FolderPaused {
        let (kind, message) = match verdict {
            Verdict::Other(id) => (
                PauseKind::MarkerOther,
                format!(
                    "folder {name}: the marker {FOLDER_MARKER} at {root} {what} — is the right disk mounted? Nothing is synced until it is fixed; `varsto folder repair-marker {name}` if the directory is right",
                    name = rec.name,
                    root = root.display(),
                    what = if id.is_empty() {
                        "cannot be read".to_string()
                    } else {
                        format!("belongs to another folder ({})", &id[..id.len().min(8)])
                    },
                ),
            ),
            _ => (
                PauseKind::MarkerMissing,
                format!(
                    "folder {name}: the marker {FOLDER_MARKER} is missing at {root} — is the disk mounted? Nothing is synced until it is back; `varsto folder repair-marker {name}` if the directory is right",
                    name = rec.name,
                    root = root.display(),
                ),
            ),
        };
        FolderPaused {
            folder: rec.name.clone(),
            kind,
            message,
            path: root.to_path_buf(),
        }
    }

    /// Before anything reads the folder's directory as its state or writes
    /// into it: the root must carry this folder's marker. An older mount
    /// whose files are there gets one now.
    pub(super) fn ensure_marker(&self, rec: &FolderRecord, root: &Path) -> Result<()> {
        if !self.marker_applies(rec) {
            return Ok(());
        }
        match self.verdict(rec, root) {
            Verdict::Ours => {
                self.set_marker_flag(&rec.folder_id);
                Ok(())
            }
            Verdict::Adopt => {
                write_marker(root, rec)?;
                self.set_marker_flag(&rec.folder_id);
                Ok(())
            }
            v => Err(self.marker_pause(rec, root, &v).into()),
        }
    }

    fn held_pause(&self, rec: &FolderRecord, root: &Path, held: &HeldDeletions) -> FolderPaused {
        let n = held.paths.len();
        let message = match &held.from_device {
            None => format!(
                "folder {name}: {n} of {of} files were deleted at once on this device; the deletions are held and nothing is synced until you decide: `varsto folder confirm-deletions {name}` deletes them on every device, `varsto folder confirm-deletions {name} --discard` restores them",
                name = rec.name,
                of = held.of_files,
            ),
            Some(dev) => format!(
                "folder {name}: {who} deleted {n} of {of} files at once; nothing is deleted here and nothing is synced until you decide: `varsto folder confirm-deletions {name}` deletes them here too, `varsto folder confirm-deletions {name} --discard` keeps them and restores them on every device",
                name = rec.name,
                who = self.device_name_of(dev),
                of = held.of_files,
            ),
        };
        FolderPaused {
            folder: rec.name.clone(),
            kind: PauseKind::DeletionsHeld,
            message,
            path: root.to_path_buf(),
        }
    }

    fn device_name_of(&self, dev: &DeviceId) -> String {
        self.devices
            .devices
            .get(dev)
            .map(|r| r.name.clone())
            .or_else(|| self.devices.members.get(dev).map(|r| r.name.clone()))
            .unwrap_or_else(|| format!("device {}", dev.short()))
    }

    /// Held deletions pause the folder. Files this device's scan found gone
    /// that are back again (a disk mounted again, files moved back) are no
    /// longer held; once none is left the folder resumes by itself.
    pub(super) fn check_held(
        &self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
    ) -> Result<()> {
        let rules = self.local_rules(root);
        let names = &state.local_names;
        let Some(held) = state.held.as_mut() else {
            return Ok(());
        };
        if held.from_device.is_none() {
            let before = held.paths.len();
            held.paths.retain(|p| {
                let disk = names.disk(root, rules, p);
                !(disk.exists() || placeholder_path(&disk).exists())
            });
            if held.paths.is_empty() {
                state.held = None;
                self.save_state(&rec.folder_id, state)?;
                return Ok(());
            }
            if held.paths.len() != before {
                self.save_state(&rec.folder_id, state)?;
            }
        }
        let held = state.held.as_ref().expect("held deletions");
        Err(self.held_pause(rec, root, held).into())
    }

    /// The scan found `gone` files deleted: hold them when the guard says so
    /// (the caller then stops with the returned pause).
    pub(super) fn hold_local_deletions(
        &self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
        gone: &[String],
    ) -> Option<FolderPaused> {
        let live = state.files.values().filter(|f| !f.deleted).count() as u64;
        if rec.is_backup()
            || !self
                .deletion_guard(&rec.folder_id)
                .trips(gone.len() as u64, live)
        {
            return None;
        }
        let held = HeldDeletions {
            from_device: None,
            detected_utc: util::now_utc(),
            of_files: live,
            paths: gone.iter().cloned().collect(),
            remote: BTreeMap::new(),
        };
        let pause = self.held_pause(rec, root, &held);
        state.held = Some(held);
        Some(pause)
    }

    /// Another device's file list would delete these files here: hold them
    /// when the guard says so.
    pub(super) fn hold_remote_deletions(
        &self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
        device: &DeviceId,
        entries: &[(&String, &FileState)],
    ) -> Option<FolderPaused> {
        let deletes: BTreeMap<String, FileState> = entries
            .iter()
            .filter(|(path, remote)| {
                remote.deleted
                    && state.files.get(*path).is_some_and(|l| !l.deleted)
                    && matches!(
                        manifest::merge(state.files.get(*path), remote),
                        Merge::TakeRemote
                    )
            })
            .map(|(p, r)| ((*p).clone(), (*r).clone()))
            .collect();
        let live = state.files.values().filter(|f| !f.deleted).count() as u64;
        if deletes.is_empty()
            || !self
                .deletion_guard(&rec.folder_id)
                .trips(deletes.len() as u64, live)
        {
            return None;
        }
        let held = HeldDeletions {
            from_device: Some(device.clone()),
            detected_utc: util::now_utc(),
            of_files: live,
            paths: deletes.keys().cloned().collect(),
            remote: deletes,
        };
        let pause = self.held_pause(rec, root, &held);
        state.held = Some(held);
        Some(pause)
    }

    /// A new version of `prev` written by this device: `others` (another
    /// device's version vector) is folded in, so the result is newer than both.
    fn bumped(
        &mut self,
        prev: &FileState,
        others: Option<&manifest::VersionVector>,
    ) -> Result<FileState> {
        let clock = self.tick()?;
        let me = self.vault.device_id.clone();
        let mut f = prev.clone();
        if let Some(o) = others {
            f.version = manifest::vv_max(&f.version, o);
        }
        f.version.insert(me.clone(), clock);
        f.modified_by = me;
        f.modified_clock = clock;
        Ok(f)
    }

    fn tombstone_of(
        &mut self,
        prev: &FileState,
        others: Option<&manifest::VersionVector>,
    ) -> Result<FileState> {
        let mut f = self.bumped(prev, others)?;
        f.deleted = true;
        f.size = 0;
        f.mtime = 0;
        f.content_hash = String::new();
        f.chunks = vec![];
        Ok(f)
    }

    /// Move a local file into this device's trash.
    pub(super) fn move_to_trash(&self, folder: &FolderId, disk: &Path, path: &str) -> Result<()> {
        let trash = trash_path(&self.home, |r| self.local_rules(r), folder, path)?;
        if let Some(p) = trash.parent() {
            fs::create_dir_all(p)?;
        }
        let link = fs::symlink_metadata(disk).is_ok_and(|m| m.file_type().is_symlink());
        fs::rename(disk, &trash).or_else(|e| {
            if link {
                // A link is never copied (that would follow it).
                return fs::remove_file(disk).map_err(|_| e);
            }
            fs::copy(disk, &trash)
                .map(|_| ())
                .and_then(|_| fs::remove_file(disk))
        })?;
        Ok(())
    }

    /// Receive-only: a remote version is about to replace `path`; the
    /// local change goes to the trash first, so nothing is lost.
    pub(super) fn drop_local_change(
        &self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
        path: &str,
    ) -> Result<()> {
        if let Some(kind) = state.local_changes.remove(path) {
            util::check_rel_path(path)?;
            let disk = self.disk_of(root, state, path);
            if kind != ChangeKind::Deleted && disk.is_file() {
                self.move_to_trash(&rec.folder_id, &disk, path)?;
                state.local_index.remove(path);
            }
        }
        Ok(())
    }

    // ----- commands ------------------------------------------------------------

    /// Write the marker into the folder's directory again: the directory is
    /// the right one (the user says so). Returns the directory.
    pub fn repair_marker(&mut self, folder: &str) -> Result<PathBuf> {
        let (rec, root) = self.resolve_folder(folder)?;
        if !self.marker_applies(&rec) {
            bail!(
                "{} keeps its files encrypted on this device; it has no marker",
                rec.name
            );
        }
        if !root.is_dir() {
            bail!(
                "{} does not exist: mount the disk it is on, or detach the folder and attach it elsewhere",
                root.display()
            );
        }
        write_marker(&root, &rec)?;
        self.set_marker_flag(&rec.folder_id);
        Ok(root)
    }

    /// Set the folder's mode on this device.
    pub fn set_folder_mode(&mut self, folder: &str, mode: FolderMode) -> Result<()> {
        let (rec, _) = self.resolve_folder(folder)?;
        if mode == FolderMode::SendOnly && self.share_read_only(&rec) {
            bail!(
                "{} is shared with this device read-only: it publishes nothing, so it cannot be send-only",
                rec.name
            );
        }
        if mode == FolderMode::ReceiveOnly && self.mount_is_encrypted(&rec.folder_id) {
            bail!(
                "{} keeps its files encrypted on this device: receive-only is for folders with plain files",
                rec.name
            );
        }
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.mode = mode;
        }
        self.config.save(&self.home)
    }

    /// Set (or with None reset to the default) the folder's mass-deletion guard.
    pub fn set_deletion_guard(&mut self, folder: &str, guard: Option<DeletionGuard>) -> Result<()> {
        let (rec, _) = self.resolve_folder(folder)?;
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.deletion_guard = guard.filter(|g| *g != DeletionGuard::default());
        }
        self.config.save(&self.home)
    }

    /// Confirm held deletions: this device's are published as deletions
    /// with the next sync (files that came back are left out); another
    /// device's are applied here (the files go to the trash). Returns the
    /// number of files deleted.
    pub fn confirm_deletions(&mut self, folder: &str) -> Result<u64> {
        let (rec, root) = self.resolve_for_write(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let Some(held) = state.held.take() else {
            bail!("folder {}: no deletions wait for confirmation", rec.name);
        };
        let mut n = 0u64;
        match held.from_device {
            None => {
                let rules = self.local_rules(&root);
                let mut trashed: Vec<(FileState, u64)> = Vec::new();
                for path in held.paths {
                    let disk = self.disk_of(&root, &state, &path);
                    if disk.exists() || placeholder_path(&disk).exists() {
                        continue; // back again: not a deletion any more
                    }
                    let Some(prev) = state.files.get(&path).filter(|f| !f.deleted).cloned() else {
                        continue;
                    };
                    let tomb = self.tombstone_of(&prev, None)?;
                    let clock = tomb.modified_clock;
                    state.files.insert(path.clone(), tomb);
                    state.local_index.remove(&path);
                    state.local_names.forget(rules, &path);
                    trashed.push((prev, clock));
                    n += 1;
                }
                // The deleted versions go to the vault's trash (`trash`).
                self.trash_record_deletions(&rec, &state, trashed)?;
            }
            Some(_) => {
                let fk = self.folder_keys(&rec)?;
                let mut report = PullReport::default();
                for (path, tomb) in held.remote {
                    if matches!(
                        manifest::merge(state.files.get(&path), &tomb),
                        Merge::TakeRemote
                    ) {
                        self.drop_local_change(&rec, &root, &mut state, &path)?;
                        self.apply_remote(&rec, &fk, &root, &mut state, tomb, &[], &mut report)?;
                        n += 1;
                    }
                }
            }
        }
        self.save_state(&rec.folder_id, &state)?;
        Ok(n)
    }

    /// Discard held deletions: files this device's scan found gone are
    /// restored from the storages (or peers); files another device deleted
    /// are kept here and published as the newest version, so every device
    /// gets them back. Files that cannot be restored now stay held.
    pub fn discard_deletions(&mut self, folder: &str) -> Result<DiscardReport> {
        let (rec, root) = self.resolve_for_write(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let Some(mut held) = state.held.take() else {
            bail!("folder {}: no deletions wait for confirmation", rec.name);
        };
        let mut report = DiscardReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        match held.from_device {
            None => {
                let fk = self.folder_keys(&rec)?;
                let storages = self.open_storages(false)?;
                let selective = self.mount_is_selective(&rec.folder_id);
                let mut paths: Vec<FileState> = held
                    .paths
                    .iter()
                    .filter_map(|p| state.files.get(p).filter(|f| !f.deleted).cloned())
                    .collect();
                // Newest first, as every download.
                paths.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
                let mut pull = PullReport::default();
                let mut left = BTreeSet::new();
                for file in paths {
                    util::check_rel_path(&file.path)?;
                    let disk = self.place(&root, &mut state, &file.path, None)?;
                    if disk.exists() || placeholder_path(&disk).exists() {
                        report.restored += 1;
                        continue;
                    }
                    if selective && !state.pinned.contains(&file.path) {
                        Self::write_placeholder(&disk, &file)?;
                        report.restored += 1;
                        continue;
                    }
                    let written = match file.symlink() {
                        Some(target) => crate::fsmeta::write_link(&disk, target).map(|_| ()),
                        None => self.download_to(&rec, &fk, &disk, &file, &storages, &mut pull),
                    };
                    match written {
                        Ok(()) => {
                            let seen = self.settle_meta(
                                &rec.folder_id,
                                &disk,
                                &file,
                                &mut pull.metadata_problems,
                            );
                            state.local_index.insert(
                                file.path.clone(),
                                index_entry(&disk, &file.content_hash, seen)?,
                            );
                            report.restored += 1;
                        }
                        Err(e) => {
                            report.unavailable.push(format!("{}: {e:#}", file.path));
                            left.insert(file.path.clone());
                        }
                    }
                }
                if !left.is_empty() {
                    held.paths = left;
                    state.held = Some(held);
                }
                self.defer_events()?;
            }
            Some(_) => {
                for (path, tomb) in std::mem::take(&mut held.remote) {
                    let Some(local) = state.files.get(&path).filter(|f| !f.deleted).cloned() else {
                        continue;
                    };
                    let kept = self.bumped(&local, Some(&tomb.version))?;
                    state.files.insert(path, kept);
                    report.restored += 1;
                }
            }
        }
        self.save_state(&rec.folder_id, &state)?;
        Ok(report)
    }

    /// Send-only: make every device match this one. Each remote change not
    /// applied here becomes a newer version of this device's state of the
    /// file (its content, or its absence), published with the next sync.
    /// Returns the number of files.
    pub fn override_remote(&mut self, folder: &str) -> Result<u64> {
        let (rec, _) = self.resolve_folder(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        if state.not_applied.is_empty() {
            bail!("folder {}: no remote changes wait here", rec.name);
        }
        let mut n = 0u64;
        for (path, remote) in std::mem::take(&mut state.not_applied) {
            let local = state.files.get(&path).cloned();
            let next = match local {
                Some(l) if !l.deleted => self.bumped(&l, Some(&remote.version))?,
                Some(l) => self.tombstone_of(&l, Some(&remote.version))?,
                // Never here: published as deleted.
                None => self.tombstone_of(&remote, None)?,
            };
            state.files.insert(path, next);
            n += 1;
        }
        self.save_state(&rec.folder_id, &state)?;
        Ok(n)
    }

    /// Receive-only: replace this device's local changes with the vault's
    /// versions. Changed and added files go to the trash first.
    pub fn revert_local(&mut self, folder: &str) -> Result<RevertReport> {
        let (rec, root) = self.resolve_for_write(folder)?;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut report = RevertReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        if state.local_changes.is_empty() {
            bail!("folder {}: no local changes to revert", rec.name);
        }
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(false)?;
        let mut pull = PullReport::default();
        let mut changes: Vec<(String, ChangeKind)> = std::mem::take(&mut state.local_changes)
            .into_iter()
            .collect();
        let mtime_of = |p: &str| state.files.get(p).map(|f| f.mtime).unwrap_or(0);
        changes.sort_by(|a, b| mtime_of(&b.0).cmp(&mtime_of(&a.0)).then(a.0.cmp(&b.0)));
        for (path, kind) in changes {
            util::check_rel_path(&path)?;
            let disk = self.disk_of(&root, &state, &path);
            if kind != ChangeKind::Deleted && disk.is_file() {
                self.move_to_trash(&rec.folder_id, &disk, &path)?;
                report.moved_to_trash += 1;
            }
            state.local_index.remove(&path);
            let vault = state.files.get(&path).filter(|f| !f.deleted).cloned();
            let Some(file) = vault else {
                report.reverted += 1; // added here: gone again
                continue;
            };
            let written = match file.symlink() {
                Some(target) => crate::fsmeta::write_link(&disk, target).map(|_| ()),
                None => self.download_to(&rec, &fk, &disk, &file, &storages, &mut pull),
            };
            match written {
                Ok(()) => {
                    let seen =
                        self.settle_meta(&rec.folder_id, &disk, &file, &mut pull.metadata_problems);
                    state
                        .local_index
                        .insert(path.clone(), index_entry(&disk, &file.content_hash, seen)?);
                    let _ = fs::remove_file(placeholder_path(&disk));
                    report.reverted += 1;
                }
                Err(e) => {
                    report.unavailable.push(format!("{path}: {e:#}"));
                    // The local copy is in the trash; the file is missing here.
                    state.local_changes.insert(path, ChangeKind::Deleted);
                }
            }
        }
        self.defer_events()?;
        self.save_state(&rec.folder_id, &state)?;
        Ok(report)
    }

    /// What waits for a decision in a folder.
    pub fn folder_changes(&self, folder: &str) -> Result<FolderChanges> {
        let (rec, root) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        Ok(FolderChanges {
            folder: rec.name.clone(),
            mode: self.mount_mode(&rec.folder_id),
            deletion_guard: self.deletion_guard(&rec.folder_id),
            paused: self.pause_of(&rec, &root, &state),
            held: self.held_summary(&state),
            held_paths: state
                .held
                .as_ref()
                .map(|h| h.paths.iter().cloned().collect())
                .unwrap_or_default(),
            local_changes: state
                .local_changes
                .iter()
                .map(|(p, k)| ChangeEntry {
                    path: p.clone(),
                    kind: *k,
                })
                .collect(),
            remote_not_applied: state
                .not_applied
                .iter()
                .map(|(p, r)| ChangeEntry {
                    path: p.clone(),
                    kind: remote_kind(state.files.get(p), r),
                })
                .collect(),
        })
    }

    /// Why the folder is paused on this device now, if it is (read only).
    pub(super) fn pause_of(
        &self,
        rec: &FolderRecord,
        root: &Path,
        state: &FolderState,
    ) -> Option<FolderPaused> {
        if self.marker_applies(rec) {
            match self.verdict(rec, root) {
                Verdict::Ours | Verdict::Adopt => {}
                v => return Some(self.marker_pause(rec, root, &v)),
            }
        }
        state.held.as_ref().map(|h| self.held_pause(rec, root, h))
    }

    pub(super) fn held_summary(&self, state: &FolderState) -> Option<HeldSummary> {
        state.held.as_ref().map(|h| HeldSummary {
            origin: if h.from_device.is_some() {
                "remote".into()
            } else {
                "local".into()
            },
            device: h.from_device.as_ref().map(|d| self.device_name_of(d)),
            files: h.paths.len() as u64,
            of_files: h.of_files,
            detected_utc: h.detected_utc,
            sample: h.paths.iter().take(10).cloned().collect(),
        })
    }
}
