// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Version history (`docs/spec/alpha-0-format.md`, the section after the
//! trash).
//!
//! When a file is replaced by a new version, the device that wrote the new
//! version keeps the previous one as a *history entry*: the same shape as a
//! trash entry (path, size, modification time, content hash, block list,
//! when and by which device it was replaced), in the same per-device,
//! per-folder trash record (`versions`), so every device that holds the
//! folder key sees it and can restore it. The blocks of the versions the
//! history keeps count as used exactly like those of the trash (data moves,
//! storage removal, `fsck`, the trash storage); content-defined chunking
//! means a version shares every unchanged block with the newer versions, so
//! only the changed blocks cost space.
//!
//! The history thins each file's versions over time (Syncthing's
//! "staggered versioning", with fixed buckets so every device decides the
//! same): every version replaced in the last hour is kept; older than an
//! hour, at most one per clock hour for a day; older than a day, one per
//! calendar day (UTC) for 30 days; older than 30 days, one per week until
//! the history days (90 by default; per vault and per folder; "off" keeps
//! no new versions). In each bucket the newest version stays. The daily
//! trash upkeep queues the blocks of versions let go and drops those that
//! nothing else uses.

use super::trash::{entry_id, TrashEntry, TrashRestorePlan, TrashSettings};
use super::*;

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const WEEK: i64 = 7 * DAY;
/// Days replaced versions are kept unless the vault or folder says otherwise.
pub const DEFAULT_HISTORY_DAYS: u32 = 90;
/// Longest history that can be set (ten years).
pub const MAX_HISTORY_DAYS: u32 = 3650;
/// Every version younger than this is kept.
pub const HISTORY_KEEP_ALL_SECS: i64 = HOUR;
/// Until this age, at most one version per hour.
pub const HISTORY_HOURLY_SECS: i64 = DAY;
/// Until this age, at most one version per day; after it one per week.
pub const HISTORY_DAILY_SECS: i64 = 30 * DAY;

/// Which versions the history keeps at `now`: `versions` holds the time
/// each was replaced, the clock of the replacement and its id (clock and
/// id break ties), `days` the history days. Every version younger than an
/// hour is kept; an older one only while no newer version was replaced in
/// the same clock hour (until it is a day old), the same UTC day (until 30
/// days), the same week from the Unix epoch (until `days`); nothing older.
/// So the last hour keeps everything, the last day one version per hour,
/// the last 30 days one per day, and then one per week. Buckets are fixed
/// and only grow as a version ages, so a version let go never comes back,
/// and every device that knows the same versions keeps the same ones.
pub fn history_kept(versions: &[(i64, u64, &str)], now: i64, days: u32) -> Vec<bool> {
    let limit = days.max(1) as i64 * DAY;
    // The newest version of every bucket of every size.
    let mut newest: HashMap<(i64, i64), (i64, u64, &str)> = HashMap::new();
    for v in versions {
        for size in [HOUR, DAY, WEEK] {
            let e = newest.entry((size, v.0.div_euclid(size))).or_insert(*v);
            if *v > *e {
                *e = *v;
            }
        }
    }
    versions
        .iter()
        .map(|v| {
            let age = now - v.0;
            if age >= limit {
                return false;
            }
            if age < HISTORY_KEEP_ALL_SECS {
                return true;
            }
            let size = if age < HISTORY_HOURLY_SECS {
                HOUR
            } else if age < HISTORY_DAILY_SECS {
                DAY
            } else {
                WEEK
            };
            newest.get(&(size, v.0.div_euclid(size))) == Some(v)
        })
        .collect()
}

/// A time given as `YYYY-MM-DD` (the end of that day), `YYYY-MM-DD HH:MM`
/// or `YYYY-MM-DDTHH:MM:SS`, in UTC (a trailing `Z` or ` UTC` is allowed).
pub fn parse_utc(text: &str) -> Option<i64> {
    let t = text.trim();
    let t = t
        .strip_suffix(" UTC")
        .or_else(|| t.strip_suffix('Z'))
        .unwrap_or(t)
        .trim();
    let (date, time) = match t.split_once(['T', ' ']) {
        Some((d, tm)) => (d, Some(tm.trim())),
        None => (t, None),
    };
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) || date.len() != 10
    {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = match time {
        None => DAY - 1,
        Some(tm) => {
            let mut p = tm.split(':');
            let h: i64 = p.next()?.parse().ok()?;
            let mi: i64 = p.next()?.parse().ok()?;
            let s: i64 = match p.next() {
                Some(s) => s.parse().ok()?,
                None => 0,
            };
            if p.next().is_some() || h > 23 || mi > 59 || s > 59 || h < 0 || mi < 0 || s < 0 {
                return None;
            }
            h * HOUR + mi * 60 + s
        }
    };
    Some(days * DAY + secs)
}

/// One kept version as listed.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryItem {
    pub id: String,
    pub path: String,
    pub size: u64,
    /// Modification time of the version (nanoseconds).
    pub mtime: i64,
    /// When it was replaced by the next version.
    pub replaced_utc: i64,
    pub replaced_by: String,
    pub replaced_by_id: String,
    /// The device that wrote this version, when known.
    pub author: Option<String>,
    /// Bytes of blocks this version adds to the current file and the newer
    /// versions (unchanged blocks are shared).
    pub new_bytes: u64,
    /// Lamport clock of the replacement (orders versions replaced in the
    /// same second).
    pub clock: u64,
    pub storages: Vec<String>,
    /// Its blocks are on cold storage only: restoring needs a confirmed cold read.
    pub cold_only: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct HistoryList {
    pub folder: String,
    pub path: String,
    /// The folder's history days; `None` when it keeps no new versions.
    pub days: Option<u32>,
    /// The current version's size, when the file exists.
    pub current_size: Option<u64>,
    pub current_mtime: Option<i64>,
    /// Newest first.
    pub versions: Vec<HistoryItem>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct FolderHistory {
    pub folder: String,
    pub folder_id: String,
    /// `None`: no new versions are kept.
    pub days: Option<u32>,
    pub files: u64,
    pub versions: u64,
    /// Sum of the versions' sizes.
    pub bytes: u64,
    /// Bytes of blocks only versions use (what the history really costs).
    pub extra_bytes: u64,
    /// Those blocks per storage (a block on two storages counts twice).
    pub by_storage: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct HistoryStatus {
    /// The vault's history days; 0 keeps no new versions.
    pub days: u32,
    /// Folders with their own days (0: off).
    pub folder_days: BTreeMap<String, u32>,
    /// The thinning schedule, in words.
    pub schedule: Vec<String>,
    pub folders: Vec<FolderHistory>,
    pub versions: u64,
    pub extra_bytes: u64,
    pub by_storage: BTreeMap<String, u64>,
    /// The trash storage, which also takes blocks only versions use.
    pub storage: Option<String>,
    pub storage_cold: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct HistoryRestoreReport {
    pub folder: String,
    pub path: String,
    pub version: String,
    pub replaced_utc: i64,
    /// Where the version was written.
    pub to: String,
    pub size: u64,
    /// The version was restored over the current file, which became a
    /// version itself.
    pub replaced_current: bool,
    pub cold_read: bool,
}

/// How a version is restored.
#[derive(Clone, Debug, Default)]
pub struct HistoryTarget {
    /// Under this directory of the folder, as `name (restored).ext` when taken.
    pub to: Option<String>,
    /// As this name (beside the file) or folder path; refused when taken.
    pub as_name: Option<String>,
}

impl Engine {
    /// Days a folder's history keeps versions; `None` when it keeps no new ones.
    pub fn history_days_for(&self, folder: &FolderId) -> Option<u32> {
        let s = self.trash_settings();
        let d = s
            .folder_history
            .get(folder)
            .copied()
            .unwrap_or(s.history_days);
        (d > 0).then(|| d.min(MAX_HISTORY_DAYS))
    }

    /// Days the versions already kept stay (a folder turned off keeps its
    /// versions on the vault's schedule).
    pub(super) fn history_keep_days(&self, folder: &FolderId) -> u32 {
        self.history_days_for(folder).unwrap_or_else(|| {
            let v = self.trash_settings().history_days;
            if v > 0 {
                v.min(MAX_HISTORY_DAYS)
            } else {
                DEFAULT_HISTORY_DAYS
            }
        })
    }

    /// Record the versions this device replaced (a scan that found a file
    /// changed, a write into a folder kept encrypted here): `replaced`
    /// holds each previous version and the clock of the new one. A version
    /// whose blocks are on no storage and in no cache here (written and
    /// replaced between two uploads) cannot be restored and is not kept.
    pub(super) fn history_record_replacements(
        &self,
        rec: &FolderRecord,
        replaced: Vec<(FileState, u64)>,
    ) -> Result<()> {
        if replaced.is_empty() || rec.is_backup() || self.history_days_for(&rec.folder_id).is_none()
        {
            return Ok(());
        }
        let view = self.view()?;
        let me = self.vault.device_id.clone();
        let now = util::now_utc();
        let mut out = Vec::new();
        for (prev, clock) in replaced {
            if prev.deleted {
                continue;
            }
            let readable = prev.chunks.iter().all(|c| {
                view.locate(&rec.folder_id, &c.chunk)
                    .is_some_and(|r| r.object == c.object && !r.storages.is_empty())
                    || self.cached_object(&c.object).is_some()
            });
            if !readable {
                continue;
            }
            out.push(TrashEntry {
                id: entry_id(&rec.folder_id, &prev.path, &me, clock),
                author: Some(prev.modified_by),
                path: prev.path,
                size: prev.size,
                mtime: prev.mtime,
                content_hash: prev.content_hash,
                chunks: prev.chunks,
                deleted_utc: now,
                deleted_by: me.clone(),
                clock,
            });
        }
        self.add_own_versions(&rec.folder_id, out)
    }

    /// The versions of a file the history keeps at `now`, newest first.
    fn versions_of(&self, folder: &FolderId, path: &str, now: i64) -> Vec<TrashEntry> {
        self.trash_sets(folder, now)
            .versions
            .into_iter()
            .filter(|e| e.path == path)
            .collect()
    }

    /// The versions of a file, newest first.
    pub fn history_list(&mut self, folder: &str, path: &str) -> Result<HistoryList> {
        self.history_list_at(folder, path, util::now_utc())
    }

    /// `history_list` as if it were `now` (tests).
    pub fn history_list_at(&mut self, folder: &str, path: &str, now: i64) -> Result<HistoryList> {
        self.trash_refresh(true)?;
        let rec = self
            .trash_folders(Some(folder))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let path = path.trim_matches('/');
        util::check_rel_path(path)?;
        let state = self.load_state(&rec.folder_id)?;
        let current = state.files.get(path).filter(|f| !f.deleted);
        let mut seen: HashSet<ChunkId> = current
            .map(|f| f.chunks.iter().map(|c| c.chunk.clone()).collect())
            .unwrap_or_default();
        let view = self.view()?;
        let mut list = HistoryList {
            folder: rec.name.clone(),
            path: path.to_string(),
            days: self.history_days_for(&rec.folder_id),
            current_size: current.map(|f| f.size),
            current_mtime: current.map(|f| f.mtime),
            versions: Vec::new(),
        };
        for e in self.versions_of(&rec.folder_id, path, now) {
            let mut new_bytes = 0;
            for c in &e.chunks {
                if seen.insert(c.chunk.clone()) {
                    new_bytes += c.size;
                }
            }
            let (storages, cold_only) = self.entry_storages(&view, &rec.folder_id, &e);
            list.versions.push(HistoryItem {
                id: e.id.clone(),
                path: e.path.clone(),
                size: e.size,
                mtime: e.mtime,
                replaced_utc: e.deleted_utc,
                replaced_by: self.device_name(&e.deleted_by),
                replaced_by_id: e.deleted_by.to_string(),
                author: e.author.as_ref().map(|d| self.device_name(d)),
                new_bytes,
                clock: e.clock,
                storages,
                cold_only,
            });
        }
        Ok(list)
    }

    /// The version `which` names: an id (or its first six or more
    /// characters), or a time (`parse_utc`): the version that was current
    /// then, i.e. the first one replaced after it.
    fn pick_version(
        &self,
        rec: &FolderRecord,
        path: &str,
        which: &str,
        now: i64,
    ) -> Result<TrashEntry> {
        let versions = self.versions_of(&rec.folder_id, path, now);
        if versions.is_empty() {
            bail!("{path} in {} has no earlier versions", rec.name);
        }
        let w = which.trim().to_ascii_lowercase();
        if w.len() >= 6 && w.bytes().all(|b| b.is_ascii_hexdigit()) {
            let hits: Vec<&TrashEntry> = versions.iter().filter(|e| e.id.starts_with(&w)).collect();
            match hits.len() {
                1 => return Ok(hits[0].clone()),
                0 => {}
                _ => bail!("{which} names more than one version; give more of the id"),
            }
        }
        let Some(t) = parse_utc(which) else {
            bail!("no version {which} of {path}: give a version id from `varsto history` or a time (YYYY-MM-DD or YYYY-MM-DD HH:MM, UTC)");
        };
        versions
            .into_iter()
            .filter(|e| e.deleted_utc > t)
            .min_by(|a, b| {
                (a.deleted_utc, a.clock, &a.id).cmp(&(b.deleted_utc, b.clock, &b.id))
            })
            .ok_or_else(|| anyhow!("{path} has not changed since {which}: the current version is the one of that time"))
    }

    /// Where a version goes: its own path (over the current file), a free
    /// name under `to`, or `as_name`.
    fn history_target(
        &self,
        rec: &FolderRecord,
        root: &Path,
        e: &TrashEntry,
        target: &HistoryTarget,
    ) -> Result<String> {
        match (&target.to, &target.as_name) {
            (Some(_), Some(_)) => bail!("give either a directory or a new name, not both"),
            (Some(to), None) => {
                let picked = vec![(e.clone(), e.path.clone())];
                let mut t = self.restore_targets(rec, root, &picked, Some(to))?;
                Ok(t.remove(0))
            }
            (None, Some(name)) => {
                let name = name.trim_matches('/');
                if name.is_empty() {
                    bail!("give the new name");
                }
                let target = if name.contains('/') {
                    name.to_string()
                } else {
                    match e.path.rsplit_once('/') {
                        Some((dir, _)) => format!("{dir}/{name}"),
                        None => name.to_string(),
                    }
                };
                util::check_rel_path(&target)?;
                let state = self.load_state(&rec.folder_id)?;
                let taken = state.files.get(&target).is_some_and(|f| !f.deleted)
                    || state
                        .pending_remote
                        .get(&target)
                        .is_some_and(|f| !f.deleted)
                    || (!self.mount_is_encrypted(&rec.folder_id) && {
                        let d = self.disk_of(root, &state, &target);
                        d.exists() || placeholder_path(&d).exists()
                    });
                if taken {
                    bail!("{target} already exists: choose another name (nothing is overwritten)");
                }
                Ok(target)
            }
            (None, None) => Ok(e.path.clone()),
        }
    }

    /// What restoring a version takes: where it goes, what is read from
    /// cold storage and what that costs.
    pub fn history_restore_plan(
        &mut self,
        folder: &str,
        path: &str,
        which: &str,
        target: &HistoryTarget,
    ) -> Result<TrashRestorePlan> {
        self.trash_refresh(true)?;
        let (rec, root) = self.resolve_folder(folder)?;
        let path = path.trim_matches('/');
        let e = self.pick_version(&rec, path, which, util::now_utc())?;
        let to = self.history_target(&rec, &root, &e, target)?;
        Ok(self.version_plan(&rec, &e, to))
    }

    fn version_plan(&self, rec: &FolderRecord, e: &TrashEntry, to: String) -> TrashRestorePlan {
        let mut plan = TrashRestorePlan {
            folder: rec.name.clone(),
            files: 1,
            bytes: e.size,
            targets: vec![(e.path.clone(), to)],
            ..Default::default()
        };
        let mut cold = BTreeSet::new();
        if let Ok(view) = self.view() {
            self.plan_reads(&view, &rec.folder_id, e, &mut plan, &mut cold);
        }
        self.plan_finish(&mut plan, cold);
        plan
    }

    /// Restore a version of a file. Without a target it becomes the current
    /// version at its path, and the current version is kept as a version
    /// itself (the folder is synced first, so a change not yet seen is not
    /// lost); with `to` or `as_name` it is written to another, free path.
    /// Nothing is overwritten without becoming a version. Blocks only a
    /// cold storage holds are read only with `confirm_cold_read`.
    pub fn history_restore(
        &mut self,
        folder: &str,
        path: &str,
        which: &str,
        target: &HistoryTarget,
        confirm_cold_read: bool,
    ) -> Result<HistoryRestoreReport> {
        self.ensure_active()?;
        self.trash_refresh(true)?;
        let (rec, root) = self.resolve_for_write(folder)?;
        // A read-only member restores nothing into the shared folder.
        self.ensure_share_writable(&rec)?;
        if self.mount_mode(&rec.folder_id) == crate::vault::FolderMode::ReceiveOnly {
            // A restored file would be a local change this device does not
            // publish (`folder_safety`).
            bail!(
                "folder {} is receive-only on this device: a restored version would not reach the other devices; restore it on another device or change the folder's mode first",
                rec.name
            );
        }
        let path = path.trim_matches('/').to_string();
        util::check_rel_path(&path)?;
        let now = util::now_utc();
        let e = self.pick_version(&rec, &path, which, now)?;
        let to = self.history_target(&rec, &root, &e, target)?;
        let in_place = to == e.path;
        let plan = self.version_plan(&rec, &e, to.clone());
        if !plan.cold_storages.is_empty() && !confirm_cold_read {
            return Err(Self::cold_read_refusal(&plan));
        }
        if !plan.unavailable.is_empty() {
            bail!("some blocks of this version of {path} are not available on any storage this device can read");
        }
        let encrypted = self.mount_is_encrypted(&rec.folder_id);
        if in_place {
            // Whatever is on disk now is recorded (and uploaded) first: it
            // becomes a version when the restored one replaces it.
            self.push(rec.folder_id.as_str())?;
            let state = self.load_state(&rec.folder_id)?;
            if state
                .files
                .get(&path)
                .is_some_and(|f| !f.deleted && f.content_hash == e.content_hash)
            {
                bail!("this version of {path} is already the current one");
            }
        }
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(confirm_cold_read)?;
        let task = activity::start(
            activity::HISTORY_RESTORE,
            &rec.name,
            e.size,
            activity::Unit::Bytes,
        );
        let tmp_dir = self.home.join("trash").join(".restore");
        util::private_dir(&self.home.join("trash"))?;
        fs::create_dir_all(&tmp_dir)?;
        let tmp = tmp_dir.join(format!("{}-v{}", std::process::id(), e.id));
        let got = self.restore_from_blocks(&rec, &fk, &e, &tmp, &storages);
        if let Err(err) = got {
            let _ = fs::remove_file(&tmp);
            return Err(err.context(format!("restore a version of {path}")));
        }
        if Self::file_content_hash(&fk, &tmp).as_deref() != Some(e.content_hash.as_str()) {
            let _ = fs::remove_file(&tmp);
            bail!("the restored version of {path} did not match its content hash");
        }
        task.advance(e.size);
        let mut state = self.load_state(&rec.folder_id)?;
        let replaced_current = in_place && state.files.get(&path).is_some_and(|f| !f.deleted);
        if encrypted {
            // The write replaces the cached file; the replaced one is kept
            // as a version (`record_cached`).
            let written = fs::File::open(&tmp)
                .map_err(anyhow::Error::from)
                .and_then(|f| {
                    self.write_from_reader_sized(rec.folder_id.as_str(), &to, f, Some(e.size))
                });
            let _ = fs::remove_file(&tmp);
            written?;
        } else {
            // Under the local name the path has (or gets) here (`crate::names`).
            util::check_rel_path(&to)?;
            let disk = self.place(&root, &mut state, &to, None)?;
            self.check_no_link_above(&root, &state, &to)?;
            self.save_state(&rec.folder_id, &state)?;
            if fs::symlink_metadata(&disk).is_ok_and(|m| m.file_type().is_symlink()) {
                let _ = fs::remove_file(&tmp);
                bail!("{to} is a symbolic link here; a version is not written through it");
            }
            if in_place {
                // Changed after the sync above: not overwritten.
                let unchanged = match (fs::metadata(&disk), state.local_index.get(&to)) {
                    (Err(_), _) => true,
                    (Ok(md), Some(ix)) => {
                        let mtime = md
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_nanos() as i64)
                            .unwrap_or(0);
                        md.len() == ix.size && mtime == ix.mtime
                    }
                    (Ok(_), None) => false,
                };
                if !unchanged {
                    let _ = fs::remove_file(&tmp);
                    bail!("{to} changed while restoring; nothing was overwritten, try again");
                }
            } else if disk.exists() || placeholder_path(&disk).exists() {
                let _ = fs::remove_file(&tmp);
                bail!("{to} appeared meanwhile; nothing was overwritten");
            }
            if let Some(parent) = disk.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::rename(&tmp, &disk).is_err() {
                fs::copy(&tmp, &disk)?;
                let _ = fs::remove_file(&tmp);
            }
            let _ = fs::remove_file(placeholder_path(&disk));
            if !in_place && e.mtime > 0 {
                let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(e.mtime as u64);
                if let Ok(f) = fs::File::options().write(true).open(&disk) {
                    let _ = f.set_modified(t);
                }
            }
            // A new version; the one it replaced is kept by the scan.
            self.push(rec.folder_id.as_str())?;
        }
        Ok(HistoryRestoreReport {
            folder: rec.name.clone(),
            path,
            version: e.id.clone(),
            replaced_utc: e.deleted_utc,
            to,
            size: e.size,
            replaced_current,
            cold_read: !plan.cold_storages.is_empty(),
        })
    }

    /// Settings, versions and the bytes the history really takes per folder
    /// and storage.
    pub fn history_status(&mut self) -> Result<HistoryStatus> {
        self.history_status_at(util::now_utc())
    }

    fn history_status_at(&mut self, now: i64) -> Result<HistoryStatus> {
        self.trash_refresh(true)?;
        let settings = self.trash_settings();
        let view = self.view()?;
        let mut st = HistoryStatus {
            days: settings.history_days,
            schedule: schedule_words(),
            storage: self.trash_storage_here(),
            ..Default::default()
        };
        if let Some(n) = &st.storage {
            st.storage_cold = self
                .config
                .storages
                .iter()
                .any(|s| s.name() == n && s.is_cold());
        }
        for (fid, d) in &settings.folder_history {
            if let Some(r) = self.keyring.folders.get(fid).filter(|r| !r.is_removed()) {
                st.folder_days.insert(r.name.clone(), *d);
            }
        }
        for rec in self.trash_folders(None)? {
            let state = self.load_state(&rec.folder_id).unwrap_or_default();
            let current: HashSet<ChunkId> = state
                .files
                .values()
                .chain(state.pending_remote.values())
                .filter(|f| !f.deleted)
                .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
                .collect();
            let mut fh = FolderHistory {
                folder: rec.name.clone(),
                folder_id: rec.folder_id.to_string(),
                days: self.history_days_for(&rec.folder_id),
                ..Default::default()
            };
            let mut files: HashSet<String> = HashSet::new();
            let mut seen: HashSet<ChunkId> = HashSet::new();
            for e in self.trash_sets(&rec.folder_id, now).versions {
                fh.versions += 1;
                fh.bytes += e.size;
                files.insert(e.path.clone());
                for c in &e.chunks {
                    if current.contains(&c.chunk) || !seen.insert(c.chunk.clone()) {
                        continue;
                    }
                    fh.extra_bytes += c.size;
                    if let Some(r) = view.locate(&rec.folder_id, &c.chunk) {
                        for n in r.storages.keys() {
                            *fh.by_storage.entry(n.clone()).or_default() += c.size;
                        }
                    }
                }
            }
            fh.files = files.len() as u64;
            st.versions += fh.versions;
            st.extra_bytes += fh.extra_bytes;
            for (n, b) in &fh.by_storage {
                *st.by_storage.entry(n.clone()).or_default() += b;
            }
            st.folders.push(fh);
        }
        Ok(st)
    }

    /// Change how long versions are kept: for the vault (`days`, or `off`),
    /// or with `folder` for one folder (`days`, `off`, or days 0 to follow
    /// the vault again). Published with the trash settings.
    pub fn history_set(
        &mut self,
        days: Option<u32>,
        folder: Option<&str>,
        off: bool,
    ) -> Result<HistoryStatus> {
        if self.vault.member {
            bail!("a member device cannot change the owner's history settings");
        }
        self.org_allows(
            |p| p.members_may_set_policies,
            "change the history settings",
        )?;
        let mut s: TrashSettings = self.trash_settings_fresh()?;
        if off && days.is_some() {
            bail!("give either --days or --off");
        }
        if days.is_some_and(|d| d > MAX_HISTORY_DAYS) {
            bail!("the history keeps versions at most {MAX_HISTORY_DAYS} days");
        }
        match folder {
            Some(f) => {
                let rec = self
                    .keyring
                    .find(f)
                    .filter(|r| !r.is_removed() && !r.is_backup())
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown folder {f}"))?;
                match (days, off) {
                    (_, true) => {
                        s.folder_history.insert(rec.folder_id.clone(), 0);
                    }
                    (Some(0), _) => {
                        s.folder_history.remove(&rec.folder_id);
                    }
                    (Some(d), _) => {
                        s.folder_history.insert(rec.folder_id.clone(), d);
                    }
                    (None, false) => bail!("give --days or --off with --folder"),
                }
            }
            None => match (days, off) {
                (_, true) => s.history_days = 0,
                (Some(0), _) => bail!("use --off to keep no versions"),
                (Some(d), _) => s.history_days = d,
                (None, false) => bail!("give --days or --off"),
            },
        }
        self.publish_trash_settings(s)?;
        self.history_status()
    }
}

/// The thinning schedule, in words.
pub fn schedule_words() -> Vec<String> {
    vec![
        "every version for 1 hour".to_string(),
        "one per hour for 1 day".to_string(),
        "one per day for 30 days".to_string(),
        "one per week until the history days".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_parse_in_utc() {
        assert_eq!(parse_utc("1970-01-01 00:00"), Some(0));
        assert_eq!(parse_utc("1970-01-02T01:02:03Z"), Some(DAY + HOUR + 123));
        assert_eq!(parse_utc("1970-01-01"), Some(DAY - 1));
        assert_eq!(parse_utc("2026-10-13 12:00 UTC"), Some(1_791_892_800));
        assert_eq!(parse_utc("2024-02-29"), Some(1_709_251_199));
        assert_eq!(parse_utc("2026-13-01"), None);
        assert_eq!(parse_utc("abcdef"), None);
        assert_eq!(parse_utc("2026-10-13 25:00"), None);
    }

    #[test]
    fn ties_keep_one_version_per_bucket() {
        let now = 100 * WEEK;
        let t = now - 2 * DAY + HOUR;
        let v = [(t, 5, "b"), (t, 5, "a"), (t, 4, "d"), (t - 10, 9, "c")];
        assert_eq!(history_kept(&v, now, 90), vec![true, false, false, false]);
        // Past the history days: nothing.
        assert_eq!(history_kept(&v, now + 100 * DAY, 90), vec![false; 4]);
        // A version from a clock ahead of this one's is kept.
        assert_eq!(history_kept(&[(now + 50, 1, "x")], now, 1), vec![true]);
    }
}
