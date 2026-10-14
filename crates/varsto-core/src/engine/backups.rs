// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backups (`docs/spec/alpha-0-format.md` section 31): read-only snapshots
//! of a directory on one device, kept on storages only.
//!
//! A backup is a folder record with `backup` set. It has its own keys,
//! placement and ledger chunk records like any folder, but it is never
//! mounted: only its source device writes it, by taking snapshots of the
//! directory (scan, upload what the storages lack, then write the snapshot
//! object and record `Event::SnapshotTaken`). No device records holding its
//! blocks (`ChunkOnDevice`) and peers never serve them, so the contents stay
//! on the storages, never on the vault's other devices. Transferrers are
//! never written.
//!
//! A snapshot fixes its expiry when it is taken (retention in days). Expired
//! snapshots are deleted with the blocks no live snapshot of the backup uses:
//! after a grace period, by the source device, or by any device once the
//! backup is stopped, its source is removed from the vault, or two days have
//! passed. The expiry and the drops are sealed and pushed before anything is
//! deleted, and the snapshot listing is read again first, so a snapshot
//! written meanwhile keeps its blocks. A source device that just wrote a
//! snapshot checks the ledger again and writes back any of its blocks that
//! a concurrent expiry dropped.
//!
//! A restore writes one snapshot (or some of its paths) into a directory the
//! user names, which must be empty unless overwriting is asked for.

use super::*;
use crate::ledger::SnapshotRecord;
use crate::placement::Placement;
use crate::snapshot::Snapshot;
use crate::vault::{BackupInfo, BackupSchedule, BackupSource, DEFAULT_BACKUP_RETENTION_DAYS};

const DAY: i64 = 86_400;
/// An expired snapshot is deleted this long after its expiry time, so that
/// devices whose clocks differ a little agree about it.
pub const EXPIRY_GRACE_SECS: i64 = DAY;
/// Devices other than the source expire snapshots of a backup whose source
/// is still in the vault only this long after their expiry time.
pub const OTHERS_EXPIRE_AFTER_SECS: i64 = 2 * DAY;

/// How a new backup is kept.
#[derive(Clone, Debug)]
pub struct BackupOptions {
    pub retention_days: u32,
    pub schedule: BackupSchedule,
    /// Storages or places to keep it on; `None`: every storage of this
    /// device that is not a transferrer.
    pub placement: Option<Placement>,
}

impl Default for BackupOptions {
    fn default() -> Self {
        BackupOptions {
            retention_days: DEFAULT_BACKUP_RETENTION_DAYS,
            schedule: BackupSchedule::default(),
            placement: None,
        }
    }
}

/// Which snapshot a restore takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotPick {
    Latest,
    Seq(u64),
    /// The newest snapshot taken at or before this time (UTC seconds).
    OnOrBefore(i64),
}

impl SnapshotPick {
    /// "latest", a sequence number, or a day "YYYY-MM-DD" (the newest
    /// snapshot taken by the end of that day, UTC).
    pub fn parse(s: &str) -> Result<SnapshotPick> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("latest") {
            return Ok(SnapshotPick::Latest);
        }
        if let Ok(n) = s.parse::<u64>() {
            return Ok(SnapshotPick::Seq(n));
        }
        let parts: Vec<&str> = s.split('-').collect();
        if let [y, m, d] = parts.as_slice() {
            if let (Ok(y), Ok(m), Ok(d)) = (y.parse::<i64>(), m.parse::<i64>(), d.parse::<i64>()) {
                if (1..=12).contains(&m) && (1..=31).contains(&d) && y >= 1970 {
                    return Ok(SnapshotPick::OnOrBefore(
                        days_from_civil(y, m, d) * DAY + DAY - 1,
                    ));
                }
            }
        }
        bail!("give a snapshot number, \"latest\" or a day as YYYY-MM-DD, not {s:?}")
    }
}

/// Days since 1970-01-01 of a calendar day (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[derive(Clone, Debug, Serialize)]
pub struct BackupSummary {
    pub backup_id: String,
    pub name: String,
    pub source_device: String,
    pub source_device_id: String,
    pub source_path: String,
    /// This device takes the snapshots.
    pub this_device: bool,
    pub retention_days: u32,
    /// "daily", "weekly", "manual", "every N h"; only on the source device.
    pub schedule: Option<String>,
    pub stopped: bool,
    /// Live snapshots.
    pub snapshots: u64,
    pub latest_seq: Option<u64>,
    pub latest_utc: Option<i64>,
    pub latest_files: u64,
    pub latest_bytes: u64,
    /// The storages it is kept on (as this device names them).
    pub storages: Vec<String>,
    /// When the next scheduled snapshot is due (source device only).
    pub next_due_utc: Option<i64>,
    /// A snapshot was asked for and the service has not taken it yet.
    pub snapshot_requested: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotInfo {
    pub seq: u64,
    pub device: String,
    pub taken_utc: i64,
    pub expires_utc: i64,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SnapshotReport {
    pub backup: String,
    pub seq: u64,
    pub taken_utc: i64,
    pub expires_utc: i64,
    pub files: u64,
    pub bytes: u64,
    pub files_changed: u64,
    pub chunks_uploaded: u64,
    pub bytes_uploaded: u64,
    /// Files left out: unreadable, or not stored completely.
    pub skipped: Vec<String>,
    pub storages_unavailable: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RestoreReport {
    pub backup: String,
    pub seq: u64,
    pub taken_utc: i64,
    pub to: PathBuf,
    pub files_restored: u64,
    pub bytes_restored: u64,
    /// Files that could not be restored, with the reason.
    pub unavailable: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExpireReport {
    pub snapshots_expired: u64,
    pub snapshots_deleted: u64,
    pub objects_deleted: u64,
    /// Stopped backups whose last snapshot expired: removed from the vault.
    pub backups_removed: Vec<String>,
    /// Backups whose deletions wait because a live snapshot could not be read.
    pub waiting: Vec<String>,
}

/// What this device remembers of a backup's snapshots:
/// `state/backups/<backup>.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct BackupCache {
    /// The blocks of each snapshot read or written here, by "<device>/<seq>".
    #[serde(default)]
    snapshots: BTreeMap<String, Vec<(ChunkId, ObjectName)>>,
    /// Expired snapshots whose blocks and object are deleted.
    #[serde(default)]
    cleaned: BTreeSet<String>,
}

fn snap_key(device: &DeviceId, seq: u64) -> String {
    format!("{device}/{seq}")
}

fn blocks_of(snap: &Snapshot) -> Vec<(ChunkId, ObjectName)> {
    let mut seen = HashSet::new();
    snap.files
        .values()
        .flat_map(|f| f.chunks.iter())
        .filter(|c| seen.insert(c.object.clone()))
        .map(|c| (c.chunk.clone(), c.object.clone()))
        .collect()
}

/// Whether `path` is one of `wanted` or inside one of them (no filter: all).
fn path_wanted(path: &str, wanted: &[String]) -> bool {
    wanted.is_empty()
        || wanted.iter().any(|w| {
            let w = w.trim_matches('/');
            w.is_empty() || path == w || path.strip_prefix(w).is_some_and(|r| r.starts_with('/'))
        })
}

impl Engine {
    // ----- records -----------------------------------------------------------

    /// Create a backup of the directory `path` on this device. Nothing is
    /// read yet: `take_snapshot` takes the first snapshot.
    pub fn add_backup(&mut self, name: &str, path: &Path, opts: BackupOptions) -> Result<FolderId> {
        crate::logged_op_plain!("add backup", name, {
            self.add_backup_inner(name, path, opts)
        })
    }

    fn add_backup_inner(
        &mut self,
        name: &str,
        path: &Path,
        opts: BackupOptions,
    ) -> Result<FolderId> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("this device is a member of a shared folder only; it cannot make backups in the owner's vault");
        }
        if opts.retention_days == 0 {
            bail!("a backup keeps its snapshots for at least one day");
        }
        if opts.schedule == BackupSchedule::EveryHours(0) {
            bail!("a schedule needs at least one hour between snapshots");
        }
        let source =
            canonical(path).with_context(|| format!("{} cannot be read", path.display()))?;
        if !source.is_dir() {
            bail!("{} is not a directory", source.display());
        }
        if !self.config.storages.iter().any(|s| !s.is_carrier()) {
            bail!("backups are kept on storages only, and this device has none (transferrers do not count): add a storage first");
        }
        let placement = self.checked_placement(opts.placement)?;
        self.ensure_unique_folder_name(name)?;
        let now = util::now_utc();
        let me = self.vault.device_id.clone();
        let rec = FolderRecord {
            folder_id: FolderId::random(),
            name: name.trim().to_string(),
            key_hex: SecretKey::random().to_hex(),
            created_by: me.clone(),
            created_utc: now,
            shared: false,
            policy: None,
            policy_updated_utc: 0,
            placement_updated_utc: if placement.is_some() { now } else { 0 },
            placement,
            strongroom: None,
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
            backup: Some(BackupInfo {
                source_device: me,
                source_path: source.display().to_string(),
                retention_days: opts.retention_days,
                created_utc: now,
            }),
            share_join: None,
        };
        let id = rec.folder_id.clone();
        self.keyring.folders.insert(id.clone(), rec);
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.config.backups.push(BackupSource {
            folder_id: id.clone(),
            path: source,
            schedule: opts.schedule,
            retention_days: opts.retention_days,
            last_taken_utc: 0,
            last_seq: 0,
            stopped: false,
            take_now: false,
        });
        self.config.save(&self.home)?;
        self.pending.push(Event::FolderAdded { folder: id.clone() });
        self.publish_registry()?;
        self.commit_batch()?;
        Ok(id)
    }

    fn resolve_backup(&self, name_or_id: &str) -> Result<FolderRecord> {
        self.keyring
            .find_backup(name_or_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown backup {name_or_id}"))
    }

    /// This device's settings for a backup it is the source of.
    fn backup_source(&self, rec: &FolderRecord) -> Result<BackupSource> {
        if let Some(src) = self
            .config
            .backups
            .iter()
            .find(|b| b.folder_id == rec.folder_id)
        {
            return Ok(src.clone());
        }
        let source = rec
            .backup
            .as_ref()
            .map(|b| self.device_name(&b.source_device))
            .unwrap_or_default();
        bail!(
            "{} is backed up from {source}: only that device takes its snapshots and changes its settings",
            rec.name
        )
    }

    fn save_backup_source(&mut self, src: BackupSource) -> Result<()> {
        for b in self.config.backups.iter_mut() {
            if b.folder_id == src.folder_id {
                *b = src.clone();
            }
        }
        self.config.save(&self.home)
    }

    /// The snapshots of one backup the ledger knows, in order.
    fn snapshot_records(
        view: &LedgerView,
        backup: &FolderId,
    ) -> Vec<((DeviceId, u64), SnapshotRecord)> {
        let mut out: Vec<((DeviceId, u64), SnapshotRecord)> = view
            .snapshots
            .iter()
            .filter(|((b, _, _), _)| b == backup)
            .map(|((_, d, s), r)| ((d.clone(), *s), r.clone()))
            .collect();
        out.sort_by(|a, b| (a.1.taken_utc, a.0 .1, &a.0 .0).cmp(&(b.1.taken_utc, b.0 .1, &b.0 .0)));
        out
    }

    // ----- listing -------------------------------------------------------------

    /// The vault's backups.
    pub fn backups(&self) -> Result<Vec<BackupSummary>> {
        let view = self.view()?;
        let now = util::now_utc();
        let mut out = Vec::new();
        for rec in self
            .keyring
            .folders
            .values()
            .filter(|r| r.is_backup() && !r.is_removed())
        {
            let info = rec.backup.as_ref().expect("a backup");
            let local = self
                .config
                .backups
                .iter()
                .find(|b| b.folder_id == rec.folder_id);
            let live: Vec<SnapshotRecord> = Self::snapshot_records(&view, &rec.folder_id)
                .into_iter()
                .map(|(_, r)| r)
                .filter(|r| r.is_live())
                .collect();
            let latest_seq = Self::snapshot_records(&view, &rec.folder_id)
                .into_iter()
                .filter(|(_, r)| r.is_live())
                .map(|(k, _)| k.1)
                .next_back();
            let latest = live.last();
            let stopped =
                view.backups_stopped.contains(&rec.folder_id) || local.is_some_and(|l| l.stopped);
            let storages = self
                .placement(rec.folder_id.as_str())
                .map(|p| p.targets)
                .unwrap_or_default();
            out.push(BackupSummary {
                backup_id: rec.folder_id.to_string(),
                name: rec.name.clone(),
                source_device: self.device_name(&info.source_device),
                source_device_id: info.source_device.to_string(),
                source_path: info.source_path.clone(),
                this_device: info.source_device == self.vault.device_id,
                retention_days: local
                    .map(|l| l.retention_days)
                    .unwrap_or(info.retention_days),
                schedule: local.map(|l| l.schedule.describe()),
                stopped,
                snapshots: live.len() as u64,
                latest_seq,
                latest_utc: latest.map(|r| r.taken_utc),
                latest_files: latest.map(|r| r.files).unwrap_or(0),
                latest_bytes: latest.map(|r| r.bytes).unwrap_or(0),
                storages,
                next_due_utc: local.filter(|_| !stopped).and_then(|l| match l.schedule {
                    BackupSchedule::Manual => None,
                    BackupSchedule::EveryHours(_) if l.last_taken_utc == 0 => Some(now),
                    BackupSchedule::EveryHours(h) => Some(l.last_taken_utc + h as i64 * 3600),
                }),
                snapshot_requested: local.is_some_and(|l| l.take_now && !stopped),
            });
        }
        out.sort_by_key(|b| b.name.to_lowercase());
        Ok(out)
    }

    /// The live snapshots of a backup, oldest first.
    pub fn backup_snapshots(&self, backup: &str) -> Result<Vec<SnapshotInfo>> {
        let rec = self.resolve_backup(backup)?;
        let view = self.view()?;
        Ok(Self::snapshot_records(&view, &rec.folder_id)
            .into_iter()
            .filter(|(_, r)| r.is_live())
            .map(|((d, seq), r)| SnapshotInfo {
                seq,
                device: self.device_name(&d),
                taken_utc: r.taken_utc,
                expires_utc: r.expires_utc,
                files: r.files,
                bytes: r.bytes,
            })
            .collect())
    }

    /// Names of the backups of this device whose scheduled snapshot is due.
    pub fn backups_due(&self, now: i64) -> Vec<String> {
        let stopped = self.view().map(|v| v.backups_stopped).unwrap_or_default();
        self.config
            .backups
            .iter()
            .filter(|b| !b.stopped && !stopped.contains(&b.folder_id))
            .filter(|b| {
                b.take_now
                    || match b.schedule {
                        BackupSchedule::Manual => false,
                        BackupSchedule::EveryHours(h) => now >= b.last_taken_utc + h as i64 * 3600,
                    }
            })
            .filter_map(|b| {
                self.keyring
                    .folders
                    .get(&b.folder_id)
                    .filter(|r| r.is_backup() && !r.is_removed())
                    .map(|r| r.name.clone())
            })
            .collect()
    }

    // ----- settings ------------------------------------------------------------

    /// Change the retention or the schedule of a backup of this device. The
    /// retention applies to snapshots taken from now on.
    pub fn set_backup(
        &mut self,
        backup: &str,
        retention_days: Option<u32>,
        schedule: Option<BackupSchedule>,
    ) -> Result<()> {
        let rec = self.resolve_backup(backup)?;
        let mut src = self.backup_source(&rec)?;
        if let Some(days) = retention_days {
            if days == 0 {
                bail!("a backup keeps its snapshots for at least one day");
            }
            src.retention_days = days;
        }
        if let Some(s) = schedule {
            if s == BackupSchedule::EveryHours(0) {
                bail!("a schedule needs at least one hour between snapshots");
            }
            src.schedule = s;
        }
        self.save_backup_source(src)
    }

    /// Ask for a snapshot of a backup of this device without waiting for
    /// it: the background service takes it on its next run, so a request
    /// from the interface returns at once even for a large directory.
    pub fn request_snapshot(&mut self, backup: &str) -> Result<()> {
        let rec = self.resolve_backup(backup)?;
        let mut src = self.backup_source(&rec)?;
        if src.stopped {
            bail!("backup {} is stopped: it takes no more snapshots", rec.name);
        }
        src.take_now = true;
        self.save_backup_source(src)
    }

    /// Stop a backup: no more snapshots are taken. The snapshots kept expire
    /// as they would, and the backup goes with the last of them.
    pub fn stop_backup(&mut self, backup: &str) -> Result<()> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot change the owner's backups");
        }
        let rec = self.resolve_backup(backup)?;
        if !self.view()?.backups_stopped.contains(&rec.folder_id) {
            self.pending.push(Event::BackupStopped {
                backup: rec.folder_id.clone(),
            });
            self.commit_batch()?;
        }
        if let Ok(mut src) = self.backup_source(&rec) {
            src.stopped = true;
            self.save_backup_source(src)?;
        }
        Ok(())
    }

    // ----- snapshots -------------------------------------------------------------

    /// Take a snapshot of a backup of this device: read the directory,
    /// upload the blocks the storages lack, and write the snapshot. A
    /// snapshot is written also when nothing changed.
    pub fn take_snapshot(&mut self, backup: &str) -> Result<SnapshotReport> {
        crate::logged_op!("take snapshot", backup, {
            self.take_snapshot_inner(backup)
        })
    }

    fn take_snapshot_inner(&mut self, backup: &str) -> Result<SnapshotReport> {
        self.ensure_active()?;
        self.ensure_ledger_writable()?;
        let rec = self.resolve_backup(backup)?;
        let mut src = self.backup_source(&rec)?;
        if src.stopped || self.view()?.backups_stopped.contains(&rec.folder_id) {
            bail!("{} is stopped: it takes no more snapshots", rec.name);
        }
        if !src.path.is_dir() {
            bail!(
                "{} is not there any more: nothing to back up",
                src.path.display()
            );
        }
        let me = self.vault.device_id.clone();
        let metadata: OpenStorages = self
            .metadata_storages(true)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        if metadata.is_empty() {
            bail!("no storage of this device can keep the snapshot: add one first");
        }
        self.pull_ledger()?;
        // The scan and the upload below list their own tasks.
        let _task = crate::activity::start(
            crate::activity::BACKUP_SNAPSHOT,
            &rec.name,
            0,
            crate::activity::Unit::Items,
        );

        // 1. Read the directory and store what the storages lack.
        let mut state = self.load_state(&rec.folder_id)?;
        let mut push = PushReport::default();
        let (_, changed) = self.scan(&rec, &src.path, &mut state)?;
        let mut report = SnapshotReport {
            backup: rec.name.clone(),
            files_changed: changed,
            ..Default::default()
        };
        self.upload_missing(&rec, &src.path, &state, &mut push)?;

        // 2. Every file in the snapshot must be on a storage; a file that
        // changed while it was read gets one more try.
        let mut incomplete = self.incomplete_files(&rec, &state)?;
        if !incomplete.is_empty() {
            let (_, changed) = self.scan(&rec, &src.path, &mut state)?;
            report.files_changed += changed;
            self.upload_missing(&rec, &src.path, &state, &mut push)?;
            incomplete = self.incomplete_files(&rec, &state)?;
        }
        let mut skipped: BTreeSet<String> = incomplete;
        skipped.extend(state.unreadable.iter().cloned());

        // 3. The snapshot itself, written once to every storage.
        let files: BTreeMap<String, FileState> = state
            .files
            .values()
            .filter(|f| !f.deleted && !skipped.contains(&f.path))
            .map(|f| (f.path.clone(), f.clone()))
            .collect();
        let view = self.view()?;
        let mut seq = view
            .snapshots
            .keys()
            .filter(|(b, d, _)| b == &rec.folder_id && d == &me)
            .map(|(_, _, s)| *s)
            .max()
            .unwrap_or(0)
            .max(src.last_seq)
            + 1;
        // A number an interrupted earlier attempt wrote is not reused.
        while metadata.iter().any(|(_, b)| {
            b.exists(&Snapshot::storage_key(&rec.folder_id, &me, seq))
                .unwrap_or(false)
        }) {
            seq += 1;
        }
        let now = util::now_utc();
        let snap = Snapshot {
            format_version: crate::FORMAT_VERSION,
            backup: rec.folder_id.clone(),
            device: me.clone(),
            seq,
            taken_utc: now,
            expires_utc: now + src.retention_days as i64 * DAY,
            retention_days: src.retention_days,
            files,
            skipped: skipped.into_iter().collect(),
        };
        let fk = self.folder_keys(&rec)?;
        let env = snap.seal(&self.vault.vault_id, fk.epoch, &fk.meta, &self.keys.signer)?;
        let blob = env.to_bytes();
        let key = Snapshot::storage_key(&rec.folder_id, &me, seq);
        for (_, backend) in &metadata {
            backend.put_if_absent(&key, &blob)?;
        }
        self.pending.push(Event::SnapshotTaken {
            backup: rec.folder_id.clone(),
            seq,
            taken_utc: snap.taken_utc,
            expires_utc: snap.expires_utc,
            files: snap.files.len() as u64,
            bytes: snap.bytes(),
            snapshot_hash: env.body_hash.clone(),
        });
        self.save_state(&rec.folder_id, &state)?;
        src.last_taken_utc = now;
        src.last_seq = seq;
        src.take_now = false;
        self.save_backup_source(src.clone())?;
        let mut cache = self.load_backup_cache(&rec.folder_id);
        cache.snapshots.insert(snap_key(&me, seq), blocks_of(&snap));
        self.save_backup_cache(&rec.folder_id, &cache)?;
        self.commit_batch()?;

        // 4. An expiry elsewhere may have dropped a block this snapshot
        // uses before it saw the snapshot: write such blocks back.
        self.pull_ledger()?;
        self.upload_missing(&rec, &src.path, &state, &mut push)?;
        self.commit_batch()?;

        report.seq = seq;
        report.taken_utc = snap.taken_utc;
        report.expires_utc = snap.expires_utc;
        report.files = snap.files.len() as u64;
        report.bytes = snap.bytes();
        report.chunks_uploaded = push.chunks_uploaded;
        report.bytes_uploaded = push.bytes_uploaded;
        report.skipped = snap.skipped;
        report.storages_unavailable = push.storages_unavailable;
        Ok(report)
    }

    /// Live files of `state` with a block that no storage holds.
    fn incomplete_files(
        &self,
        rec: &FolderRecord,
        state: &FolderState,
    ) -> Result<BTreeSet<String>> {
        let view = self.view()?;
        let carriers: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name())
            .collect();
        Ok(state
            .files
            .values()
            .filter(|f| !f.deleted)
            .filter(|f| {
                !f.chunks.iter().all(|c| {
                    view.locate(&rec.folder_id, &c.chunk)
                        .filter(|r| r.object == c.object)
                        .is_some_and(|r| r.storages.keys().any(|s| !carriers.contains(s.as_str())))
                })
            })
            .map(|f| f.path.clone())
            .collect())
    }

    fn backup_cache_path(&self, backup: &FolderId) -> PathBuf {
        self.home
            .join("state")
            .join("backups")
            .join(format!("{backup}.json"))
    }

    fn load_backup_cache(&self, backup: &FolderId) -> BackupCache {
        util::read_json_or_default(&self.backup_cache_path(backup)).unwrap_or_default()
    }

    fn save_backup_cache(&self, backup: &FolderId, cache: &BackupCache) -> Result<()> {
        let path = self.backup_cache_path(backup);
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        util::write_json(&path, cache)
    }

    /// Read a snapshot from the first storage whose copy matches the hash
    /// the ledger recorded.
    fn fetch_snapshot(
        &self,
        rec: &FolderRecord,
        device: &DeviceId,
        seq: u64,
        record: &SnapshotRecord,
        include_cold: bool,
    ) -> Result<Snapshot> {
        let key = Snapshot::storage_key(&rec.folder_id, device, seq);
        let fk = self.folder_keys(rec)?;
        let meta_for = |e: u32| fk.meta_key_for(e);
        let writer = self
            .writer_key(device)
            .ok_or_else(|| anyhow!("snapshot {seq} of {} has an unknown writer", rec.name))?;
        let mut altered = false;
        for (spec, backend) in self.metadata_storages(include_cold)? {
            if spec.is_carrier() {
                continue;
            }
            let Ok(Some(blob)) = backend.get(&key) else {
                continue;
            };
            // The signed copy the writer announced, and nothing else.
            match Snapshot::open(
                &blob,
                &self.vault.vault_id,
                &rec.folder_id,
                device,
                seq,
                &writer,
                &meta_for,
            ) {
                Ok((snap, env)) if env.body_hash == record.hash => return Ok(snap),
                _ => {
                    altered = true;
                    continue;
                }
            }
        }
        if altered {
            bail!(
                "snapshot {seq} of {} was altered on the storages: no copy matches the one recorded when it was taken",
                rec.name
            );
        }
        bail!(
            "snapshot {seq} of {} is on no readable storage{}",
            rec.name,
            if include_cold {
                ""
            } else {
                " (cold storages are read only when confirmed)"
            }
        )
    }

    /// Objects of the live snapshots of a backup in `view` (read from the
    /// storages where this device has not seen them yet). `None` when one
    /// of them cannot be read.
    fn live_backup_objects(
        &self,
        rec: &FolderRecord,
        view: &LedgerView,
        cache: &mut BackupCache,
    ) -> Option<HashSet<ObjectName>> {
        let mut live = HashSet::new();
        let records = Self::snapshot_records(view, &rec.folder_id);
        for ((device, seq), r) in records.iter().filter(|(_, r)| r.is_live()) {
            let k = snap_key(device, *seq);
            if !cache.snapshots.contains_key(&k) {
                let snap = self.fetch_snapshot(rec, device, *seq, r, false).ok()?;
                cache.snapshots.insert(k.clone(), blocks_of(&snap));
            }
            live.extend(cache.snapshots[&k].iter().map(|(_, o)| o.clone()));
        }
        cache.snapshots.retain(|k, _| {
            records
                .iter()
                .any(|((d, s), r)| r.is_live() && snap_key(d, *s) == *k)
        });
        Some(live)
    }

    /// Blocks of the live snapshots this device has read or written, for
    /// checks that must not count them as unused.
    pub(super) fn backup_blocks_known(&self, backup: &FolderId) -> Vec<(ChunkId, ObjectName)> {
        self.load_backup_cache(backup)
            .snapshots
            .into_values()
            .flatten()
            .collect()
    }

    // ----- restore ------------------------------------------------------------------

    /// Restore a snapshot (or the files under `paths` in it) into `to`,
    /// which must be empty unless `overwrite`. Cold storages are read only
    /// with `confirm_cold_read`.
    pub fn restore_snapshot(
        &mut self,
        backup: &str,
        pick: SnapshotPick,
        to: &Path,
        paths: &[String],
        overwrite: bool,
        confirm_cold_read: bool,
    ) -> Result<RestoreReport> {
        crate::logged_op_plain!("restore snapshot", backup, {
            self.restore_snapshot_inner(backup, pick, to, paths, overwrite, confirm_cold_read)
        })
    }

    fn restore_snapshot_inner(
        &mut self,
        backup: &str,
        pick: SnapshotPick,
        to: &Path,
        paths: &[String],
        overwrite: bool,
        confirm_cold_read: bool,
    ) -> Result<RestoreReport> {
        self.ensure_active()?;
        let rec = self.resolve_backup(backup)?;
        self.one_batch(|e| e.restore_inner(&rec, pick, to, paths, overwrite, confirm_cold_read))
    }

    fn restore_inner(
        &mut self,
        rec: &FolderRecord,
        pick: SnapshotPick,
        to: &Path,
        paths: &[String],
        overwrite: bool,
        confirm_cold_read: bool,
    ) -> Result<RestoreReport> {
        self.pull_ledger_once()?;
        let view = self.view()?;
        let live: Vec<((DeviceId, u64), SnapshotRecord)> =
            Self::snapshot_records(&view, &rec.folder_id)
                .into_iter()
                .filter(|(_, r)| r.taken)
                .collect();
        let chosen = match pick {
            SnapshotPick::Latest => live.iter().rfind(|(_, r)| !r.expired),
            SnapshotPick::Seq(n) => {
                let found = live.iter().find(|((_, s), _)| *s == n);
                if found.is_some_and(|(_, r)| r.expired) {
                    bail!("snapshot {n} of {} has expired", rec.name);
                }
                found
            }
            SnapshotPick::OnOrBefore(t) => {
                live.iter().rfind(|(_, r)| !r.expired && r.taken_utc <= t)
            }
        };
        let Some(((device, seq), record)) = chosen.cloned() else {
            bail!(match pick {
                SnapshotPick::Latest => format!("{} has no snapshot yet", rec.name),
                SnapshotPick::Seq(n) => format!("{} has no snapshot {n}", rec.name),
                SnapshotPick::OnOrBefore(_) => format!("{} has no snapshot that old", rec.name),
            });
        };
        let snap = self.fetch_snapshot(rec, &device, seq, &record, confirm_cold_read)?;
        let wanted: Vec<FileState> = snap
            .files
            .values()
            .filter(|f| path_wanted(&f.path, paths))
            .cloned()
            .collect();
        if !paths.is_empty() && wanted.is_empty() {
            bail!(
                "none of the given paths is in snapshot {seq} of {}",
                rec.name
            );
        }
        if to.exists() {
            if !to.is_dir() {
                bail!("{} is not a directory", to.display());
            }
            if !overwrite && fs::read_dir(to)?.next().is_some() {
                bail!(
                    "{} is not empty: restore into an empty directory, or allow overwriting",
                    to.display()
                );
            }
        }
        fs::create_dir_all(to)?;
        let root = canonical(to)?;
        let fk = self.folder_keys(rec)?;
        let storages: OpenStorages = self
            .open_storages(confirm_cold_read)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let mut report = RestoreReport {
            backup: rec.name.clone(),
            seq,
            taken_utc: snap.taken_utc,
            to: root.clone(),
            ..Default::default()
        };
        let mut pull = PullReport::default();
        // Counted by the files' downloads (`progress`).
        let _task = crate::activity::start(
            crate::activity::RESTORE,
            &rec.name,
            wanted.iter().map(|f| f.size).sum(),
            crate::activity::Unit::Bytes,
        );
        // Names the target's filesystem does not take are mapped as a
        // synced folder maps them (`crate::names`).
        let rules = self.local_rules(&root);
        let mut names = crate::names::LocalNames::default();
        for f in &wanted {
            let placed = names.place(&root, rules, &f.path).and_then(|(d, _)| {
                // Never through a link above the entry.
                crate::fsmeta::check_no_link_above(&root, &names.local_rel(rules, &f.path))?;
                Ok(d)
            });
            let disk = match placed {
                Ok(d) => d,
                Err(e) => {
                    report.unavailable.push(format!("{}: {e:#}", f.path));
                    continue;
                }
            };
            if disk.is_dir() {
                report
                    .unavailable
                    .push(format!("{}: a directory is in the way", f.path));
                continue;
            }
            // A link is restored as a link; permissions and extended
            // attributes as this system can hold them (`fsmeta`).
            let written = match f.symlink() {
                Some(target) => crate::fsmeta::write_link(&disk, target).map(|_| ()),
                None => self.download_to(rec, &fk, &disk, f, &storages, &mut pull),
            };
            match written {
                Ok(()) => {
                    report.files_restored += 1;
                    report.bytes_restored += f.size;
                    if let Some(m) = &f.meta {
                        let settings = crate::fsmeta::MetaSettings::default();
                        // Metadata never stops a restore.
                        let _ = crate::fsmeta::apply(&disk, m, &self.meta_caps, &settings);
                    }
                    if f.mtime > 0 && !f.is_symlink() {
                        let t =
                            std::time::UNIX_EPOCH + std::time::Duration::from_nanos(f.mtime as u64);
                        if let Ok(file) = fs::File::options().write(true).open(&disk) {
                            let _ = file.set_modified(t);
                        }
                    }
                }
                Err(e) => report.unavailable.push(format!("{}: {e:#}", f.path)),
            }
        }
        Ok(report)
    }

    // ----- expiry ---------------------------------------------------------------------

    /// Expire the snapshots due now and delete what only they used.
    pub fn backup_upkeep(&mut self) -> Result<ExpireReport> {
        self.expire_backups_at(util::now_utc())
    }

    /// Expire every snapshot whose time (plus the grace period) is past at
    /// `now` and that this device may expire, delete the blocks no live
    /// snapshot of its backup uses and the snapshot objects, and remove
    /// stopped backups that have no snapshot left.
    pub fn expire_backups_at(&mut self, now: i64) -> Result<ExpireReport> {
        crate::logged_op!("expire backups at", "", {
            self.expire_backups_at_inner(now)
        })
    }

    fn expire_backups_at_inner(&mut self, now: i64) -> Result<ExpireReport> {
        self.ensure_active()?;
        let mut report = ExpireReport::default();
        if self.vault.member || self.forked_self {
            return Ok(report);
        }
        let backups: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| r.is_backup() && !r.is_removed())
            .cloned()
            .collect();
        if backups.is_empty() {
            return Ok(report);
        }
        self.pull_ledger()?;
        for rec in backups {
            self.expire_backup(&rec, now, &mut report)?;
        }
        self.flush_pack_deletions();
        Ok(report)
    }

    fn expire_backup(
        &mut self,
        rec: &FolderRecord,
        now: i64,
        report: &mut ExpireReport,
    ) -> Result<()> {
        let Some(info) = rec.backup.clone() else {
            return Ok(());
        };
        let me = self.vault.device_id.clone();
        let view = self.view()?;
        let stopped = view.backups_stopped.contains(&rec.folder_id);
        let ours = info.source_device == me;
        // The source was removed from the vault: nobody else would expire.
        let source_gone = !ours && self.is_revoked(&info.source_device);
        let records = Self::snapshot_records(&view, &rec.folder_id);
        let may_expire = |r: &SnapshotRecord| {
            r.is_live()
                && now >= r.expires_utc + EXPIRY_GRACE_SECS
                && (ours
                    || stopped
                    || source_gone
                    || now >= r.expires_utc + OTHERS_EXPIRE_AFTER_SECS)
        };
        let due: Vec<(DeviceId, u64)> = records
            .iter()
            .filter(|(_, r)| may_expire(r))
            .map(|(k, _)| k.clone())
            .collect();
        let mut cache = self.load_backup_cache(&rec.folder_id);
        let unclean = records
            .iter()
            .any(|((d, s), r)| r.expired && !cache.cleaned.contains(&snap_key(d, *s)));
        let may_clean = ours || stopped || source_gone || !due.is_empty();
        if due.is_empty() && !(unclean && may_clean) {
            return self.remove_backup_if_done(rec, &view, stopped, report);
        }

        // 1. The expiries go into the ledger first.
        for (device, seq) in &due {
            self.pending.push(Event::SnapshotExpired {
                backup: rec.folder_id.clone(),
                device: device.clone(),
                seq: *seq,
            });
            report.snapshots_expired += 1;
        }
        let view = self.view()?;
        let Some(mut live) = self.live_backup_objects(rec, &view, &mut cache) else {
            report.waiting.push(rec.name.clone());
            return self.commit_batch().map(|_| ());
        };

        // 2. Blocks of the backup that no live snapshot uses, and that no
        // other folder names (objects are per folder; this is a safeguard).
        let others: HashSet<&ObjectName> = view
            .chunks
            .iter()
            .filter(|((f, _), _)| f != &rec.folder_id)
            .map(|(_, r)| &r.object)
            .collect();
        let local: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| s.name())
            .collect();
        let mut candidates: Vec<(ChunkId, ObjectName)> = Vec::new();
        for ((f, chunk), r) in &view.chunks {
            if f != &rec.folder_id || live.contains(&r.object) || others.contains(&r.object) {
                continue;
            }
            for storage in r.storages.keys().filter(|s| local.contains(s.as_str())) {
                self.pending.push(Event::ChunkDropped {
                    folder: rec.folder_id.clone(),
                    chunk: chunk.clone(),
                    object: r.object.clone(),
                    storage: storage.clone(),
                });
            }
            if !r.storages.is_empty() || !r.dropped.is_empty() {
                candidates.push((chunk.clone(), r.object.clone()));
            }
        }
        // Sealed and pushed before anything is deleted.
        self.commit_batch()?;

        // 3. A snapshot written meanwhile keeps its blocks: list the
        // snapshots again and read the ones the ledger did not know.
        let metadata: OpenStorages = self
            .metadata_storages(true)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let mut listed: BTreeMap<String, (DeviceId, u64)> = BTreeMap::new();
        for (_, backend) in &metadata {
            for key in backend.list(&Snapshot::backup_prefix(&rec.folder_id))? {
                if let Some(id) = Snapshot::parse_key(&rec.folder_id, &key) {
                    listed.insert(key, id);
                }
            }
        }
        let known = |v: &LedgerView, d: &DeviceId, s: u64| {
            v.snapshots
                .get(&(rec.folder_id.clone(), d.clone(), s))
                .is_some_and(|r| r.taken)
        };
        let mut view = view;
        if listed.values().any(|(d, s)| !known(&view, d, *s)) {
            self.pull_ledger()?;
            view = self.view()?;
            match self.live_backup_objects(rec, &view, &mut cache) {
                Some(l) => live = l,
                None => {
                    report.waiting.push(rec.name.clone());
                    return Ok(());
                }
            }
            let fk = self.folder_keys(rec)?;
            let meta_for = |e: u32| fk.meta_key_for(e);
            for (key, (d, s)) in &listed {
                if known(&view, d, *s) {
                    continue;
                }
                // Not in the ledger yet: its blocks stay.
                let writer = self.writer_key(d);
                let opened = metadata.iter().find_map(|(_, b)| {
                    let blob = b.get(key).ok()??;
                    Snapshot::open(
                        &blob,
                        &self.vault.vault_id,
                        &rec.folder_id,
                        d,
                        *s,
                        writer.as_ref()?,
                        &meta_for,
                    )
                    .ok()
                    .map(|(snap, _)| snap)
                });
                match opened {
                    Some(snap) => live.extend(blocks_of(&snap).into_iter().map(|(_, o)| o)),
                    None => {
                        report.waiting.push(rec.name.clone());
                        return Ok(());
                    }
                }
            }
        }

        // 4. Delete the blocks, then the expired snapshot objects.
        for (spec, backend) in self.open_storages(true)? {
            if spec.is_carrier() {
                continue;
            }
            for (_, object) in candidates.iter().filter(|(_, o)| !live.contains(o)) {
                let key = chunk_storage_key(object);
                if backend.exists(&key)? {
                    backend.delete(&key)?;
                    report.objects_deleted += 1;
                }
            }
        }
        let expired: Vec<String> = Self::snapshot_records(&view, &rec.folder_id)
            .into_iter()
            .filter(|(_, r)| r.expired)
            .map(|((d, s), _)| snap_key(&d, s))
            .collect();
        for (_, backend) in &metadata {
            for (key, (d, s)) in &listed {
                if expired.contains(&snap_key(d, *s)) {
                    backend.delete(key)?;
                    report.snapshots_deleted += 1;
                }
            }
        }
        cache.cleaned.extend(expired);
        self.save_backup_cache(&rec.folder_id, &cache)?;
        self.remove_backup_if_done(rec, &view, stopped, report)
    }

    /// A stopped backup goes once its last snapshot has expired.
    fn remove_backup_if_done(
        &mut self,
        rec: &FolderRecord,
        view: &LedgerView,
        stopped: bool,
        report: &mut ExpireReport,
    ) -> Result<()> {
        let live = Self::snapshot_records(view, &rec.folder_id)
            .iter()
            .any(|(_, r)| r.is_live());
        if !stopped || live {
            return Ok(());
        }
        report.objects_deleted += self.remove_record(rec, true)?;
        let _ = fs::remove_file(self.backup_cache_path(&rec.folder_id));
        report.backups_removed.push(rec.name.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{path_wanted, SnapshotPick};

    #[test]
    fn snapshot_picks_parse() {
        assert_eq!(SnapshotPick::parse("latest").unwrap(), SnapshotPick::Latest);
        assert_eq!(SnapshotPick::parse("12").unwrap(), SnapshotPick::Seq(12));
        // 2026-10-12 ends at 1_791_849_599 UTC.
        assert_eq!(
            SnapshotPick::parse("2026-10-12").unwrap(),
            SnapshotPick::OnOrBefore(1_791_849_599)
        );
        assert_eq!(
            SnapshotPick::parse("1970-01-01").unwrap(),
            SnapshotPick::OnOrBefore(86_399)
        );
        assert!(SnapshotPick::parse("2026-13-01").is_err());
        assert!(SnapshotPick::parse("yesterday").is_err());
    }

    #[test]
    fn restore_paths_match_files_and_directories() {
        let w = vec!["docs".to_string()];
        assert!(path_wanted("docs/a.txt", &w));
        assert!(path_wanted("docs", &w));
        assert!(!path_wanted("docs2/a.txt", &w));
        assert!(path_wanted("x", &[]));
        assert!(path_wanted("docs/a.txt", &["docs/".to_string()]));
    }
}
