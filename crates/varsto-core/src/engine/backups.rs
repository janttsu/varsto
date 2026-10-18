// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backups (`docs/spec/alpha-0-format.md` section 31 and section 77 for
//! format 3): read-only snapshots of a directory on one device, kept on
//! storages only.
//!
//! A backup is a folder record whose settings say `backup` (the JSON of
//! its `BackupInfo`). It has its own keys (granted to the devices that may
//! restore it), placement and block map like any folder, but it is never
//! mounted: only its source device writes it, by taking snapshots of the
//! directory (scan, upload what the storages lack, then write a `snapshot`
//! record, a base or a differential against a base, and announce it with
//! `Event::SnapshotTaken` and `record_published`). The backup lists no
//! block as held by a device, and peers never serve its blocks, so the
//! contents stay on the storages, never on the vault's other devices.
//! Transferrers are never written.
//!
//! A snapshot fixes its expiry when it is taken (retention in days). Expired
//! snapshots are expired by the source device after a grace period, or by
//! any device once the backup is stopped, its source is removed from the
//! vault, or two days have passed. The expiry is sealed and pushed before
//! any record is deleted; a base stays while an unexpired differential
//! names it. The blocks only expired snapshots used are collected by
//! garbage collection, which counts the unexpired snapshots of a backup as
//! references (`backup_references3`).
//!
//! A restore writes one snapshot (or some of its paths) into a directory the
//! user names, which must be empty unless overwriting is asked for.

use super::*;
use crate::ledger3::events::{Announcement, Event as Event3};
use crate::ledger3::view::SnapshotRecord as SnapRec;
use crate::ledger3::LedgerView as View3;
use crate::manifest3::FileEntry;
use crate::placement::Placement;
use crate::record::{Id16, KeyId};
use crate::snapshot3::{self, BackupSnapshots, SnapshotWriter};
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

fn blocks_of<'a>(files: impl Iterator<Item = &'a FileEntry>) -> Vec<(ChunkId, ObjectName)> {
    let mut seen = HashSet::new();
    files
        .flat_map(|f| f.chunks.iter())
        .filter(|c| seen.insert(c.object))
        .map(|c| (ChunkId::from_bytes(&c.chunk), ObjectName::from_bytes(&c.object)))
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

/// The snapshots of one backup the ledger knows (taken, expired or not),
/// oldest first.
fn snapshot_rows(view: &View3, backup: &Id16) -> Vec<((Id16, u64), SnapRec)> {
    let mut out: Vec<((Id16, u64), SnapRec)> = view
        .snapshots
        .range((*backup, [0u8; 16], 0)..=(*backup, [0xff; 16], u64::MAX))
        .filter(|(_, r)| r.taken)
        .map(|((_, d, s), r)| ((*d, *s), r.clone()))
        .collect();
    out.sort_by(|a, b| (a.1.taken_utc, a.0 .1, a.0 .0).cmp(&(b.1.taken_utc, b.0 .1, b.0 .0)));
    out
}

/// This device's snapshot writer as it was left: the base it builds on.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredSnapWriter {
    seq: u64,
    base_seq: u64,
    base_bytes: u64,
    on_base: u32,
    force_base: bool,
    base_files: Vec<FileState>,
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
        let info = BackupInfo {
            source_device: me.clone(),
            source_path: source.display().to_string(),
            retention_days: opts.retention_days,
            created_utc: now,
        };
        // A backup is a folder record that says so in its settings; its
        // keys are granted to this device like any folder's.
        let mut settings = BTreeMap::new();
        settings.insert(
            members3::BACKUP_SETTING.to_string(),
            serde_json::to_string(&info)?,
        );
        let k1 = self.f3.recovery.clone();
        let created = self
            .with_enrolled3(|m| m.create_folder(name.trim(), settings, k1.as_ref()))?
            .ok_or_else(|| {
                anyhow!("add a storage first: a backup's records live on the vault's storages")
            })?;
        let granted = self
            .f3
            .members
            .granted
            .get(&created)
            .cloned()
            .ok_or_else(|| anyhow!("the grant of the new backup did not open here"))?;
        let k9_0 = granted
            .epochs
            .get(&0)
            .ok_or_else(|| anyhow!("the grant of the new backup has no first epoch"))?;
        let rec = FolderRecord {
            folder_id: FolderId::from_bytes(&created),
            name: name.trim().to_string(),
            key_hex: k9_0.to_hex(),
            k11_hex: granted.k11.to_hex(),
            created_by: me,
            created_utc: now,
            shared: false,
            policy: None,
            policy_updated_utc: 0,
            placement_updated_utc: if placement.is_some() { now } else { 0 },
            placement,
            strongroom: None,
            removed_utc: 0,
            epoch_keys: BTreeMap::new(),
            backup: Some(info),
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

    // ----- listing -------------------------------------------------------------

    /// The vault's backups.
    pub fn backups(&self) -> Result<Vec<BackupSummary>> {
        let view = self.view3()?;
        let now = util::now_utc();
        let mut out = Vec::new();
        for rec in self
            .keyring
            .folders
            .values()
            .filter(|r| r.is_backup() && !r.is_removed())
        {
            let info = rec.backup.as_ref().expect("a backup");
            let fb = members3::bin(&rec.folder_id)?;
            let local = self
                .config
                .backups
                .iter()
                .find(|b| b.folder_id == rec.folder_id);
            let rows = snapshot_rows(&view, &fb);
            let live: Vec<&((Id16, u64), SnapRec)> =
                rows.iter().filter(|(_, r)| r.is_live()).collect();
            let latest = live.last();
            let stopped = view.backups_stopped.contains(&fb) || local.is_some_and(|l| l.stopped);
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
                latest_seq: latest.map(|((_, s), _)| *s),
                latest_utc: latest.map(|(_, r)| r.taken_utc),
                latest_files: latest.map(|(_, r)| r.files).unwrap_or(0),
                latest_bytes: latest.map(|(_, r)| r.bytes).unwrap_or(0),
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
        let view = self.view3()?;
        let fb = members3::bin(&rec.folder_id)?;
        Ok(snapshot_rows(&view, &fb)
            .into_iter()
            .filter(|(_, r)| r.is_live())
            .map(|((d, seq), r)| SnapshotInfo {
                seq,
                device: self.device_name(&DeviceId::from_bytes(&d)),
                taken_utc: r.taken_utc,
                expires_utc: r.expires_utc,
                files: r.files,
                bytes: r.bytes,
            })
            .collect())
    }

    /// Names of the backups of this device whose scheduled snapshot is due.
    pub fn backups_due(&self, now: i64) -> Vec<String> {
        let stopped = self
            .view3()
            .map(|v| v.backups_stopped.clone())
            .unwrap_or_default();
        self.config
            .backups
            .iter()
            .filter(|b| {
                !b.stopped
                    && !members3::bin(&b.folder_id)
                        .map(|f| stopped.contains(&f))
                        .unwrap_or(false)
            })
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
        let fb = members3::bin(&rec.folder_id)?;
        if !self.view3()?.backups_stopped.contains(&fb) {
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
        let fb = members3::bin(&rec.folder_id)?;
        if src.stopped || self.view3()?.backups_stopped.contains(&fb) {
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

        // 1. Read the directory and store what the storages lack: the
        // packs, the map record of their members and the batch that
        // claims them.
        let epoch = self.folder_keys(&rec)?.epoch;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut push = PushReport::default();
        let (_, changed) = self.scan(&rec, &src.path, &mut state)?;
        let mut report = SnapshotReport {
            backup: rec.name.clone(),
            files_changed: changed,
            ..Default::default()
        };
        self.store_missing3(&rec, &fb, epoch, &src.path, &state, &mut push)?;

        // 2. Every file in the snapshot must be on a storage; a file that
        // changed while it was read gets one more try.
        let mut incomplete = self.incomplete_files(&rec, &state)?;
        if !incomplete.is_empty() {
            let (_, changed) = self.scan(&rec, &src.path, &mut state)?;
            report.files_changed += changed;
            self.store_missing3(&rec, &fb, epoch, &src.path, &state, &mut push)?;
            incomplete = self.incomplete_files(&rec, &state)?;
        }
        let mut skipped: BTreeSet<String> = incomplete;
        skipped.extend(state.unreadable.iter().cloned());

        // 3. The snapshot itself, written once to every storage.
        let mut current: BTreeMap<String, FileEntry> = BTreeMap::new();
        for f in state
            .files
            .values()
            .filter(|f| !f.deleted && !skipped.contains(&f.path))
        {
            let e = FileEntry::from_state(f, false)?;
            current.insert(e.path.clone(), e);
        }
        let now = util::now_utc();
        let expires = now + src.retention_days as i64 * DAY;
        let stream = snapshot3::stream(fb, self.me3());
        let key = KeyId::Meta { folder: fb, epoch };
        let mut writer = self.load_snap_writer(&fb);
        let highest = self.highest_seq3(&metadata, &stream)?;
        writer.resume(highest.max(src.last_seq));
        let lamport = self.tick()?;
        let published = self.with_writer3(|rw| {
            for _ in 0..8 {
                let p = writer.seal(rw, &key, &current, lamport, now, expires)?;
                // A number an interrupted earlier attempt wrote is not
                // reused.
                let mut taken = false;
                for (name, bytes) in &p.sealed.parts {
                    if !metadata[0].1.put_if_absent(name, bytes)? {
                        taken = true;
                        break;
                    }
                }
                if taken {
                    writer.abandon(p);
                    continue;
                }
                for (_, b) in &metadata[1..] {
                    for (name, bytes) in &p.sealed.parts {
                        b.put_if_absent(name, bytes)?;
                    }
                }
                let out = p.sealed.published.clone();
                writer.commit(p);
                return Ok(out);
            }
            bail!("no free sequence number for the next snapshot")
        })?;
        let seq = published.seq;
        let bytes: u64 = current.values().map(|f| f.size).sum();
        self.f3.pending.push(Event3::RecordPublished(Announcement {
            kind: published.kind,
            scope: published.scope,
            seq,
            base: published.base,
            parts: published.parts,
            body_hash: published.body_hash,
            size: published.size,
        }));
        self.pending.push(Event::SnapshotTaken {
            backup: rec.folder_id.clone(),
            seq,
            taken_utc: now,
            expires_utc: expires,
            files: current.len() as u64,
            bytes,
            snapshot_hash: hex::encode(published.body_hash),
        });
        self.save_snap_writer(&writer);
        self.save_state(&rec.folder_id, &state)?;
        src.last_taken_utc = now;
        src.last_seq = seq;
        src.take_now = false;
        self.save_backup_source(src.clone())?;
        let mut cache = self.load_backup_cache(&rec.folder_id);
        cache
            .snapshots
            .insert(snap_key(&me, seq), blocks_of(current.values()));
        self.save_backup_cache(&rec.folder_id, &cache)?;
        self.commit_batch()?;

        report.seq = seq;
        report.taken_utc = now;
        report.expires_utc = expires;
        report.files = current.len() as u64;
        report.bytes = bytes;
        report.chunks_uploaded = push.chunks_uploaded;
        report.bytes_uploaded = push.bytes_uploaded;
        report.skipped = skipped.into_iter().collect();
        report.storages_unavailable = push.storages_unavailable;
        Ok(report)
    }

    /// Write the blocks of `state` the storages lack into packs, publish
    /// the map record of their members and claim them in a batch.
    fn store_missing3(
        &mut self,
        rec: &FolderRecord,
        folder: &Id16,
        epoch: u32,
        root: &Path,
        state: &FolderState,
        push: &mut PushReport,
    ) -> Result<()> {
        let written = self.upload_missing(rec, root, state, push)?;
        let view = self.view3()?;
        self.publish_map3(folder, epoch, &written, &view)?;
        self.commit_batch()?;
        Ok(())
    }

    /// Live files of `state` with a block that no storage holds (a place of
    /// a pack claimed on a storage that is not a transferrer).
    fn incomplete_files(
        &self,
        rec: &FolderRecord,
        state: &FolderState,
    ) -> Result<BTreeSet<String>> {
        let view = self.view3()?;
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
                    self.block_copies3(&view, &rec.folder_id, &c.object)
                        .iter()
                        .any(|s| !carriers.contains(s.as_str()))
                })
            })
            .map(|f| f.path.clone())
            .collect())
    }

    fn snap_writer_path(&self, backup: &Id16) -> PathBuf {
        self.home
            .join("state")
            .join("backups")
            .join(format!("{}-writer.json", hex::encode(backup)))
    }

    /// This device's snapshot stream of `backup` as it left it.
    fn load_snap_writer(&self, backup: &Id16) -> SnapshotWriter {
        let mut w = SnapshotWriter::new(*backup, self.me3());
        let stored: StoredSnapWriter =
            util::read_json_or_default(&self.snap_writer_path(backup)).unwrap_or_default();
        w.seq = stored.seq;
        w.base_seq = stored.base_seq;
        w.base_bytes = stored.base_bytes;
        w.on_base = stored.on_base;
        w.force_base = stored.force_base;
        for f in &stored.base_files {
            if let Ok(e) = FileEntry::from_state(f, false) {
                w.base_files.insert(e.path.clone(), e);
            }
        }
        w
    }

    fn save_snap_writer(&self, w: &SnapshotWriter) {
        let stored = StoredSnapWriter {
            seq: w.seq,
            base_seq: w.base_seq,
            base_bytes: w.base_bytes,
            on_base: w.on_base,
            force_base: w.force_base,
            base_files: w.base_files.values().map(FileEntry::to_state).collect(),
        };
        let path = self.snap_writer_path(&w.backup);
        if let Some(p) = path.parent() {
            let _ = fs::create_dir_all(p);
        }
        if let Err(e) = util::write_json(&path, &stored) {
            log::warn!("snapshot writer state not saved: {e:#}");
        }
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

    /// Read the unexpired snapshots of a backup (and the bases they name)
    /// from the metadata storages, each record through the acceptance rule.
    /// Cold storages only with `include_cold`. A record that is not
    /// accepted anywhere (altered, or not what the ledger announced) is
    /// counted in the second result.
    pub(super) fn load_snapshots3(
        &self,
        rec: &FolderRecord,
        view: &View3,
        include_cold: bool,
        now: i64,
    ) -> Result<(BackupSnapshots, Vec<(Id16, u64)>)> {
        let fb = members3::bin(&rec.folder_id)?;
        let mut snaps = BackupSnapshots::new(fb);
        let storages: OpenStorages = self
            .metadata_storages(include_cold)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let mut refused: Vec<(Id16, u64)> = Vec::new();
        self.each_store3(&storages, view, |_, store, counter| {
            if snaps.wanted(view, now).is_empty() {
                return Ok(());
            }
            let r = snaps.pull(store, view, now, counter)?;
            for x in r.refused {
                if let (Some(d), true) = (x.device, x.seq > 0) {
                    refused.push((d, x.seq));
                }
            }
            Ok(())
        })?;
        // What was loaded later from another storage is not refused.
        refused.retain(|(d, s)| !snaps.is_loaded(d, *s));
        Ok((snaps, refused))
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
        let view = self.view3()?;
        let fb = members3::bin(&rec.folder_id)?;
        let live: Vec<((Id16, u64), SnapRec)> = snapshot_rows(&view, &fb);
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
        // The keys first: a device without the backup's grant says so.
        let fk = self.folder_keys(rec)?;
        let now = util::now_utc();
        let (snaps, refused) = self.load_snapshots3(rec, &view, confirm_cold_read, now)?;
        if !snaps.is_loaded(&device, seq) {
            if refused.iter().any(|(d, s)| *d == device && *s == seq) {
                bail!(
                    "snapshot {seq} of {} was altered on the storages: no copy matches the one recorded when it was taken",
                    rec.name
                );
            }
            bail!(
                "snapshot {seq} of {} is on no readable storage{}",
                rec.name,
                if confirm_cold_read {
                    ""
                } else {
                    " (cold storages are read only when confirmed)"
                }
            );
        }
        let listing = snaps
            .reconstruct(&device, seq)
            .map_err(|e| anyhow!("snapshot {seq} of {}: {e}", rec.name))?;
        let wanted: Vec<FileState> = listing
            .values()
            .map(FileEntry::to_state)
            .filter(|f| path_wanted(&f.path, paths))
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
        // The places of the blocks: the map records of the backup.
        self.pull_folder_records3(&fb, &view)?;
        let storages: OpenStorages = self
            .open_storages(confirm_cold_read)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let mut report = RestoreReport {
            backup: rec.name.clone(),
            seq,
            taken_utc: record.taken_utc,
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
        // What this device now knows of the backup's blocks.
        let mut cache = self.load_backup_cache(&rec.folder_id);
        for info in snaps.list(&view, now) {
            if let Ok(l) = snaps.reconstruct(&info.device, info.seq) {
                cache.snapshots.insert(
                    snap_key(&DeviceId::from_bytes(&info.device), info.seq),
                    blocks_of(l.values()),
                );
            }
        }
        let _ = self.save_backup_cache(&rec.folder_id, &cache);
        Ok(report)
    }

    // ----- expiry ---------------------------------------------------------------------

    /// Expire the snapshots due now and delete the records nothing needs.
    pub fn backup_upkeep(&mut self) -> Result<ExpireReport> {
        self.expire_backups_at(util::now_utc())
    }

    /// Expire every snapshot whose time (plus the grace period) is past at
    /// `now` and that this device may expire, delete the snapshot records
    /// no unexpired snapshot needs, and remove stopped backups that have no
    /// snapshot left. The blocks only expired snapshots used are garbage
    /// collection's: the snapshots stop referencing them (`snapshots3`
    /// references), and the collector marks and drops them as it does for
    /// any folder.
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
        let fb = members3::bin(&rec.folder_id)?;
        let me = self.vault.device_id.clone();
        let view = self.view3()?;
        let stopped = view.backups_stopped.contains(&fb);
        let ours = info.source_device == me;
        // The source was removed from the vault: nobody else would expire.
        let source_gone = !ours && self.is_revoked(&info.source_device);
        let rows = snapshot_rows(&view, &fb);
        let may_expire = |r: &SnapRec| {
            r.is_live()
                && now >= r.expires_utc + EXPIRY_GRACE_SECS
                && (ours
                    || stopped
                    || source_gone
                    || now >= r.expires_utc + OTHERS_EXPIRE_AFTER_SECS)
        };
        let due: Vec<(Id16, u64)> = rows
            .iter()
            .filter(|(_, r)| may_expire(r))
            .map(|(k, _)| *k)
            .collect();
        let mut cache = self.load_backup_cache(&rec.folder_id);
        // Expired snapshots whose records are still on a storage.
        let may_clean = ours || stopped || source_gone || !due.is_empty();

        // 1. The expiries go into the ledger first.
        for (device, seq) in &due {
            self.pending.push(Event::SnapshotExpired {
                backup: rec.folder_id.clone(),
                device: DeviceId::from_bytes(device),
                seq: *seq,
            });
            report.snapshots_expired += 1;
        }
        if !due.is_empty() {
            self.commit_batch()?;
        }
        let view = self.view3()?;

        // 2. The records of expired snapshots no unexpired one builds on.
        if may_clean {
            let devices: BTreeSet<Id16> = rows.iter().map(|((d, _), _)| *d).collect();
            let storages: OpenStorages = self
                .metadata_storages(true)?
                .into_iter()
                .filter(|(s, _)| !s.is_carrier())
                .collect();
            for d in devices {
                let seqs = snapshot3::reader::deletable(&view, &fb, &d, now);
                if seqs.is_empty() {
                    continue;
                }
                for (_, backend) in &storages {
                    snapshot3::reader::delete_records(backend.as_ref(), &fb, &d, &seqs)?;
                }
                report.snapshots_deleted += seqs.len() as u64;
                for s in &seqs {
                    cache.snapshots.remove(&snap_key(&DeviceId::from_bytes(&d), *s));
                }
            }
            self.save_backup_cache(&rec.folder_id, &cache)?;
        }
        self.remove_backup_if_done(rec, &view, stopped, report)
    }

    /// The unexpired snapshots of a backup, loaded from the storages: what
    /// garbage collection treats as references of the backup
    /// (`trash3::Refs`).
    pub(super) fn backup_references3(
        &self,
        rec: &FolderRecord,
        now: i64,
    ) -> Result<(BackupSnapshots, View3)> {
        let view = self.view3()?;
        let (snaps, _) = self.load_snapshots3(rec, &view, false, now)?;
        Ok((snaps, view))
    }

    /// A stopped backup goes once its last snapshot has expired.
    fn remove_backup_if_done(
        &mut self,
        rec: &FolderRecord,
        view: &View3,
        stopped: bool,
        report: &mut ExpireReport,
    ) -> Result<()> {
        let fb = members3::bin(&rec.folder_id)?;
        let live = snapshot_rows(view, &fb).iter().any(|(_, r)| r.is_live());
        if !stopped || live {
            return Ok(());
        }
        // The folder record goes; its blocks and records are collected
        // with the folder.
        let removed = self.with_enrolled3(|m| m.remove_folder(&fb))?;
        if removed.is_none() {
            return Ok(());
        }
        self.forget_folder(&rec.folder_id, util::now_utc())?;
        let _ = fs::remove_file(self.backup_cache_path(&rec.folder_id));
        let _ = fs::remove_file(self.snap_writer_path(&fb));
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
