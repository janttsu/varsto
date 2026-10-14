// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Torrent jobs: a torrent far larger than the local disk is downloaded by
//! a local transmission-daemon in batches that fit the disk, and every
//! batch goes into a Varsto folder before the next one starts
//! (`docs/spec/alpha-0-format.md` section "Torrents through a local
//! transmission daemon", `docs/torrents.md`).
//!
//! A job is a file, `state/torrents/<info hash>.json`. Each step
//! ([`Engine::torrent_tick`]) reads transmission's state of the torrent and
//! the folder's import book again, so a job carries on after a crash or a
//! restart from what is true, not from what it last wrote:
//!
//! 1. files transmission completed (every piece checked against the
//!    torrent's hashes) and still on disk are imported with the import of
//!    a local directory (section 42, `Engine::import_run`) restricted to
//!    them, then removed with its rule (`Engine::import_cleanup`): only once
//!    every block is on a storage, one copy was read back intact and the
//!    folder's policy holds;
//! 2. files the book shows removed are marked unwanted in transmission, and
//!    transmission re-checks its data so that it neither downloads nor
//!    offers them again;
//! 3. when no batch is in flight, the next files in torrent order whose
//!    size fits in the free space above the reserve become wanted and the
//!    torrent runs; while a batch is in flight and the free space falls
//!    below the reserve, the torrent is stopped until there is room again.
//!
//! The job is `complete` when every file of the torrent is in the folder
//! with the content imported, was removed from the download directory by
//! the import's rule, and has every block on a storage.

use super::*;
use crate::freespace::MinFree;
use crate::import::dir::DirSource;
use crate::import::{ImportSource, Listing, SourceInfo, Wanted};
use crate::pool::DiskSpace;
use crate::transmission::{self, AddSource, Rpc, RpcSettings};
use std::any::Any;

/// Job files live in `state/torrents/`.
pub const TORRENTS_DIR: &str = "torrents";
/// The free space kept on the download disk unless `--free-min` says otherwise.
pub const DEFAULT_FREE_MIN: MinFree = MinFree::Basis(1500);
/// While a magnet link's metadata arrives the torrent may download at most
/// this fast (kB/s): transmission wants every file once it knows them.
const METADATA_LIMIT_KBPS: u64 = 50;
/// A torrent stopped by a local error is started again after this long.
const RETRY_SECS: i64 = 60;
/// Errors kept in a job file.
const ERRORS_KEPT: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Saved; transmission does not have the torrent yet.
    Adding,
    /// A magnet link whose file list has not arrived.
    Metadata,
    Downloading,
    /// transmission re-checks its data.
    Checking,
    /// No room for the next file above the reserve, or the free space fell
    /// below it during a batch.
    WaitingSpace,
    /// Downloaded files wait for the folder's policy before they can go.
    WaitingPolicy,
    Paused,
    Complete,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Adding => "adding",
            JobState::Metadata => "metadata",
            JobState::Downloading => "downloading",
            JobState::Checking => "checking",
            JobState::WaitingSpace => "waiting_space",
            JobState::WaitingPolicy => "waiting_policy",
            JobState::Paused => "paused",
            JobState::Complete => "complete",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobFile {
    pub index: usize,
    /// As transmission names it; also the path in the folder.
    pub path: String,
    pub size: u64,
    /// Imported, verified on a storage and removed from the download
    /// directory (the import book's removal record).
    #[serde(default)]
    pub done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobError {
    pub utc: i64,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TorrentJob {
    /// The info hash (lowercase hex): the job's id.
    pub hash: String,
    pub name: String,
    pub folder: String,
    /// The folder's placement, when given.
    #[serde(default)]
    pub storages: Vec<String>,
    /// The reserve on the download disk as given ("15%", "20GB").
    pub free_min: String,
    /// `<download dir>/<info hash>`: transmission writes the torrent here.
    pub download_dir: PathBuf,
    /// Where a folder that is not attached is attached (selectively).
    pub folder_parent: PathBuf,
    pub rpc_url: String,
    #[serde(default)]
    pub rpc_user: Option<String>,
    /// The RPC password is in the device's secret store under this name.
    #[serde(default)]
    pub rpc_secret: Option<String>,
    #[serde(default)]
    pub magnet: Option<String>,
    pub created_utc: i64,
    pub updated_utc: i64,
    pub state: JobState,
    /// What the job does or waits for, in a sentence.
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub user_paused: bool,
    /// Stopped by the job because the free space fell below the reserve.
    #[serde(default)]
    pub stopped_for_space: bool,
    /// Files were removed since transmission last re-checked its data.
    #[serde(default)]
    pub verify_pending: bool,
    #[serde(default)]
    pub piece_size: u64,
    #[serde(default)]
    pub files: Vec<JobFile>,
    /// File indices of the batch in flight.
    #[serde(default)]
    pub batch: Vec<usize>,
    #[serde(default)]
    pub batch_bytes: u64,
    #[serde(default)]
    pub batches: u64,
    #[serde(default)]
    pub bytes_stored: u64,
    /// The reserve and free space at the last step (bytes).
    #[serde(default)]
    pub reserve_bytes: u64,
    #[serde(default)]
    pub free_bytes: Option<u64>,
    /// Bytes the next file needs above the reserve, while waiting for space.
    #[serde(default)]
    pub need_bytes: u64,
    #[serde(default)]
    pub errors: Vec<JobError>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_retry_utc: i64,
    #[serde(default)]
    pub completed_utc: Option<i64>,
}

impl TorrentJob {
    pub fn short(&self) -> &str {
        &self.hash[..self.hash.len().min(8)]
    }
    pub fn files_done(&self) -> u64 {
        self.files.iter().filter(|f| f.done).count() as u64
    }
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
    pub fn running(&self) -> bool {
        self.state != JobState::Complete && !self.user_paused
    }
    fn push_error(&mut self, utc: i64, text: String) {
        if self.errors.last().is_some_and(|e| e.text == text) {
            self.last_error = Some(text);
            return;
        }
        self.errors.push(JobError {
            utc,
            text: text.clone(),
        });
        if self.errors.len() > ERRORS_KEPT {
            let n = self.errors.len() - ERRORS_KEPT;
            self.errors.drain(..n);
        }
        self.last_error = Some(text);
    }

    /// One line for `varsto torrent list` and `varsto status`.
    pub fn line(&self) -> String {
        format!(
            "torrent {} {}: {}, {} of {} files ({} of {}) in folder {}{}",
            self.short(),
            self.name,
            self.state.as_str().replace('_', " "),
            self.files_done(),
            self.files.len(),
            crate::util::human_bytes(self.bytes_stored),
            crate::util::human_bytes(self.total_bytes()),
            self.folder,
            if self.text.is_empty() {
                String::new()
            } else {
                format!(": {}", self.text)
            }
        )
    }
}

/// What a step needs from around it: free space (tests simulate a small
/// disk), the time, and a hold on the background service while an import
/// runs (the command line pauses it).
pub trait TorrentEnv {
    fn space(&mut self, dir: &Path) -> Option<DiskSpace> {
        crate::freespace::space_at(dir)
    }
    fn now(&mut self) -> i64 {
        util::now_utc()
    }
    fn before_import(&mut self) -> Option<Box<dyn Any>> {
        None
    }
    /// Called after the named point of a step; an error there ends the
    /// step as a crash would (tests).
    fn checkpoint(&mut self, _at: &str) -> Result<()> {
        Ok(())
    }
}

/// The plain environment: the real disk and clock.
pub struct SystemEnv;
impl TorrentEnv for SystemEnv {}

/// What to add.
pub struct TorrentAddOptions {
    pub source: AddSource,
    pub folder: String,
    pub storages: Vec<String>,
    pub free_min: MinFree,
    /// The download directory; default: transmission's own.
    pub download_dir: Option<PathBuf>,
    /// Where a new folder is attached (selectively).
    pub folder_parent: PathBuf,
    /// The policy a new folder gets (copies on storages); `None` keeps the
    /// default policy.
    pub min_copies: Option<u32>,
    pub rpc: RpcSettings,
}

// ----- the batch planner ----------------------------------------------------------

/// A file that may go into the next batch: its index, the bytes still to
/// download, and whether it follows the previous candidate directly in the
/// torrent's data (no file with data between them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub index: usize,
    pub remaining: u64,
    pub joins_previous: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchPlan {
    pub files: Vec<usize>,
    /// What the batch may put on the disk: the files' remaining bytes and,
    /// per run of consecutive files, up to a piece on each side (pieces
    /// that reach into neighbouring files are written whole).
    pub bytes: u64,
    /// The first file that did not fit, and what it alone would need.
    pub blocked: Option<(usize, u64)>,
}

/// The next batch: candidates in torrent order, as many as fit in `room`
/// bytes, stopping at the first that does not (so files arrive in order
/// and a large one is not passed over for ever).
pub fn plan_batch(candidates: &[Candidate], room: u64, piece: u64) -> BatchPlan {
    let mut c: Vec<Candidate> = candidates.to_vec();
    c.sort_by_key(|x| x.index);
    let mut plan = BatchPlan::default();
    for (n, x) in c.into_iter().enumerate() {
        let new_run = n == 0 || !x.joins_previous;
        let extra = x.remaining + if new_run { 2 * piece } else { 0 };
        if plan.bytes + extra > room {
            plan.blocked = Some((x.index, x.remaining + 2 * piece));
            break;
        }
        plan.bytes += extra;
        plan.files.push(x.index);
    }
    plan
}

// ----- the source: a directory restricted to completed files ------------------

/// The job's download directory as an import source, listing only the
/// files transmission completed.
pub struct CompletedFiles {
    inner: DirSource,
    only: BTreeSet<String>,
}

impl CompletedFiles {
    pub fn open(dir: &Path, only: BTreeSet<String>) -> Result<CompletedFiles> {
        Ok(CompletedFiles {
            inner: DirSource::open(dir)?,
            only,
        })
    }
}

impl ImportSource for CompletedFiles {
    fn info(&self) -> &SourceInfo {
        self.inner.info()
    }
    fn list(&mut self) -> Result<Listing> {
        let mut l = self.inner.list()?;
        l.items.retain(|i| self.only.contains(&i.path));
        l.skipped.retain(|n| self.only.contains(&n.path));
        l.warnings.retain(|n| self.only.contains(&n.path));
        Ok(l)
    }
    fn deliver(&mut self, wanted: &[Wanted], sink: &mut crate::import::Sink) -> Result<()> {
        self.inner.deliver(wanted, sink)
    }
    fn wants_source_hash(&self) -> bool {
        true
    }
}

// ----- job files ---------------------------------------------------------------------

fn jobs_dir(home: &Path) -> PathBuf {
    home.join("state").join(TORRENTS_DIR)
}

fn job_path(home: &Path, hash: &str) -> PathBuf {
    jobs_dir(home).join(format!("{hash}.json"))
}

/// Every torrent job of a device directory (read without the passphrase:
/// `varsto status`).
pub fn torrent_jobs_at(home: &Path) -> Vec<TorrentJob> {
    let mut out: Vec<TorrentJob> = fs::read_dir(jobs_dir(home))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| util::read_json::<TorrentJob>(&e.path()).ok())
        .collect();
    out.sort_by_key(|j| j.created_utc);
    out
}

fn save_job(home: &Path, job: &mut TorrentJob, now: i64) -> Result<()> {
    job.updated_utc = now;
    let p = job_path(home, &job.hash);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    util::write_json(&p, job)
}

/// A job by info hash (or its start, 6 characters or more), folder or name.
pub fn find_job(home: &Path, key: &str) -> Result<TorrentJob> {
    let k = key.trim().to_lowercase();
    let jobs = torrent_jobs_at(home);
    let hits: Vec<&TorrentJob> = jobs
        .iter()
        .filter(|j| {
            (k.len() >= 6 && j.hash.starts_with(&k))
                || j.folder.to_lowercase() == k
                || j.name.to_lowercase() == k
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no torrent job {key}: `varsto torrent list` shows them"),
        _ => bail!("{key} names more than one torrent job: give its info hash"),
    }
}

/// Holds a job while one step changes it (the command line and the
/// background service may both drive it).
struct JobLock {
    _file: fs::File,
}

fn lock_job(home: &Path, hash: &str, wait: bool) -> Result<Option<JobLock>> {
    let p = jobs_dir(home).join(format!("{hash}.lock"));
    fs::create_dir_all(jobs_dir(home))?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let flags = if wait {
            libc::LOCK_EX
        } else {
            libc::LOCK_EX | libc::LOCK_NB
        };
        // SAFETY: flock on a descriptor this function owns.
        let r = unsafe { libc::flock(file.as_raw_fd(), flags) };
        if r != 0 {
            return Ok(None);
        }
    }
    #[cfg(not(unix))]
    let _ = wait;
    Ok(Some(JobLock { _file: file }))
}

#[cfg(unix)]
fn same_fs(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_fs(_a: &Path, _b: &Path) -> bool {
    false
}

fn secret_name(hash: &str) -> String {
    format!("transmission:{hash}")
}

impl Engine {
    /// The RPC settings of a job: what is given, else the environment, else
    /// what the job was added with.
    pub fn torrent_rpc(&self, job: &TorrentJob, given: &RpcSettings) -> RpcSettings {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let stored = || {
            job.rpc_secret
                .as_ref()
                .and_then(|r| self.secret_store().ok()?.secrets.get(r).cloned())
        };
        RpcSettings {
            url: Some(given.url.clone())
                .filter(|u| !u.is_empty())
                .or_else(|| env("VARSTO_TRANSMISSION_URL"))
                .unwrap_or_else(|| job.rpc_url.clone()),
            user: given
                .user
                .clone()
                .or_else(|| env("VARSTO_TRANSMISSION_USER"))
                .or_else(|| job.rpc_user.clone()),
            password: given
                .password
                .clone()
                .or_else(|| env("VARSTO_TRANSMISSION_PASSWORD"))
                .or_else(stored),
        }
    }

    /// The free space the download disk keeps: the job's reserve, and never
    /// less than Varsto's own minimum (section 53) of a folder, a directory
    /// storage or this device's directory on the same disk (5 % by default).
    fn torrent_reserve(&self, job: &TorrentJob, dir: &Path, total: u64) -> u64 {
        let mut r = MinFree::parse(&job.free_min)
            .unwrap_or(DEFAULT_FREE_MIN)
            .bytes(total)
            .max(crate::freespace::DEFAULT.bytes(total));
        for m in &self.config.folders {
            if same_fs(dir, &m.path) {
                r = r.max(m.min_free.unwrap_or(crate::freespace::DEFAULT).bytes(total));
            }
        }
        for s in &self.config.storages {
            if let StorageSpec::LocalDir { path, min_free, .. } = s {
                if same_fs(dir, path) {
                    r = r.max(min_free.unwrap_or(crate::freespace::DEFAULT).bytes(total));
                }
            }
        }
        r
    }

    /// Register a torrent job: the folder is created (attached selectively,
    /// with the placement and policy asked for), and the torrent is added
    /// to transmission stopped, with every file unwanted.
    pub fn torrent_add(&mut self, opts: &TorrentAddOptions, rpc: &Rpc) -> Result<TorrentJob> {
        self.ensure_active()?;
        let (hash, name, files, piece, metainfo) = match &opts.source {
            AddSource::Metainfo(bytes) => {
                let m = transmission::parse_metainfo(bytes)?;
                (m.hash, m.name, m.files, m.piece_length, Some(bytes.clone()))
            }
            AddSource::Magnet(uri) => {
                let (h, n) = transmission::parse_magnet(uri)?;
                (h.clone(), n.unwrap_or(h), Vec::new(), 0, None)
            }
        };
        if job_path(&self.home, &hash).exists() {
            bail!(
                "there is a torrent job for this torrent already: varsto torrent status {}",
                &hash[..8]
            );
        }
        for (p, _) in &files {
            util::check_rel_path(p).with_context(|| {
                format!("the torrent names a file Varsto cannot store as it is: {p}")
            })?;
        }
        let session = rpc.session_get()?;
        if session
            .get("incomplete-dir-enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            bail!("transmission keeps unfinished downloads in its incomplete-dir, on a disk Varsto does not watch: turn incomplete-dir-enabled off (see docs/torrents.md)");
        }
        if rpc.get(&hash)?.is_some() {
            bail!("transmission has this torrent already: remove it there first (keeping its data), so that Varsto adds it with every file unwanted");
        }
        let base = match &opts.download_dir {
            Some(d) => std::path::absolute(d)?,
            None => PathBuf::from(
                session
                    .get("download-dir")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow!("transmission names no download directory: give --download-dir")
                    })?,
            ),
        };
        fs::create_dir_all(&base)
            .with_context(|| format!("create the download directory {}", base.display()))?;
        let dir = base.join(&hash);
        let made = !dir.exists();
        fs::create_dir_all(&dir)?;
        let undo = |dir: &Path| {
            if made {
                let _ = fs::remove_dir(dir);
            }
        };
        // The folder and its import book, by an import of nothing yet: it
        // refuses a download directory inside a Varsto folder or the
        // device directory, and a folder name that holds other data.
        let mut src = CompletedFiles::open(&dir, BTreeSet::new())?;
        let report = match self.import_run(
            &mut src,
            &ImportOptions {
                folder: Some(opts.folder.clone()),
                selective: true,
                remove_source: true,
                default_parent: Some(opts.folder_parent.clone()),
                ..Default::default()
            },
        ) {
            Ok(r) => r,
            Err(e) => {
                undo(&dir);
                return Err(e);
            }
        };
        if !opts.storages.is_empty() {
            self.set_placement(
                &report.folder,
                Some(crate::placement::Placement {
                    storages: opts.storages.clone(),
                    ..Default::default()
                }),
            )?;
        }
        if let (true, Some(n)) = (report.created_folder, opts.min_copies) {
            self.set_policy(
                &report.folder,
                Some(crate::policy::Policy {
                    min_copies: n.max(1),
                    ..Default::default()
                }),
            )?;
        }
        let rpc_secret = match &opts.rpc.password {
            Some(p) => {
                self.store_secret(&secret_name(&hash), p)?;
                Some(secret_name(&hash))
            }
            None => None,
        };
        let now = util::now_utc();
        let mut job = TorrentJob {
            hash: hash.clone(),
            name,
            folder: report.folder.clone(),
            storages: opts.storages.clone(),
            free_min: opts.free_min.setting(),
            download_dir: dir.clone(),
            folder_parent: opts.folder_parent.clone(),
            rpc_url: opts.rpc.url.clone(),
            rpc_user: opts.rpc.user.clone(),
            rpc_secret,
            magnet: match &opts.source {
                AddSource::Magnet(m) => Some(m.clone()),
                _ => None,
            },
            created_utc: now,
            updated_utc: now,
            state: JobState::Adding,
            text: String::new(),
            user_paused: false,
            stopped_for_space: false,
            verify_pending: false,
            piece_size: piece,
            files: files
                .iter()
                .enumerate()
                .map(|(i, (p, s))| JobFile {
                    index: i,
                    path: p.clone(),
                    size: *s,
                    done: false,
                })
                .collect(),
            batch: Vec::new(),
            batch_bytes: 0,
            batches: 0,
            bytes_stored: 0,
            reserve_bytes: 0,
            free_bytes: None,
            need_bytes: 0,
            errors: Vec::new(),
            last_error: None,
            last_retry_utc: 0,
            completed_utc: None,
        };
        if let Some(m) = &metainfo {
            let p = jobs_dir(&self.home).join(format!("{hash}.torrent"));
            fs::create_dir_all(jobs_dir(&self.home))?;
            util::write_atomic(&p, m)?;
        }
        save_job(&self.home, &mut job, now)?;
        self.torrent_ensure_added(&mut job, rpc)?;
        save_job(&self.home, &mut job, now)?;
        Ok(job)
    }

    /// Add the job's torrent to transmission, stopped and with nothing
    /// wanted (also when it went missing there).
    fn torrent_ensure_added(&self, job: &mut TorrentJob, rpc: &Rpc) -> Result<()> {
        let source = match &job.magnet {
            Some(m) => AddSource::Magnet(m.clone()),
            None => AddSource::Metainfo(
                fs::read(jobs_dir(&self.home).join(format!("{}.torrent", job.hash)))
                    .context("the job's copy of the torrent file is gone")?,
            ),
        };
        let unwanted: Vec<usize> = (0..job.files.len()).collect();
        let added = rpc.add(&source, &job.download_dir.display().to_string(), &unwanted)?;
        if added.hash != job.hash {
            bail!(
                "transmission added a torrent with another info hash ({}) than expected",
                added.hash
            );
        }
        if job.files.is_empty() {
            // A magnet link: fetch the file list slowly; nothing is wanted
            // yet, but transmission will want everything once it knows it.
            rpc.limit_download(&job.hash, Some(METADATA_LIMIT_KBPS))?;
            rpc.start(&job.hash)?;
            job.state = JobState::Metadata;
            job.text = "waiting for the torrent's file list".into();
        } else {
            rpc.all_unwanted(&job.hash)?;
            rpc.stop(&job.hash)?;
            job.state = JobState::Downloading;
            job.text = String::new();
        }
        Ok(())
    }

    /// One step of a job (see the module documentation). `wait`: wait for
    /// another step of the same job to finish; otherwise `None` while one
    /// runs.
    pub fn torrent_tick(
        &mut self,
        key: &str,
        rpc: &Rpc,
        env: &mut dyn TorrentEnv,
        wait: bool,
    ) -> Result<Option<TorrentJob>> {
        let job = find_job(&self.home, key)?;
        let Some(_lock) = lock_job(&self.home, &job.hash, wait)? else {
            return Ok(None);
        };
        // Read again under the lock.
        let mut job: TorrentJob = util::read_json(&job_path(&self.home, &job.hash))?;
        if job.state == JobState::Complete {
            return Ok(Some(job));
        }
        match self.torrent_step(&mut job, rpc, env) {
            Ok(()) => {
                let now = env.now();
                save_job(&self.home, &mut job, now)?;
                Ok(Some(job))
            }
            Err(e) => {
                // The step's own changes are saved as they happen; this
                // records why it stopped (read again: the step may have
                // saved since).
                let now = env.now();
                let mut saved: TorrentJob =
                    util::read_json(&job_path(&self.home, &job.hash)).unwrap_or(job);
                saved.push_error(now, format!("{e:#}"));
                save_job(&self.home, &mut saved, now)?;
                Err(e)
            }
        }
    }

    fn torrent_step(
        &mut self,
        job: &mut TorrentJob,
        rpc: &Rpc,
        env: &mut dyn TorrentEnv,
    ) -> Result<()> {
        let now = env.now();
        job.last_error = None;
        let Some(info) = rpc.get(&job.hash)? else {
            job.push_error(
                now,
                "transmission did not have the torrent: added again".into(),
            );
            self.torrent_ensure_added(job, rpc)?;
            save_job(&self.home, job, now)?;
            return Ok(());
        };
        // A magnet link's file list.
        if info.files.is_empty() {
            job.state = JobState::Metadata;
            job.text = "waiting for the torrent's file list".into();
            if info.stopped() && !job.user_paused {
                rpc.start(&job.hash)?;
            }
            return Ok(());
        }
        if job.files.is_empty() {
            rpc.stop(&job.hash)?;
            rpc.all_unwanted(&job.hash)?;
            rpc.limit_download(&job.hash, None)?;
            for f in &info.files {
                util::check_rel_path(&f.name).with_context(|| {
                    format!(
                        "the torrent names a file Varsto cannot store as it is: {}",
                        f.name
                    )
                })?;
            }
            job.files = info
                .files
                .iter()
                .enumerate()
                .map(|(i, f)| JobFile {
                    index: i,
                    path: f.name.clone(),
                    size: f.length,
                    done: false,
                })
                .collect();
            job.piece_size = info.piece_size;
            job.name = info.name.clone();
            job.state = JobState::Downloading;
            job.text = String::new();
            save_job(&self.home, job, now)?;
            return Ok(());
        }
        if info.files.len() != job.files.len() {
            bail!(
                "transmission lists {} files for this torrent, the job {}",
                info.files.len(),
                job.files.len()
            );
        }
        if job.piece_size == 0 {
            job.piece_size = info.piece_size;
        }
        // Errors: reported, and a torrent stopped by one is started again.
        if info.error != 0 {
            let what = match info.error {
                1 => "tracker warning",
                2 => "tracker error",
                _ => "error",
            };
            job.push_error(now, format!("transmission {what}: {}", info.error_string));
            if info.error == 3
                && info.stopped()
                && !job.user_paused
                && !job.stopped_for_space
                && now - job.last_retry_utc >= RETRY_SECS
            {
                job.last_retry_utc = now;
                rpc.start(&job.hash)?;
            }
        }
        if info.checking() {
            job.state = JobState::Checking;
            job.text = "transmission is checking its data".into();
            return Ok(());
        }

        let rec = self
            .keyring
            .folders
            .values()
            .find(|r| !r.is_removed() && r.name.to_lowercase() == job.folder.to_lowercase())
            .cloned()
            .ok_or_else(|| anyhow!("the vault has no folder {} any more", job.folder))?;
        // Files the book shows removed (safely stored): done.
        self.torrent_mark_done(job, &rec)?;

        // Empty files have nothing to download; transmission may not
        // create them.
        for f in job.files.iter().filter(|f| f.size == 0 && !f.done) {
            let p = util::safe_join(&job.download_dir, &f.path)?;
            if fs::symlink_metadata(&p).is_err() {
                if let Some(d) = p.parent() {
                    fs::create_dir_all(d)?;
                }
                fs::write(&p, b"")?;
            }
        }
        // 1. Import what transmission completed and is still on disk.
        let ready: BTreeSet<String> = job
            .files
            .iter()
            .filter(|f| !f.done && info.files[f.index].complete())
            .filter(|f| {
                fs::symlink_metadata(job.download_dir.join(&f.path))
                    .is_ok_and(|m| m.file_type().is_file())
            })
            .map(|f| f.path.clone())
            .collect();
        let mut waiting_policy: Option<String> = None;
        if !ready.is_empty() {
            job.text = format!("importing {} file(s)", ready.len());
            save_job(&self.home, job, now)?;
            let _hold = env.before_import();
            let mut src = CompletedFiles::open(&job.download_dir, ready.clone())?;
            let report = self.import_run(
                &mut src,
                &ImportOptions {
                    folder: Some(job.folder.clone()),
                    selective: true,
                    remove_source: true,
                    default_parent: Some(job.folder_parent.clone()),
                    ..Default::default()
                },
            )?;
            for n in &report.failed {
                job.push_error(now, format!("{}: {}", n.path, n.reason));
            }
            for d in &report.damaged {
                job.push_error(now, format!("{}: {}", d.path, d.detail));
            }
            env.checkpoint("imported")?;
            let cleanup = self.import_cleanup(&job.folder, true)?;
            if let Some(w) = cleanup.waiting.iter().find(|w| ready.contains(&w.path)) {
                waiting_policy = Some(format!("{}: {}", w.path, w.reason));
            }
            drop(_hold);
            self.torrent_mark_done(job, &rec)?;
            save_job(&self.home, job, now)?;
            env.checkpoint("removed")?;
        }

        // 2. Removed files: unwanted, and forgotten by transmission.
        let unwanted: Vec<usize> = job
            .files
            .iter()
            .filter(|f| f.done && info.files[f.index].wanted)
            .map(|f| f.index)
            .collect();
        rpc.set_files(&job.hash, &[], &unwanted)?;
        // A batch is over for a file once it is downloaded (it may wait
        // for the policy before it can go, holding its space meanwhile).
        job.batch
            .retain(|i| !job.files[*i].done && !info.files[*i].complete());
        if job.verify_pending {
            rpc.verify(&job.hash)?;
            job.verify_pending = false;
            save_job(&self.home, job, now)?;
            env.checkpoint("verify")?;
            job.state = JobState::Checking;
            job.text = "transmission is checking its data".into();
            return Ok(());
        }

        // 3. Everything stored: check and finish.
        if job.files.iter().all(|f| f.done) {
            let problems = self.torrent_check_complete(job, &rec)?;
            if !problems.is_empty() {
                bail!("not complete yet: {}", problems.join("; "));
            }
            if !info.stopped() {
                rpc.stop(&job.hash)?;
            }
            self.torrent_sweep(job)?;
            job.state = JobState::Complete;
            job.text = format!("every file is in folder {}", job.folder);
            job.completed_utc = Some(now);
            job.batch.clear();
            return Ok(());
        }

        // 4. The batch in flight, or the next one.
        if job.user_paused {
            if !info.stopped() {
                rpc.stop(&job.hash)?;
            }
            job.state = JobState::Paused;
            job.text = "paused".into();
            return Ok(());
        }
        let space = env.space(&job.download_dir).ok_or_else(|| {
            anyhow!(
                "the free space of {} cannot be read",
                job.download_dir.display()
            )
        })?;
        let reserve = self.torrent_reserve(job, &job.download_dir, space.total);
        job.reserve_bytes = reserve;
        job.free_bytes = Some(space.free);
        let short = |need: u64| {
            format!(
                "{} free on the download disk, the reserve is {}; {} more is needed",
                util::human_bytes(space.free),
                util::human_bytes(reserve),
                util::human_bytes(need)
            )
        };
        if !job.batch.is_empty() {
            let remaining: u64 = job
                .batch
                .iter()
                .map(|i| {
                    let f = &info.files[*i];
                    f.length.saturating_sub(f.bytes_completed)
                })
                .sum();
            if space.free < reserve && remaining > 0 {
                if !info.stopped() {
                    rpc.stop(&job.hash)?;
                }
                job.stopped_for_space = true;
                job.need_bytes = reserve - space.free;
                job.state = JobState::WaitingSpace;
                job.text = short(job.need_bytes);
                return Ok(());
            }
            if job.stopped_for_space && remaining > 0 && space.free < reserve + remaining {
                job.need_bytes = reserve + remaining - space.free;
                job.state = JobState::WaitingSpace;
                job.text = short(job.need_bytes);
                return Ok(());
            }
            job.stopped_for_space = false;
            job.need_bytes = 0;
            let wanted: Vec<usize> = job
                .batch
                .iter()
                .copied()
                .filter(|i| !info.files[*i].wanted)
                .collect();
            rpc.set_files(&job.hash, &wanted, &[])?;
            if info.stopped() && (info.error != 3 || now - job.last_retry_utc >= RETRY_SECS) {
                rpc.start(&job.hash)?;
            }
            job.state = if waiting_policy.is_some() && remaining == 0 {
                JobState::WaitingPolicy
            } else {
                JobState::Downloading
            };
            job.text = match &waiting_policy {
                Some(w) if remaining == 0 => w.clone(),
                _ => format!(
                    "batch {}: {} file(s), {} left to download",
                    job.batches,
                    job.batch.len(),
                    util::human_bytes(remaining)
                ),
            };
            return Ok(());
        }
        // Files downloaded but still waiting for the policy hold their
        // space; they are not downloaded again.
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut prev_with_data: Option<usize> = None;
        for f in job.files.iter().filter(|f| f.size > 0) {
            if !f.done && !info.files[f.index].complete() {
                candidates.push(Candidate {
                    index: f.index,
                    remaining: f.size.saturating_sub(info.files[f.index].bytes_completed),
                    joins_previous: prev_with_data
                        .is_some_and(|p| candidates.last().is_some_and(|c| c.index == p)),
                });
            }
            prev_with_data = Some(f.index);
        }
        if candidates.is_empty() {
            // Everything left is downloaded and waits for the policy.
            if !info.stopped() {
                rpc.stop(&job.hash)?;
            }
            job.state = JobState::WaitingPolicy;
            job.text = waiting_policy.unwrap_or_else(|| {
                "downloaded files wait until they can be removed (varsto import cleanup shows why)"
                    .into()
            });
            return Ok(());
        }
        let room = space.free.saturating_sub(reserve);
        let plan = plan_batch(&candidates, room, job.piece_size);
        if plan.files.is_empty() {
            if !info.stopped() {
                rpc.stop(&job.hash)?;
            }
            let need = plan
                .blocked
                .map(|(_, n)| n)
                .unwrap_or(0)
                .saturating_sub(room);
            job.need_bytes = need;
            job.state = JobState::WaitingSpace;
            job.text = match plan.blocked {
                Some((i, _)) => format!("{} for {}", short(need), job.files[i].path),
                None => short(need),
            };
            return Ok(());
        }
        job.batch = plan.files.clone();
        job.batch_bytes = plan.bytes;
        job.batches += 1;
        job.need_bytes = 0;
        job.stopped_for_space = false;
        job.state = JobState::Downloading;
        job.text = format!(
            "batch {}: {} file(s), {}",
            job.batches,
            job.batch.len(),
            util::human_bytes(plan.bytes)
        );
        save_job(&self.home, job, now)?;
        rpc.set_files(&job.hash, &plan.files, &[])?;
        rpc.start(&job.hash)?;
        Ok(())
    }

    /// Mark the files the import book shows removed from the download
    /// directory, with the folder holding their content, as done.
    fn torrent_mark_done(&self, job: &mut TorrentJob, rec: &FolderRecord) -> Result<()> {
        let book = self.load_book(&rec.folder_id).unwrap_or_default();
        let state = self.load_state(&rec.folder_id)?;
        let removed: HashMap<&str, &crate::import::Removal> =
            book.removals.iter().map(|r| (r.path.as_str(), r)).collect();
        let mut changed = false;
        for f in job.files.iter_mut().filter(|f| !f.done) {
            let Some(r) = removed.get(f.path.as_str()) else {
                continue;
            };
            let in_folder = state
                .files
                .get(&f.path)
                .is_some_and(|s| !s.deleted && s.size == f.size && r.size == f.size);
            if in_folder {
                f.done = true;
                changed = true;
            }
        }
        if changed {
            job.verify_pending = true;
            job.bytes_stored = job.files.iter().filter(|f| f.done).map(|f| f.size).sum();
        }
        Ok(())
    }

    /// Why the job is not complete, if it is not: every file must be in the
    /// folder with content the book imported (with the SHA-256 recorded at
    /// removal) and every block must have a storage copy.
    fn torrent_check_complete(&self, job: &TorrentJob, rec: &FolderRecord) -> Result<Vec<String>> {
        let book = self.load_book(&rec.folder_id).unwrap_or_default();
        let state = self.load_state(&rec.folder_id)?;
        let view = self.view()?;
        let mut problems = Vec::new();
        for f in &job.files {
            let Some(s) = state.files.get(&f.path).filter(|s| !s.deleted) else {
                problems.push(format!("{} is not in the folder", f.path));
                continue;
            };
            let removal = book.removals.iter().rev().find(|r| r.path == f.path);
            let imported = removal.is_some_and(|r| {
                book.imported.values().any(|x| {
                    x.hash == s.content_hash
                        && x.size == f.size
                        && x.sha256.as_deref() == Some(r.sha256.as_str())
                })
            });
            if s.size != f.size || !imported {
                problems.push(format!("{} differs from what was imported", f.path));
                continue;
            }
            let unstored = s.chunks.iter().any(|c| {
                view.locate(&rec.folder_id, &c.chunk)
                    .filter(|r| r.object == c.object)
                    .is_none_or(|r| r.storages.values().all(|l| l.claimed_by.is_empty()))
            });
            if unstored {
                problems.push(format!("{} has blocks without a storage copy", f.path));
            }
        }
        Ok(problems)
    }

    /// At the end: pieces transmission wrote into files that were stored
    /// already (a piece reaching across two files is written whole) are
    /// removed, then empty directories, then the job's directory.
    fn torrent_sweep(&self, job: &TorrentJob) -> Result<()> {
        let dir = &job.download_dir;
        for f in job.files.iter().filter(|f| f.done) {
            let p = util::safe_join(dir, &f.path)?;
            for q in [p.clone(), PathBuf::from(format!("{}.part", p.display()))] {
                if fs::symlink_metadata(&q).is_ok_and(|m| m.file_type().is_file()) {
                    fs::remove_file(&q).with_context(|| format!("remove {}", q.display()))?;
                }
            }
        }
        let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_dir())
            .map(|e| e.path().to_path_buf())
            .collect();
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            let _ = fs::remove_dir(&d);
        }
        Ok(())
    }

    /// Pause or resume a job (`varsto torrent pause|resume`).
    pub fn torrent_set_paused(&mut self, key: &str, paused: bool, rpc: &Rpc) -> Result<TorrentJob> {
        let job = find_job(&self.home, key)?;
        let _lock = lock_job(&self.home, &job.hash, true)?;
        let mut job: TorrentJob = util::read_json(&job_path(&self.home, &job.hash))?;
        if job.state == JobState::Complete {
            bail!("torrent job {} is complete", job.short());
        }
        job.user_paused = paused;
        if paused {
            rpc.stop(&job.hash)?;
            job.state = JobState::Paused;
            job.text = "paused".into();
        } else {
            job.state = JobState::Downloading;
            job.text = String::new();
        }
        save_job(&self.home, &mut job, util::now_utc())?;
        Ok(job)
    }

    /// Forget a job (`varsto torrent remove`): transmission drops the
    /// torrent too unless `keep_in_transmission`; nothing in the download
    /// directory is deleted (files there were not stored yet).
    pub fn torrent_remove(
        &mut self,
        key: &str,
        keep_in_transmission: bool,
        rpc: Option<&Rpc>,
    ) -> Result<TorrentJob> {
        let job = find_job(&self.home, key)?;
        let _lock = lock_job(&self.home, &job.hash, true)?;
        if !keep_in_transmission {
            if let Some(rpc) = rpc {
                rpc.remove(&job.hash, false)?;
            }
        }
        if let Some(r) = &job.rpc_secret {
            let mut store = self.secret_store()?;
            if store.secrets.remove(r).is_some() {
                store.save(
                    &self.home,
                    &self.keys,
                    &self.vault.vault_id,
                    &self.vault.device_id,
                )?;
            }
        }
        for ext in ["json", "torrent", "lock"] {
            let _ = fs::remove_file(jobs_dir(&self.home).join(format!("{}.{ext}", job.hash)));
        }
        let _ = fs::remove_dir(&job.download_dir);
        Ok(job)
    }

    /// The jobs the background service drives: not complete, not paused.
    pub fn torrents_to_run(&self) -> Vec<TorrentJob> {
        torrent_jobs_at(&self.home)
            .into_iter()
            .filter(|j| j.running())
            .collect()
    }

    /// The jobs as the Help page sees them.
    pub(super) fn torrent_help_inputs(&self) -> Vec<crate::help::TorrentIn> {
        torrent_jobs_at(&self.home)
            .into_iter()
            .map(|j| crate::help::TorrentIn {
                job: j.short().to_string(),
                name: j.name.clone(),
                folder: j.folder.clone(),
                state: j.state.as_str().to_string(),
                files: j.files.len() as u64,
                files_done: j.files_done(),
                free: j.free_bytes.unwrap_or(0),
                need: j.need_bytes,
                completed_utc: j.completed_utc,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Candidates following each other in the torrent.
    fn run(list: &[(usize, u64)]) -> Vec<Candidate> {
        list.iter()
            .enumerate()
            .map(|(n, (index, remaining))| Candidate {
                index: *index,
                remaining: *remaining,
                joins_previous: n > 0,
            })
            .collect()
    }

    #[test]
    fn batches_fill_the_room_in_torrent_order() {
        // Pieces of 10: a run of files costs up to 20 extra.
        let files = run(&[(0, 50), (1, 30), (2, 100), (3, 500)]);
        let mut shuffled = files.clone();
        shuffled.reverse();
        let p = plan_batch(&shuffled, 200, 10);
        assert_eq!(p.files, vec![0, 1, 2], "{p:?}");
        assert_eq!(p.bytes, 50 + 30 + 100 + 20);
        assert_eq!(p.blocked, Some((3, 520)));
        // One byte short: the third file waits.
        assert_eq!(plan_batch(&files, 200 - 1, 10).files, vec![0, 1]);
        // Nothing fits: the first file blocks.
        let p = plan_batch(&files, 60, 10);
        assert!(p.files.is_empty());
        assert_eq!(p.blocked, Some((0, 70)));
        // It does not pass over a large file for smaller ones after it.
        let p = plan_batch(&run(&[(0, 1000), (1, 1)]), 500, 0);
        assert!(p.files.is_empty());
    }

    #[test]
    fn gaps_cost_extra_pieces_and_resumption_counts_what_is_left() {
        // Files 1 and 3 are elsewhere: candidates 0, 2, 4 are three runs.
        let gaps: Vec<Candidate> = [0, 2, 4]
            .iter()
            .map(|i| Candidate {
                index: *i,
                remaining: 10,
                joins_previous: false,
            })
            .collect();
        let p = plan_batch(&gaps, 1000, 100);
        assert_eq!(p.files, vec![0, 2, 4]);
        assert_eq!(p.bytes, 30 + 3 * 200);
        // A file half downloaded before a restart needs only the rest.
        let p = plan_batch(&run(&[(0, 40)]), 60, 10);
        assert_eq!(p.files, vec![0]);
        assert_eq!(p.bytes, 60);
        // No room at all.
        assert!(plan_batch(&run(&[(0, 1)]), 0, 0).files.is_empty());
        assert_eq!(plan_batch(&run(&[(0, 0)]), 0, 0).files, vec![0]);
    }

    // ----- steps against the fake transmission ------------------------------------

    use crate::transmission::fake::FakeTransmission;
    use crate::transmission::make_metainfo;

    const PASS: &str = "correct horse battery staple";

    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s & 0xff) as u8
            })
            .collect()
    }

    fn du(dir: &Path) -> u64 {
        walkdir::WalkDir::new(dir)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    struct Env {
        dir: PathBuf,
        capacity: u64,
        /// Taken by something else on the disk.
        other: u64,
        now: i64,
        crash_at: Option<&'static str>,
    }

    impl TorrentEnv for Env {
        fn space(&mut self, _dir: &Path) -> Option<DiskSpace> {
            Some(DiskSpace {
                free: self.capacity.saturating_sub(du(&self.dir) + self.other),
                total: self.capacity,
            })
        }
        fn now(&mut self) -> i64 {
            self.now += 1;
            self.now
        }
        fn checkpoint(&mut self, at: &str) -> Result<()> {
            if self.crash_at == Some(at) {
                self.crash_at = None;
                bail!("simulated crash at {at}");
            }
            Ok(())
        }
    }

    struct Lab {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        e: Engine,
        fake: FakeTransmission,
        rpc: Rpc,
        meta: Vec<u8>,
        contents: Vec<Vec<u8>>,
        env: Env,
    }

    /// Six files of 3000 bytes; room for two at a time above a 10 000
    /// byte reserve.
    fn lab() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let (mut e, _) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
        e.chunker = crate::chunking::ChunkerParams::SMALL;
        e.add_storage(StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        })
        .unwrap();
        let contents: Vec<Vec<u8>> = (0..6).map(|i| bytes(3000, 5 + i)).collect();
        let names: Vec<String> = (0..6).map(|i| format!("f{i}.bin")).collect();
        let files: Vec<(&str, &[u8])> = names
            .iter()
            .zip(&contents)
            .map(|(n, c)| (n.as_str(), c.as_slice()))
            .collect();
        let meta = make_metainfo("T", &files, 512);
        let fake = FakeTransmission::start(&root);
        fake.provide(&meta, &contents);
        let rpc = Rpc::new(fake.settings());
        let env = Env {
            dir: root.join("dl"),
            capacity: 10_000 + 2 * 3000 + 2 * 512 + 10,
            other: 0,
            now: 1_800_000_000,
            crash_at: None,
        };
        Lab {
            _tmp: tmp,
            root,
            e,
            fake,
            rpc,
            meta,
            contents,
            env,
        }
    }

    fn add(l: &mut Lab) -> TorrentJob {
        l.e.torrent_add(
            &TorrentAddOptions {
                source: AddSource::Metainfo(l.meta.clone()),
                folder: "t".into(),
                storages: vec!["box".into()],
                free_min: MinFree::Bytes(10_000),
                download_dir: Some(l.root.join("dl")),
                folder_parent: l.root.join("folders"),
                min_copies: Some(1),
                rpc: l.fake.settings(),
            },
            &l.rpc,
        )
        .unwrap()
    }

    fn tick(l: &mut Lab, hash: &str) -> Result<TorrentJob> {
        l.e.torrent_tick(hash, &l.rpc, &mut l.env, true)
            .map(|j| j.unwrap())
    }

    #[test]
    fn added_paused_with_every_file_unwanted() {
        let mut l = lab();
        let job = add(&mut l);
        assert_eq!(job.state, JobState::Downloading);
        assert!(l.fake.has(&job.hash));
        assert!(!l.fake.running(&job.hash));
        assert_eq!(l.fake.wanted(&job.hash), vec![false; 6]);
        assert_eq!(job.download_dir, l.root.join("dl").join(&job.hash));
        assert!(job_path(&l.e.home, &job.hash).is_file());
        let p = l.e.placement("t").unwrap();
        assert_eq!(p.targets, vec!["box".to_string()]);
        // Again: refused, the job is there.
        let e =
            l.e.torrent_add(
                &TorrentAddOptions {
                    source: AddSource::Metainfo(l.meta.clone()),
                    folder: "t2".into(),
                    storages: vec![],
                    free_min: DEFAULT_FREE_MIN,
                    download_dir: Some(l.root.join("dl")),
                    folder_parent: l.root.join("folders"),
                    min_copies: None,
                    rpc: l.fake.settings(),
                },
                &l.rpc,
            )
            .unwrap_err();
        assert!(format!("{e:#}").contains("there is a torrent job"), "{e:#}");
    }

    #[test]
    fn refuses_a_download_dir_in_varsto_and_a_torrent_transmission_has() {
        let mut l = lab();
        let opts = |dl: PathBuf, l: &Lab| TorrentAddOptions {
            source: AddSource::Metainfo(l.meta.clone()),
            folder: "t".into(),
            storages: vec![],
            free_min: DEFAULT_FREE_MIN,
            download_dir: Some(dl),
            folder_parent: l.root.join("folders"),
            min_copies: Some(1),
            rpc: l.fake.settings(),
        };
        let o = opts(l.root.join("home").join("downloads"), &l);
        let e = l.e.torrent_add(&o, &l.rpc).unwrap_err();
        assert!(format!("{e:#}").contains("Varsto home"), "{e:#}");
        assert!(!l
            .root
            .join("home/downloads")
            .join(parse_hash(&l.meta))
            .exists());
        // Inside a folder of the vault.
        let docs = l.root.join("docs");
        fs::create_dir_all(&docs).unwrap();
        l.e.add_folder("docs", &docs).unwrap();
        let o = opts(docs.join("dl"), &l);
        let e = l.e.torrent_add(&o, &l.rpc).unwrap_err();
        assert!(format!("{e:#}").contains("Varsto folder docs"), "{e:#}");
        // transmission has it already.
        l.rpc
            .add(&AddSource::Metainfo(l.meta.clone()), "/tmp/elsewhere", &[])
            .unwrap();
        let o = opts(l.root.join("dl"), &l);
        let e = l.e.torrent_add(&o, &l.rpc).unwrap_err();
        assert!(
            format!("{e:#}").contains("has this torrent already"),
            "{e:#}"
        );
    }

    fn parse_hash(meta: &[u8]) -> String {
        transmission::parse_metainfo(meta).unwrap().hash
    }

    #[test]
    fn a_batch_is_wanted_completed_imported_and_removed() {
        let mut l = lab();
        let job = add(&mut l);
        let h = job.hash.clone();
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.batch, vec![0, 1]);
        assert_eq!(
            l.fake.wanted(&h),
            vec![true, true, false, false, false, false]
        );
        assert!(l.fake.running(&h));
        // Half of the first file: nothing to import yet.
        l.fake.step(1500);
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.files_done(), 0);
        assert_eq!(j.state, JobState::Downloading);
        l.fake.step(u64::MAX);
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.files_done(), 2, "{j:#?}");
        assert_eq!(j.bytes_stored, 6000);
        assert!(!j.download_dir.join("T/f0.bin").exists());
        assert!(!j.download_dir.join("T/f1.bin").exists());
        assert_eq!(
            l.fake.wanted(&h),
            vec![false; 6],
            "removed files are unwanted"
        );
        assert_eq!(l.fake.calls("torrent-verify"), 1);
        assert_eq!(l.e.read_file("t", "T/f0.bin").unwrap(), l.contents[0]);
        assert_eq!(l.e.read_file("t", "T/f1.bin").unwrap(), l.contents[1]);
        // The next batch.
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.batch, vec![2, 3]);
        assert_eq!(j.batches, 2);
    }

    #[test]
    fn a_crash_between_import_and_unwanted_is_carried_on() {
        let mut l = lab();
        let h = add(&mut l).hash;
        tick(&mut l, &h).unwrap();
        l.fake.step(u64::MAX);
        // Crash after the import, before the files went.
        l.env.crash_at = Some("imported");
        let e = tick(&mut l, &h).unwrap_err();
        assert!(format!("{e:#}").contains("simulated crash"));
        let j = find_job(&l.e.home, &h).unwrap();
        assert_eq!(j.files_done(), 0);
        assert!(j.last_error.is_some());
        assert!(
            j.download_dir.join("T/f0.bin").exists(),
            "nothing removed yet"
        );
        // Crash after removal, before transmission was told.
        l.env.crash_at = Some("removed");
        tick(&mut l, &h).unwrap_err();
        assert!(!j.download_dir.join("T/f0.bin").exists());
        assert_eq!(l.fake.wanted(&h)[..2], [true, true], "still wanted");
        let removals_before = l.e.import_status(Some("t")).unwrap()[0].removed_files;
        // Restart: a new engine reads the job and transmission again.
        let home = l.e.home.clone();
        l.e = Engine::open(&home, PASS).unwrap();
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.files_done(), 2);
        assert_eq!(l.fake.wanted(&h), vec![false; 6]);
        assert_eq!(l.fake.calls("torrent-verify"), 1);
        assert_eq!(
            l.e.import_status(Some("t")).unwrap()[0].removed_files,
            removals_before,
            "nothing imported or removed twice"
        );
        assert_eq!(j.errors.len(), 2);
        assert!(j.last_error.is_none());
    }

    #[test]
    fn free_space_falling_below_the_reserve_mid_batch_pauses() {
        let mut l = lab();
        let h = add(&mut l).hash;
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.batch, vec![0, 1]);
        l.fake.step(1000);
        // Something else fills the disk below the reserve.
        l.env.other = 7000;
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::WaitingSpace, "{j:#?}");
        assert!(j.stopped_for_space);
        assert!(!l.fake.running(&h));
        assert!(j.need_bytes > 0);
        // Still short of the reserve plus the rest of the batch.
        l.env.other = 2000;
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::WaitingSpace);
        assert!(!l.fake.running(&h));
        // Room again: it goes on.
        l.env.other = 0;
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::Downloading);
        assert!(!j.stopped_for_space);
        assert!(l.fake.running(&h));
        // The Help page while waiting.
        l.env.other = 7000;
        tick(&mut l, &h).unwrap();
        let ins = l.e.torrent_help_inputs();
        assert_eq!(ins[0].state, "waiting_space");
    }

    #[test]
    fn no_room_for_the_next_file_waits_without_starting() {
        let mut l = lab();
        let h = add(&mut l).hash;
        l.env.other = 9000;
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::WaitingSpace);
        assert!(j.batch.is_empty());
        assert!(!l.fake.running(&h));
        assert!(j.text.contains("T/f0.bin"), "{}", j.text);
    }

    #[test]
    fn a_transmission_error_is_reported_and_retried() {
        let mut l = lab();
        let h = add(&mut l).hash;
        tick(&mut l, &h).unwrap();
        l.fake.set_error(&h, 3, "No space left on device");
        let j = tick(&mut l, &h).unwrap();
        assert!(
            j.last_error.as_deref().unwrap().contains("No space left"),
            "{j:#?}"
        );
        assert!(l.fake.running(&h), "started again");
        assert_eq!(j.batch, vec![0, 1], "the batch stays");
        l.fake.set_error(&h, 3, "No space left on device");
        let j = tick(&mut l, &h).unwrap();
        assert!(!l.fake.running(&h), "not again within a minute");
        assert_eq!(j.errors.len(), 1, "the same error once");
        l.env.now += RETRY_SECS;
        tick(&mut l, &h).unwrap();
        assert!(l.fake.running(&h));
        l.fake.step(u64::MAX);
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.files_done(), 2);
    }

    #[test]
    fn a_magnet_link_gets_its_file_list_first() {
        let mut l = lab();
        let h = parse_hash(&l.meta);
        let job =
            l.e.torrent_add(
                &TorrentAddOptions {
                    source: AddSource::Magnet(format!("magnet:?xt=urn:btih:{h}&dn=T")),
                    folder: "t".into(),
                    storages: vec![],
                    free_min: MinFree::Bytes(10_000),
                    download_dir: Some(l.root.join("dl")),
                    folder_parent: l.root.join("folders"),
                    min_copies: Some(1),
                    rpc: l.fake.settings(),
                },
                &l.rpc,
            )
            .unwrap();
        assert_eq!(job.state, JobState::Metadata);
        assert!(l.fake.running(&h) && l.fake.limited(&h));
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::Metadata);
        l.fake.step(0); // the metadata arrives: transmission wants everything
        assert_eq!(l.fake.wanted(&h), vec![true; 6]);
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.files.len(), 6);
        assert_eq!(l.fake.wanted(&h), vec![false; 6]);
        assert!(!l.fake.running(&h) && !l.fake.limited(&h));
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.batch, vec![0, 1]);
    }

    #[test]
    fn pause_resume_and_a_torrent_gone_from_transmission() {
        let mut l = lab();
        let h = add(&mut l).hash;
        tick(&mut l, &h).unwrap();
        let j = l.e.torrent_set_paused(&h[..8], true, &l.rpc).unwrap();
        assert_eq!(j.state, JobState::Paused);
        assert!(!l.fake.running(&h));
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.state, JobState::Paused);
        assert!(!l.fake.running(&h));
        l.e.torrent_set_paused("t", false, &l.rpc).unwrap();
        tick(&mut l, &h).unwrap();
        assert!(l.fake.running(&h));
        // Someone removed it in transmission: added again, nothing wanted
        // until the job says so.
        l.rpc.remove(&h, false).unwrap();
        let j = tick(&mut l, &h).unwrap();
        assert!(l.fake.has(&h));
        assert!(j.errors.iter().any(|e| e.text.contains("added again")));
        let j = tick(&mut l, &h).unwrap();
        assert_eq!(j.batch, vec![0, 1]);
        assert_eq!(l.fake.wanted(&h)[..2], [true, true]);
    }

    #[test]
    fn reserve_is_never_below_the_section_53_minimum() {
        assert_eq!(DEFAULT_FREE_MIN.bytes(1000), 150);
        assert_eq!(
            MinFree::parse("1%")
                .unwrap()
                .bytes(1000)
                .max(crate::freespace::DEFAULT.bytes(1000)),
            50
        );
    }
}
