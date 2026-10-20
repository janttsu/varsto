// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! YouTube jobs: a channel, playlist or video is listed with the local
//! `yt-dlp` and downloaded politely, one video at a time, into a spool
//! directory on the download disk; each finished video goes into a Varsto
//! folder (encrypted onto the storages) and leaves the spool once the
//! folder's durability policy holds (`docs/spec/alpha-0-format.md` section
//! "YouTube channels through yt-dlp", `docs/youtube.md`).
//!
//! A job is a file, `state/youtube/<job id>.json`. Each step
//! ([`Engine::youtube_tick`]) does one thing and saves:
//!
//! 1. a yt-dlp run that ended is taken in: a listing becomes the job's
//!    video list (new videos are added, nothing is forgotten); a probe gives
//!    a video's expected size; a download is moved from yt-dlp's work
//!    directory to `<channel>/<date> <title> [<id>].<ext>` in the spool;
//! 2. videos in the spool are imported (the import of a local directory,
//!    section 42, with the spool as a `youtube` source) and removed with its
//!    rule once every block is on a storage, one copy was read back and the
//!    policy holds;
//! 3. the next yt-dlp run starts: a listing when none was made or the last
//!    is older than the refresh interval, else a probe of the next video,
//!    else its download when its expected size fits above the reserve.
//!
//! Before a video is probed or downloaded, its id is looked up in the
//! vault's YouTube index (every folder's import book, the folders attached
//! here and the device's own scans, [`Engine::youtube_index`]): a video
//! that is anywhere already is never downloaded again. A video that fails
//! (private, removed, blocked in this country) is recorded with yt-dlp's
//! reason and tried again later, an hour, then four times longer each time
//! up to a week; after six failures it is given up until `youtube resume`.
//!
//! The background service leaves yt-dlp running between steps (it checks
//! on it after each sync); the command line waits for it
//! ([`YoutubeEnv::blocking`]).

use super::*;
use crate::freespace::MinFree;
use crate::import::youtube::SpoolSource;
use crate::import::TreeEntry;
use crate::pool::DiskSpace;
use crate::youtube::{self as yt, Throttle, UrlKind};
use std::any::Any;
use std::process::{Child, Command, Stdio};

/// Job files live in `state/youtube/`.
pub const YOUTUBE_DIR: &str = "youtube";
/// The free space kept on the download disk unless `--free-min` says otherwise.
pub const DEFAULT_YT_FREE_MIN: MinFree = MinFree::Basis(1500);
/// How often a job lists its channel again for new videos (hours).
pub const DEFAULT_REFRESH_HOURS: u32 = 24;
/// yt-dlp's own files in the spool (hidden from the import like every
/// `.varsto` name).
pub const WORK_DIR: &str = ".varsto-work";
/// A probe's size is used for this long.
const PROBE_FRESH_SECS: i64 = 6 * 3600;
const ERRORS_KEPT: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum YtState {
    /// yt-dlp lists the channel.
    Listing,
    /// yt-dlp reads a video's size.
    Probing,
    Downloading,
    /// No room for the next video above the reserve.
    WaitingSpace,
    /// Downloaded videos wait for the folder's policy before they leave
    /// the spool; nothing else to download.
    WaitingPolicy,
    /// Only videos that failed are left; they are tried again later.
    WaitingRetry,
    Paused,
    /// Every listed video is stored; the channel is listed again later.
    UpToDate,
    /// Every video is stored and the job does not list again.
    Complete,
}

impl YtState {
    pub fn as_str(self) -> &'static str {
        match self {
            YtState::Listing => "listing",
            YtState::Probing => "probing",
            YtState::Downloading => "downloading",
            YtState::WaitingSpace => "waiting_space",
            YtState::WaitingPolicy => "waiting_policy",
            YtState::WaitingRetry => "waiting_retry",
            YtState::Paused => "paused",
            YtState::UpToDate => "up_to_date",
            YtState::Complete => "complete",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VideoStatus {
    Pending,
    /// In the spool, waiting to be imported or to leave it.
    Downloaded,
    /// In the folder and gone from the spool.
    Stored,
    /// The vault had it before this job would have downloaded it.
    AlreadyStored,
    /// Failed; tried again at `next_try_utc`.
    Failed,
    /// Failed too often; `youtube resume` tries it again.
    GaveUp,
}

impl VideoStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VideoStatus::Pending => "pending",
            VideoStatus::Downloaded => "downloaded",
            VideoStatus::Stored => "stored",
            VideoStatus::AlreadyStored => "already_stored",
            VideoStatus::Failed => "failed",
            VideoStatus::GaveUp => "gave_up",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Video {
    pub id: String,
    #[serde(default)]
    pub title: String,
    pub url: String,
    pub status: VideoStatus,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_try_utc: i64,
    #[serde(default)]
    pub last_error: Option<String>,
    /// From the probe (`filesize` or `filesize_approx`).
    #[serde(default)]
    pub size_estimate: Option<u64>,
    #[serde(default)]
    pub probed_utc: i64,
    /// Its files, as paths in the spool and the folder.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub bytes: u64,
    /// Where the vault has it (`AlreadyStored`).
    #[serde(default)]
    pub found_in: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    List,
    Probe,
    Download,
}

/// The yt-dlp run in flight.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Running {
    pub kind: TaskKind,
    #[serde(default)]
    pub video: Option<String>,
    pub pid: u32,
    pub started_utc: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct YtError {
    pub utc: i64,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct YoutubeJob {
    /// 16 hex digits; also the spool directory's name.
    pub id: String,
    /// The canonical address (`crate::youtube::parse_source_url`).
    pub url: String,
    pub kind: UrlKind,
    pub label: String,
    pub folder: String,
    #[serde(default)]
    pub storages: Vec<String>,
    /// The reserve on the download disk as given ("15%", "20GB").
    pub free_min: String,
    /// `<download dir>/<job id>`.
    pub spool_dir: PathBuf,
    pub folder_parent: PathBuf,
    /// yt-dlp to run; empty: `VARSTO_YTDLP`, else `yt-dlp` from the PATH.
    #[serde(default)]
    pub ytdlp: Option<PathBuf>,
    pub throttle: Throttle,
    #[serde(default)]
    pub thumbnails: bool,
    /// Subtitle languages (`en,fi`); empty: none.
    #[serde(default)]
    pub subtitles: String,
    /// 0: list once.
    pub refresh_hours: u32,
    pub created_utc: i64,
    pub updated_utc: i64,
    pub state: YtState,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub user_paused: bool,
    #[serde(default)]
    pub last_list_utc: Option<i64>,
    #[serde(default)]
    pub list_failures: u32,
    #[serde(default)]
    pub next_list_utc: i64,
    /// List at the next step whatever the interval (`--retry-failed`).
    #[serde(default)]
    pub list_now: bool,
    #[serde(default)]
    pub videos: Vec<Video>,
    #[serde(default)]
    pub running: Option<Running>,
    #[serde(default)]
    pub reserve_bytes: u64,
    #[serde(default)]
    pub free_bytes: Option<u64>,
    #[serde(default)]
    pub need_bytes: u64,
    #[serde(default)]
    pub errors: Vec<YtError>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub completed_utc: Option<i64>,
}

/// How many videos are where.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct VideoCounts {
    pub listed: u64,
    pub pending: u64,
    pub downloaded: u64,
    pub stored: u64,
    pub already_stored: u64,
    pub failed: u64,
    pub gave_up: u64,
    pub stored_bytes: u64,
}

impl YoutubeJob {
    pub fn short(&self) -> &str {
        &self.id[..self.id.len().min(8)]
    }

    pub fn counts(&self) -> VideoCounts {
        let mut c = VideoCounts {
            listed: self.videos.len() as u64,
            ..Default::default()
        };
        for v in &self.videos {
            match v.status {
                VideoStatus::Pending => c.pending += 1,
                VideoStatus::Downloaded => c.downloaded += 1,
                VideoStatus::Stored => {
                    c.stored += 1;
                    c.stored_bytes += v.bytes;
                }
                VideoStatus::AlreadyStored => c.already_stored += 1,
                VideoStatus::Failed => c.failed += 1,
                VideoStatus::GaveUp => c.gave_up += 1,
            }
        }
        c
    }

    pub fn running(&self) -> bool {
        self.state != YtState::Complete && !self.user_paused
    }

    fn push_error(&mut self, utc: i64, text: String) {
        if self.errors.last().is_some_and(|e| e.text == text) {
            self.last_error = Some(text);
            return;
        }
        self.errors.push(YtError {
            utc,
            text: text.clone(),
        });
        if self.errors.len() > ERRORS_KEPT {
            let n = self.errors.len() - ERRORS_KEPT;
            self.errors.drain(..n);
        }
        self.last_error = Some(text);
    }

    fn work_dir(&self) -> PathBuf {
        self.spool_dir.join(WORK_DIR)
    }

    fn video_mut(&mut self, id: &str) -> Option<&mut Video> {
        self.videos.iter_mut().find(|v| v.id == id)
    }

    /// One line for `varsto youtube status` and `varsto status`.
    pub fn line(&self) -> String {
        let c = self.counts();
        format!(
            "youtube {} {}: {}, {} of {} videos stored ({}), {} already in the vault, {} failed{} into folder {}{}",
            self.short(),
            self.label,
            self.state.as_str().replace('_', " "),
            c.stored,
            c.listed,
            util::human_bytes(c.stored_bytes),
            c.already_stored,
            c.failed + c.gave_up,
            if c.gave_up > 0 {
                format!(" ({} given up)", c.gave_up)
            } else {
                String::new()
            },
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
/// disk), the time, a hold on the background service while an import runs
/// (the command line pauses it), and whether to wait for yt-dlp.
pub trait YoutubeEnv {
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
    /// Wait for each yt-dlp run within the step (the command line).
    fn blocking(&self) -> bool {
        false
    }
}

/// The background service's environment: the real disk and clock, yt-dlp
/// left running between steps.
pub struct ServiceYoutubeEnv;
impl YoutubeEnv for ServiceYoutubeEnv {}

/// The command line's: like the service's, but every yt-dlp run is waited for.
pub struct BlockingYoutubeEnv;
impl YoutubeEnv for BlockingYoutubeEnv {
    fn blocking(&self) -> bool {
        true
    }
}

/// What to add.
#[derive(Clone, Debug)]
pub struct YoutubeAddOptions {
    pub url: String,
    pub folder: Option<String>,
    /// Storage names, or `cheapest`.
    pub storages: Vec<String>,
    pub free_min: MinFree,
    /// Where the spool goes (`<dir>/<job id>`).
    pub download_dir: PathBuf,
    pub folder_parent: PathBuf,
    /// The policy a new folder gets (copies on storages); `None` keeps the
    /// default policy.
    pub min_copies: Option<u32>,
    pub throttle: Throttle,
    pub thumbnails: bool,
    pub subtitles: String,
    pub refresh_hours: u32,
    pub ytdlp: Option<PathBuf>,
}

/// What `youtube scan` found.
#[derive(Clone, Debug, Default, Serialize)]
pub struct YoutubeScanReport {
    /// The folder or directory scanned.
    pub target: String,
    /// `folder` (recorded with the folder, for every device) or
    /// `directory` (recorded on this device only).
    pub kind: String,
    pub files_with_id: u64,
    pub videos: u64,
    /// Videos the index did not have.
    pub new_videos: u64,
}

/// Videos this device knows of outside Varsto (`youtube scan <dir>`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KnownLocal {
    videos: BTreeMap<String, String>,
}

// ----- job files ---------------------------------------------------------------------

fn jobs_dir(home: &Path) -> PathBuf {
    home.join("state").join(YOUTUBE_DIR)
}

fn job_path(home: &Path, id: &str) -> PathBuf {
    jobs_dir(home).join(format!("{id}.json"))
}

/// Every YouTube job of a device directory (read without the passphrase:
/// `varsto status`).
pub fn youtube_jobs_at(home: &Path) -> Vec<YoutubeJob> {
    let mut out: Vec<YoutubeJob> = fs::read_dir(jobs_dir(home))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".json") && n != "known.json"
        })
        .filter_map(|e| util::read_json::<YoutubeJob>(&e.path()).ok())
        .collect();
    out.sort_by_key(|j| j.created_utc);
    out
}

fn save_job(home: &Path, job: &mut YoutubeJob, now: i64) -> Result<()> {
    job.updated_utc = now;
    let p = job_path(home, &job.id);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    util::write_json(&p, job)
}

/// A job by id (or its start, 4 characters or more), folder, label or address.
pub fn find_youtube_job(home: &Path, key: &str) -> Result<YoutubeJob> {
    let k = key.trim().to_lowercase();
    let canonical = yt::parse_source_url(key).ok().map(|s| s.canonical);
    let jobs = youtube_jobs_at(home);
    let hits: Vec<&YoutubeJob> = jobs
        .iter()
        .filter(|j| {
            (k.len() >= 4 && j.id.starts_with(&k))
                || j.folder.to_lowercase() == k
                || j.label.to_lowercase() == k
                || canonical.as_deref() == Some(j.url.as_str())
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no YouTube job {key}: `varsto youtube status` lists them"),
        _ => bail!("{key} names more than one YouTube job: give its id"),
    }
}

/// Holds a job while one step changes it (the command line and the
/// background service may both drive it).
struct JobLock {
    _file: fs::File,
}

fn lock_job(home: &Path, id: &str, wait: bool) -> Result<Option<JobLock>> {
    let p = jobs_dir(home).join(format!("{id}.lock"));
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

// ----- yt-dlp runs ---------------------------------------------------------------------

/// yt-dlp runs this process started, by job id: polled (and stopped, when
/// the disk runs short) by later steps.
static CHILDREN: std::sync::Mutex<BTreeMap<String, Child>> = std::sync::Mutex::new(BTreeMap::new());

enum Poll {
    Running,
    /// Ended; its exit code when this process started it (else unknown).
    Ended(Option<i32>),
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn poll_child(job_id: &str, r: &Running) -> Poll {
    let mut children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = children.get_mut(job_id) {
        if c.id() == r.pid {
            return match c.try_wait() {
                Ok(Some(status)) => {
                    children.remove(job_id);
                    Poll::Ended(status.code().or(Some(-1)))
                }
                Ok(None) => Poll::Running,
                Err(_) => {
                    children.remove(job_id);
                    Poll::Ended(None)
                }
            };
        }
        // A run of an earlier step that another process took in.
        let mut old = children.remove(job_id).expect("present");
        let _ = old.try_wait();
    }
    // Started by another process (the service, or before a restart).
    if pid_alive(r.pid) {
        Poll::Running
    } else {
        Poll::Ended(None)
    }
}

/// Stop a run this process started (by its PID, never by name).
fn stop_child(job_id: &str) -> bool {
    let mut children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    match children.remove(job_id) {
        Some(mut c) => {
            let _ = c.kill();
            let _ = c.wait();
            true
        }
        None => false,
    }
}

fn wait_child(job_id: &str) -> Option<i32> {
    let child = CHILDREN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(job_id);
    child
        .and_then(|mut c| c.wait().ok())
        .map(|s| s.code().unwrap_or(-1))
}

fn read_text(p: &Path) -> String {
    fs::read(p)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default()
}

/// The files of a task: (stdout, stderr).
fn task_files(job: &YoutubeJob, kind: TaskKind, video: Option<&str>) -> (PathBuf, PathBuf) {
    // Apart from the downloads, whose names start with the video id.
    let w = job.work_dir().join("logs");
    let name = match (kind, video) {
        (TaskKind::List, _) => "list".to_string(),
        (TaskKind::Probe, Some(v)) => format!("probe-{v}"),
        (TaskKind::Download, Some(v)) => format!("download-{v}"),
        (_, None) => "task".to_string(),
    };
    (w.join(format!("{name}.out")), w.join(format!("{name}.err")))
}

/// The arguments of a task (after the program).
pub fn task_args(job: &YoutubeJob, kind: TaskKind, video: Option<&Video>) -> Vec<String> {
    let t = &job.throttle;
    let mut a: Vec<String> = Vec::new();
    match kind {
        TaskKind::List => {
            a.extend([
                "--flat-playlist".to_string(),
                "--ignore-errors".to_string(),
                "--no-warnings".to_string(),
                "--print".to_string(),
                yt::LIST_TEMPLATE.to_string(),
            ]);
            // (a format given for the downloads means nothing to a listing)
            a.extend(
                Throttle {
                    format: String::new(),
                    ..t.clone()
                }
                .common_args(),
            );
            a.push("--".into());
            a.push(job.url.clone());
        }
        TaskKind::Probe => {
            a.extend([
                "--skip-download".to_string(),
                "--no-playlist".to_string(),
                "--no-warnings".to_string(),
                "--sleep-requests".to_string(),
                t.sleep_requests.to_string(),
                "--print".to_string(),
                "%(filesize,filesize_approx)s".to_string(),
            ]);
            a.extend(t.common_args());
            a.push("--".into());
            a.push(video.map(|v| v.url.clone()).unwrap_or_default());
        }
        TaskKind::Download => {
            a.extend(t.download_args());
            a.extend([
                "--no-playlist".to_string(),
                "--write-info-json".to_string(),
                "--no-write-playlist-metafiles".to_string(),
                "--no-progress".to_string(),
                "--newline".to_string(),
            ]);
            if job.thumbnails {
                a.push("--write-thumbnail".into());
            }
            if !job.subtitles.is_empty() {
                a.extend([
                    "--write-subs".to_string(),
                    "--sub-langs".to_string(),
                    job.subtitles.clone(),
                ]);
            }
            a.push("-o".into());
            a.push(job.work_dir().join("%(id)s.%(ext)s").display().to_string());
            a.push("--".into());
            a.push(video.map(|v| v.url.clone()).unwrap_or_default());
        }
    }
    a
}

impl Engine {
    fn ytdlp_program(&self, job: &YoutubeJob) -> PathBuf {
        job.ytdlp
            .clone()
            .filter(|p| !p.as_os_str().is_empty())
            .or_else(|| std::env::var_os("VARSTO_YTDLP").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("yt-dlp"))
    }

    /// Start a yt-dlp run for the job (recorded in it; waited for when the
    /// environment blocks, then `Some(exit code)`).
    fn start_task(
        &self,
        job: &mut YoutubeJob,
        kind: TaskKind,
        video: Option<&str>,
        env: &mut dyn YoutubeEnv,
    ) -> Result<Option<Option<i32>>> {
        fs::create_dir_all(job.work_dir().join("logs"))?;
        let v = video
            .and_then(|id| job.videos.iter().find(|x| x.id == id))
            .cloned();
        let args = task_args(job, kind, v.as_ref());
        let (out, err) = task_files(job, kind, video);
        let program = self.ytdlp_program(job);
        let child = Command::new(&program)
            .args(&args)
            .current_dir(job.work_dir())
            .stdin(Stdio::null())
            .stdout(fs::File::create(&out)?)
            .stderr(fs::File::create(&err)?)
            .spawn()
            .with_context(|| {
                format!(
                    "start {} (install yt-dlp, or name it with --ytdlp-path or VARSTO_YTDLP)",
                    program.display()
                )
            })?;
        let now = env.now();
        job.running = Some(Running {
            kind,
            video: video.map(str::to_string),
            pid: child.id(),
            started_utc: now,
        });
        CHILDREN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job.id.clone(), child);
        save_job(&self.home, job, now)?;
        if env.blocking() {
            return Ok(Some(wait_child(&job.id)));
        }
        Ok(None)
    }

    /// Take in a run that ended.
    fn finish_task(
        &self,
        job: &mut YoutubeJob,
        r: &Running,
        code: Option<i32>,
        now: i64,
    ) -> Result<()> {
        job.running = None;
        let (out, err) = task_files(job, r.kind, r.video.as_deref());
        match r.kind {
            TaskKind::List => {
                job.list_now = false;
                let entries = yt::parse_flat_listing(&read_text(&out));
                let failed = code.is_none_or(|c| c != 0) && entries.is_empty();
                if failed {
                    job.list_failures += 1;
                    job.next_list_utc = now + yt::backoff_secs(job.list_failures);
                    let why = if code.is_none() {
                        "the listing was interrupted".to_string()
                    } else {
                        yt::error_reason(&read_text(&err))
                    };
                    job.push_error(now, format!("listing {}: {why}", job.url));
                } else {
                    job.list_failures = 0;
                    job.last_list_utc = Some(now);
                    let known: BTreeSet<String> = job.videos.iter().map(|v| v.id.clone()).collect();
                    for e in entries {
                        if known.contains(&e.id) {
                            if let Some(v) = job.video_mut(&e.id) {
                                if v.title.is_empty() {
                                    v.title = e.title;
                                }
                            }
                            continue;
                        }
                        job.videos.push(Video {
                            id: e.id,
                            title: e.title,
                            url: e.url,
                            status: VideoStatus::Pending,
                            attempts: 0,
                            next_try_utc: 0,
                            last_error: None,
                            size_estimate: None,
                            probed_utc: 0,
                            paths: Vec::new(),
                            bytes: 0,
                            found_in: None,
                        });
                    }
                }
            }
            TaskKind::Probe => {
                let Some(id) = r.video.clone() else {
                    return Ok(());
                };
                let size = yt::parse_probe_size(&read_text(&out));
                let reason = yt::error_reason(&read_text(&err));
                let Some(v) = job.video_mut(&id) else {
                    return Ok(());
                };
                match code {
                    Some(0) => {
                        v.size_estimate = size;
                        v.probed_utc = now;
                    }
                    // Interrupted: probed again.
                    None => {}
                    Some(_) => fail_video(v, reason, now),
                }
            }
            TaskKind::Download => {
                let Some(id) = r.video.clone() else {
                    return Ok(());
                };
                let reason = yt::error_reason(&read_text(&err));
                match self.take_download(job, &id)? {
                    Some((paths, bytes)) => {
                        if let Some(v) = job.video_mut(&id) {
                            v.status = VideoStatus::Downloaded;
                            v.paths = paths;
                            v.bytes = bytes;
                            v.last_error = None;
                        }
                        let _ = fs::remove_file(&out);
                        let _ = fs::remove_file(&err);
                    }
                    None => {
                        if let Some(v) = job.video_mut(&id) {
                            match code {
                                // Interrupted (a restart): tried again, not a failure.
                                None => {}
                                Some(_) => fail_video(v, reason, now),
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Move a finished download from the work directory to its place in
    /// the spool: (paths, bytes), or `None` when there is no media file.
    fn take_download(&self, job: &YoutubeJob, id: &str) -> Result<Option<(Vec<String>, u64)>> {
        let work = job.work_dir();
        let mut files: Vec<(String, yt::FileRole)> = Vec::new();
        for e in fs::read_dir(&work).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            if let Some(role) = yt::kept_file(id, &name) {
                files.push((name, role));
            }
        }
        if !files.iter().any(|(_, r)| *r == yt::FileRole::Media) {
            return Ok(None);
        }
        let meta = files
            .iter()
            .find(|(_, r)| *r == yt::FileRole::Info)
            .map(|(n, _)| yt::read_info_json(&fs::read(work.join(n)).unwrap_or_default()))
            .unwrap_or_default();
        let title = if meta.title.is_empty() {
            job.videos
                .iter()
                .find(|v| v.id == id)
                .map(|v| v.title.clone())
                .unwrap_or_default()
        } else {
            meta.title.clone()
        };
        let channel = if meta.channel.is_empty() {
            job.label.trim_start_matches('@').to_string()
        } else {
            meta.channel.clone()
        };
        let mut paths = Vec::new();
        let mut bytes = 0u64;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, _) in files {
            let suffix = &name[id.len()..];
            let rel = yt::video_path(&channel, meta.date.as_deref(), &title, id, suffix);
            util::check_rel_path(&rel)?;
            let dest = util::safe_join(&job.spool_dir, &rel)?;
            if let Some(d) = dest.parent() {
                fs::create_dir_all(d)?;
            }
            fs::rename(work.join(&name), &dest)
                .with_context(|| format!("move the download to {}", dest.display()))?;
            bytes += fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
            paths.push(rel);
        }
        Ok(Some((paths, bytes)))
    }

    /// The vault's YouTube index: video id -> where it is ("folder X:
    /// path"): every folder's import book (all devices' records), the file
    /// names of the folders attached here, and this device's scans of
    /// directories outside Varsto.
    pub fn youtube_index(&mut self) -> Result<BTreeMap<String, String>> {
        let _ = self.pull_registry();
        let _ = self.refresh_books();
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        let live: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_backup())
            .cloned()
            .collect();
        for rec in &live {
            if let Some(b) = self.load_book(&rec.folder_id) {
                for (id, paths) in &b.youtube {
                    let at = paths.iter().next().cloned().unwrap_or_default();
                    out.entry(id.clone())
                        .or_insert_with(|| format!("folder {}: {at}", rec.name));
                }
            }
        }
        let attached: Vec<FolderId> = self
            .config
            .folders
            .iter()
            .map(|m| m.folder_id.clone())
            .collect();
        for fid in attached {
            let Some(rec) = live.iter().find(|r| r.folder_id == fid) else {
                continue;
            };
            let Ok(state) = self.load_state(&fid) else {
                continue;
            };
            for f in state.files.values().filter(|f| !f.deleted) {
                if let Some(id) = yt::id_from_filename(&f.path) {
                    out.entry(id)
                        .or_insert_with(|| format!("folder {}: {}", rec.name, f.path));
                }
            }
        }
        let known: KnownLocal =
            util::read_json_or_default(&jobs_dir(&self.home).join("known.json"))
                .unwrap_or_default();
        for (id, at) in known.videos {
            out.entry(id).or_insert(at);
        }
        Ok(out)
    }

    /// Register videos that are somewhere already by the `[<id>]` in their
    /// file names: a Varsto folder (recorded with the folder, for every
    /// device) or a directory outside Varsto (recorded on this device).
    pub fn youtube_scan(&mut self, target: &str) -> Result<YoutubeScanReport> {
        self.ensure_active()?;
        if let Some(rec) = self
            .keyring
            .find(target)
            .filter(|r| !r.is_removed() && !r.is_backup())
            .cloned()
        {
            let attached = self
                .config
                .folders
                .iter()
                .any(|m| m.folder_id == rec.folder_id);
            if !attached {
                bail!(
                    "folder {} is not attached here: attach it (selectively is enough) to scan it",
                    rec.name
                );
            }
            let index = self.youtube_index()?;
            let state = self.load_state(&rec.folder_id)?;
            let mut book = self.load_book(&rec.folder_id).unwrap_or_default();
            let mut report = YoutubeScanReport {
                target: rec.name.clone(),
                kind: "folder".into(),
                ..Default::default()
            };
            let mut seen = BTreeSet::new();
            for f in state.files.values().filter(|f| !f.deleted) {
                let Some(id) = yt::id_from_filename(&f.path) else {
                    continue;
                };
                report.files_with_id += 1;
                if seen.insert(id.clone()) {
                    let fresh = !book.youtube.contains_key(&id);
                    if fresh && !index.contains_key(&id) {
                        report.new_videos += 1;
                    }
                }
                book.youtube.entry(id).or_default().insert(f.path.clone());
            }
            report.videos = seen.len() as u64;
            self.save_book(&rec.folder_id, &book)?;
            let rec = self.with_key(&rec)?;
            self.publish_book(&rec, &book)?;
            return Ok(report);
        }
        let dir = PathBuf::from(target);
        if !dir.is_dir() {
            bail!("{target} is neither a folder of the vault nor a directory here");
        }
        let dir = dir.canonicalize()?;
        let index = self.youtube_index()?;
        let p = jobs_dir(&self.home).join("known.json");
        let mut known: KnownLocal = util::read_json_or_default(&p).unwrap_or_default();
        let mut report = YoutubeScanReport {
            target: dir.display().to_string(),
            kind: "directory".into(),
            ..Default::default()
        };
        let mut seen = BTreeSet::new();
        for e in walkdir::WalkDir::new(&dir)
            .follow_links(false)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
        {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = yt::id_from_filename(&name) else {
                continue;
            };
            report.files_with_id += 1;
            if seen.insert(id.clone()) && !index.contains_key(&id) {
                report.new_videos += 1;
            }
            known
                .videos
                .entry(id)
                .or_insert_with(|| format!("{} (this device)", e.path().display()));
        }
        report.videos = seen.len() as u64;
        fs::create_dir_all(jobs_dir(&self.home))?;
        util::write_json(&p, &known)?;
        Ok(report)
    }

    /// The free space the download disk keeps: the job's reserve, and never
    /// less than Varsto's own minimum (section 53) of a folder or directory
    /// storage on the same disk.
    fn youtube_reserve(&self, job: &YoutubeJob, total: u64) -> u64 {
        let mut r = MinFree::parse(&job.free_min)
            .unwrap_or(DEFAULT_YT_FREE_MIN)
            .bytes(total)
            .max(crate::freespace::DEFAULT.bytes(total));
        for m in &self.config.folders {
            if same_fs(&job.spool_dir, &m.path) {
                r = r.max(m.min_free.unwrap_or(crate::freespace::DEFAULT).bytes(total));
            }
        }
        for s in &self.config.storages {
            if let StorageSpec::LocalDir { path, min_free, .. } = s {
                if same_fs(&job.spool_dir, path) {
                    r = r.max(min_free.unwrap_or(crate::freespace::DEFAULT).bytes(total));
                }
            }
        }
        r
    }

    /// The storages `--storage` names; `cheapest`: the `copies` storages
    /// with the lowest known price per GB-month.
    fn youtube_storages(&self, given: &[String], copies: u32) -> Result<Vec<String>> {
        if !given.iter().any(|s| s.eq_ignore_ascii_case("cheapest")) {
            for s in given {
                if !self.config.storages.iter().any(|x| x.name() == s) {
                    bail!("unknown storage {s}");
                }
            }
            return Ok(given.to_vec());
        }
        if given.len() > 1 {
            bail!("--storage cheapest picks the storages itself: give no other");
        }
        let mut priced: Vec<(f64, String)> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .filter_map(|s| {
                let p = self.storage_price(s.name())?.storage_per_gb_month?;
                Some((p, s.name().to_string()))
            })
            .collect();
        if priced.is_empty() {
            bail!("no storage has a price per GB-month: set one with `varsto storage price`, or name the storages with --storage");
        }
        priced.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(priced
            .into_iter()
            .take(copies.max(1) as usize)
            .map(|(_, n)| n)
            .collect())
    }

    /// Register a YouTube job: the folder is created (attached selectively,
    /// with the placement and policy asked for) and the spool directory is
    /// made; nothing is downloaded yet.
    pub fn youtube_add(&mut self, opts: &YoutubeAddOptions) -> Result<YoutubeJob> {
        self.ensure_active()?;
        let src = yt::parse_source_url(&opts.url)?;
        if let Some(j) = youtube_jobs_at(&self.home)
            .into_iter()
            .find(|j| j.url == src.canonical)
        {
            bail!(
                "there is a YouTube job for {} already: varsto youtube status {}",
                src.canonical,
                j.short()
            );
        }
        for a in &opts.throttle.extra {
            yt::check_extra_arg(a)?;
        }
        let storages = self.youtube_storages(&opts.storages, opts.min_copies.unwrap_or(1))?;
        let id = util::random_suffix();
        let base = std::path::absolute(&opts.download_dir)?;
        fs::create_dir_all(&base)
            .with_context(|| format!("create the download directory {}", base.display()))?;
        let spool = base.join(&id);
        fs::create_dir_all(&spool)?;
        let folder = opts
            .folder
            .clone()
            .unwrap_or_else(|| crate::import::folder_name_from(src.label.trim_start_matches('@')));
        // The folder and its import book, by an import of nothing yet: it
        // refuses a spool inside a Varsto folder or the device directory,
        // and a folder name that holds other data.
        let mut source = SpoolSource::open(&spool, &src.canonical, &src.label, BTreeSet::new())?;
        let report = match self.import_run(
            &mut source,
            &ImportOptions {
                folder: Some(folder.clone()),
                selective: true,
                remove_source: true,
                default_parent: Some(opts.folder_parent.clone()),
                ..Default::default()
            },
        ) {
            Ok(r) => r,
            Err(e) => {
                let _ = fs::remove_dir(&spool);
                return Err(e);
            }
        };
        if !storages.is_empty() {
            self.set_placement(
                &report.folder,
                Some(crate::placement::Placement {
                    storages: storages.clone(),
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
        let now = util::now_utc();
        let mut job = YoutubeJob {
            id,
            url: src.canonical.clone(),
            kind: src.kind,
            label: src.label.clone(),
            folder: report.folder.clone(),
            storages,
            free_min: opts.free_min.setting(),
            spool_dir: spool,
            folder_parent: opts.folder_parent.clone(),
            ytdlp: opts.ytdlp.clone(),
            throttle: opts.throttle.clone(),
            thumbnails: opts.thumbnails,
            subtitles: opts.subtitles.clone(),
            refresh_hours: if src.kind == UrlKind::Video {
                0
            } else {
                opts.refresh_hours
            },
            created_utc: now,
            updated_utc: now,
            state: YtState::Listing,
            text: "waiting for the first listing".into(),
            user_paused: false,
            last_list_utc: None,
            list_failures: 0,
            next_list_utc: 0,
            list_now: false,
            videos: Vec::new(),
            running: None,
            reserve_bytes: 0,
            free_bytes: None,
            need_bytes: 0,
            errors: Vec::new(),
            last_error: None,
            completed_utc: None,
        };
        save_job(&self.home, &mut job, now)?;
        Ok(job)
    }

    /// One step of a job (see the module documentation). `wait`: wait for
    /// another step of the same job to finish; otherwise `None` while one
    /// runs.
    pub fn youtube_tick(
        &mut self,
        key: &str,
        env: &mut dyn YoutubeEnv,
        wait: bool,
    ) -> Result<Option<YoutubeJob>> {
        let job = find_youtube_job(&self.home, key)?;
        let Some(_lock) = lock_job(&self.home, &job.id, wait)? else {
            return Ok(None);
        };
        let mut job: YoutubeJob = util::read_json(&job_path(&self.home, &job.id))?;
        match self.youtube_step(&mut job, env) {
            Ok(()) => {
                let now = env.now();
                save_job(&self.home, &mut job, now)?;
                Ok(Some(job))
            }
            Err(e) => {
                let now = env.now();
                let mut saved: YoutubeJob =
                    util::read_json(&job_path(&self.home, &job.id)).unwrap_or(job);
                saved.push_error(now, format!("{e:#}"));
                save_job(&self.home, &mut saved, now)?;
                Err(e)
            }
        }
    }

    fn youtube_step(&mut self, job: &mut YoutubeJob, env: &mut dyn YoutubeEnv) -> Result<()> {
        let now = env.now();
        job.last_error = None;
        // 1. The yt-dlp run in flight.
        if let Some(r) = job.running.clone() {
            match poll_child(&job.id, &r) {
                Poll::Running => {
                    if r.kind == TaskKind::Download {
                        if let Some(space) = env.space(&job.spool_dir) {
                            let reserve = self.youtube_reserve(job, space.total);
                            job.reserve_bytes = reserve;
                            job.free_bytes = Some(space.free);
                            if space.free < reserve && stop_child(&job.id) {
                                // The partial download stays; yt-dlp
                                // continues it when there is room.
                                job.running = None;
                                job.need_bytes = reserve - space.free;
                                job.state = YtState::WaitingSpace;
                                job.text = short_text(space.free, reserve, job.need_bytes);
                                return Ok(());
                            }
                        }
                    }
                    job.state = match r.kind {
                        TaskKind::List => YtState::Listing,
                        TaskKind::Probe => YtState::Probing,
                        TaskKind::Download => YtState::Downloading,
                    };
                    let mine = CHILDREN
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(&job.id);
                    job.text = running_text(job, &r, !mine);
                    return Ok(());
                }
                Poll::Ended(code) => {
                    self.finish_task(job, &r, code, now)?;
                    save_job(&self.home, job, now)?;
                    env.checkpoint("finished")?;
                }
            }
        }
        let rec = self
            .keyring
            .folders
            .values()
            .find(|r| !r.is_removed() && r.name.to_lowercase() == job.folder.to_lowercase())
            .cloned()
            .ok_or_else(|| anyhow!("the vault has no folder {} any more", job.folder))?;

        // 2. Videos in the spool: imported, and removed once safe.
        let waiting_policy = self.youtube_import_ready(job, &rec, env, now)?;

        if job.user_paused {
            job.state = YtState::Paused;
            job.text = "paused".into();
            return Ok(());
        }
        // 3. A listing when due.
        let due = match job.last_list_utc {
            _ if job.list_now => true,
            None => now >= job.next_list_utc,
            Some(t) => {
                job.refresh_hours > 0
                    && now - t >= job.refresh_hours as i64 * 3600
                    && now >= job.next_list_utc
            }
        };
        if due {
            job.state = YtState::Listing;
            job.text = format!("listing {}", job.url);
            if let Some(code) = self.start_task(job, TaskKind::List, None, env)? {
                let r = job.running.clone().expect("started");
                self.finish_task(job, &r, code, now)?;
                if job.last_list_utc == Some(now) {
                    settle_state(job, waiting_policy, now);
                    if job.videos.iter().any(|v| v.status == VideoStatus::Pending) {
                        job.state = YtState::Downloading;
                        job.text = format!("{} videos listed", job.videos.len());
                    }
                } else if job.videos.iter().any(|v| v.status == VideoStatus::Pending) {
                    // The videos listed before carry on.
                    job.state = YtState::Downloading;
                    job.text = format!(
                        "the listing failed ({}); listed again later",
                        job.last_error.clone().unwrap_or_default()
                    );
                } else {
                    job.state = YtState::WaitingRetry;
                    job.text = format!(
                        "the listing failed ({}); tried again in {} min",
                        job.last_error.clone().unwrap_or_default(),
                        (job.next_list_utc - now).max(0) / 60
                    );
                }
            }
            return Ok(());
        }
        if job.last_list_utc.is_none() {
            job.state = YtState::WaitingRetry;
            job.text = format!(
                "the listing failed; tried again in {} min",
                (job.next_list_utc - now).max(0) / 60
            );
            return Ok(());
        }
        // 4. What the vault has already is not downloaded.
        let wants_index = job
            .videos
            .iter()
            .any(|v| matches!(v.status, VideoStatus::Pending | VideoStatus::Failed));
        if wants_index {
            let index = self.youtube_index()?;
            for v in job
                .videos
                .iter_mut()
                .filter(|v| matches!(v.status, VideoStatus::Pending | VideoStatus::Failed))
            {
                if let Some(at) = index.get(&v.id) {
                    v.status = VideoStatus::AlreadyStored;
                    v.found_in = Some(at.clone());
                    v.last_error = None;
                }
            }
        }
        // 5. The next video.
        let next = job
            .videos
            .iter()
            .find(|v| {
                v.status == VideoStatus::Pending
                    || (v.status == VideoStatus::Failed && v.next_try_utc <= now)
            })
            .cloned();
        let Some(v) = next else {
            settle_state(job, waiting_policy, now);
            return Ok(());
        };
        let space = env.space(&job.spool_dir).ok_or_else(|| {
            anyhow!(
                "the free space of {} cannot be read",
                job.spool_dir.display()
            )
        })?;
        let reserve = self.youtube_reserve(job, space.total);
        job.reserve_bytes = reserve;
        job.free_bytes = Some(space.free);
        if space.free < reserve {
            job.need_bytes = reserve - space.free;
            job.state = YtState::WaitingSpace;
            job.text = short_text(space.free, reserve, job.need_bytes);
            return Ok(());
        }
        // 6. Its size, then its download.
        if v.probed_utc == 0 || now - v.probed_utc > PROBE_FRESH_SECS {
            job.state = YtState::Probing;
            job.text = format!("reading the size of {} [{}]", v.title, v.id);
            if let Some(code) = self.start_task(job, TaskKind::Probe, Some(&v.id), env)? {
                let r = job.running.clone().expect("started");
                self.finish_task(job, &r, code, now)?;
            }
            return Ok(());
        }
        let partial: u64 = fs::read_dir(job.work_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{}.", v.id))
            })
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        let estimate = v.size_estimate.unwrap_or(0);
        // (merging audio and video writes the file once more)
        let need = (estimate + estimate / 20).saturating_sub(partial);
        let room = space.free - reserve;
        if need > room {
            job.need_bytes = need - room;
            job.state = YtState::WaitingSpace;
            job.text = format!(
                "{} for {} [{}] ({})",
                short_text(space.free, reserve, job.need_bytes),
                v.title,
                v.id,
                util::human_bytes(estimate)
            );
            return Ok(());
        }
        job.need_bytes = 0;
        job.state = YtState::Downloading;
        job.text = format!(
            "downloading {} [{}]{}",
            v.title,
            v.id,
            match v.size_estimate {
                Some(s) => format!(", about {}", util::human_bytes(s)),
                None => String::new(),
            }
        );
        if let Some(code) = self.start_task(job, TaskKind::Download, Some(&v.id), env)? {
            let r = job.running.clone().expect("started");
            self.finish_task(job, &r, code, now)?;
            save_job(&self.home, job, now)?;
            env.checkpoint("downloaded")?;
        }
        Ok(())
    }
}

/// Nothing to start: the state says what the job waits for.
fn settle_state(job: &mut YoutubeJob, waiting_policy: Option<String>, now: i64) {
    if job.videos.iter().any(|v| v.status == VideoStatus::Pending) {
        return;
    }
    if let Some(w) = waiting_policy.or_else(|| {
        job.videos
            .iter()
            .any(|v| v.status == VideoStatus::Downloaded)
            .then(|| {
                "downloaded videos wait until they can leave the download directory".to_string()
            })
    }) {
        job.state = YtState::WaitingPolicy;
        job.text = w;
        return;
    }
    if let Some(t) = job
        .videos
        .iter()
        .filter(|v| v.status == VideoStatus::Failed)
        .map(|v| v.next_try_utc)
        .min()
    {
        job.state = YtState::WaitingRetry;
        job.text = format!(
            "{} failed video(s), tried again in {} min",
            job.videos
                .iter()
                .filter(|v| v.status == VideoStatus::Failed)
                .count(),
            (t - now).max(0) / 60
        );
        return;
    }
    if job.refresh_hours == 0 {
        job.state = YtState::Complete;
        job.text = format!("every video is in folder {}", job.folder);
        job.completed_utc.get_or_insert(now);
    } else {
        job.state = YtState::UpToDate;
        job.text = format!("listed again in {} h", job.refresh_hours);
    }
}

impl Engine {
    /// Import the downloaded videos and remove what is safe; `Some(reason)`
    /// when one of them waits for the policy.
    fn youtube_import_ready(
        &mut self,
        job: &mut YoutubeJob,
        rec: &FolderRecord,
        env: &mut dyn YoutubeEnv,
        now: i64,
    ) -> Result<Option<String>> {
        let ready: BTreeSet<String> = job
            .videos
            .iter()
            .filter(|v| v.status == VideoStatus::Downloaded)
            .flat_map(|v| v.paths.iter().cloned())
            .filter(|p| {
                util::safe_join(&job.spool_dir, p)
                    .ok()
                    .and_then(|x| fs::symlink_metadata(x).ok())
                    .is_some_and(|m| m.file_type().is_file())
            })
            .collect();
        let mut waiting: Option<String> = None;
        if !ready.is_empty() {
            job.text = format!("importing {} file(s)", ready.len());
            save_job(&self.home, job, now)?;
            let hold = env.before_import();
            let mut src = SpoolSource::open(&job.spool_dir, &job.url, &job.label, ready.clone())?;
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
            for n in report
                .kept_in_varsto
                .iter()
                .filter(|n| ready.contains(&n.path))
            {
                job.push_error(now, format!("{}: {}", n.path, n.reason));
            }
            env.checkpoint("imported")?;
            let entries: Vec<(String, TreeEntry)> = ready
                .iter()
                .filter_map(|p| {
                    let md = fs::metadata(util::safe_join(&job.spool_dir, p).ok()?).ok()?;
                    Some((
                        p.clone(),
                        TreeEntry {
                            id: crate::import::youtube::path_content_id(p)?,
                            size: md.len(),
                            mtime_ns: crate::import::dir::mtime_ns(&md),
                        },
                    ))
                })
                .collect();
            let cleanup =
                self.import_cleanup_at(&job.folder, Some((&job.spool_dir, entries)), true)?;
            if let Some(w) = cleanup.waiting.first() {
                waiting = Some(format!("{}: {}", w.path, w.reason));
            }
            drop(hold);
            env.checkpoint("removed")?;
        }
        // Videos whose files all left the spool and are in the folder.
        let state = self.load_state(&rec.folder_id)?;
        for v in job
            .videos
            .iter_mut()
            .filter(|v| v.status == VideoStatus::Downloaded)
        {
            let gone = v.paths.iter().all(|p| {
                util::safe_join(&job.spool_dir, p)
                    .ok()
                    .is_some_and(|x| fs::symlink_metadata(x).is_err())
            });
            let in_folder = v
                .paths
                .iter()
                .all(|p| state.files.get(p).is_some_and(|f| !f.deleted));
            if gone && in_folder {
                v.status = VideoStatus::Stored;
            } else if gone {
                // Removed from the spool by hand before it was stored.
                v.status = VideoStatus::Pending;
                v.paths.clear();
                v.last_error = Some("its download left the spool before it was stored".into());
            }
        }
        Ok(waiting)
    }

    /// Pause or resume a job. Resuming also tries videos that were given up
    /// again (and failed ones at once).
    pub fn youtube_set_paused(&mut self, key: &str, paused: bool) -> Result<YoutubeJob> {
        let job = find_youtube_job(&self.home, key)?;
        let _lock = lock_job(&self.home, &job.id, true)?;
        let mut job: YoutubeJob = util::read_json(&job_path(&self.home, &job.id))?;
        job.user_paused = paused;
        if paused {
            stop_child(&job.id);
            if job.running.as_ref().is_some_and(|r| !pid_alive(r.pid)) {
                job.running = None;
            }
            job.state = YtState::Paused;
            job.text = "paused".into();
        } else {
            retry_failed(&mut job);
            job.state = YtState::Downloading;
            job.text = String::new();
            job.completed_utc = None;
        }
        save_job(&self.home, &mut job, util::now_utc())?;
        Ok(job)
    }

    /// Try failed and given-up videos again now, and list again
    /// (`youtube run --retry-failed`).
    pub fn youtube_retry_failed(&mut self, key: &str) -> Result<YoutubeJob> {
        let job = find_youtube_job(&self.home, key)?;
        let _lock = lock_job(&self.home, &job.id, true)?;
        let mut job: YoutubeJob = util::read_json(&job_path(&self.home, &job.id))?;
        retry_failed(&mut job);
        job.next_list_utc = 0;
        job.list_now = true;
        save_job(&self.home, &mut job, util::now_utc())?;
        Ok(job)
    }

    /// Forget a job. Files in its spool that were not stored yet stay
    /// there (the report names the directory); nothing in the folder changes.
    pub fn youtube_remove(&mut self, key: &str) -> Result<YoutubeJob> {
        let job = find_youtube_job(&self.home, key)?;
        let _lock = lock_job(&self.home, &job.id, true)?;
        stop_child(&job.id);
        for ext in ["json", "lock"] {
            let _ = fs::remove_file(jobs_dir(&self.home).join(format!("{}.{ext}", job.id)));
        }
        // Empty directories go; anything with a file stays.
        let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(&job.spool_dir)
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
        Ok(job)
    }

    /// The jobs the background service drives: not complete, not paused.
    pub fn youtube_to_run(&self) -> Vec<YoutubeJob> {
        youtube_jobs_at(&self.home)
            .into_iter()
            .filter(|j| j.running())
            .collect()
    }
}

fn retry_failed(job: &mut YoutubeJob) {
    for v in job
        .videos
        .iter_mut()
        .filter(|v| matches!(v.status, VideoStatus::Failed | VideoStatus::GaveUp))
    {
        v.status = VideoStatus::Failed;
        v.attempts = v.attempts.min(yt::MAX_ATTEMPTS - 1);
        v.next_try_utc = 0;
    }
}

fn fail_video(v: &mut Video, reason: String, now: i64) {
    v.attempts += 1;
    v.last_error = Some(reason);
    v.next_try_utc = now + yt::backoff_secs(v.attempts);
    v.status = if v.attempts >= yt::MAX_ATTEMPTS {
        VideoStatus::GaveUp
    } else {
        VideoStatus::Failed
    };
}

fn short_text(free: u64, reserve: u64, need: u64) -> String {
    format!(
        "{} free on the download disk, the reserve is {}; {} more is needed",
        util::human_bytes(free),
        util::human_bytes(reserve),
        util::human_bytes(need)
    )
}

fn running_text(job: &YoutubeJob, r: &Running, elsewhere: bool) -> String {
    let what = match (&r.kind, &r.video) {
        (TaskKind::List, _) => format!("listing {}", job.url),
        (kind, Some(id)) => {
            let title = job
                .videos
                .iter()
                .find(|v| &v.id == id)
                .map(|v| v.title.clone())
                .unwrap_or_default();
            match kind {
                TaskKind::Probe => format!("reading the size of {title} [{id}]"),
                _ => format!("downloading {title} [{id}]"),
            }
        }
        (_, None) => "working".into(),
    };
    if elsewhere {
        format!(
            "{what} (yt-dlp process {}, started by another Varsto process)",
            r.pid
        )
    } else {
        what
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> YoutubeJob {
        YoutubeJob {
            id: "0123456789abcdef".into(),
            url: "https://www.youtube.com/@ExampleMakers/videos".into(),
            kind: UrlKind::Channel,
            label: "@ExampleMakers".into(),
            folder: "makers".into(),
            storages: Vec::new(),
            free_min: "15%".into(),
            spool_dir: PathBuf::from("/spool/0123456789abcdef"),
            folder_parent: PathBuf::from("/folders"),
            ytdlp: None,
            throttle: Throttle::default(),
            thumbnails: true,
            subtitles: "en".into(),
            refresh_hours: 24,
            created_utc: 0,
            updated_utc: 0,
            state: YtState::Listing,
            text: String::new(),
            user_paused: false,
            last_list_utc: None,
            list_failures: 0,
            next_list_utc: 0,
            list_now: false,
            videos: vec![Video {
                id: "aBcDeFgHi_-".into(),
                title: "T".into(),
                url: "https://www.youtube.com/watch?v=aBcDeFgHi_-".into(),
                status: VideoStatus::Pending,
                attempts: 0,
                next_try_utc: 0,
                last_error: None,
                size_estimate: None,
                probed_utc: 0,
                paths: Vec::new(),
                bytes: 0,
                found_in: None,
            }],
            running: None,
            reserve_bytes: 0,
            free_bytes: None,
            need_bytes: 0,
            errors: Vec::new(),
            last_error: None,
            completed_utc: None,
        }
    }

    #[test]
    fn task_arguments() {
        let j = job();
        let list = task_args(&j, TaskKind::List, None).join(" ");
        assert!(list.starts_with("--flat-playlist"), "{list}");
        assert!(list.ends_with("-- https://www.youtube.com/@ExampleMakers/videos"));
        let v = j.videos[0].clone();
        let dl = task_args(&j, TaskKind::Download, Some(&v)).join(" ");
        assert!(dl.starts_with("--sleep-interval 25 --max-sleep-interval 65 --sleep-requests 2 --limit-rate 600K --concurrent-fragments 1 --ignore-errors --no-abort-on-error"), "{dl}");
        assert!(
            dl.contains("--write-thumbnail --write-subs --sub-langs en"),
            "{dl}"
        );
        assert!(
            dl.contains("-o /spool/0123456789abcdef/.varsto-work/%(id)s.%(ext)s"),
            "{dl}"
        );
        assert!(dl.ends_with("-- https://www.youtube.com/watch?v=aBcDeFgHi_-"));
        let probe = task_args(&j, TaskKind::Probe, Some(&v)).join(" ");
        assert!(probe.contains("--skip-download") && probe.contains("--sleep-requests 2"));
    }

    #[test]
    fn failures_go_to_backoff_then_give_up() {
        let mut j = job();
        let v = &mut j.videos[0];
        for n in 1..yt::MAX_ATTEMPTS {
            fail_video(v, "Private video".into(), 1000);
            assert_eq!(v.status, VideoStatus::Failed);
            assert_eq!(v.next_try_utc, 1000 + yt::backoff_secs(n));
        }
        fail_video(v, "Private video".into(), 1000);
        assert_eq!(v.status, VideoStatus::GaveUp);
        retry_failed(&mut j);
        assert_eq!(j.videos[0].status, VideoStatus::Failed);
        assert_eq!(j.videos[0].next_try_utc, 0);
        assert_eq!(j.counts().failed, 1);
    }

    #[test]
    fn job_states_after_the_work() {
        let mut j = job();
        // A pending video: the state is left to the step that starts it.
        j.state = YtState::Downloading;
        settle_state(&mut j, None, 0);
        assert_eq!(j.state, YtState::Downloading);
        // Downloaded, waiting for the policy.
        j.videos[0].status = VideoStatus::Downloaded;
        settle_state(&mut j, Some("x: waiting for the policy".into()), 0);
        assert_eq!(j.state, YtState::WaitingPolicy);
        assert_eq!(j.text, "x: waiting for the policy");
        // Failed: waits for the retry.
        j.videos[0].status = VideoStatus::Failed;
        j.videos[0].next_try_utc = 7200;
        settle_state(&mut j, None, 0);
        assert_eq!(j.state, YtState::WaitingRetry);
        assert!(j.text.contains("120 min"), "{}", j.text);
        // Stored: up to date until the next listing, or complete.
        j.videos[0].status = VideoStatus::Stored;
        settle_state(&mut j, None, 0);
        assert_eq!(j.state, YtState::UpToDate);
        j.refresh_hours = 0;
        settle_state(&mut j, None, 5);
        assert_eq!(j.state, YtState::Complete);
        assert_eq!(j.completed_utc, Some(5));
        // Given up counts as done for the state (status shows it).
        j.videos[0].status = VideoStatus::GaveUp;
        j.state = YtState::Downloading;
        settle_state(&mut j, None, 6);
        assert_eq!(j.state, YtState::Complete);
    }
}
