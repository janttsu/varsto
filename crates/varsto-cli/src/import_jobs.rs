// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Every import of this device in one list, for `varsto import jobs` and the
//! Import page (`GET /api/import/jobs`):
//!
//! - torrent jobs (`crate::torrent`, `state/torrents/`) and YouTube jobs
//!   (`crate::youtube`, `state/youtube/`), named `torrent:<info hash>` and
//!   `youtube:<job id>` (a bare name is looked up in both kinds);
//! - imports the page started (a local directory, a git-annex repository,
//!   a cloud drive through rclone), `run:<n>`, kept in memory while the
//!   service runs;
//! - imports a command of this device runs (reported to the service as
//!   activity), `activity:<n>`, shown without actions.
//!
//! The page's requests are answered without waiting for the service's state
//! (a sync or an import may hold it for a long time): the list is read from
//! the job files and the activity registry, and the work a request asks for
//! (start an import, pause or remove a job) runs on a thread of its own that
//! takes the state when it is free. A thread here also steps the running
//! torrent and YouTube jobs every few seconds between the service's syncs,
//! and announces every change of the list as the event `import.jobs`.

use crate::desktop::Shared;
use crate::torrent::RpcArgs;
use crate::{print, Cli};
use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tiny_http::{Method, Request};
use varsto_core::engine::{
    find_job, find_youtube_job, torrent_jobs_at, youtube_jobs_at, FileOutcome, JobState,
    TorrentAddOptions, TorrentJob, VideoStatus, YoutubeAddOptions, YoutubeJob, YtState,
    DEFAULT_REFRESH_HOURS,
};
use varsto_core::freespace::MinFree;
use varsto_core::transmission::{self, AddSource, Rpc, RpcSettings};
use varsto_core::Engine;

/// The running torrent and YouTube jobs are stepped this often (seconds)
/// besides after every sync.
const STEP_SECS: u64 = 20;
/// Finished and failed imports the page started, kept for the list.
const RUNS_KEPT: usize = 20;

// ----- one row per import ---------------------------------------------------------

/// One import in the uniform list.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct JobRow {
    /// `torrent:<info hash>`, `youtube:<job id>`, `run:<n>` or `activity:<n>`.
    pub id: String,
    /// `dir`, `git-annex`, `rclone`, `dropbox`, `onedrive`, `torrent`,
    /// `youtube`, or `import` (a command of this device).
    pub kind: String,
    pub folder: String,
    pub title: String,
    /// The source as given (a directory, a remote, an address).
    pub source: String,
    /// `waiting` (for the service), `running`, `failed`, `done`, or the
    /// job's own state (`downloading`, `waiting_space`, `waiting_policy`,
    /// `waiting_retry`, `paused`, `metadata`, `listing`, `up_to_date`,
    /// `complete`, ...).
    pub state: String,
    /// What the job does or waits for, in a sentence.
    pub text: String,
    pub done: u64,
    pub total: u64,
    /// What `done` and `total` count: `files` or `videos`.
    pub unit: &'static str,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// The file or video in hand.
    pub current: Option<String>,
    /// Bytes per second, when known.
    pub speed: Option<u64>,
    pub last_error: Option<String>,
    /// When the job tries again after a failure.
    pub retry_utc: Option<i64>,
    /// Files or videos the vault had already (not downloaded).
    pub already_stored: Option<u64>,
    /// Torrent files that differ from the folder's (left in the download
    /// directory).
    pub conflicts: Option<u64>,
    /// Videos that failed, with the reason.
    pub failed: Vec<FailedItem>,
    /// Nothing more to do: complete, finished or failed for good.
    pub finished: bool,
    /// An action asked for and not carried out yet (`pause`, `resume`,
    /// `remove`, `retry`).
    pub pending: Option<String>,
    pub started_utc: i64,
    pub updated_utc: i64,
    /// What `POST /api/import/jobs/<id>/<action>` accepts for this row.
    pub actions: Vec<&'static str>,
}

/// A video of a YouTube job that failed.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct FailedItem {
    pub id: String,
    pub title: String,
    pub reason: String,
    pub attempts: u32,
    /// The next try; `None` once given up.
    pub next_try_utc: Option<i64>,
    pub gave_up: bool,
}

pub fn torrent_row(j: &TorrentJob) -> JobRow {
    let complete = j.state == JobState::Complete;
    let batch: Vec<&str> = j
        .batch
        .iter()
        .filter_map(|i| j.files.get(*i).map(|f| f.path.as_str()))
        .collect();
    let current = match batch.as_slice() {
        [] => None,
        [one] => Some(one.to_string()),
        [first, rest @ ..] => Some(format!("{first} and {} more", rest.len())),
    };
    let mut actions = Vec::new();
    if !complete {
        actions.push(if j.user_paused { "resume" } else { "pause" });
    }
    actions.push("remove");
    JobRow {
        id: format!("torrent:{}", j.hash),
        kind: "torrent".into(),
        folder: j.folder.clone(),
        title: j.name.clone(),
        source: j.magnet.clone().unwrap_or_default(),
        state: j.state.as_str().to_string(),
        text: j.text.clone(),
        done: j.files_done(),
        total: j.files.len() as u64,
        unit: "files",
        bytes_done: j.bytes_stored + j.bytes_deduped,
        bytes_total: j.total_bytes(),
        current,
        speed: None,
        last_error: j.last_error.clone(),
        // A torrent stopped by an error is started again after a minute.
        retry_utc: (!complete && j.last_error.is_some() && j.last_retry_utc > 0)
            .then_some(j.last_retry_utc + 60),
        already_stored: Some(j.count(FileOutcome::Present) + j.count(FileOutcome::Identical)),
        conflicts: Some(j.count(FileOutcome::Conflict)),
        failed: Vec::new(),
        finished: complete,
        pending: None,
        started_utc: j.created_utc,
        updated_utc: j.updated_utc,
        actions,
    }
}

pub fn youtube_row(j: &YoutubeJob) -> JobRow {
    let c = j.counts();
    let complete = j.state == YtState::Complete;
    let current = j.running.as_ref().map(|r| match &r.video {
        Some(v) => j
            .videos
            .iter()
            .find(|x| &x.id == v)
            .map(|x| {
                if x.title.is_empty() {
                    x.id.clone()
                } else {
                    x.title.clone()
                }
            })
            .unwrap_or_else(|| v.clone()),
        None => j.label.clone(),
    });
    let failed: Vec<FailedItem> = j
        .videos
        .iter()
        .filter(|v| matches!(v.status, VideoStatus::Failed | VideoStatus::GaveUp))
        .map(|v| FailedItem {
            id: v.id.clone(),
            title: v.title.clone(),
            reason: v.last_error.clone().unwrap_or_default(),
            attempts: v.attempts,
            next_try_utc: (v.status == VideoStatus::Failed && v.next_try_utc > 0)
                .then_some(v.next_try_utc),
            gave_up: v.status == VideoStatus::GaveUp,
        })
        .collect();
    let mut actions = Vec::new();
    if !complete {
        actions.push(if j.user_paused { "resume" } else { "pause" });
    }
    if !failed.is_empty() {
        actions.push("retry");
    }
    actions.push("remove");
    JobRow {
        id: format!("youtube:{}", j.id),
        kind: "youtube".into(),
        folder: j.folder.clone(),
        title: j.label.clone(),
        source: j.url.clone(),
        state: j.state.as_str().to_string(),
        text: j.text.clone(),
        done: c.stored + c.already_stored,
        total: c.listed,
        unit: "videos",
        bytes_done: c.stored_bytes,
        bytes_total: 0,
        current,
        speed: None,
        last_error: j.last_error.clone(),
        retry_utc: failed.iter().filter_map(|f| f.next_try_utc).min(),
        already_stored: Some(c.already_stored),
        conflicts: None,
        failed,
        finished: complete,
        pending: None,
        started_utc: j.created_utc,
        updated_utc: j.updated_utc,
        actions,
    }
}

// ----- imports the page started ---------------------------------------------------

#[derive(Clone, Debug)]
struct Run {
    n: u64,
    kind: String,
    title: String,
    source: String,
    folder: String,
    /// `waiting`, `running`, `done` or `failed`.
    state: &'static str,
    error: Option<String>,
    /// An action on a job (`pause`, ...): `target` is the job's id.
    verb: Option<String>,
    target: Option<String>,
    started_utc: i64,
    updated_utc: i64,
    /// What the import reported (`ImportReport`), when done.
    report: Option<Value>,
}

static RUNS: Mutex<Vec<Run>> = Mutex::new(Vec::new());
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

fn runs() -> std::sync::MutexGuard<'static, Vec<Run>> {
    RUNS.lock().unwrap_or_else(|e| e.into_inner())
}

fn set_run(n: u64, f: impl FnOnce(&mut Run)) {
    if let Some(r) = runs().iter_mut().find(|r| r.n == n) {
        f(r);
        r.updated_utc = varsto_core::util::now_utc();
    }
}

fn drop_run(n: u64) {
    runs().retain(|r| r.n != n);
}

/// The list changed: open pages load it again.
fn changed() {
    varsto_core::events::publish("import.jobs", json!({}));
}

type Work = Box<dyn FnOnce(&mut Engine) -> Result<Value> + Send>;

/// What a run is about, for the list.
struct RunInfo {
    kind: String,
    title: String,
    source: String,
    folder: String,
    verb: Option<String>,
    target: Option<String>,
    /// Kept in the list once done (a directory, annex or cloud import);
    /// otherwise the job's own row takes over.
    keep: bool,
}

/// Run `work` with the engine on a thread of its own, once the state is
/// free; the run is in the list meanwhile. Returns its id.
fn spawn(state: &Shared, info: RunInfo, work: Work) -> String {
    let n = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
    let now = varsto_core::util::now_utc();
    {
        let mut list = runs();
        list.push(Run {
            n,
            kind: info.kind,
            title: info.title,
            source: info.source,
            folder: info.folder,
            state: "waiting",
            error: None,
            verb: info.verb,
            target: info.target,
            started_utc: now,
            updated_utc: now,
            report: None,
        });
        // The oldest finished ones go first.
        while list.len() > RUNS_KEPT {
            match list
                .iter()
                .position(|r| matches!(r.state, "done" | "failed"))
            {
                Some(i) => {
                    list.remove(i);
                }
                None => break,
            }
        }
    }
    changed();
    let keep = info.keep;
    let state = state.clone();
    let spawned = std::thread::Builder::new()
        .name("import-run".into())
        .spawn(move || {
            let result = {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                set_run(n, |r| r.state = "running");
                changed();
                let st = &mut *guard;
                match st.engine.as_mut() {
                    None => Err(anyhow!("the vault is locked: unlock it and start again")),
                    Some(e) => {
                        let r =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || work(e)))
                                .unwrap_or_else(|_| Err(anyhow!("stopped on an internal error")));
                        st.service.folders_changed = true;
                        st.service.request_sync();
                        r
                    }
                }
            };
            match result {
                Ok(v) if keep => set_run(n, |r| {
                    r.state = "done";
                    if let Some(f) = v.get("folder").and_then(Value::as_str) {
                        r.folder = f.to_string();
                    }
                    r.report = Some(v);
                }),
                Ok(_) => drop_run(n),
                Err(e) => {
                    log::warn!("import from the interface failed: {e:#}");
                    set_run(n, |r| {
                        r.state = "failed";
                        r.error = Some(format!("{e:#}"));
                    })
                }
            }
            changed();
        });
    if let Err(e) = spawned {
        set_run(n, |r| {
            r.state = "failed";
            r.error = Some(format!("cannot start: {e}"));
        });
    }
    format!("run:{n}")
}

fn run_row(r: &Run, task: Option<&varsto_core::activity::TaskView>) -> JobRow {
    let finished = matches!(r.state, "done" | "failed");
    let mut row = JobRow {
        id: format!("run:{}", r.n),
        kind: r.kind.clone(),
        folder: r.folder.clone(),
        title: r.title.clone(),
        source: r.source.clone(),
        state: r.state.to_string(),
        unit: "files",
        last_error: r.error.clone(),
        finished,
        pending: if finished { None } else { r.verb.clone() },
        started_utc: r.started_utc,
        updated_utc: r.updated_utc,
        // A running import cannot be stopped half-way from here; running
        // it again later carries on where it stopped.
        actions: if finished { vec!["remove"] } else { Vec::new() },
        ..Default::default()
    };
    if let Some(rep) = &r.report {
        let n = |k: &str| rep.get(k).and_then(Value::as_u64).unwrap_or(0);
        row.done = n("imported_files") + n("already_ids");
        row.total = row.done + n("failed_count");
        row.bytes_done = n("imported_bytes");
        row.text = format!(
            "{} file(s) imported, {} imported before, {} could not be read",
            n("imported_files"),
            n("already_ids"),
            n("failed_count")
        );
    }
    if let Some(t) = task {
        apply_task(&mut row, t);
    }
    row
}

/// Progress of the import task in hand onto a row.
fn apply_task(row: &mut JobRow, t: &varsto_core::activity::TaskView) {
    match t.unit {
        varsto_core::activity::Unit::Bytes => {
            if row.unit != "videos" {
                row.bytes_done = t.done;
                row.bytes_total = t.total;
            }
        }
        varsto_core::activity::Unit::Items => {
            if row.unit == "files" && row.kind != "torrent" {
                row.done = t.done;
                row.total = t.total;
            }
        }
    }
    if t.rate > 0 {
        row.speed = Some(t.rate);
    }
    if row.current.is_none() {
        row.current = t.detail.clone();
    }
}

// ----- the list ---------------------------------------------------------------------

/// The torrent and YouTube jobs of a device directory (read without the
/// passphrase).
pub fn job_rows(home: &Path) -> Vec<JobRow> {
    let mut out: Vec<JobRow> = torrent_jobs_at(home).iter().map(torrent_row).collect();
    out.extend(youtube_jobs_at(home).iter().map(youtube_row));
    out
}

/// Everything: the jobs, the imports the page started, and the imports of
/// other commands of this device. Unfinished ones first, then by start.
pub fn rows(home: &Path) -> Vec<JobRow> {
    let tasks: Vec<varsto_core::activity::TaskView> = varsto_core::activity::tasks()
        .into_iter()
        .filter(|t| t.kind == varsto_core::activity::IMPORT)
        .collect();
    let mut used = vec![false; tasks.len()];
    let mut claim = |folder: &str| -> Option<usize> {
        let i = (0..tasks.len()).find(|&i| {
            !used[i] && (folder.is_empty() || tasks[i].subject.eq_ignore_ascii_case(folder))
        })?;
        used[i] = true;
        Some(i)
    };
    let mut out = job_rows(home);
    let list = runs().clone();
    // Actions waiting for the state show on their job's row.
    for r in list.iter().filter(|r| r.target.is_some()) {
        if matches!(r.state, "waiting" | "running") {
            if let Some(row) = out.iter_mut().find(|x| Some(&x.id) == r.target.as_ref()) {
                row.pending = r.verb.clone();
            }
        }
    }
    for row in out.iter_mut() {
        if !row.finished {
            if let Some(i) = claim(&row.folder) {
                apply_task(row, &tasks[i]);
            }
        }
    }
    for r in &list {
        // A pending action is on its job's row; a failed one stays visible.
        if r.target.is_some() && r.state != "failed" {
            continue;
        }
        let task = (r.state == "running" && r.target.is_none())
            .then(|| claim(&r.folder))
            .flatten()
            .map(|i| &tasks[i]);
        out.push(run_row(r, task));
    }
    for (i, t) in tasks.iter().enumerate() {
        if used[i] {
            continue;
        }
        let mut row = JobRow {
            id: format!("activity:{}", t.id),
            kind: "import".into(),
            folder: t.subject.clone(),
            title: t.subject.clone(),
            state: "running".into(),
            text: "started on the command line".into(),
            unit: "files",
            started_utc: t.started_utc,
            updated_utc: t.updated_utc,
            ..Default::default()
        };
        apply_task(&mut row, t);
        out.push(row);
    }
    out.sort_by(|a, b| {
        a.finished
            .cmp(&b.finished)
            .then(a.started_utc.cmp(&b.started_utc))
    });
    out
}

/// Whether a program is on the `PATH` (or named by `env`).
fn on_path(program: &str, env: &str) -> bool {
    if std::env::var_os(env).is_some_and(|v| !v.is_empty()) {
        return true;
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path)
        .any(|d| d.join(program).is_file() || d.join(format!("{program}.exe")).is_file())
}

/// `GET /api/import/jobs`.
pub fn jobs_json(home: &Path) -> Value {
    let mobile = crate::desktop::mobile();
    json!({
        "jobs": rows(home),
        "platform": {
            "mobile": mobile,
            "torrents": cfg!(target_os = "linux") && !mobile,
            "youtube": !mobile && !cfg!(any(target_os = "android", target_os = "ios")),
        },
        "tools": {
            "yt_dlp": on_path("yt-dlp", "VARSTO_YTDLP"),
            "transmission": on_path("transmission-daemon", "VARSTO_TRANSMISSION_URL"),
            "rclone": on_path("rclone", "VARSTO_RCLONE"),
            "git": on_path("git", "VARSTO_GIT"),
        },
        "defaults": {
            "free_min": "15%",
            "youtube_download_dir": crate::youtube::default_download_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
            "sleep": "25-65",
            "sleep_requests": 2,
            "rate": "600K",
            "concurrent_fragments": 1,
            "refresh_hours": DEFAULT_REFRESH_HOURS,
        },
    })
}

// ----- the page's requests ----------------------------------------------------------

/// `GET /api/import/jobs`, `POST /api/import/jobs/<id>/<action>` and
/// `POST /api/import/start`, answered without waiting for the state (the
/// caller checked the token).
pub fn serve(state: &Shared, home: &Path, mut request: Request) -> Result<()> {
    let path = request.url().split('?').next().unwrap_or("").to_string();
    let method = request.method().clone();
    let (status, v) = if method == Method::Get && path == "/api/import/jobs" {
        (200, jobs_json(home))
    } else if method == Method::Post {
        let mut body = String::new();
        // A .torrent file comes in the body (base64).
        request
            .as_reader()
            .take(8 << 20)
            .read_to_string(&mut body)?;
        let input: Value = serde_json::from_str(&body).unwrap_or(json!({}));
        if path == "/api/import/start" {
            match start(state, home, &input) {
                Ok(id) => (202, json!({"ok": true, "id": id})),
                Err(e) => (400, json!({"error": format!("{e:#}")})),
            }
        } else if let Some(rest) = path.strip_prefix("/api/import/jobs/") {
            action(state, home, rest)
        } else {
            (404, json!({"error": "not found"}))
        }
    } else {
        (404, json!({"error": "not found"}))
    };
    request.respond(crate::desktop::json_response(status, &v))?;
    Ok(())
}

fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn yes(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn num(v: &Value, k: &str, default: u64) -> u64 {
    v.get(k)
        .and_then(|x| x.as_u64().or_else(|| x.as_str()?.trim().parse().ok()))
        .unwrap_or(default)
}

fn or(s: String, default: &str) -> String {
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

/// `storage`: empty (the folder's usual placement), `cheapest`, or a
/// storage name; or `storages`, a list.
fn storages_of(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .get("storages")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let one = text(v, "storage");
    if !one.is_empty() && !out.contains(&one) {
        out.push(one);
    }
    out
}

/// The target of a directory, annex or cloud import.
fn import_options(home: &Path, v: &Value) -> varsto_core::engine::ImportOptions {
    let dest = Some(text(v, "dest"))
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    varsto_core::engine::ImportOptions {
        folder: Some(text(v, "folder")).filter(|f| !f.is_empty()),
        selective: dest.is_none() || yes(v, "selective"),
        dest,
        dry_run: false,
        remove_source: false,
        no_verify: false,
        default_parent: Some(crate::desktop::folder_root(home)),
        staging: None,
    }
}

/// `POST /api/import/start`: check what can be checked at once, then start
/// the import (or register the job) on a thread of its own.
fn start(state: &Shared, home: &Path, input: &Value) -> Result<String> {
    let kind = text(input, "kind");
    let folder = text(input, "folder");
    let mobile = crate::desktop::mobile();
    if mobile && kind != "dir" {
        bail!("this device imports folders of its own only; other sources are imported on a computer of the vault");
    }
    let (home, input) = (home.to_path_buf(), input.clone());
    let info = |kind: &str, source: &str| RunInfo {
        kind: kind.to_string(),
        title: source.to_string(),
        source: source.to_string(),
        folder: folder.clone(),
        verb: None,
        target: None,
        keep: true,
    };
    let id = match kind.as_str() {
        "dir" => {
            let source = text(&input, "source");
            if source.is_empty() {
                bail!("choose the folder to import");
            }
            let remove = yes(&input, "remove_source");
            let ri = info("dir", &source);
            spawn(
                state,
                ri,
                Box::new(move |e: &mut Engine| {
                    let mut opts = import_options(&home, &input);
                    opts.remove_source = remove;
                    let mut src = varsto_core::import::dir::DirSource::open(Path::new(&source))?;
                    let mut r = e.import_run(&mut src, &opts)?;
                    if remove {
                        r.cleanup = Some(e.import_cleanup(&r.folder, false)?);
                    }
                    Ok(serde_json::to_value(r)?)
                }),
            )
        }
        "git-annex" => {
            let repo = text(&input, "source");
            if repo.is_empty() {
                bail!("choose the git-annex repository");
            }
            let git_ref = or(text(&input, "git_ref"), "HEAD");
            let no_verify = yes(&input, "no_verify");
            let ri = info("git-annex", &repo);
            spawn(
                state,
                ri,
                Box::new(move |e: &mut Engine| {
                    let mut opts = import_options(&home, &input);
                    opts.no_verify = no_verify;
                    let mut src =
                        varsto_core::import::annex::AnnexSource::open(Path::new(&repo), &git_ref)?;
                    let r = e.import_run(&mut src, &opts)?;
                    Ok(serde_json::to_value(r)?)
                }),
            )
        }
        "rclone" | "dropbox" | "onedrive" => {
            let remote = text(&input, "source");
            if !remote.contains(':') {
                bail!("give an rclone remote, such as mydropbox: or gdrive:Photos");
            }
            let expect = (kind != "rclone").then(|| kind.clone());
            let transfers = num(&input, "transfers", 4).clamp(1, 32) as u32;
            let hash = Some(text(&input, "hash_type")).filter(|h| !h.is_empty());
            let ri = info(&kind, &remote);
            spawn(
                state,
                ri,
                Box::new(move |e: &mut Engine| {
                    let opts = import_options(&home, &input);
                    // Downloads are staged on the folder's disk; this is
                    // only the fallback the import replaces.
                    let fallback = home.join("state").join("import-downloads");
                    let mut src = varsto_core::import::rclone::RcloneSource::open(
                        &remote,
                        expect.as_deref(),
                        hash.as_deref(),
                        transfers,
                        &fallback,
                    )?;
                    let r = e.import_run(&mut src, &opts)?;
                    Ok(serde_json::to_value(r)?)
                }),
            )
        }
        "torrent" => {
            if !cfg!(target_os = "linux") {
                bail!("torrent imports run on Linux only (they drive a local transmission-daemon)");
            }
            let magnet = text(&input, "magnet");
            let b64 = text(&input, "torrent_base64");
            let file = text(&input, "torrent_path");
            let (source, name) = if magnet.starts_with("magnet:") {
                let (hash, name) = transmission::parse_magnet(&magnet)?;
                (AddSource::Magnet(magnet.clone()), name.unwrap_or(hash))
            } else if !b64.is_empty() {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .context("the .torrent file did not arrive whole")?;
                let name = transmission::parse_metainfo(&bytes)?.name;
                (AddSource::Metainfo(bytes), name)
            } else if !file.is_empty() {
                let bytes = std::fs::read(&file).with_context(|| format!("read {file}"))?;
                let name = transmission::parse_metainfo(&bytes)?.name;
                (AddSource::Metainfo(bytes), name)
            } else {
                bail!("give a magnet link or a .torrent file");
            };
            let folder = if folder.is_empty() {
                varsto_core::import::folder_name_from(&name)
            } else {
                folder.clone()
            };
            let free_min = MinFree::parse(&or(text(&input, "free_min"), "15%"))?;
            let download_dir = Some(text(&input, "download_dir"))
                .filter(|d| !d.is_empty())
                .map(PathBuf::from);
            let min_copies = (!yes(&input, "keep_policy"))
                .then(|| num(&input, "min_copies", 1).clamp(1, 16) as u32);
            let verify_existing = yes(&input, "verify_existing");
            let storages = storages_of(&input);
            let settings = RpcSettings::resolve(
                Some(text(&input, "rpc_url"))
                    .filter(|u| !u.is_empty())
                    .as_deref(),
                None,
                None,
            );
            let ri = RunInfo {
                kind: "torrent".into(),
                title: name.clone(),
                source: if magnet.is_empty() {
                    file
                } else {
                    magnet.clone()
                },
                folder: folder.clone(),
                verb: None,
                target: None,
                keep: false,
            };
            spawn(
                state,
                ri,
                Box::new(move |e: &mut Engine| {
                    let rpc = Rpc::new(settings.clone());
                    let job = e.torrent_add(
                        &TorrentAddOptions {
                            source,
                            folder,
                            storages,
                            free_min,
                            download_dir,
                            folder_parent: crate::desktop::folder_root(&home),
                            min_copies,
                            verify_existing,
                            rpc: settings,
                        },
                        &rpc,
                    )?;
                    Ok(serde_json::to_value(&job)?)
                }),
            )
        }
        "youtube" => {
            let url = text(&input, "url");
            let parsed = varsto_core::youtube::parse_source_url(&url)?;
            let (sleep_min, sleep_max) =
                varsto_core::youtube::parse_sleep(&or(text(&input, "sleep"), "25-65"))?;
            let throttle = varsto_core::youtube::Throttle {
                sleep_min,
                sleep_max,
                sleep_requests: num(&input, "sleep_requests", 2).min(3600) as u32,
                rate: varsto_core::youtube::parse_rate(&or(text(&input, "rate"), "600K"))?,
                concurrent_fragments: num(&input, "concurrent_fragments", 1).clamp(1, 16) as u32,
                format: text(&input, "format"),
                cookies_from_browser: text(&input, "cookies_from_browser"),
                extra: Vec::new(),
            };
            let opts = YoutubeAddOptions {
                url: url.clone(),
                folder: Some(folder.clone()).filter(|f| !f.is_empty()),
                storages: storages_of(&input),
                free_min: MinFree::parse(&or(text(&input, "free_min"), "15%"))?,
                download_dir: match text(&input, "download_dir") {
                    d if d.is_empty() => crate::youtube::default_download_dir()?,
                    d => PathBuf::from(d),
                },
                folder_parent: crate::desktop::folder_root(&home),
                min_copies: (!yes(&input, "keep_policy"))
                    .then(|| num(&input, "min_copies", 1).clamp(1, 16) as u32),
                throttle,
                thumbnails: yes(&input, "thumbnails"),
                subtitles: text(&input, "subs"),
                refresh_hours: num(&input, "refresh_hours", DEFAULT_REFRESH_HOURS as u64)
                    .min(24 * 365) as u32,
                ytdlp: None,
            };
            let ri = RunInfo {
                kind: "youtube".into(),
                title: parsed.label.clone(),
                source: url,
                folder: folder.clone(),
                verb: None,
                target: None,
                keep: false,
            };
            spawn(
                state,
                ri,
                Box::new(move |e: &mut Engine| {
                    let job = e.youtube_add(&opts)?;
                    Ok(serde_json::to_value(&job)?)
                }),
            )
        }
        "" => bail!("choose what to import"),
        other => bail!("unknown import source {other}"),
    };
    Ok(id)
}

/// `POST /api/import/jobs/<id>/<action>`: queue the action; the answer
/// comes at once (202), the list follows when it is done.
fn action(state: &Shared, home: &Path, rest: &str) -> (u16, Value) {
    let Some((id, verb)) = rest.rsplit_once('/') else {
        return (404, json!({"error": "not found"}));
    };
    let id = crate::desktop::percent_decode(id);
    if let Some(n) = id.strip_prefix("run:") {
        // Only a finished or failed one can be taken off the list.
        let Ok(n) = n.parse::<u64>() else {
            return (404, json!({"error": format!("no import {id}")}));
        };
        if verb != "remove" {
            return (
                400,
                json!({"error": "an import started here can only be taken off the list"}),
            );
        }
        let mut list = runs();
        return match list.iter().position(|r| r.n == n) {
            None => (404, json!({"error": format!("no import {id}")})),
            Some(i) if !matches!(list[i].state, "done" | "failed") => (
                409,
                json!({"error": "this import is running; it cannot be stopped half-way (running it again later carries on)"}),
            ),
            Some(i) => {
                list.remove(i);
                drop(list);
                changed();
                (200, json!({"ok": true}))
            }
        };
    }
    if !matches!(verb, "pause" | "resume" | "remove" | "retry") {
        return (404, json!({"error": format!("no action {verb}")}));
    }
    // Exact ids only here: the page sends what it was given.
    let job = match find(home, &id) {
        Ok(j) if j.id() == id => j,
        Ok(_) | Err(_) => return (404, json!({"error": format!("no import job {id}")})),
    };
    if verb == "retry" && matches!(job, JobRef::Torrent(_)) {
        return (400, json!({"error": "a torrent job tries again by itself"}));
    }
    let (kind, title, folder) = match &job {
        JobRef::Torrent(j) => ("torrent", j.name.clone(), j.folder.clone()),
        JobRef::Youtube(j) => ("youtube", j.label.clone(), j.folder.clone()),
    };
    let verb = verb.to_string();
    let info = RunInfo {
        kind: kind.into(),
        title,
        source: String::new(),
        folder,
        verb: Some(verb.clone()),
        target: Some(id.clone()),
        keep: false,
    };
    let run = spawn(
        state,
        info,
        Box::new(move |e: &mut Engine| apply_action(e, job, &verb, false)),
    );
    (202, json!({"ok": true, "queued": run}))
}

/// Carry out `pause`, `resume`, `remove` or `retry` on a job; the job as it
/// is afterwards.
fn apply_action(
    e: &mut Engine,
    job: JobRef,
    verb: &str,
    keep_in_transmission: bool,
) -> Result<Value> {
    match job {
        JobRef::Torrent(j) => {
            let rpc = Rpc::new(e.torrent_rpc(&j, &RpcSettings::default()));
            let after = match verb {
                "pause" => e.torrent_set_paused(&j.hash, true, &rpc)?,
                "resume" => e.torrent_set_paused(&j.hash, false, &rpc)?,
                "remove" => e.torrent_remove(&j.hash, keep_in_transmission, Some(&rpc))?,
                other => bail!("a torrent job cannot {other}"),
            };
            tagged(&after, &format!("torrent:{}", after.hash), "torrent")
        }
        JobRef::Youtube(j) => {
            let after = match verb {
                "pause" => e.youtube_set_paused(&j.id, true)?,
                "resume" => e.youtube_set_paused(&j.id, false)?,
                "remove" => e.youtube_remove(&j.id)?,
                "retry" => e.youtube_retry_failed(&j.id)?,
                other => bail!("a YouTube job cannot {other}"),
            };
            tagged(&after, &format!("youtube:{}", after.id), "youtube")
        }
    }
}

// ----- stepping the jobs between syncs ----------------------------------------------

/// Step the running torrent and YouTube jobs every [`STEP_SECS`] while the
/// state is free (the service also steps them after every sync), and
/// announce changes of the list (`import.jobs`), whoever made them.
pub fn spawn_driver(state: Shared, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let spawned = std::thread::Builder::new()
        .name("import-jobs".into())
        .spawn(move || {
            let home = state.lock().unwrap_or_else(|e| e.into_inner()).home.clone();
            let mut last = fingerprint(&home);
            let mut waited = 0;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(2));
                waited += 2;
                if waited >= STEP_SECS {
                    waited = 0;
                    step_jobs(&state, &home);
                }
                let now = fingerprint(&home);
                if now != last {
                    last = now;
                    changed();
                }
            }
        });
    if spawned.is_err() {
        log::warn!("cannot start the import jobs thread");
    }
}

/// What the list shows, without the figures that move all the time.
fn fingerprint(home: &Path) -> String {
    job_rows(home)
        .iter()
        .map(|r| {
            format!(
                "{} {} {} {} {} {:?} {:?}",
                r.id, r.state, r.done, r.total, r.text, r.last_error, r.actions
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn step_jobs(state: &Shared, home: &Path) {
    let any = torrent_jobs_at(home).iter().any(|j| j.running())
        || youtube_jobs_at(home).iter().any(|j| j.running());
    if !any {
        return;
    }
    // A sync or an import holds the state: the jobs wait for the next
    // round (or the step after that sync).
    let Ok(mut guard) = state.try_lock() else {
        return;
    };
    let st = &mut *guard;
    if st.service.paused {
        return;
    }
    if let Some(e) = st.engine.as_mut() {
        st.service.torrents_if_due(e);
    }
    if let Some(e) = st.engine.as_mut() {
        st.service.youtube_if_due(e);
    }
}

// ----- `varsto import jobs` ---------------------------------------------------------

/// `varsto import jobs`: the torrent and YouTube imports of this device.
#[derive(Subcommand)]
pub enum JobsCmd {
    /// Every import job of this device (torrents and YouTube), one line
    /// each with its kind.
    List,
    /// A job's state, files or videos and errors (every job without a name).
    Status {
        job: Option<String>,
        /// List every video of a YouTube job with its state.
        #[arg(long)]
        videos: bool,
    },
    /// Work on a job in this terminal: a torrent job until it is complete
    /// (download a batch, import it, remove it from the disk, the next
    /// batch), a YouTube job until it waits (for space, the policy, a retry,
    /// the next listing). Without a job: every YouTube job until it waits
    /// and one step of every torrent job. Stop with Ctrl-C; running it again
    /// carries on.
    Run {
        job: Option<String>,
        /// Seconds between the steps of a torrent job.
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// One step only.
        #[arg(long)]
        once: bool,
        /// YouTube: try failed and given-up videos again now, and list again.
        #[arg(long)]
        retry_failed: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Stop a job's downloads; the job stays.
    Pause {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Carry on (YouTube: videos that were given up are tried again).
    Resume {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Forget a job. The folder stays; files in the download directory that
    /// were not stored yet stay there too.
    Remove {
        job: String,
        /// Torrent: leave the torrent in transmission.
        #[arg(long)]
        keep_in_transmission: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
}

/// A job of either kind.
pub enum JobRef {
    Torrent(TorrentJob),
    Youtube(YoutubeJob),
}

impl JobRef {
    /// `torrent:<info hash>` or `youtube:<job id>`.
    pub fn id(&self) -> String {
        match self {
            JobRef::Torrent(j) => format!("torrent:{}", j.hash),
            JobRef::Youtube(j) => format!("youtube:{}", j.id),
        }
    }
    fn line(&self) -> String {
        match self {
            JobRef::Torrent(j) => j.line(),
            JobRef::Youtube(j) => j.line(),
        }
    }
    fn value(&self) -> Result<Value> {
        match self {
            JobRef::Torrent(j) => tagged(j, &self.id(), "torrent"),
            JobRef::Youtube(j) => tagged(j, &self.id(), "youtube"),
        }
    }
    fn describe(&self, videos: bool) -> String {
        match self {
            JobRef::Torrent(j) => crate::torrent::describe(j),
            JobRef::Youtube(j) => crate::youtube::describe_jobs(std::slice::from_ref(j), videos),
        }
    }
}

/// A job's own JSON with `job` (its id in the list) and `job_kind`.
fn tagged<T: Serialize>(job: &T, id: &str, kind: &str) -> Result<Value> {
    let mut v = serde_json::to_value(job)?;
    if let Some(o) = v.as_object_mut() {
        o.insert("job".into(), json!(id));
        o.insert("job_kind".into(), json!(kind));
    }
    Ok(v)
}

/// Every job of both kinds, oldest first.
fn all_jobs(home: &Path) -> Vec<JobRef> {
    let mut out: Vec<(i64, JobRef)> = torrent_jobs_at(home)
        .into_iter()
        .map(|j| (j.created_utc, JobRef::Torrent(j)))
        .collect();
    out.extend(
        youtube_jobs_at(home)
            .into_iter()
            .map(|j| (j.created_utc, JobRef::Youtube(j))),
    );
    out.sort_by_key(|(t, _)| *t);
    out.into_iter().map(|(_, j)| j).collect()
}

/// A job by `torrent:<key>`, `youtube:<key>`, or a key of either kind: an
/// id (or its start), a folder, a name or a YouTube address.
pub fn find(home: &Path, key: &str) -> Result<JobRef> {
    let key = key.trim();
    if let Some(k) = key.strip_prefix("torrent:") {
        return Ok(JobRef::Torrent(find_job(home, k)?));
    }
    if let Some(k) = key.strip_prefix("youtube:") {
        return Ok(JobRef::Youtube(find_youtube_job(home, k)?));
    }
    match (find_job(home, key), find_youtube_job(home, key)) {
        (Ok(t), Err(_)) => Ok(JobRef::Torrent(t)),
        (Err(_), Ok(y)) => Ok(JobRef::Youtube(y)),
        (Ok(_), Ok(_)) => bail!(
            "{key} names a torrent job and a YouTube job: write torrent:{key} or youtube:{key}"
        ),
        (Err(t), Err(y)) => {
            // Several jobs of one kind: that answer says more.
            let many = [t, y]
                .into_iter()
                .map(|e| format!("{e:#}"))
                .find(|m| m.contains("more than one"));
            match many {
                Some(m) => bail!("{m}"),
                None => bail!("no import job {key}: `varsto import jobs list` shows them"),
            }
        }
    }
}

/// `varsto import jobs ...`.
pub fn jobs(cli: &Cli, home: &Path, cmd: &JobsCmd) -> Result<()> {
    match cmd {
        JobsCmd::List => {
            let rows = job_rows(home);
            let lines: Vec<String> = all_jobs(home).iter().map(JobRef::line).collect();
            print(cli, &rows, |_| {
                if lines.is_empty() {
                    "no import jobs (varsto import torrent ..., varsto import youtube ...)".into()
                } else {
                    lines.join("\n")
                }
            })
        }
        JobsCmd::Status { job, videos } => match job {
            Some(k) => {
                let j = find(home, k)?;
                let text = j.describe(*videos);
                print(cli, &j.value()?, |_| text)
            }
            None => {
                let list = all_jobs(home);
                let values = list.iter().map(JobRef::value).collect::<Result<Vec<_>>>()?;
                let text = if list.is_empty() {
                    "no import jobs (varsto import torrent ..., varsto import youtube ...)"
                        .to_string()
                } else {
                    list.iter()
                        .map(|j| j.describe(*videos))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                };
                print(cli, &values, |_| text)
            }
        },
        JobsCmd::Run {
            job,
            interval,
            once,
            retry_failed,
            rpc,
        } => {
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            match job {
                Some(k) => {
                    let after = run_one(
                        cli,
                        home,
                        &mut engine,
                        find(home, k)?,
                        *interval,
                        *once,
                        *retry_failed,
                        rpc,
                    )?;
                    let text = after.describe(false);
                    print(cli, &after.value()?, |_| text)
                }
                None => {
                    let mut out = Vec::new();
                    for j in engine.youtube_to_run() {
                        out.push(run_one(
                            cli,
                            home,
                            &mut engine,
                            JobRef::Youtube(j),
                            *interval,
                            true,
                            *retry_failed,
                            rpc,
                        )?);
                    }
                    if cfg!(target_os = "linux") {
                        for j in engine.torrents_to_run() {
                            out.push(run_one(
                                cli,
                                home,
                                &mut engine,
                                JobRef::Torrent(j),
                                *interval,
                                true,
                                false,
                                rpc,
                            )?);
                        }
                    }
                    let values = out.iter().map(JobRef::value).collect::<Result<Vec<_>>>()?;
                    let text = if out.is_empty() {
                        "no import job to run".to_string()
                    } else {
                        out.iter().map(JobRef::line).collect::<Vec<_>>().join("\n")
                    };
                    print(cli, &values, |_| text)
                }
            }
        }
        JobsCmd::Pause { job, rpc } | JobsCmd::Resume { job, rpc } => {
            let paused = matches!(cmd, JobsCmd::Pause { .. });
            let j = find(home, job)?;
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            let after = match j {
                JobRef::Torrent(j) => {
                    crate::torrent::linux_only()?;
                    let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
                    JobRef::Torrent(engine.torrent_set_paused(&j.hash, paused, &client)?)
                }
                JobRef::Youtube(j) => JobRef::Youtube(engine.youtube_set_paused(&j.id, paused)?),
            };
            let text = after.line();
            print(cli, &after.value()?, |_| text)
        }
        JobsCmd::Remove {
            job,
            keep_in_transmission,
            rpc,
        } => {
            let j = find(home, job)?;
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            match j {
                JobRef::Torrent(j) => {
                    crate::torrent::linux_only()?;
                    let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
                    let j = engine.torrent_remove(&j.hash, *keep_in_transmission, Some(&client))?;
                    let left = std::fs::read_dir(&j.download_dir)
                        .map(|d| d.count())
                        .unwrap_or(0);
                    let text = format!(
                        "removed torrent job {} ({}); folder {} stays{}{}",
                        j.short(),
                        j.name,
                        j.folder,
                        if *keep_in_transmission {
                            "; the torrent stays in transmission"
                        } else {
                            ""
                        },
                        if left > 0 {
                            format!(
                                "; {} holds files that were not stored yet",
                                j.download_dir.display()
                            )
                        } else {
                            String::new()
                        }
                    );
                    print(cli, &JobRef::Torrent(j).value()?, |_| text)
                }
                JobRef::Youtube(j) => {
                    if *keep_in_transmission {
                        bail!("--keep-in-transmission is for torrent jobs");
                    }
                    let j = engine.youtube_remove(&j.id)?;
                    let mut text = format!(
                        "YouTube job {} removed; folder {} keeps its videos.",
                        j.short(),
                        j.folder
                    );
                    if j.spool_dir.exists() {
                        text += &format!(
                            "\nFiles not stored yet stay in {} (remove them yourself when you no longer need them).",
                            j.spool_dir.display()
                        );
                    }
                    print(cli, &JobRef::Youtube(j).value()?, |_| text)
                }
            }
        }
    }
}

/// Work on one job in this terminal (see [`JobsCmd::Run`]).
#[allow(clippy::too_many_arguments)]
fn run_one(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    job: JobRef,
    interval: u64,
    once: bool,
    retry_failed: bool,
    rpc: &RpcArgs,
) -> Result<JobRef> {
    match job {
        JobRef::Torrent(j) => {
            crate::torrent::linux_only()?;
            let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
            let after = crate::torrent::drive(cli, home, engine, &j.hash, &client, interval, once)?;
            Ok(JobRef::Torrent(after))
        }
        JobRef::Youtube(j) => {
            if retry_failed {
                engine.youtube_retry_failed(&j.id)?;
            }
            let after = crate::youtube::run_job(engine, home, &j.id, !cli.json)?;
            Ok(JobRef::Youtube(after))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn torrent_json(hash: &str, state: &str, paused: bool) -> Value {
        json!({
            "hash": hash,
            "name": "Example set",
            "folder": "example-set",
            "free_min": "15%",
            "download_dir": format!("/tmp/dl/{hash}"),
            "folder_parent": "/tmp/folders",
            "rpc_url": "http://127.0.0.1:9091/transmission/rpc",
            "created_utc": 1_790_000_000i64,
            "updated_utc": 1_790_000_100i64,
            "state": state,
            "user_paused": paused,
            "files": [
                {"index": 0, "path": "Example set/a.bin", "size": 100, "done": true, "outcome": "stored"},
                {"index": 1, "path": "Example set/b.bin", "size": 300, "done": true, "outcome": "present"},
                {"index": 2, "path": "Example set/c.bin", "size": 600},
            ],
            "batch": [2],
            "bytes_stored": 100,
            "bytes_deduped": 300,
            "last_error": "transmission: no data found",
            "last_retry_utc": 1_790_000_050i64,
        })
    }

    fn youtube_json(id: &str, state: &str) -> Value {
        json!({
            "id": id,
            "url": "https://www.youtube.com/@ExampleChannel/videos",
            "kind": "channel",
            "label": "@ExampleChannel",
            "folder": "example-channel",
            "free_min": "15%",
            "spool_dir": format!("/tmp/yt/{id}"),
            "folder_parent": "/tmp/folders",
            "throttle": {"sleep_min": 25, "sleep_max": 65, "sleep_requests": 2, "rate": "600K", "concurrent_fragments": 1},
            "refresh_hours": 24,
            "created_utc": 1_790_000_200i64,
            "updated_utc": 1_790_000_300i64,
            "state": state,
            "videos": [
                {"id": "exAAAAAAAA1", "title": "One", "url": "https://www.youtube.com/watch?v=exAAAAAAAA1", "status": "stored", "bytes": 1000},
                {"id": "exBBBBBBBB2", "title": "Two", "url": "https://www.youtube.com/watch?v=exBBBBBBBB2", "status": "already_stored", "found_in": "folder old"},
                {"id": "exCCCCCCCC3", "title": "Three", "url": "https://www.youtube.com/watch?v=exCCCCCCCC3", "status": "failed", "attempts": 2, "next_try_utc": 1_790_010_000i64, "last_error": "Private video"},
                {"id": "exDDDDDDDD4", "title": "Four", "url": "https://www.youtube.com/watch?v=exDDDDDDDD4", "status": "gave_up", "attempts": 6, "last_error": "Video unavailable"},
                {"id": "exEEEEEEEE5", "title": "Five", "url": "https://www.youtube.com/watch?v=exEEEEEEEE5", "status": "pending"},
            ],
            "running": {"kind": "download", "video": "exEEEEEEEE5", "pid": 1, "started_utc": 1_790_000_250i64},
        })
    }

    /// Job files as the engine writes them, in `home`.
    pub(crate) fn write_jobs(home: &Path) -> (String, String) {
        let hash = "0123456789abcdef0123456789abcdef01234567".to_string();
        let yid = "fedcba9876543210".to_string();
        let t = home.join("state").join("torrents");
        let y = home.join("state").join("youtube");
        std::fs::create_dir_all(&t).unwrap();
        std::fs::create_dir_all(&y).unwrap();
        std::fs::write(
            t.join(format!("{hash}.json")),
            torrent_json(&hash, "downloading", false).to_string(),
        )
        .unwrap();
        std::fs::write(
            y.join(format!("{yid}.json")),
            youtube_json(&yid, "waiting_retry").to_string(),
        )
        .unwrap();
        (hash, yid)
    }

    #[test]
    fn torrent_and_youtube_jobs_are_rows_of_one_list() {
        let tmp = tempfile::tempdir().unwrap();
        let (hash, yid) = write_jobs(tmp.path());
        let rows = job_rows(tmp.path());
        assert_eq!(rows.len(), 2, "{rows:#?}");
        let t = rows.iter().find(|r| r.kind == "torrent").unwrap();
        assert_eq!(t.id, format!("torrent:{hash}"));
        assert_eq!(t.state, "downloading");
        assert_eq!((t.done, t.total, t.unit), (2, 3, "files"));
        assert_eq!((t.bytes_done, t.bytes_total), (400, 1000));
        assert_eq!(t.current.as_deref(), Some("Example set/c.bin"));
        assert_eq!(t.already_stored, Some(1));
        assert_eq!(t.retry_utc, Some(1_790_000_110));
        assert_eq!(t.actions, vec!["pause", "remove"]);
        assert!(!t.finished);
        let y = rows.iter().find(|r| r.kind == "youtube").unwrap();
        assert_eq!(y.id, format!("youtube:{yid}"));
        assert_eq!(y.state, "waiting_retry");
        assert_eq!((y.done, y.total, y.unit), (2, 5, "videos"));
        assert_eq!(y.already_stored, Some(1));
        assert_eq!(y.current.as_deref(), Some("Five"));
        assert_eq!(y.failed.len(), 2);
        assert_eq!(y.failed[0].reason, "Private video");
        assert_eq!(y.failed[0].next_try_utc, Some(1_790_010_000));
        assert!(y.failed[1].gave_up && y.failed[1].next_try_utc.is_none());
        assert_eq!(y.retry_utc, Some(1_790_010_000));
        assert_eq!(y.actions, vec!["pause", "retry", "remove"]);
    }

    #[test]
    fn paused_and_complete_jobs_offer_what_they_can() {
        let mut j: TorrentJob =
            serde_json::from_value(torrent_json(&"ab".repeat(20), "paused", true)).unwrap();
        assert_eq!(torrent_row(&j).actions, vec!["resume", "remove"]);
        j.state = JobState::Complete;
        let r = torrent_row(&j);
        assert!(r.finished);
        assert_eq!(r.actions, vec!["remove"]);
        assert_eq!(r.retry_utc, None);
    }

    #[test]
    fn jobs_are_found_by_prefixed_or_bare_names() {
        let tmp = tempfile::tempdir().unwrap();
        let (hash, yid) = write_jobs(tmp.path());
        assert!(matches!(
            find(tmp.path(), &format!("torrent:{hash}")).unwrap(),
            JobRef::Torrent(_)
        ));
        assert!(matches!(
            find(tmp.path(), &format!("youtube:{yid}")).unwrap(),
            JobRef::Youtube(_)
        ));
        assert!(matches!(
            find(tmp.path(), "example-set").unwrap(),
            JobRef::Torrent(_)
        ));
        assert!(matches!(
            find(tmp.path(), "example-channel").unwrap(),
            JobRef::Youtube(_)
        ));
        assert_eq!(
            find(tmp.path(), &yid[..8]).unwrap().id(),
            format!("youtube:{yid}")
        );
        let e = find(tmp.path(), "nothing-like-it").err().unwrap();
        assert!(format!("{e:#}").contains("import jobs list"), "{e:#}");
        let v = find(tmp.path(), "example-set").unwrap().value().unwrap();
        assert_eq!(v["job"], format!("torrent:{hash}"));
        assert_eq!(v["job_kind"], "torrent");
        assert_eq!(v["hash"], hash.as_str());
    }

    #[test]
    fn a_finished_run_is_a_row_with_its_report() {
        let r = Run {
            n: 7,
            kind: "dir".into(),
            title: "/data/photos".into(),
            source: "/data/photos".into(),
            folder: "photos".into(),
            state: "done",
            error: None,
            verb: None,
            target: None,
            started_utc: 1,
            updated_utc: 2,
            report: Some(
                json!({"folder": "photos", "imported_files": 3, "already_ids": 2, "failed_count": 1, "imported_bytes": 4096}),
            ),
        };
        let row = run_row(&r, None);
        assert_eq!(row.id, "run:7");
        assert!(row.finished);
        assert_eq!((row.done, row.total, row.bytes_done), (5, 6, 4096));
        assert_eq!(row.actions, vec!["remove"]);
    }
}
