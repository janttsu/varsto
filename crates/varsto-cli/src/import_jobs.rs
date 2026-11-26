// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Every import of this device in one list, for the Import page
//! (`GET /api/import/jobs`):
//!
//! - imports the page started (a local directory, a git-annex repository,
//!   a cloud drive through rclone), `run:<n>`, kept in memory while the
//!   service runs;
//! - imports a command of this device runs (reported to the service as
//!   activity), `activity:<n>`, shown without actions.
//!
//! The page's requests are answered without waiting for the service's state
//! (a sync or an import may hold it for a long time): the list is read from
//! the activity registry, and the work a request asks for (start an import)
//! runs on a thread of its own that takes the state when it is free.
//! Every change of the list is announced as the event `import.jobs`.

use crate::desktop::Shared;
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tiny_http::{Method, Request};
use varsto_core::Engine;

/// Finished and failed imports the page started, kept for the list.
const RUNS_KEPT: usize = 20;

// ----- one row per import ---------------------------------------------------------

/// One import in the uniform list.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct JobRow {
    /// `run:<n>` or `activity:<n>`.
    pub id: String,
    /// `dir`, `git-annex`, `rclone`, `dropbox`, `onedrive`, or `import`
    /// (a command of this device).
    pub kind: String,
    pub folder: String,
    pub title: String,
    /// The source as given (a directory or a remote).
    pub source: String,
    /// `waiting` (for the service), `running`, `failed` or `done`.
    pub state: String,
    /// What the import does or waits for, in a sentence.
    pub text: String,
    pub done: u64,
    pub total: u64,
    /// What `done` and `total` count: `files`.
    pub unit: &'static str,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// The file in hand.
    pub current: Option<String>,
    /// Bytes per second, when known.
    pub speed: Option<u64>,
    pub last_error: Option<String>,
    /// Nothing more to do: finished or failed.
    pub finished: bool,
    pub started_utc: i64,
    pub updated_utc: i64,
    /// What `POST /api/import/jobs/<id>/<action>` accepts for this row.
    pub actions: Vec<&'static str>,
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
                Ok(v) => set_run(n, |r| {
                    r.state = "done";
                    if let Some(f) = v.get("folder").and_then(Value::as_str) {
                        r.folder = f.to_string();
                    }
                    r.report = Some(v);
                }),
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
            row.bytes_done = t.done;
            row.bytes_total = t.total;
        }
        varsto_core::activity::Unit::Items => {
            row.done = t.done;
            row.total = t.total;
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

/// Everything: the imports the page started and the imports of other
/// commands of this device. Unfinished ones first, then by start.
pub fn rows() -> Vec<JobRow> {
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
    let mut out = Vec::new();
    for r in runs().clone() {
        // A failed import stays visible; a running one shows the task in hand.
        let task = (r.state == "running")
            .then(|| claim(&r.folder))
            .flatten()
            .map(|i| &tasks[i]);
        out.push(run_row(&r, task));
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
pub fn jobs_json() -> Value {
    let mobile = crate::desktop::mobile();
    json!({
        "jobs": rows(),
        "platform": {
            "mobile": mobile,
        },
        "tools": {
            "rclone": on_path("rclone", "VARSTO_RCLONE"),
            "git": on_path("git", "VARSTO_GIT"),
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
        (200, jobs_json())
    } else if method == Method::Post {
        let mut body = String::new();
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
            action(rest)
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
/// the import on a thread of its own.
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
        "" => bail!("choose what to import"),
        other => bail!("unknown import source {other}"),
    };
    Ok(id)
}

/// `POST /api/import/jobs/<id>/<action>`: only an import the page started
/// and that is finished can be taken off the list (`run:<n>`, `remove`).
fn action(rest: &str) -> (u16, Value) {
    let Some((id, verb)) = rest.rsplit_once('/') else {
        return (404, json!({"error": "not found"}));
    };
    let id = crate::desktop::percent_decode(id);
    let Some(n) = id.strip_prefix("run:") else {
        return (404, json!({"error": format!("no import job {id}")}));
    };
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
    match list.iter().position(|r| r.n == n) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn only_a_finished_run_can_be_taken_off_the_list() {
        let n = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        runs().push(Run {
            n,
            kind: "dir".into(),
            title: "t".into(),
            source: "t".into(),
            folder: "t".into(),
            state: "running",
            error: None,
            started_utc: 1,
            updated_utc: 1,
            report: None,
        });
        let id = format!("run%3A{n}");
        assert_eq!(action(&format!("{id}/remove")).0, 409);
        set_run(n, |r| r.state = "failed");
        assert_eq!(action(&format!("{id}/remove")).0, 200);
        assert_eq!(action(&format!("{id}/remove")).0, 404);
        assert_eq!(action("torrent%3A00ff00ff/pause").0, 404);
        assert_eq!(action("run%3A1/explode").0, 400);
    }
}
