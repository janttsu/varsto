// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Staged moves: persistent, resumable move jobs
//! (`docs/spec/alpha-0-format.md`, "Staged moves to disk pools").
//!
//! A job records that a folder (or some of its paths) is to be moved from
//! one storage to another, typically to a disk pool whose disks are docked
//! one at a time. The file `<home>/state/moves/<id>.json` holds only
//! progress and settings, never block names: what is left to move is worked
//! out from the ledger at every run, so a job survives a crash, a restart
//! and a different device finishing part of the move.

use crate::util;
use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// `<home>/state/moves`.
pub const DIR: &str = "state/moves";

/// A run that holds a job's lock for longer than this without progress is
/// taken to have died.
const LOCK_STALE_SECS: u64 = 600;

/// Where a job stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Runs whenever it can.
    #[default]
    Open,
    /// Kept, but not run until `resume`.
    Paused,
    /// Everything in scope is moved (or cannot be, see `errors`).
    Done,
    /// Stopped by the user; what was moved stays moved.
    Cancelled,
}

impl JobState {
    pub fn is_open(self) -> bool {
        self == JobState::Open
    }
    pub fn label(self) -> &'static str {
        match self {
            JobState::Open => "open",
            JobState::Paused => "paused",
            JobState::Done => "done",
            JobState::Cancelled => "cancelled",
        }
    }
}

/// What an open job waits for.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Waiting {
    /// "disk" (room on the target pool), "room" (a quota or full storage),
    /// "place" (a disk in another place, under a disk group rule).
    pub kind: String,
    /// The disk to attach, when a known one has room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<String>,
    /// A sentence for people.
    pub text: String,
}

/// A move job (`state/moves/<id>.json`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MoveJob {
    pub id: String,
    pub folder: String,
    pub folder_id: String,
    /// Folder paths (a file or a directory) the job is limited to; empty:
    /// the whole folder.
    pub paths: Vec<String>,
    pub from: String,
    pub to: String,
    pub idle_days: Option<i64>,
    /// Copy and check, but never drop from `from`.
    pub keep_source: bool,
    pub confirm_cold_read: bool,
    /// The folder's copy rules when the job started, in words.
    pub policy: String,
    pub state: JobState,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub bytes_remaining: u64,
    pub blocks_total: u64,
    pub blocks_done: u64,
    /// Bytes copied to a pool disk whose block waits for a copy in another
    /// place before it counts as moved (disk group rule).
    pub need_second_place_bytes: u64,
    /// Labels of the pool disks written to so far.
    pub disks_used: Vec<String>,
    pub started_utc: i64,
    pub last_progress_utc: i64,
    pub finished_utc: i64,
    pub runs: u32,
    pub waiting: Option<Waiting>,
    /// Which attached disks had how much room when the job last waited for
    /// room: the service runs the job again when this changes.
    pub room_sig: String,
    /// The smallest block that found no room at the last wait: a disk
    /// with less room than this cannot continue the job.
    pub room_needed: u64,
    /// Blocks in scope that stay on `from` (the folder's policy needs the
    /// copy there, a cold read is not confirmed).
    pub kept_blocks: u64,
    pub errors: Vec<String>,
}

impl MoveJob {
    pub fn path(home: &Path, id: &str) -> PathBuf {
        home.join(DIR).join(format!("{id}.json"))
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        fs::create_dir_all(home.join(DIR))?;
        util::write_json(&Self::path(home, &self.id), self)
    }

    /// Whether the job targets a pool (as opposed to an ordinary storage):
    /// the job file does not know, the engine decides from its storages.
    pub fn scope(&self) -> String {
        if self.paths.is_empty() {
            format!("folder {}", self.folder)
        } else {
            format!("{} in folder {}", self.paths.join(", "), self.folder)
        }
    }

    /// One line for `move status` and `varsto status`.
    pub fn line(&self) -> String {
        let mut s = format!(
            "{} {}: {} -> {}, {} of {} moved, {} left",
            self.id,
            self.state.label(),
            self.scope(),
            self.to,
            util::human_bytes(self.bytes_done),
            util::human_bytes(self.bytes_total),
            util::human_bytes(self.bytes_remaining),
        );
        if self.keep_source {
            s += " (source kept)";
        }
        if self.need_second_place_bytes > 0 {
            s += &format!(
                "; {} need a second place",
                util::human_bytes(self.need_second_place_bytes)
            );
        }
        if self.state.is_open() {
            if let Some(w) = &self.waiting {
                s += &format!("; {}", w.text);
            }
        }
        s
    }
}

/// A fresh job id: `mv-` and eight hex digits.
pub fn new_id() -> String {
    let mut b = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("mv-{}", hex::encode(b))
}

/// Every job, oldest first. Unreadable files are skipped.
pub fn list(home: &Path) -> Vec<MoveJob> {
    let mut out: Vec<MoveJob> = fs::read_dir(home.join(DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| util::read_json::<MoveJob>(&e.path()).ok())
        .collect();
    out.sort_by(|a, b| a.started_utc.cmp(&b.started_utc).then(a.id.cmp(&b.id)));
    out
}

/// The jobs that can still run (open or paused).
pub fn list_active(home: &Path) -> Vec<MoveJob> {
    list(home)
        .into_iter()
        .filter(|j| matches!(j.state, JobState::Open | JobState::Paused))
        .collect()
}

/// A job by id or unambiguous id prefix.
pub fn find(home: &Path, id: &str) -> Result<MoveJob> {
    if id.is_empty() || id.contains(['/', '\\']) || id.contains("..") {
        bail!("no move job {id}");
    }
    let all = list(home);
    if let Some(j) = all.iter().find(|j| j.id == id) {
        return Ok(j.clone());
    }
    let hits: Vec<&MoveJob> = all.iter().filter(|j| j.id.starts_with(id)).collect();
    match hits.as_slice() {
        [j] => Ok((*j).clone()),
        [] => Err(anyhow!("no move job {id}; `varsto move status` lists them")),
        _ => Err(anyhow!("{id} matches several move jobs: be more specific")),
    }
}

/// Held while a process runs a job, so the service and the command line do
/// not move the same blocks at once.
pub struct JobLock {
    path: PathBuf,
}

impl JobLock {
    /// `None` when another run holds the job.
    pub fn acquire(home: &Path, id: &str) -> Option<JobLock> {
        let dir = home.join(DIR);
        fs::create_dir_all(&dir).ok()?;
        let path = dir.join(format!("{id}.lock"));
        for _ in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => {
                    let _ = fs::write(&path, std::process::id().to_string());
                    return Some(JobLock { path });
                }
                Err(_) => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > LOCK_STALE_SECS);
                    if stale {
                        let _ = fs::remove_file(&path);
                    } else {
                        return None;
                    }
                }
            }
        }
        None
    }

}

/// Show that a run is alive (called after every group of blocks).
pub fn touch_lock(home: &Path, id: &str) {
    let path = home.join(DIR).join(format!("{id}.lock"));
    if path.exists() {
        let _ = fs::write(path, std::process::id().to_string());
    }
}

impl Drop for JobLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// An open job that waits for pool room, as the disk suggestion sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoveWait {
    pub id: String,
    pub folder: String,
    /// The pool the job moves to.
    pub pool: String,
    pub bytes_left: u64,
    pub need_second_place_bytes: u64,
    /// A disk with less room than this cannot continue the job.
    #[serde(default)]
    pub room_needed: u64,
}
