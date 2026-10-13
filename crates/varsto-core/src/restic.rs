// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backups with restic (`docs/spec/alpha-0-format.md`, section "Backups
//! with restic").
//!
//! One device of the vault, the *restic device*, keeps every folder of the
//! vault (or the ones chosen) as a full plaintext copy under one directory,
//! the *mirror root*: `<root>/<folder name>/...`. Those are ordinary,
//! non-selective folder mounts. A run (`varsto restic run`) syncs them,
//! checks that the mirror is complete (every live file of every mirror
//! folder is on disk with the recorded content), holds the folders so that
//! Varsto does not write into them, writes `<root>/VARSTO-SNAPSHOT.txt` and
//! runs `restic backup <root>`. The restic repository lives outside the
//! storages of the vault and is restored with restic alone.
//!
//! This module has what needs no engine: the settings kept in
//! `config.json` (`restic`), the record of runs (`state/restic.json`), the
//! cache of verified hashes (`state/restic-verified.json`), the hold file
//! (`state/restic-hold.json`), the run lock (`restic.lock`), the restic
//! command lines, restic's JSON messages, the snapshot description and the
//! restore instructions. The mirror itself (setup, completeness, fixes) is
//! `engine::restic_mirror`.

use crate::ids::FolderId;
use crate::util;
use crate::vault::BackupSchedule;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Name of the description written at the top of the mirror root.
pub const SNAPSHOT_FILE: &str = "VARSTO-SNAPSHOT.txt";
/// Tag of every snapshot a run takes (with `vault:<short id>`).
pub const TAG: &str = "varsto";
/// Patterns restic leaves out: Varsto's temporary files and directories
/// (`.varsto-tmp-*`, `.varsto-upload-*`, `.varsto-scrub-*`, ...) and
/// placeholders, which a complete mirror has none of anyway.
pub const EXCLUDES: &[&str] = &[".varsto*", "*.varsto-placeholder"];
/// How long a hold lasts unless renewed (the run renews it every minute).
pub const HOLD_LEASE_SECS: i64 = 300;
pub const HOLD_RENEW_SECS: u64 = 60;
/// A failed or aborted scheduled run is tried again after this long.
pub const RETRY_SECS: i64 = 3600;

const STATE_FILE: &str = "state/restic.json";
const VERIFIED_FILE: &str = "state/restic-verified.json";
const HOLD_FILE: &str = "state/restic-hold.json";
const LOCK_FILE: &str = "restic.lock";

/// Where restic gets the repository password. Only the command or the
/// file's path is kept, never the password.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PasswordSource {
    /// `RESTIC_PASSWORD_COMMAND`: a command that prints the password.
    Command(String),
    /// `RESTIC_PASSWORD_FILE`: a file holding the password.
    File(PathBuf),
}

/// Which folders the mirror keeps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FolderChoice {
    /// Every folder of the vault, also those added later (they are
    /// attached on this device when their record arrives).
    #[default]
    All,
    /// Only these.
    Named(Vec<FolderId>),
}

/// How many snapshots `restic forget` keeps (`--keep-daily` and so on);
/// zero leaves a rule out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keep {
    pub daily: u32,
    pub weekly: u32,
    pub monthly: u32,
}

impl Default for Keep {
    fn default() -> Self {
        Keep {
            daily: 7,
            weekly: 5,
            monthly: 12,
        }
    }
}

impl Keep {
    pub fn is_empty(&self) -> bool {
        self.daily == 0 && self.weekly == 0 && self.monthly == 0
    }
    pub fn describe(&self) -> String {
        format!(
            "{} daily, {} weekly, {} monthly",
            self.daily, self.weekly, self.monthly
        )
    }
}

/// The restic settings of this device (`config.json`, `restic`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResticConfig {
    /// The mirror root: `<root>/<folder name>` per folder.
    pub root: PathBuf,
    /// `RESTIC_REPOSITORY`.
    pub repository: String,
    pub password: PasswordSource,
    /// `KEY=VALUE` lines handed to restic (cloud credentials of the
    /// repository, for example); never shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<PathBuf>,
    /// The restic program (a name looked up in `PATH`, or a path).
    #[serde(default = "default_binary")]
    pub binary: String,
    #[serde(default)]
    pub folders: FolderChoice,
    /// Folders shared with other people are mirrored too.
    #[serde(default)]
    pub include_shared: bool,
    /// Strongroom folders are mirrored too (they must be unlocked for a
    /// run: a plaintext copy of them is what a Strongroom avoids, so they
    /// are left out unless asked for).
    #[serde(default)]
    pub include_strongroom: bool,
    #[serde(default)]
    pub keep: Keep,
    /// `restic check --read-data-subset` every this many days (0: never
    /// unless asked for).
    #[serde(default = "default_check_days")]
    pub check_every_days: u32,
    #[serde(default = "default_check_subset")]
    pub check_subset: String,
    /// When the background service runs it.
    #[serde(default)]
    pub schedule: BackupSchedule,
    /// Short id of the vault (`vault:<id>` tag) and this device's name
    /// (`--host`), fixed at setup so that the snapshots of the vault stay
    /// one series and the restore instructions work without the vault.
    pub vault_short: String,
    pub host: String,
    pub created_utc: i64,
}

fn default_binary() -> String {
    "restic".to_string()
}
fn default_check_days() -> u32 {
    7
}
fn default_check_subset() -> String {
    "5%".to_string()
}

/// `--check-subset`: `5%`, `1/10` or a size such as `500M`, as restic takes it.
pub fn check_subset_valid(s: &str) -> bool {
    let s = s.trim();
    if let Some(p) = s.strip_suffix('%') {
        return p.parse::<f64>().is_ok_and(|v| v > 0.0 && v <= 100.0);
    }
    if let Some((n, m)) = s.split_once('/') {
        return matches!((n.parse::<u32>(), m.parse::<u32>()), (Ok(a), Ok(b)) if a >= 1 && a <= b);
    }
    let digits = s.trim_end_matches(['K', 'M', 'G', 'T', 'k', 'm', 'g', 't']);
    !digits.is_empty() && digits.len() + 1 >= s.len() && digits.parse::<u64>().is_ok_and(|v| v > 0)
}

impl ResticConfig {
    /// Tags of every snapshot: `varsto` and `vault:<short id>`.
    pub fn tags(&self) -> [String; 2] {
        [TAG.to_string(), format!("vault:{}", self.vault_short)]
    }

    /// The tag filter that selects this vault's snapshots (both tags).
    pub fn tag_filter(&self) -> String {
        self.tags().join(",")
    }

    /// Environment for restic: the repository and the password source.
    /// The variables in `REMOVED_ENV` are taken away first so that a
    /// password in the caller's environment cannot be used instead.
    pub fn env(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        if let Some(f) = &self.env_file {
            let text = std::fs::read_to_string(f)
                .with_context(|| format!("read the environment file {}", f.display()))?;
            out.extend(parse_env_file(&text)?);
        }
        out.push(("RESTIC_REPOSITORY".into(), self.repository.clone()));
        match &self.password {
            PasswordSource::Command(c) => out.push(("RESTIC_PASSWORD_COMMAND".into(), c.clone())),
            PasswordSource::File(f) => {
                out.push(("RESTIC_PASSWORD_FILE".into(), f.display().to_string()))
            }
        }
        // One progress message a second in JSON mode.
        out.push(("RESTIC_PROGRESS_FPS".into(), "1".into()));
        Ok(out)
    }

    /// `restic backup` arguments (after the program name).
    pub fn backup_args(&self, dry_run: bool) -> Vec<String> {
        let mut a = vec!["backup".to_string(), self.root.display().to_string()];
        for t in self.tags() {
            a.push("--tag".into());
            a.push(t);
        }
        a.push("--host".into());
        a.push(self.host.clone());
        a.push("--exclude-caches".into());
        for e in EXCLUDES {
            a.push("--exclude".into());
            a.push(e.to_string());
        }
        if dry_run {
            a.push("--dry-run".into());
        }
        a.push("--json".into());
        a
    }

    /// `restic forget` arguments: this vault's snapshots only, pruned.
    pub fn forget_args(&self) -> Vec<String> {
        let mut a = vec![
            "forget".to_string(),
            "--tag".into(),
            self.tag_filter(),
            "--host".into(),
            self.host.clone(),
        ];
        for (flag, n) in [
            ("--keep-daily", self.keep.daily),
            ("--keep-weekly", self.keep.weekly),
            ("--keep-monthly", self.keep.monthly),
        ] {
            if n > 0 {
                a.push(flag.into());
                a.push(n.to_string());
            }
        }
        a.push("--prune".into());
        a.push("--json".into());
        a
    }

    pub fn check_args(&self) -> Vec<String> {
        vec![
            "check".into(),
            "--read-data-subset".into(),
            self.check_subset.clone(),
        ]
    }

    pub fn snapshots_args(&self, json: bool) -> Vec<String> {
        let mut a = vec!["snapshots".to_string(), "--tag".into(), self.tag_filter()];
        if json {
            a.push("--json".into());
        } else {
            a.push("--compact".into());
        }
        a
    }

    /// Whether `restic check` is due (`last`: the last check's time).
    pub fn check_due(&self, last: Option<i64>, now: i64) -> bool {
        self.check_every_days > 0
            && last.is_none_or(|t| now - t >= i64::from(self.check_every_days) * 86_400)
    }

    /// After how many hours without a good snapshot the mirror is overdue
    /// (twice the interval, at least two days); none for manual runs.
    pub fn stale_after_hours(&self) -> Option<i64> {
        match self.schedule {
            BackupSchedule::Manual => None,
            BackupSchedule::EveryHours(h) => Some((2 * i64::from(h)).max(48)),
        }
    }

    /// The commands to list and restore the snapshots without Varsto.
    pub fn restore_hint(&self) -> String {
        let q = shell_quote;
        let mut t = String::new();
        t.push_str(
            "Restoring needs only restic (https://restic.net) and the repository password.\n\n",
        );
        t.push_str(&format!(
            "export RESTIC_REPOSITORY={}\n",
            q(&self.repository)
        ));
        match &self.password {
            PasswordSource::Command(c) => {
                t.push_str(&format!("export RESTIC_PASSWORD_COMMAND={}\n", q(c)))
            }
            PasswordSource::File(f) => t.push_str(&format!(
                "export RESTIC_PASSWORD_FILE={}\n",
                q(&f.display().to_string())
            )),
        }
        if let Some(f) = &self.env_file {
            t.push_str(&format!(
                "set -a; . {}; set +a    # the repository's credentials\n",
                q(&f.display().to_string())
            ));
        }
        let filter = format!("--tag {} --host {}", self.tag_filter(), q(&self.host));
        let root = self.root.display().to_string();
        t.push_str(&format!(
            "\n# The snapshots of this vault:\nrestic snapshots {filter}\n"
        ));
        t.push_str(&format!(
            "\n# What the newest one holds (one directory per folder, and {SNAPSHOT_FILE}):\nrestic ls latest {filter} {}\n",
            q(&root)
        ));
        t.push_str(&format!(
            "\n# Everything, into /tmp/restore (the files land under /tmp/restore{root}):\nrestic restore latest {filter} --target /tmp/restore\n"
        ));
        t.push_str(&format!(
            "\n# One folder only (here \"Documents\"), straight into /tmp/Documents:\nrestic restore {} {filter} --target /tmp/Documents\n",
            q(&format!("latest:{root}/Documents"))
        ));
        t.push_str(
            "\n# An older snapshot: use its ID from `restic snapshots` instead of latest.\n",
        );
        t.push_str(&format!(
            "# {SNAPSHOT_FILE} in each snapshot names the vault, the device, the time and every folder's state.\n"
        ));
        t
    }
}

/// Lines `KEY=VALUE` (`export ` allowed, `#` comments, optional quotes).
pub fn parse_env_file(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            bail!("line {} of the environment file is not KEY=VALUE", n + 1);
        };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            bail!("line {} of the environment file has no valid name", n + 1);
        }
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Variables never inherited by restic from the caller's environment.
pub const REMOVED_ENV: &[&str] = &[
    "RESTIC_REPOSITORY",
    "RESTIC_REPOSITORY_FILE",
    "RESTIC_PASSWORD",
    "RESTIC_PASSWORD_FILE",
    "RESTIC_PASSWORD_COMMAND",
];

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:,=@%+".contains(c))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A folder name as a directory name under the mirror root.
pub fn dir_name(folder: &str) -> Result<String> {
    let n = folder.trim();
    if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\', '\0']) {
        bail!("folder name {folder:?} cannot be a directory name in the mirror");
    }
    if n.eq_ignore_ascii_case(SNAPSHOT_FILE) || n.starts_with(".varsto") {
        bail!("folder name {folder:?} is reserved in the mirror");
    }
    Ok(n.to_string())
}

// ----- restic's JSON messages ---------------------------------------------------

/// One line of `restic backup --json`.
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Status(Status),
    Summary(Summary),
    Error(String),
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub percent_done: f64,
    #[serde(default)]
    pub total_files: u64,
    #[serde(default)]
    pub files_done: u64,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub bytes_done: u64,
    #[serde(default)]
    pub seconds_remaining: Option<u64>,
    #[serde(default)]
    pub error_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    #[serde(default)]
    pub files_new: u64,
    #[serde(default)]
    pub files_changed: u64,
    #[serde(default)]
    pub files_unmodified: u64,
    #[serde(default)]
    pub data_added: u64,
    #[serde(default)]
    pub total_files_processed: u64,
    #[serde(default)]
    pub total_bytes_processed: u64,
    #[serde(default)]
    pub total_duration: f64,
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

pub fn parse_message(line: &str) -> Message {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
        return Message::Other;
    };
    match v.get("message_type").and_then(|t| t.as_str()) {
        Some("status") => serde_json::from_value(v)
            .map(Message::Status)
            .unwrap_or(Message::Other),
        Some("summary") => serde_json::from_value(v)
            .map(Message::Summary)
            .unwrap_or(Message::Other),
        Some("error") => {
            let msg = v
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .or_else(|| v.get("error").and_then(|m| m.as_str()))
                .unwrap_or("error");
            let item = v.get("item").and_then(|i| i.as_str()).unwrap_or("");
            Message::Error(if item.is_empty() {
                msg.to_string()
            } else {
                format!("{item}: {msg}")
            })
        }
        _ => Message::Other,
    }
}

/// How many snapshots `restic forget --json` kept and removed.
pub fn forget_counts(json: &str) -> (u64, u64) {
    let Ok(groups) = serde_json::from_str::<Vec<serde_json::Value>>(json.trim()) else {
        return (0, 0);
    };
    let n = |g: &serde_json::Value, k: &str| {
        g.get(k)
            .and_then(|x| x.as_array())
            .map_or(0, |a| a.len() as u64)
    };
    groups
        .iter()
        .fold((0, 0), |(k, r), g| (k + n(g, "keep"), r + n(g, "remove")))
}

// ----- the mirror's completeness -------------------------------------------------

/// Why a file keeps the mirror from being complete.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// Not on disk.
    Missing,
    /// A placeholder stands in its place.
    Placeholder,
    /// A newer version is known that has not been downloaded.
    NotDownloaded,
    /// Its size or modification time is not what this device recorded
    /// (changed on disk after the last sync).
    Changed,
    /// Its content does not hash to the recorded hash.
    HashMismatch,
    Unreadable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Problem {
    pub path: String,
    pub kind: ProblemKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// One mirror folder as checked.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct FolderCheck {
    pub folder: String,
    pub folder_id: String,
    pub path: PathBuf,
    /// Live files and their bytes.
    pub files: u64,
    pub bytes: u64,
    /// Files hashed in this check, and those whose hash came from the cache.
    pub rehashed: u64,
    pub cached: u64,
    /// This device's manifest of the folder, and the newest manifest of
    /// every other device applied here (device short id -> sequence).
    pub manifest_seq: u64,
    pub manifest_hash: String,
    pub seen: BTreeMap<String, u64>,
    /// A digest of (path, content hash) of every live file: two mirrors of
    /// the same folder state have the same digest.
    pub state_digest: String,
    pub problems: Vec<Problem>,
    /// Files fetched again or restored by this check.
    pub fixed: Vec<String>,
    /// Files on disk that the folder does not know (yet); they are backed
    /// up as they are.
    pub unknown: Vec<String>,
}

/// A folder of the vault that the mirror leaves out, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Excluded {
    pub folder: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Completeness {
    pub complete: bool,
    pub checked_utc: i64,
    pub root: PathBuf,
    pub folders: Vec<FolderCheck>,
    pub excluded: Vec<Excluded>,
    /// Entries at the top of the mirror root that are not mirror folders.
    pub stray: Vec<String>,
    /// Folders that should be in the mirror but are not attached there.
    pub not_attached: Vec<String>,
    /// Without hashing (status): presence, size and time only.
    pub quick: bool,
}

impl Completeness {
    pub fn problem_count(&self) -> usize {
        self.folders.iter().map(|f| f.problems.len()).sum::<usize>() + self.not_attached.len()
    }

    pub fn describe(&self) -> String {
        let mut out = Vec::new();
        for n in &self.not_attached {
            out.push(format!("folder {n} is not attached in the mirror"));
        }
        for f in &self.folders {
            for p in f.problems.iter().take(20) {
                let what = match p.kind {
                    ProblemKind::Missing => "missing",
                    ProblemKind::Placeholder => "only a placeholder",
                    ProblemKind::NotDownloaded => "newer version not downloaded",
                    ProblemKind::Changed => "changed on disk since the last sync",
                    ProblemKind::HashMismatch => "content does not match the recorded hash",
                    ProblemKind::Unreadable => "unreadable",
                };
                out.push(format!(
                    "{}/{}: {what}{}",
                    f.folder,
                    p.path,
                    if p.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", p.detail)
                    }
                ));
            }
            if f.problems.len() > 20 {
                out.push(format!("{}: {} more", f.folder, f.problems.len() - 20));
            }
        }
        out.join("\n")
    }
}

/// `VARSTO-SNAPSHOT.txt`: what the snapshot holds. No keys, no hashes of
/// file contents (the state digest is keyed).
pub fn snapshot_text(cfg: &ResticConfig, utc: i64, c: &Completeness) -> String {
    let mut t = String::new();
    t.push_str("VARSTO SNAPSHOT\n");
    t.push_str(&format!("vault: {}\n", cfg.vault_short));
    t.push_str(&format!("device: {}\n", cfg.host));
    t.push_str(&format!("time: {} (unix {utc})\n", util::format_date(utc)));
    t.push_str(&format!("mirror root: {}\n", cfg.root.display()));
    t.push_str(&format!(
        "varsto: {}\n\nEvery folder below was complete when this snapshot was taken: every file the vault holds\nwas on disk with the recorded content. Restore with restic alone (`varsto restic restore-hint`).\n\n",
        env!("CARGO_PKG_VERSION")
    ));
    for f in &c.folders {
        t.push_str(&format!("folder: {}\n", f.folder));
        t.push_str(&format!("  id: {}\n", f.folder_id));
        t.push_str(&format!("  files: {}\n  bytes: {}\n", f.files, f.bytes));
        t.push_str(&format!(
            "  manifest: seq {} hash {}\n",
            f.manifest_seq,
            if f.manifest_hash.is_empty() {
                "-"
            } else {
                &f.manifest_hash
            }
        ));
        if !f.seen.is_empty() {
            let seen: Vec<String> = f.seen.iter().map(|(d, s)| format!("{d}:{s}")).collect();
            t.push_str(&format!("  devices: {}\n", seen.join(" ")));
        }
        t.push_str(&format!("  state: {}\n", f.state_digest));
    }
    for e in &c.excluded {
        t.push_str(&format!("left out: {} ({})\n", e.folder, e.reason));
    }
    t
}

// ----- the record of runs ---------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunResult {
    Ok,
    /// The mirror was not complete: restic did not run.
    Incomplete,
    /// restic failed (backup, or forget/check after a good backup).
    ResticFailed,
    /// Something else went wrong before restic ran.
    Aborted,
    DryRun,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RunRecord {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub result: Option<RunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub bytes_added: u64,
    #[serde(default)]
    pub duration_secs: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Snapshots kept and removed by `restic forget`, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forget: Option<(u64, u64)>,
    #[serde(default)]
    pub scheduled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct CheckRecord {
    pub utc: i64,
    pub ok: bool,
    pub subset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `state/restic.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ResticState {
    #[serde(default)]
    pub last_run: Option<RunRecord>,
    #[serde(default)]
    pub last_success: Option<RunRecord>,
    #[serde(default)]
    pub last_check: Option<CheckRecord>,
    #[serde(default)]
    pub runs: u64,
}

impl ResticState {
    pub fn load(home: &Path) -> ResticState {
        util::read_json_or_default(&home.join(STATE_FILE)).unwrap_or_default()
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join(STATE_FILE), self)
    }
    /// Record a finished run (dry runs are not runs).
    pub fn record(&mut self, r: RunRecord) {
        if r.result == Some(RunResult::DryRun) {
            return;
        }
        self.runs += 1;
        if r.result == Some(RunResult::Ok) {
            self.last_success = Some(r.clone());
        }
        self.last_run = Some(r);
    }

    /// When the schedule wants the next run: the interval after the last
    /// good snapshot, or an hour after a failed attempt if that is later.
    pub fn next_run_utc(&self, cfg: &ResticConfig) -> Option<i64> {
        let BackupSchedule::EveryHours(h) = cfg.schedule else {
            return None;
        };
        let after_good = self
            .last_success
            .as_ref()
            .map(|r| r.started_utc + i64::from(h) * 3600)
            .unwrap_or(0);
        let after_try = self
            .last_run
            .as_ref()
            .filter(|r| r.result != Some(RunResult::Ok))
            .map(|r| r.finished_utc.max(r.started_utc) + RETRY_SECS)
            .unwrap_or(0);
        Some(after_good.max(after_try))
    }

    pub fn due(&self, cfg: &ResticConfig, now: i64) -> bool {
        self.next_run_utc(cfg).is_some_and(|t| t <= now)
    }

    /// The last good snapshot is older than the schedule allows.
    pub fn stale(&self, cfg: &ResticConfig, now: i64) -> bool {
        let Some(hours) = cfg.stale_after_hours() else {
            return false;
        };
        let since = self
            .last_success
            .as_ref()
            .map(|r| r.started_utc)
            .unwrap_or(cfg.created_utc);
        now - since > hours * 3600
    }
}

// ----- cache of verified hashes ------------------------------------------------------

/// A file whose content was hashed at a run and matched: while its size and
/// time stay the same, the next run takes the hash from here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verified {
    pub size: u64,
    pub mtime: i64,
    pub hash: String,
}

/// `state/restic-verified.json`: folder id -> path -> verified.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct VerifiedCache {
    #[serde(default)]
    pub folders: BTreeMap<String, BTreeMap<String, Verified>>,
}

impl VerifiedCache {
    pub fn load(home: &Path) -> VerifiedCache {
        util::read_json_or_default(&home.join(VERIFIED_FILE)).unwrap_or_default()
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join(VERIFIED_FILE), self)
    }
    /// The recorded hash when the file is unchanged since it was verified.
    pub fn lookup(&self, folder: &str, path: &str, size: u64, mtime: i64) -> Option<&str> {
        self.folders
            .get(folder)
            .and_then(|m| m.get(path))
            .filter(|v| v.size == size && v.mtime == mtime)
            .map(|v| v.hash.as_str())
    }
}

// ----- the hold -----------------------------------------------------------------------

/// While a run backs up the mirror, Varsto does not write into these
/// folders (no sync, fetch, free, write, move or restore there). The hold
/// lapses at `until_utc` unless renewed, and at once when the process that
/// took it is gone, so a run that dies does not stop syncing for long.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hold {
    pub token: String,
    pub folders: Vec<FolderId>,
    pub pid: u32,
    pub started_utc: i64,
    pub until_utc: i64,
}

impl Hold {
    pub fn new(token: &str, folders: Vec<FolderId>, pid: u32, now: i64) -> Hold {
        Hold {
            token: token.to_string(),
            folders,
            pid,
            started_utc: now,
            until_utc: now + HOLD_LEASE_SECS,
        }
    }

    /// In force: not expired and its process still runs.
    pub fn active(&self, now: i64) -> bool {
        self.until_utc > now && process_alive(self.pid)
    }

    pub fn path(home: &Path) -> PathBuf {
        home.join(HOLD_FILE)
    }

    /// The hold in force, if any.
    pub fn current(home: &Path, now: i64) -> Option<Hold> {
        let h: Hold = util::read_json(&Hold::path(home)).ok()?;
        h.active(now).then_some(h)
    }

    pub fn write(&self, home: &Path) -> Result<()> {
        util::write_json(&Hold::path(home), self)
    }

    /// Extend the lease, if the hold on disk is still this one.
    pub fn renew(home: &Path, token: &str, now: i64) -> Result<bool> {
        let Ok(mut h) = util::read_json::<Hold>(&Hold::path(home)) else {
            return Ok(false);
        };
        if h.token != token {
            return Ok(false);
        }
        h.until_utc = now + HOLD_LEASE_SECS;
        h.write(home)?;
        Ok(true)
    }

    /// Remove the hold if it is this one (or has lapsed).
    pub fn release(home: &Path, token: &str) {
        let path = Hold::path(home);
        if let Ok(h) = util::read_json::<Hold>(&path) {
            if h.token == token || !h.active(util::now_utc()) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Signal 0 checks only; EPERM means it exists under another user.
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(pid: u32) -> bool {
    pid != 0
}

// ----- one run at a time ----------------------------------------------------------------

/// `restic.lock` in the device directory, held for the whole run.
pub struct RunLock {
    _file: std::fs::File,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl RunLock {
    /// Take the lock, or fail at once when another run has it.
    pub fn acquire(home: &Path) -> Result<RunLock> {
        let path = home.join(LOCK_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .with_context(|| format!("open {}", path.display()))?;
            let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if r != 0 {
                bail!("another restic run of this device is in progress");
            }
            Ok(RunLock { _file: file })
        }
        #[cfg(not(unix))]
        {
            // A lock file left by a run that died more than a day ago is stale.
            if let Ok(md) = std::fs::metadata(&path) {
                let old = md
                    .modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|e| e.as_secs() > 86_400);
                if old {
                    let _ = std::fs::remove_file(&path);
                }
            }
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|_| anyhow::anyhow!("another restic run of this device is in progress"))?;
            Ok(RunLock { _file: file, path })
        }
    }
}

#[cfg(not(unix))]
impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ResticConfig {
        ResticConfig {
            root: PathBuf::from("/srv/mirror"),
            repository: "sftp:nas:/backup/restic".into(),
            password: PasswordSource::File("/root/.restic-pass".into()),
            env_file: None,
            binary: default_binary(),
            folders: FolderChoice::All,
            include_shared: false,
            include_strongroom: false,
            keep: Keep::default(),
            check_every_days: 7,
            check_subset: "5%".into(),
            schedule: BackupSchedule::EveryHours(24),
            vault_short: "ab12cd34".into(),
            host: "nas box".into(),
            created_utc: 1_000_000,
        }
    }

    #[test]
    fn backup_arguments_carry_tags_host_and_excludes() {
        let a = cfg().backup_args(false);
        assert_eq!(a[0], "backup");
        assert_eq!(a[1], "/srv/mirror");
        let s = a.join(" ");
        assert!(s.contains("--tag varsto --tag vault:ab12cd34"), "{s}");
        assert!(s.contains("--host nas box"));
        assert!(s.contains("--exclude-caches"));
        assert!(s.contains("--exclude .varsto*"));
        assert!(s.contains("--exclude *.varsto-placeholder"));
        assert!(s.ends_with("--json"));
        assert!(!s.contains("--dry-run"));
        assert!(cfg().backup_args(true).contains(&"--dry-run".to_string()));
    }

    #[test]
    fn forget_selects_this_vault_and_skips_zero_rules() {
        let mut c = cfg();
        c.keep = Keep {
            daily: 3,
            weekly: 0,
            monthly: 2,
        };
        let a = c.forget_args();
        assert_eq!(
            a,
            [
                "forget",
                "--tag",
                "varsto,vault:ab12cd34",
                "--host",
                "nas box",
                "--keep-daily",
                "3",
                "--keep-monthly",
                "2",
                "--prune",
                "--json"
            ]
        );
        assert_eq!(c.check_args(), ["check", "--read-data-subset", "5%"]);
        assert_eq!(
            c.snapshots_args(false),
            ["snapshots", "--tag", "varsto,vault:ab12cd34", "--compact"]
        );
    }

    #[test]
    fn environment_names_repository_and_password_source_only() {
        let env = cfg().env().unwrap();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("RESTIC_REPOSITORY").unwrap(), "sftp:nas:/backup/restic");
        assert_eq!(get("RESTIC_PASSWORD_FILE").unwrap(), "/root/.restic-pass");
        assert!(get("RESTIC_PASSWORD").is_none());
        assert!(get("RESTIC_PASSWORD_COMMAND").is_none());
        let mut c = cfg();
        c.password = PasswordSource::Command("pass show restic".into());
        let env = c.env().unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "RESTIC_PASSWORD_COMMAND" && v == "pass show restic"));
        assert!(REMOVED_ENV.contains(&"RESTIC_PASSWORD"));
    }

    #[test]
    fn env_file_lines() {
        let e = parse_env_file(
            "# creds\nexport AWS_ACCESS_KEY_ID=abc\nAWS_SECRET_ACCESS_KEY=\"x y\"\n\nB2='q'\n",
        )
        .unwrap();
        assert_eq!(
            e,
            [
                ("AWS_ACCESS_KEY_ID".to_string(), "abc".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "x y".to_string()),
                ("B2".to_string(), "q".to_string())
            ]
        );
        assert!(parse_env_file("nonsense\n").is_err());
        assert!(parse_env_file("A B=1\n").is_err());
    }

    #[test]
    fn subsets_and_folder_directory_names() {
        for ok in ["5%", "0.5%", "1/10", "500M", "2G", "100"] {
            assert!(check_subset_valid(ok), "{ok}");
        }
        for bad in ["", "0%", "101%", "3/2", "x", "5MB", "0/4"] {
            assert!(!check_subset_valid(bad), "{bad}");
        }
        assert_eq!(dir_name("Photos").unwrap(), "Photos");
        for bad in ["", "..", "a/b", "VARSTO-SNAPSHOT.txt", ".varsto-x"] {
            assert!(dir_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn restic_json_messages() {
        let s = parse_message(
            r#"{"message_type":"status","percent_done":0.5,"total_files":4,"files_done":2,"total_bytes":100,"bytes_done":50,"seconds_remaining":3}"#,
        );
        assert!(
            matches!(s, Message::Status(ref st) if st.files_done == 2 && st.bytes_done == 50 && st.seconds_remaining == Some(3))
        );
        let s = parse_message(
            r#"{"message_type":"summary","files_new":1,"files_changed":0,"files_unmodified":0,"data_added":760,"total_files_processed":1,"total_bytes_processed":3,"total_duration":0.6,"snapshot_id":"ae0e84fb"}"#,
        );
        match s {
            Message::Summary(sum) => {
                assert_eq!(sum.snapshot_id.as_deref(), Some("ae0e84fb"));
                assert_eq!(sum.data_added, 760);
                assert_eq!(sum.total_files_processed, 1);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            parse_message(
                r#"{"message_type":"error","error":{"message":"permission denied"},"during":"archival","item":"/srv/mirror/x"}"#
            ),
            Message::Error("/srv/mirror/x: permission denied".into())
        );
        assert_eq!(parse_message("not json"), Message::Other);
        assert_eq!(
            forget_counts(r#"[{"keep":[{},{}],"remove":[{}]},{"keep":[{}],"remove":null}]"#),
            (3, 1)
        );
        assert_eq!(forget_counts(""), (0, 0));
    }

    #[test]
    fn hold_lease_expires_and_dies_with_its_process() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let now = util::now_utc();
        let f = FolderId::random();
        let h = Hold::new("t1", vec![f.clone()], std::process::id(), now);
        h.write(home).unwrap();
        assert!(Hold::current(home, now).is_some());
        assert!(Hold::current(home, now + HOLD_LEASE_SECS - 1).is_some());
        assert!(
            Hold::current(home, now + HOLD_LEASE_SECS).is_none(),
            "the lease lapsed"
        );
        // Renewing moves the end; another token cannot.
        assert!(!Hold::renew(home, "other", now + 100).unwrap());
        assert!(Hold::renew(home, "t1", now + 100).unwrap());
        assert!(Hold::current(home, now + HOLD_LEASE_SECS + 50).is_some());
        // Another token does not release it.
        Hold::release(home, "other");
        assert!(Hold::current(home, now).is_some());
        Hold::release(home, "t1");
        assert!(Hold::current(home, now).is_none());
        // A hold whose process is gone is not in force.
        let dead = Hold::new("t2", vec![f], u32::MAX - 7, now);
        assert!(!dead.active(now));
    }

    #[test]
    fn run_lock_is_exclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let first = RunLock::acquire(tmp.path()).unwrap();
        // flock is per open file description: a second open in this process conflicts too.
        assert!(RunLock::acquire(tmp.path()).is_err());
        drop(first);
        assert!(RunLock::acquire(tmp.path()).is_ok());
    }

    #[test]
    fn schedule_retry_and_staleness() {
        let c = cfg();
        let mut st = ResticState::default();
        assert!(st.due(&c, 10), "never ran");
        st.record(RunRecord {
            started_utc: 1000,
            finished_utc: 1100,
            result: Some(RunResult::Ok),
            ..Default::default()
        });
        assert_eq!(st.next_run_utc(&c), Some(1000 + 86_400));
        assert!(!st.due(&c, 2000));
        st.record(RunRecord {
            started_utc: 90_000,
            finished_utc: 90_100,
            result: Some(RunResult::Incomplete),
            ..Default::default()
        });
        assert_eq!(st.next_run_utc(&c), Some(90_100 + RETRY_SECS));
        assert_eq!(st.last_success.as_ref().unwrap().started_utc, 1000);
        assert!(!st.stale(&c, 1000 + 47 * 3600));
        assert!(st.stale(&c, 1000 + 49 * 3600));
        let mut manual = c.clone();
        manual.schedule = BackupSchedule::Manual;
        assert!(!st.due(&manual, i64::MAX / 2));
        assert!(!st.stale(&manual, i64::MAX / 2));
        // Dry runs are not recorded.
        st.record(RunRecord {
            result: Some(RunResult::DryRun),
            ..Default::default()
        });
        assert_eq!(st.runs, 2);
        // Check due.
        assert!(c.check_due(None, 0));
        assert!(!c.check_due(Some(0), 6 * 86_400));
        assert!(c.check_due(Some(0), 7 * 86_400));
    }

    #[test]
    fn verified_cache_needs_same_size_and_time() {
        let mut v = VerifiedCache::default();
        v.folders.entry("f".into()).or_default().insert(
            "a.txt".into(),
            Verified {
                size: 3,
                mtime: 7,
                hash: "h".into(),
            },
        );
        assert_eq!(v.lookup("f", "a.txt", 3, 7), Some("h"));
        assert_eq!(v.lookup("f", "a.txt", 4, 7), None);
        assert_eq!(v.lookup("f", "a.txt", 3, 8), None);
        assert_eq!(v.lookup("g", "a.txt", 3, 7), None);
    }

    #[test]
    fn restore_hint_has_no_password_and_quotes() {
        let t = cfg().restore_hint();
        assert!(t.contains("export RESTIC_REPOSITORY=sftp:nas:/backup/restic"));
        assert!(t.contains("export RESTIC_PASSWORD_FILE=/root/.restic-pass"));
        assert!(t.contains("restic restore latest --tag varsto,vault:ab12cd34 --host 'nas box' --target /tmp/restore"));
        assert!(t.contains("latest:/srv/mirror/Documents"));
    }
}
