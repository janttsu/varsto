// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto restic`: backups of the whole vault with restic, from one device
//! that keeps every folder as a full plaintext copy under one directory
//! (the mirror). See `varsto_core::restic` and the spec section "Backups
//! with restic".
//!
//! With the background service running, the steps that need the vault
//! (sync, hold, completeness check, setup) go through its API and no
//! passphrase is asked; restic itself always runs in this process. The
//! service starts `varsto restic run --scheduled` the same way when the
//! schedule says a run is due.

use crate::{passphrase, print, service, Cli};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use varsto_core::activity;
use varsto_core::engine::{CheckOptions, SetupReport};
use varsto_core::restic::{
    self, Completeness, Hold, Keep, Message, PasswordSource, ResticConfig, ResticState, RunLock,
    RunRecord, RunResult,
};
use varsto_core::util;
use varsto_core::vault::{BackupSchedule, Config};
use varsto_core::Engine;

/// Exit codes of `varsto restic run`.
pub const EXIT_INCOMPLETE: i32 = 1;
pub const EXIT_RESTIC_FAILED: i32 = 2;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum ResticCmd {
    /// Make this device the restic device: every folder of the vault (or
    /// the chosen ones) is kept here as a full plaintext copy under
    /// ROOT/<folder name>, and `varsto restic run` backs ROOT up into the
    /// restic repository REPO. The repository lives outside the vault's
    /// storages; restoring needs only restic and its password (see
    /// `varsto restic restore-hint`). The password itself is never stored:
    /// give a command that prints it or a file holding it. New folders of
    /// the vault are attached in the mirror automatically (with --folders
    /// all). Strongroom folders and folders shared with other people are
    /// left out unless included. Do not edit files in the mirror: it is an
    /// ordinary synced copy, and changes there reach every device.
    Setup(SetupArgs),
    /// Take a snapshot now: sync the mirror, check that every file of the
    /// vault is there with the recorded content (missing ones are fetched),
    /// hold the mirror folders so Varsto does not write into them, write
    /// ROOT/VARSTO-SNAPSHOT.txt, run `restic backup`, then `restic forget
    /// --prune` with the kept counts and `restic check` when due. Exit code
    /// 0: done; 1: the mirror was incomplete and restic did not run; 2:
    /// restic failed.
    Run(RunArgs),
    /// Settings, folders in and out of the mirror, the last run and check,
    /// the next scheduled run, and whether the mirror is complete now
    /// (presence, size and time; `run` also checks the content).
    Status,
    /// The snapshots of this vault in the repository (`restic snapshots`).
    Snapshots,
    /// The restic commands that list and restore the snapshots without
    /// Varsto. Keep them with the repository password.
    RestoreHint,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("password").required(true).args(["password_command", "password_file"])))]
pub struct SetupArgs {
    /// The mirror root: every folder is kept at ROOT/<folder name>.
    #[arg(long)]
    root: PathBuf,
    /// The restic repository (anything restic takes: a path, sftp:, s3:, rest:, rclone:, ...).
    #[arg(long)]
    repo: String,
    /// A command that prints the repository password (RESTIC_PASSWORD_COMMAND).
    #[arg(long)]
    password_command: Option<String>,
    /// A file holding the repository password (RESTIC_PASSWORD_FILE).
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// KEY=VALUE lines given to restic, e.g. the repository's cloud credentials.
    #[arg(long)]
    env_file: Option<PathBuf>,
    /// The restic program (default: restic from PATH).
    #[arg(long, default_value = "restic")]
    restic_bin: String,
    /// `all` (also folders added later) or a comma-separated list of folder names.
    #[arg(long, default_value = "all")]
    folders: String,
    /// Mirror folders shared with other people too.
    #[arg(long)]
    include_shared: bool,
    /// Mirror Strongroom folders too (they must be unlocked for every run).
    #[arg(long, conflicts_with = "exclude_strongroom")]
    include_strongroom: bool,
    /// Leave Strongroom folders out (the default).
    #[arg(long)]
    exclude_strongroom: bool,
    #[arg(long, default_value_t = 7)]
    keep_daily: u32,
    #[arg(long, default_value_t = 5)]
    keep_weekly: u32,
    #[arg(long, default_value_t = 12)]
    keep_monthly: u32,
    /// Run `restic check --read-data-subset` every this many days (0: only with `run --check`).
    #[arg(long, default_value_t = 7)]
    check_every_days: u32,
    /// What `restic check` reads: a share (5%), a part (1/10) or a size (500M).
    #[arg(long, default_value = "5%")]
    check_subset: String,
    /// The background service runs a backup this often.
    #[arg(long, default_value_t = 24, conflicts_with = "manual")]
    every_hours: u32,
    /// Only `varsto restic run` takes snapshots.
    #[arg(long)]
    manual: bool,
    /// Move folders already attached elsewhere on this device into the mirror.
    #[arg(long = "move")]
    move_attached: bool,
    /// Create the repository (`restic init`) when there is none.
    #[arg(long)]
    init: bool,
}

#[derive(Args)]
pub struct RunArgs {
    /// Do not run `restic forget --prune` after the backup.
    #[arg(long)]
    no_forget: bool,
    /// Run `restic check` after the backup even when it is not due.
    #[arg(long, conflicts_with = "no_check")]
    check: bool,
    /// Do not run `restic check`, even when it is due.
    #[arg(long)]
    no_check: bool,
    /// Check the mirror and run `restic backup --dry-run`; nothing is written.
    #[arg(long)]
    dry_run: bool,
    /// Hash every file of the mirror, not only those changed since the last run.
    #[arg(long)]
    rehash_all: bool,
    /// Started by the background service's schedule.
    #[arg(long, hide = true)]
    scheduled: bool,
}

// ----- the vault: through the service or in this process ---------------------------

enum Vault {
    Service(service::ServiceFile),
    Local(Box<Engine>),
}

impl Vault {
    fn open(home: &Path) -> Result<Vault> {
        if let Some((sf, _)) = service::status(home) {
            return Ok(Vault::Service(sf));
        }
        Ok(Vault::Local(Box::new(Engine::open(home, &passphrase()?)?)))
    }

    fn api(sf: &service::ServiceFile, path: &str, body: Value, secs: u64) -> Result<Value> {
        let url = format!("http://127.0.0.1:{}{path}", sf.port);
        match service::http_post_within(&url, &sf.token, &body.to_string(), secs) {
            Ok(t) => Ok(serde_json::from_str(&t).unwrap_or(Value::Null)),
            Err(e) => {
                let msg = format!("{e:#}");
                let inner = msg
                    .split_once(": ")
                    .and_then(|(_, b)| serde_json::from_str::<Value>(b).ok())
                    .and_then(|v| v["error"].as_str().map(str::to_string));
                Err(anyhow!(inner.unwrap_or(msg)))
            }
        }
    }

    fn sync(&mut self) -> Result<()> {
        match self {
            Vault::Service(sf) => Self::api(sf, "/api/sync", json!({}), 86_400).map(|_| ()),
            Vault::Local(e) => e.sync(None).map(|_| ()),
        }
    }

    fn hold(&mut self, token: &str) -> Result<Vec<String>> {
        match self {
            Vault::Service(sf) => {
                let v = Self::api(
                    sf,
                    "/api/restic/hold",
                    json!({"token": token, "pid": std::process::id()}),
                    86_400,
                )?;
                Ok(serde_json::from_value(v["held"].clone()).unwrap_or_default())
            }
            Vault::Local(e) => e.restic_hold(token, std::process::id()),
        }
    }

    fn check(&mut self, opts: &CheckOptions) -> Result<Completeness> {
        match self {
            Vault::Service(sf) => {
                let v = Self::api(
                    sf,
                    "/api/restic/check",
                    serde_json::to_value(opts)?,
                    7 * 86_400,
                )?;
                Ok(serde_json::from_value(v)?)
            }
            Vault::Local(e) => e.restic_check(opts),
        }
    }

    fn setup(
        &mut self,
        cfg: &ResticConfig,
        names: Option<Vec<String>>,
        mv: bool,
    ) -> Result<SetupReport> {
        match self {
            Vault::Service(sf) => {
                let v = Self::api(
                    sf,
                    "/api/restic/setup",
                    json!({"config": cfg, "folders": names, "move": mv}),
                    3600,
                )?;
                Ok(serde_json::from_value(v)?)
            }
            Vault::Local(e) => e.restic_setup(cfg.clone(), names.as_deref(), mv),
        }
    }
}

/// The settings, read without the passphrase.
fn config(home: &Path) -> Result<ResticConfig> {
    Config::load(home)?.restic.ok_or_else(|| {
        anyhow!("this device is not set up for restic; run `varsto restic setup` first")
    })
}

// ----- running restic ------------------------------------------------------------------

fn restic_command(cfg: &ResticConfig, args: &[String]) -> Result<Command> {
    // The password reaches restic through its environment, never the arguments.
    // The repository can hold a login (`rest:https://user:password@host`): the
    // log gets its kind and host only.
    log::debug!(binary = cfg.binary.as_str(), repository = restic::repository_summary(&cfg.repository); "restic {}", args.join(" "));
    let mut c = Command::new(&cfg.binary);
    c.args(args);
    for k in restic::REMOVED_ENV {
        c.env_remove(k);
    }
    for (k, v) in cfg.env()? {
        c.env(k, v);
    }
    Ok(c)
}

/// Environment variable with the longest time, in seconds, that one restic
/// run may take; unset or 0 means no limit (a backup can run for hours).
const LIMIT_ENV: &str = "VARSTO_RESTIC_TIMEOUT_SECS";

fn parse_limit(v: Option<&str>) -> Option<Duration> {
    let n: u64 = v?.trim().parse().ok()?;
    (n > 0).then(|| Duration::from_secs(n))
}

fn restic_limit() -> Option<Duration> {
    parse_limit(std::env::var(LIMIT_ENV).ok().as_deref())
}

fn kill_pid(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Kills a child that outlives its wall-clock limit. Dropping it stands the
/// watch down.
struct Watchdog {
    done: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
}

impl Watchdog {
    fn start(pid: u32, limit: Option<Duration>) -> Watchdog {
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        if let Some(limit) = limit {
            let (d, f) = (done.clone(), fired.clone());
            std::thread::spawn(move || {
                let start = Instant::now();
                while !d.load(Ordering::SeqCst) {
                    if start.elapsed() >= limit {
                        f.store(true, Ordering::SeqCst);
                        kill_pid(pid);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        }
        Watchdog { done, fired }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }
}

/// Run restic to the end; (success, exit code, stdout, stderr).
fn restic_output(
    cfg: &ResticConfig,
    args: &[String],
) -> Result<(bool, Option<i32>, String, String)> {
    let t = varsto_core::logging::Timer::start();
    let child = restic_command(cfg, args)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {} (is restic installed?)", cfg.binary))?;
    let limit = restic_limit();
    let dog = Watchdog::start(child.id(), limit);
    let out = child.wait_with_output()?;
    if dog.fired() {
        bail!(
            "restic did not finish within {} s and was stopped ({LIMIT_ENV})",
            limit.map(|l| l.as_secs()).unwrap_or(0)
        );
    }
    log::debug!(
        code = out.status.code().unwrap_or(-1),
        ms = t.ms(),
        stdout = out.stdout.len(),
        stderr = tail(&String::from_utf8_lossy(&out.stderr), 3);
        "restic {} finished",
        args.first().map(String::as_str).unwrap_or("")
    );
    Ok((
        out.status.success(),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

fn tail(text: &str, lines: usize) -> String {
    let v: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    v[v.len().saturating_sub(lines)..].join("\n")
}

/// The repository is there and opens with the password; with `init`, one
/// is created when there is none (restic's exit code 10).
fn ensure_repository(cfg: &ResticConfig, init: bool) -> Result<bool> {
    let args = ["cat".to_string(), "config".to_string()];
    let (ok, code, _, err) = restic_output(cfg, &args)?;
    if ok {
        return Ok(false);
    }
    if code == Some(10) {
        if !init {
            bail!(
                "there is no restic repository at {}; run setup again with --init to create one",
                restic::display_repository(&cfg.repository)
            );
        }
        let (ok, _, _, err) = restic_output(cfg, &["init".to_string()])?;
        if !ok {
            bail!("restic init failed: {}", tail(&err, 5));
        }
        return Ok(true);
    }
    bail!(
        "the restic repository {} cannot be opened: {}",
        restic::display_repository(&cfg.repository),
        tail(&err, 5)
    )
}

/// `restic backup`, its progress on the terminal and in the activity task;
/// the summary when it succeeded.
fn backup(cfg: &ResticConfig, dry_run: bool, quiet: bool) -> Result<restic::Summary> {
    let task = activity::start(activity::RESTIC, "", 0, activity::Unit::Bytes);
    task.set_phase("backup");
    let mut child = restic_command(cfg, &cfg.backup_args(dry_run))?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {} (is restic installed?)", cfg.binary))?;
    let limit = restic_limit();
    let dog = Watchdog::start(child.id(), limit);
    let stderr = child.stderr.take().expect("piped");
    let err_lines = std::thread::spawn(move || {
        let mut kept = Vec::new();
        for l in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if !l.trim().is_empty() {
                kept.push(l);
            }
        }
        kept
    });
    let tty = std::io::stderr().is_terminal() && !quiet;
    let mut summary = None;
    let mut errors: Vec<String> = Vec::new();
    let mut shown_done = 0u64;
    let mut last_print = Instant::now() - Duration::from_secs(3600);
    let stdout = child.stdout.take().expect("piped");
    for line in std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
    {
        match restic::parse_message(&line) {
            Message::Status(s) => {
                task.set_total(s.total_bytes);
                if s.bytes_done > shown_done {
                    task.advance(s.bytes_done - shown_done);
                    shown_done = s.bytes_done;
                }
                let every = if tty {
                    Duration::from_millis(500)
                } else {
                    Duration::from_secs(30)
                };
                if !quiet && last_print.elapsed() >= every {
                    last_print = Instant::now();
                    let eta = s
                        .seconds_remaining
                        .map(|r| format!(", about {}", human_secs(r)))
                        .unwrap_or_default();
                    let text = format!(
                        "restic: {:>3.0} %  {} / {} files  {} / {}{eta}",
                        s.percent_done * 100.0,
                        s.files_done,
                        s.total_files,
                        util::human_bytes(s.bytes_done),
                        util::human_bytes(s.total_bytes)
                    );
                    if tty {
                        eprint!("\r{text:<78}");
                    } else {
                        eprintln!("{text}");
                    }
                }
            }
            Message::Summary(s) => summary = Some(s),
            Message::Error(e) => {
                if !quiet {
                    if tty {
                        eprintln!();
                    }
                    eprintln!("restic: {e}");
                }
                errors.push(e);
            }
            Message::Other => {}
        }
    }
    if tty {
        eprintln!();
    }
    let status = child.wait()?;
    let err_text = err_lines.join().unwrap_or_default();
    if dog.fired() {
        bail!(
            "restic did not finish within {} s and was stopped ({LIMIT_ENV})",
            limit.map(|l| l.as_secs()).unwrap_or(0)
        );
    }
    // Exit code 3: a snapshot was taken but some files could not be read.
    // In a complete mirror that is a failure: the snapshot is not whole.
    if !status.success() {
        let why = errors
            .last()
            .cloned()
            .or_else(|| err_text.last().cloned())
            .unwrap_or_else(|| format!("exit status {status}"));
        bail!(
            "restic backup failed ({}): {why}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        );
    }
    summary.ok_or_else(|| anyhow!("restic backup gave no summary"))
}

fn human_secs(s: u64) -> String {
    if s >= 3600 {
        format!("{} h {} min left", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{} min left", s / 60)
    } else {
        format!("{s} s left")
    }
}

/// The hold for one run: renewed every minute by a thread, released when
/// dropped (also when the run fails). If this process dies, the lease
/// lapses after five minutes, or at once when its process is gone.
struct HoldGuard {
    home: PathBuf,
    token: String,
    stop: Arc<AtomicBool>,
}

impl HoldGuard {
    fn start(home: &Path, token: &str) -> HoldGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let (h, t, s) = (home.to_path_buf(), token.to_string(), stop.clone());
        let _ = std::thread::Builder::new()
            .name("restic-hold".into())
            .spawn(move || {
                let mut since = Instant::now();
                while !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(500));
                    if since.elapsed() >= Duration::from_secs(restic::HOLD_RENEW_SECS) {
                        since = Instant::now();
                        let _ = Hold::renew(&h, &t, util::now_utc());
                    }
                }
            });
        HoldGuard {
            home: home.to_path_buf(),
            token: token.to_string(),
            stop,
        }
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        Hold::release(&self.home, &self.token);
    }
}

// ----- commands --------------------------------------------------------------------------

#[derive(Serialize)]
struct RunReport {
    result: RunResult,
    record: RunRecord,
    completeness: Option<Completeness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_check: Option<restic::CheckRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn run(cli: &Cli, home: &Path, cmd: &ResticCmd) -> Result<()> {
    match cmd {
        ResticCmd::Setup(a) => setup(cli, home, a),
        ResticCmd::Run(a) => {
            let (report, code) = take_snapshot(home, a, cli.json)?;
            print(cli, &report, describe_run)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        ResticCmd::Status => status(cli, home),
        ResticCmd::Snapshots => {
            let cfg = config(home)?;
            let st = restic_command(&cfg, &cfg.snapshots_args(cli.json))?
                .stdin(Stdio::null())
                .status()
                .with_context(|| format!("run {} (is restic installed?)", cfg.binary))?;
            if !st.success() {
                std::process::exit(EXIT_RESTIC_FAILED);
            }
            Ok(())
        }
        ResticCmd::RestoreHint => {
            let cfg = config(home)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"hint": cfg.restore_hint()}))?
                );
            } else {
                print!("{}", cfg.restore_hint());
            }
            Ok(())
        }
    }
}

fn setup(cli: &Cli, home: &Path, a: &SetupArgs) -> Result<()> {
    let password = match (&a.password_command, &a.password_file) {
        (Some(c), _) => PasswordSource::Command(c.clone()),
        (None, Some(f)) => PasswordSource::File(std::path::absolute(f)?),
        (None, None) => bail!("give --password-command or --password-file"),
    };
    let names: Option<Vec<String>> = match a.folders.trim() {
        "all" | "" => None,
        list => Some(
            list.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
    };
    let cfg = ResticConfig {
        root: std::path::absolute(&a.root)?,
        repository: a.repo.clone(),
        password,
        env_file: a.env_file.as_ref().map(std::path::absolute).transpose()?,
        binary: a.restic_bin.clone(),
        folders: Default::default(),
        include_shared: a.include_shared,
        include_strongroom: a.include_strongroom,
        keep: Keep {
            daily: a.keep_daily,
            weekly: a.keep_weekly,
            monthly: a.keep_monthly,
        },
        check_every_days: a.check_every_days,
        check_subset: a.check_subset.clone(),
        schedule: if a.manual {
            BackupSchedule::Manual
        } else {
            if a.every_hours == 0 {
                bail!("--every-hours must be at least 1 (or --manual)");
            }
            BackupSchedule::EveryHours(a.every_hours)
        },
        vault_short: String::new(),
        host: String::new(),
        created_utc: 0,
    };
    if cfg.keep.is_empty() {
        bail!("keep at least one snapshot rule (--keep-daily, --keep-weekly, --keep-monthly)");
    }
    if !restic::check_subset_valid(&cfg.check_subset) {
        bail!(
            "--check-subset {} is not a subset restic takes (5%, 1/10, 500M)",
            cfg.check_subset
        );
    }
    // The repository first: nothing is attached for a repository that does not open.
    let created = ensure_repository(&cfg, a.init)?;
    let mut vault = Vault::open(home)?;
    let report = vault.setup(&cfg, names, a.move_attached)?;
    let cfg = config(home)?;
    print(
        cli,
        &json!({"setup": report, "repository_created": created, "config": cfg}),
        |_| {
            let mut out = Vec::new();
            if created {
                out.push(format!(
                    "restic repository created at {}",
                    restic::display_repository(&cfg.repository)
                ));
            } else {
                out.push(format!(
                    "restic repository {} opens",
                    restic::display_repository(&cfg.repository)
                ));
            }
            out.push(format!("mirror root: {}", report.root.display()));
            for n in &report.attached {
                out.push(format!("  attached: {n}"));
            }
            for n in &report.moved {
                out.push(format!("  moved: {n}"));
            }
            for n in &report.kept {
                out.push(format!("  already there: {n}"));
            }
            for e in &report.excluded {
                out.push(format!("  left out: {} ({})", e.folder, e.reason));
            }
            out.push(format!(
                "schedule: {}; keeps {}; restic check of {} every {} days",
                cfg.schedule.describe(),
                cfg.keep.describe(),
                cfg.check_subset,
                cfg.check_every_days
            ));
            out.push("The folders download on the next sync; `varsto restic run` takes the first snapshot once they are complete.".into());
            out.push("Keep the repository password apart from this computer, and print `varsto restic restore-hint`.".into());
            out.join("\n")
        },
    )
}

/// One run (see `ResticCmd::Run`): the report and the exit code.
fn take_snapshot(home: &Path, a: &RunArgs, quiet: bool) -> Result<(RunReport, i32)> {
    let cfg = config(home)?;
    let _lock = RunLock::acquire(home)?;
    let started = util::now_utc();
    let t0 = Instant::now();
    let mut record = RunRecord {
        started_utc: started,
        scheduled: a.scheduled,
        ..Default::default()
    };
    let say = |s: &str| {
        if !quiet {
            eprintln!("{s}");
        }
    };
    let finish = |mut record: RunRecord,
                  result: RunResult,
                  completeness: Option<Completeness>,
                  check: Option<restic::CheckRecord>,
                  error: Option<String>|
     -> Result<(RunReport, i32)> {
        record.finished_utc = util::now_utc();
        record.duration_secs = t0.elapsed().as_secs_f64();
        record.result = Some(result);
        if record.message.is_none() {
            record.message = error.clone();
        }
        let mut st = ResticState::load(home);
        st.record(record.clone());
        if let Some(c) = &check {
            st.last_check = Some(c.clone());
        }
        st.save(home)?;
        let code = match result {
            RunResult::Ok | RunResult::DryRun => 0,
            RunResult::Incomplete | RunResult::Aborted => EXIT_INCOMPLETE,
            RunResult::ResticFailed => EXIT_RESTIC_FAILED,
        };
        Ok((
            RunReport {
                result,
                record,
                completeness,
                repository_check: check,
                error,
            },
            code,
        ))
    };
    let mut vault = match Vault::open(home) {
        Ok(v) => v,
        Err(e) => {
            return finish(
                record,
                RunResult::Aborted,
                None,
                None,
                Some(format!("{e:#}")),
            )
        }
    };
    // 1. Sync.
    say("syncing the mirror folders...");
    if let Err(e) = vault.sync() {
        // A sync that failed for one folder may still leave the mirror
        // complete; the check decides.
        say(&format!("sync: {e:#}"));
    }
    // 2-3. Hold, then check (and fetch what is missing) under the hold.
    let token = hex::encode(rand::random::<[u8; 16]>());
    let held = match vault.hold(&token) {
        Ok(h) => h,
        Err(e) => {
            return finish(
                record,
                RunResult::Aborted,
                None,
                None,
                Some(format!("{e:#}")),
            )
        }
    };
    let guard = HoldGuard::start(home, &token);
    say(&format!(
        "checking that the mirror is complete ({} folders held)...",
        held.len()
    ));
    let c = match vault.check(&CheckOptions {
        token: Some(token.clone()),
        rehash_all: a.rehash_all,
        fix: true,
        quick: false,
    }) {
        Ok(c) => c,
        Err(e) => {
            drop(guard);
            return finish(
                record,
                RunResult::Aborted,
                None,
                None,
                Some(format!("{e:#}")),
            );
        }
    };
    if !c.complete {
        drop(guard);
        let why = format!(
            "the mirror is not complete ({} problems); restic did not run:\n{}",
            c.problem_count(),
            c.describe()
        );
        return finish(record, RunResult::Incomplete, Some(c), None, Some(why));
    }
    record.files = c.folders.iter().map(|f| f.files).sum();
    record.bytes = c.folders.iter().map(|f| f.bytes).sum();
    // 4. The description.
    if !a.dry_run {
        let text = restic::snapshot_text(&cfg, started, &c);
        if let Err(e) = util::write_atomic(&cfg.root.join(restic::SNAPSHOT_FILE), text.as_bytes()) {
            drop(guard);
            return finish(
                record,
                RunResult::Aborted,
                Some(c),
                None,
                Some(format!("{e:#}")),
            );
        }
    }
    // 5. restic backup.
    say(&format!("backing up {} with restic...", cfg.root.display()));
    let summary = backup(&cfg, a.dry_run, quiet);
    // 6. Varsto may write again.
    drop(guard);
    let summary = match summary {
        Ok(s) => s,
        Err(e) => {
            return finish(
                record,
                RunResult::ResticFailed,
                Some(c),
                None,
                Some(format!("{e:#}")),
            )
        }
    };
    record.snapshot_id = summary.snapshot_id.clone();
    record.bytes_added = summary.data_added;
    record.files = summary.total_files_processed.max(record.files);
    record.bytes = summary.total_bytes_processed.max(record.bytes);
    if a.dry_run {
        return finish(record, RunResult::DryRun, Some(c), None, None);
    }
    // 7. forget --prune.
    let mut failure: Option<String> = None;
    if !a.no_forget {
        say("removing old snapshots (restic forget --prune)...");
        let task = activity::start(activity::RESTIC, "", 0, activity::Unit::Items);
        task.set_phase("forget");
        match restic_output(&cfg, &cfg.forget_args()) {
            Ok((true, _, out, _)) => record.forget = Some(restic::forget_counts(&out)),
            Ok((false, _, _, err)) => {
                failure = Some(format!("restic forget failed: {}", tail(&err, 5)))
            }
            Err(e) => failure = Some(format!("{e:#}")),
        }
    }
    // 8. check when due.
    let last_check = ResticState::load(home).last_check.map(|c| c.utc);
    let mut check = None;
    if !a.no_check && (a.check || cfg.check_due(last_check, util::now_utc())) {
        say(&format!(
            "checking the repository (restic check --read-data-subset {})...",
            cfg.check_subset
        ));
        let task = activity::start(activity::RESTIC, "", 0, activity::Unit::Items);
        task.set_phase("repo_check");
        let r = restic_output(&cfg, &cfg.check_args());
        let rec = match r {
            Ok((ok, _, out, err)) => restic::CheckRecord {
                utc: util::now_utc(),
                ok,
                subset: cfg.check_subset.clone(),
                message: (!ok).then(|| tail(&format!("{out}\n{err}"), 8)),
            },
            Err(e) => restic::CheckRecord {
                utc: util::now_utc(),
                ok: false,
                subset: cfg.check_subset.clone(),
                message: Some(format!("{e:#}")),
            },
        };
        if !rec.ok && failure.is_none() {
            failure = Some(format!(
                "restic check found problems: {}",
                rec.message.clone().unwrap_or_default()
            ));
        }
        check = Some(rec);
    }
    match failure {
        None => finish(record, RunResult::Ok, Some(c), check, None),
        Some(f) => {
            // The snapshot itself is good; the run is not.
            record.message = Some(f.clone());
            let (mut report, code) =
                finish(record, RunResult::ResticFailed, Some(c), check, Some(f))?;
            let mut st = ResticState::load(home);
            if st.last_success.is_none()
                || st.last_success.as_ref().map(|s| s.started_utc) < Some(report.record.started_utc)
            {
                st.last_success = Some(report.record.clone());
                st.save(home)?;
            }
            report.result = RunResult::ResticFailed;
            Ok((report, code))
        }
    }
}

fn describe_run(r: &RunReport) -> String {
    let rec = &r.record;
    let mut out = Vec::new();
    match r.result {
        RunResult::Ok | RunResult::DryRun => {
            out.push(format!(
                "{} {}: {} files, {} in the mirror, {} added, {:.0} s",
                if r.result == RunResult::DryRun {
                    "dry run of snapshot"
                } else {
                    "snapshot"
                },
                rec.snapshot_id
                    .as_deref()
                    .map(|s| &s[..s.len().min(8)])
                    .unwrap_or("-"),
                rec.files,
                util::human_bytes(rec.bytes),
                util::human_bytes(rec.bytes_added),
                rec.duration_secs
            ));
            if let Some((k, rm)) = rec.forget {
                out.push(format!("forget: {k} snapshots kept, {rm} removed"));
            }
        }
        RunResult::Incomplete | RunResult::Aborted | RunResult::ResticFailed => {
            if rec.snapshot_id.is_some() {
                out.push(format!(
                    "snapshot {} taken",
                    rec.snapshot_id.as_deref().unwrap_or("")
                ));
            }
            out.push(format!(
                "FAILED: {}",
                r.error.clone().unwrap_or_else(|| "unknown error".into())
            ));
        }
    }
    if let Some(c) = &r.repository_check {
        out.push(format!(
            "restic check ({}): {}",
            c.subset,
            if c.ok {
                "no problems"
            } else {
                "PROBLEMS FOUND"
            }
        ));
    }
    out.join("\n")
}

fn status(cli: &Cli, home: &Path) -> Result<()> {
    config(home)?;
    let quick = CheckOptions {
        quick: true,
        ..Default::default()
    };
    let c = match Vault::open(home) {
        Ok(mut v) => v.check(&quick),
        Err(e) => Err(e),
    };
    let v = restic::status_value(home, Some(c))?;
    print(cli, &v, describe_status)
}

pub fn describe_status(v: &Value) -> String {
    let cfg: ResticConfig = match serde_json::from_value(v["config"].clone()) {
        Ok(c) => c,
        Err(_) => return "not set up for restic".into(),
    };
    let st: ResticState = serde_json::from_value(v["state"].clone()).unwrap_or_default();
    let date = |t: i64| {
        format!(
            "{} {:02}:{:02} UTC",
            util::format_date(t),
            t.rem_euclid(86_400) / 3600,
            t.rem_euclid(3600) / 60
        )
    };
    let mut out = vec![
        format!(
            "restic repository: {}",
            restic::display_repository(&cfg.repository)
        ),
        format!(
            "password: {}",
            match &cfg.password {
                // The first word names the program; the rest may hold the password itself.
                PasswordSource::Command(c) => format!(
                    "from the command `{}`",
                    c.split_whitespace().next().unwrap_or("")
                ),
                PasswordSource::File(f) => format!("from the file {}", f.display()),
            }
        ),
        format!("mirror root: {}", cfg.root.display()),
        format!(
            "snapshots tagged varsto,vault:{} from host {}; keeps {}",
            cfg.vault_short,
            cfg.host,
            cfg.keep.describe()
        ),
        format!(
            "schedule: {}; restic check of {} every {} days",
            cfg.schedule.describe(),
            cfg.check_subset,
            cfg.check_every_days
        ),
    ];
    if let Ok(c) = serde_json::from_value::<Completeness>(v["completeness"].clone()) {
        out.push(String::from("folders:"));
        for f in &c.folders {
            out.push(format!(
                "  {}: {} files, {}{}",
                f.folder,
                f.files,
                util::human_bytes(f.bytes),
                if f.problems.is_empty() {
                    String::new()
                } else {
                    format!(", {} not complete", f.problems.len())
                }
            ));
        }
        for n in &c.not_attached {
            out.push(format!("  {n}: not attached in the mirror"));
        }
        for e in &c.excluded {
            out.push(format!("  left out: {} ({})", e.folder, e.reason));
        }
        out.push(format!(
            "mirror complete now: {}",
            if c.complete {
                "yes (files present with the recorded size and time; a run also checks their content)".to_string()
            } else {
                format!("NO, {} problems:\n{}", c.problem_count(), c.describe())
            }
        ));
    } else if let Some(e) = v["completeness_error"].as_str() {
        out.push(format!("mirror: not checked ({e})"));
    }
    match &st.last_run {
        Some(r) => out.push(format!(
            "last run: {}, {}{}{}",
            date(r.started_utc),
            match r.result {
                Some(RunResult::Ok) => "ok".to_string(),
                Some(RunResult::Incomplete) => "mirror incomplete, no snapshot".to_string(),
                Some(RunResult::ResticFailed) => "restic failed".to_string(),
                Some(RunResult::Aborted) => "aborted".to_string(),
                Some(RunResult::DryRun) | None => "-".to_string(),
            },
            r.snapshot_id
                .as_deref()
                .map(|s| format!(", snapshot {}", &s[..s.len().min(8)]))
                .unwrap_or_default(),
            r.message
                .as_deref()
                .map(|m| format!("\n  {}", m.lines().next().unwrap_or("")))
                .unwrap_or_default()
        )),
        None => out.push("last run: never".into()),
    }
    if let Some(r) = &st.last_success {
        out.push(format!(
            "last snapshot: {} {}, {} files, {} added, {:.0} s",
            date(r.started_utc),
            r.snapshot_id
                .as_deref()
                .map(|s| &s[..s.len().min(8)])
                .unwrap_or("-"),
            r.files,
            util::human_bytes(r.bytes_added),
            r.duration_secs
        ));
    }
    match &st.last_check {
        Some(c) => out.push(format!(
            "last restic check: {} ({}): {}",
            date(c.utc),
            c.subset,
            if c.ok {
                "no problems"
            } else {
                "PROBLEMS FOUND"
            }
        )),
        None => out.push("last restic check: never".into()),
    }
    if let Some(t) = v["next_run_utc"].as_i64() {
        out.push(format!("next scheduled run: {}", date(t)));
    }
    if v["stale"].as_bool() == Some(true) {
        out.push("WARNING: the last good snapshot is older than the schedule allows".into());
    }
    if v["held_now"].as_bool() == Some(true) {
        out.push("a run is backing up the mirror now".into());
    }
    out.join("\n")
}

/// For the recovery kit: where the restic snapshots are (never the password).
pub fn kit_note(home: &Path) -> Option<String> {
    let cfg = Config::load(home).ok()?.restic?;
    Some(format!(
        "\nNOTES\nBackups with restic: repository {} (device {}, mirror {}).\nThe restic repository password is kept separately, not in this kit; without it those snapshots cannot be read.\n",
        restic::display_repository(&cfg.repository),
        cfg.host,
        cfg.root.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_restic_limit_is_optional() {
        assert_eq!(parse_limit(None), None);
        assert_eq!(parse_limit(Some("")), None);
        assert_eq!(parse_limit(Some("0")), None);
        assert_eq!(parse_limit(Some("abc")), None);
        assert_eq!(parse_limit(Some(" 90 ")), Some(Duration::from_secs(90)));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_past_its_limit_is_killed() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let dog = Watchdog::start(child.id(), Some(Duration::from_millis(300)));
        let t = Instant::now();
        let status = child.wait().unwrap();
        assert!(dog.fired());
        assert!(!status.success());
        assert!(t.elapsed() < Duration::from_secs(20));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_within_its_limit_is_left_alone() {
        let mut child = Command::new("true").spawn().unwrap();
        let dog = Watchdog::start(child.id(), Some(Duration::from_secs(60)));
        assert!(child.wait().unwrap().success());
        assert!(!dog.fired());
    }

    fn config(repo: &str, password: PasswordSource) -> ResticConfig {
        serde_json::from_value(serde_json::json!({
            "root": "/srv/mirror",
            "repository": repo,
            "password": password,
            "vault_short": "ab12cd34",
            "host": "nas",
            "created_utc": 1,
            "schedule": {"every_hours": 24},
        }))
        .unwrap()
    }

    #[test]
    fn status_and_kit_show_no_login_and_no_password_command_arguments() {
        let cfg = config(
            "rest:https://u:p@h.example/r",
            PasswordSource::Command("echo x".into()),
        );
        let text = describe_status(&serde_json::json!({"config": cfg}));
        assert!(!text.contains("u:p@"), "{text}");
        assert!(text.contains("rest:https://h.example/r"), "{text}");
        assert!(text.contains("from the command `echo`"), "{text}");
        assert!(!text.contains("echo x"), "{text}");
        let home = tempfile::tempdir().unwrap();
        let c = varsto_core::vault::Config {
            restic: Some(cfg),
            ..Default::default()
        };
        c.save(home.path()).unwrap();
        let note = kit_note(home.path()).unwrap();
        assert!(
            note.contains("rest:https://h.example/r") && !note.contains("u:p@"),
            "{note}"
        );
        // The scrubber catches the same shapes should one reach a log line.
        let line = varsto_core::logging::scrub("restic failed: s3:https://K:S@h/b");
        assert!(!line.contains("K:S"), "{line}");
    }
}
