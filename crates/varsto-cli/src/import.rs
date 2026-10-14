// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto import`: bring a git-annex repository, a cloud drive (any rclone
//! remote: Dropbox, OneDrive, ...) or a local directory into a Varsto
//! folder, one folder per source; see `docs/import-git-annex.md`,
//! `docs/import-cloud.md` and `docs/import-local.md`.

use crate::{confirm, fmt_bytes, passphrase, plural, print, show, Cli};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use varsto_core::engine::{
    ImportCleanupReport, ImportOptions, ImportReport, ImportStatus, ImportVerify, MissingFile,
};
use varsto_core::import::{annex::AnnexSource, dir::DirSource, rclone::RcloneSource, ImportSource};
use varsto_core::Engine;

#[derive(Args, Clone)]
pub struct Target {
    /// The Varsto folder (default: named after the source). A source imported
    /// before always continues its own folder.
    #[arg(long)]
    folder: Option<String>,
    /// Keep a full copy of the folder in this directory (the folder is
    /// attached here). Without it the folder is attached selectively.
    #[arg(long)]
    dest: Option<PathBuf>,
    /// Attach selectively: imported files are placeholders on this device
    /// (the default without --dest; with --dest, placeholders go there).
    #[arg(long)]
    selective: bool,
    /// List and plan only; nothing is written anywhere.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
pub enum ImportCmd {
    /// Import a git-annex repository (read-only: no git-annex command is run
    /// on it). Run it once per disk that holds a clone: each continues the
    /// same folder with the content that disk has.
    #[command(name = "git-annex")]
    GitAnnex {
        repo: PathBuf,
        /// The commit whose files are imported: HEAD, a branch or a tag.
        #[arg(long = "ref", default_value = "HEAD")]
        git_ref: String,
        /// Do not check the content against the keys' hashes.
        #[arg(long)]
        no_verify: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Import any rclone remote (`remote:path`). Run it again to bring
    /// changes over; files deleted at the source are kept in Varsto.
    Rclone {
        remote: String,
        #[command(flatten)]
        cloud: CloudArgs,
    },
    /// Import from Dropbox through an rclone remote of type dropbox.
    Dropbox {
        remote: String,
        #[command(flatten)]
        cloud: CloudArgs,
    },
    /// Import from OneDrive through an rclone remote of type onedrive.
    Onedrive {
        remote: String,
        #[command(flatten)]
        cloud: CloudArgs,
    },
    /// Import a local directory. Run it again to bring changes over.
    Dir {
        source: PathBuf,
        /// Afterwards remove the source files that are safely stored and
        /// meet the folder's durability policy (asks first unless --yes).
        #[arg(long)]
        remove_source: bool,
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Imported folders: how much is in, what is missing and where it is.
    Status {
        folder: Option<String>,
        /// List the files still awaiting import with the copies that should have them.
        #[arg(long, requires = "folder")]
        missing: bool,
    },
    /// Whether an imported folder holds everything of its source, every block
    /// is on a storage and the durability policy is met: then the source (an
    /// annex disk) is no longer needed. Nothing is ever deleted there.
    Verify { folder: String },
    /// Remove the source files of an imported local directory that have since
    /// become safe (see `import dir --remove-source`).
    Cleanup {
        folder: String,
        #[arg(long)]
        yes: bool,
        /// Only say what would be removed.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args, Clone)]
pub struct CloudArgs {
    /// Hash type to check (dropbox, quickxor, sha1, md5, sha256, ... or none);
    /// default: the provider's own.
    #[arg(long)]
    hash_type: Option<String>,
    /// Parallel downloads.
    #[arg(long, default_value_t = 4)]
    transfers: u32,
    /// Where to keep downloads until they are in the folder (default:
    /// .varsto-import-staging in the folder's directory, on the same disk).
    /// Each batch needs its size plus 1 GiB free there.
    #[arg(long, value_name = "DIR")]
    staging: Option<PathBuf>,
    #[command(flatten)]
    target: Target,
}

fn options(home: &Path, t: &Target) -> ImportOptions {
    ImportOptions {
        folder: t.folder.clone(),
        dest: t.dest.clone(),
        selective: t.selective || t.dest.is_none(),
        dry_run: t.dry_run,
        remove_source: false,
        no_verify: false,
        default_parent: Some(crate::desktop::folder_root(home)),
        staging: None,
    }
}

/// A progress line on the terminal from the activity registry.
struct ProgressLine {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProgressLine {
    fn start(on: bool) -> ProgressLine {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = on.then(|| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut shown = false;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let tasks = varsto_core::activity::tasks();
                    if let Some(t) = tasks
                        .iter()
                        .find(|t| t.kind == varsto_core::activity::IMPORT)
                    {
                        let counts = match t.unit {
                            varsto_core::activity::Unit::Bytes if t.total > 0 => format!(
                                ": {} of {}{}",
                                fmt_bytes(t.done),
                                fmt_bytes(t.total),
                                if t.rate > 0 {
                                    format!(", {}/s", fmt_bytes(t.rate))
                                } else {
                                    String::new()
                                }
                            ),
                            varsto_core::activity::Unit::Items if t.total > 0 => {
                                format!(": {} of {} files", t.done, t.total)
                            }
                            _ => String::new(),
                        };
                        eprint!("\r{}{counts}   ", varsto_core::activity::describe(t));
                        shown = true;
                    }
                }
                if shown {
                    eprintln!();
                }
            })
        });
        ProgressLine { stop, thread }
    }
}

impl Drop for ProgressLine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn run(cli: &Cli, home: &Path, cmd: &ImportCmd) -> Result<()> {
    let mut engine = Engine::open(home, &passphrase()?)?;
    let progress_on = !cli.json && std::io::stderr().is_terminal();
    match cmd {
        ImportCmd::GitAnnex {
            repo,
            git_ref,
            no_verify,
            target,
        } => {
            let mut src = AnnexSource::open(repo, git_ref)?;
            let mut opts = options(home, target);
            opts.no_verify = *no_verify;
            let r = run_import(&mut engine, home, &mut src, &opts, progress_on)?;
            print(cli, &r, describe_report)?;
        }
        ImportCmd::Rclone { remote, cloud } => {
            cloud_import(cli, &mut engine, home, remote, None, cloud, progress_on)?
        }
        ImportCmd::Dropbox { remote, cloud } => cloud_import(
            cli,
            &mut engine,
            home,
            remote,
            Some("dropbox"),
            cloud,
            progress_on,
        )?,
        ImportCmd::Onedrive { remote, cloud } => cloud_import(
            cli,
            &mut engine,
            home,
            remote,
            Some("onedrive"),
            cloud,
            progress_on,
        )?,
        ImportCmd::Dir {
            source,
            remove_source,
            yes,
            target,
        } => {
            let mut src = DirSource::open(source)?;
            let mut opts = options(home, target);
            opts.remove_source = *remove_source;
            let mut r = run_import(&mut engine, home, &mut src, &opts, progress_on)?;
            if *remove_source && !opts.dry_run {
                let plan = engine.import_cleanup(&r.folder, false)?;
                r.cleanup = Some(cleanup_after_plan(cli, &mut engine, &r.folder, plan, *yes)?);
            }
            print(cli, &r, describe_report)?;
        }
        ImportCmd::Status { folder, missing } => {
            if *missing {
                let list = engine.import_missing(folder.as_deref().unwrap_or_default())?;
                print(cli, &list, |l| describe_missing(l))?;
            } else {
                let list = engine.import_status(folder.as_deref())?;
                print(cli, &list, describe_status)?;
            }
        }
        ImportCmd::Verify { folder } => {
            let v = engine.import_verify(folder)?;
            print(cli, &v, describe_verify)?;
            if !v.complete {
                std::process::exit(1);
            }
        }
        ImportCmd::Cleanup {
            folder,
            yes,
            dry_run,
        } => {
            let plan = engine.import_cleanup(folder, false)?;
            let r = if *dry_run {
                plan
            } else {
                cleanup_after_plan(cli, &mut engine, folder, plan, *yes)?
            };
            print(cli, &r, describe_cleanup)?;
        }
    }
    Ok(())
}

fn cloud_import(
    cli: &Cli,
    engine: &mut Engine,
    home: &Path,
    remote: &str,
    expect: Option<&str>,
    cloud: &CloudArgs,
    progress_on: bool,
) -> Result<()> {
    // Downloads are staged on the folder's disk (`ImportOptions::staging`);
    // this place is only a fallback the import replaces.
    let fallback = cloud
        .staging
        .clone()
        .unwrap_or_else(|| home.join("state").join("import-downloads"));
    let mut src = RcloneSource::open(
        remote,
        expect,
        cloud.hash_type.as_deref(),
        cloud.transfers,
        &fallback,
    )?;
    let mut opts = options(home, &cloud.target);
    opts.staging = cloud.staging.clone();
    let r = run_import(engine, home, &mut src, &opts, progress_on);
    print(cli, &r?, describe_report)
}

fn run_import(
    engine: &mut Engine,
    home: &Path,
    src: &mut dyn ImportSource,
    opts: &ImportOptions,
    progress_on: bool,
) -> Result<ImportReport> {
    // The background service takes no sync of its own meanwhile.
    let _pause = (!opts.dry_run).then(|| crate::drives::ServicePause::new(home));
    let _line = ProgressLine::start(progress_on);
    engine.import_run(src, opts)
}

/// Ask, then remove what the plan found eligible (checked again).
fn cleanup_after_plan(
    cli: &Cli,
    engine: &mut Engine,
    folder: &str,
    plan: ImportCleanupReport,
    yes: bool,
) -> Result<ImportCleanupReport> {
    if plan.eligible == 0 {
        return Ok(plan);
    }
    if !yes {
        let q = format!(
            "Remove {} ({}) from {}? They are stored safely and meet the folder's policy.",
            plural(plan.eligible, "source file", "source files"),
            fmt_bytes(plan.eligible_bytes),
            plan.source
        );
        if cli.json || !confirm(&q)? {
            eprintln!("nothing removed (pass --yes to remove without asking)");
            return Ok(plan);
        }
    }
    engine.import_cleanup(folder, true)
}

fn describe_report(r: &ImportReport) -> String {
    let mut out = Vec::new();
    let what = if r.dry_run {
        "Would import"
    } else {
        "Imported"
    };
    let unit = if r.kind == "git-annex" {
        "keys"
    } else {
        "files"
    };
    out.push(format!(
        "{what} into folder «{}»{} from {}{}",
        r.folder,
        if r.created_folder { " (new)" } else { "" },
        if r.source_name != r.source && !r.source_name.is_empty() {
            format!("«{}» ({})", r.source_name, r.source)
        } else {
            r.source.clone()
        },
        if r.tree_ref.is_empty() || r.kind != "git-annex" {
            String::new()
        } else {
            format!(", commit {}", &r.tree_ref[..r.tree_ref.len().min(12)])
        }
    ));
    if r.dry_run {
        out.push(format!(
            "  to read: {} {unit} ({})",
            r.to_read_ids,
            fmt_bytes(r.to_read_bytes)
        ));
    } else {
        let unverified = if r.unverified_ids > 0 && r.kind != "dir" {
            format!(
                ", {} without a hash to check (WORM/URL keys or no provider hash)",
                r.unverified_ids
            )
        } else {
            String::new()
        };
        if r.kind == "git-annex" {
            out.push(format!(
                "  imported: {} ({}) in {}{unverified}",
                plural(r.imported_ids, "key", "keys"),
                fmt_bytes(r.imported_bytes),
                plural(r.imported_files, "file", "files")
            ));
        } else {
            out.push(format!(
                "  imported: {} ({}){unverified}",
                plural(r.imported_files, "file", "files"),
                fmt_bytes(r.imported_bytes)
            ));
        }
        if r.to_read_ids > 0 {
            out.push(format!(
                "  not read yet: {} {unit} ({}): run the import again to carry on",
                r.to_read_ids,
                fmt_bytes(r.to_read_bytes)
            ));
        }
    }
    out.push(format!("  already imported: {} {unit}", r.already_ids));
    if r.linked_files > 0 {
        out.push(format!(
            "  {} for content already in the vault (nothing read)",
            plural(r.linked_files, "more path", "more paths")
        ));
    }
    if !r.damaged.is_empty() {
        out.push(format!(
            "  damaged here: {} (content does not match its hash; not imported from this copy):",
            r.damaged.len()
        ));
        for d in &r.damaged {
            out.push(format!("    {} [{}]: {}", show(&d.path), d.id, d.detail));
        }
    }
    if r.failed_count > 0 {
        out.push(format!("  failed: {}", r.failed_count));
        for n in &r.failed {
            out.push(format!("    {}: {}", show(&n.path), n.reason));
        }
    }
    if r.missing_ids > 0 {
        out.push(format!(
            "  missing here: {} {unit} in {} ({}), awaiting import",
            r.missing_ids,
            plural(r.missing_files, "file", "files"),
            fmt_bytes(r.missing_bytes)
        ));
        for (i, h) in r.holders.iter().take(8).enumerate() {
            out.push(format!(
                "  {} «{}» (has {} of the missing {unit}, {})",
                if i == 0 {
                    "Insert next:"
                } else {
                    "        then:"
                },
                h.name,
                h.items,
                fmt_bytes(h.bytes)
            ));
        }
        if r.unclaimed_ids > 0 {
            out.push(format!(
                "  {} missing {unit} are not claimed by any other repository",
                r.unclaimed_ids
            ));
        }
        if !r.holders.is_empty() {
            out.push("  (git-annex location logs may be out of date)".into());
        }
    }
    if r.skipped_count > 0 {
        out.push(format!("  not imported: {}", r.skipped_count));
        for n in &r.skipped {
            out.push(format!("    {}: {}", show(&n.path), n.reason));
        }
    }
    for n in &r.warnings {
        out.push(format!("  note: {}: {}", show(&n.path), n.reason));
    }
    if r.mapped_on_windows > 0 {
        out.push(format!(
            "  note: {}: characters Windows does not allow (such as : ? * or a name like CON) are kept as they are; a Windows device shows look-alike characters instead",
            plural(r.mapped_on_windows, "name", "names")
        ));
    }
    if r.kept_in_varsto_count > 0 {
        out.push(format!(
            "  kept as they are in Varsto: {}",
            r.kept_in_varsto_count
        ));
        for n in &r.kept_in_varsto {
            out.push(format!("    {}: {}", show(&n.path), n.reason));
        }
    }
    if r.gone_at_source > 0 {
        out.push(format!(
            "  gone from the source since an earlier import (kept in Varsto): {}",
            r.gone_at_source
        ));
        for p in &r.gone_examples {
            out.push(format!("    {}", show(p)));
        }
    }
    if let Some(c) = &r.cleanup {
        out.push(describe_cleanup(c));
    }
    out.join("\n")
}

fn describe_cleanup(c: &ImportCleanupReport) -> String {
    let mut out = Vec::new();
    if c.applied {
        out.push(format!(
            "Removed {} ({}) and {} from {}",
            plural(c.removed.len(), "source file", "source files"),
            fmt_bytes(c.removed_bytes),
            plural(c.dirs_removed, "empty directory", "empty directories"),
            c.source
        ));
    } else {
        out.push(format!(
            "{} ({}) in {} can be removed now",
            plural(c.eligible, "source file", "source files"),
            fmt_bytes(c.eligible_bytes),
            c.source
        ));
    }
    if c.waiting_count > 0 {
        out.push(format!(
            "{} {} for now:",
            plural(c.waiting_count, "file", "files"),
            if c.waiting_count == 1 {
                "stays"
            } else {
                "stay"
            }
        ));
        for w in c.waiting.iter().take(30) {
            out.push(format!("  {}: {}", show(&w.path), w.reason));
        }
    }
    out.join("\n")
}

fn describe_status(list: &Vec<ImportStatus>) -> String {
    if list.is_empty() {
        return "No folder was imported.".into();
    }
    let mut out = Vec::new();
    for s in list {
        let unit = if s.kind == "git-annex" {
            "keys"
        } else {
            "files"
        };
        out.push(format!("{} ({} import of {})", s.folder, s.kind, s.source));
        if s.kind == "git-annex" {
            out.push(format!(
                "  {}, {}: {} imported, {} missing ({} of {}), {} awaiting import",
                plural(s.files_total, "file", "files"),
                plural(s.ids_total, "key", "keys"),
                s.ids_imported,
                s.ids_missing,
                fmt_bytes(s.bytes_missing),
                fmt_bytes(s.bytes_total),
                plural(s.files_awaiting, "file", "files")
            ));
        } else {
            out.push(format!(
                "  {} ({}): {} imported, {} awaiting import",
                plural(s.files_total, "file", "files"),
                fmt_bytes(s.bytes_total),
                s.ids_imported,
                s.files_awaiting
            ));
        }
        if s.ids_damaged > 0 || s.damaged_copies > 0 {
            out.push(format!(
                "  damaged: {} {unit} still without a good copy, {} damaged copies seen",
                s.ids_damaged, s.damaged_copies
            ));
        }
        if s.gone_at_source > 0 {
            out.push(format!("  gone from the source: {}", s.gone_at_source));
        }
        for (_, r) in &s.runs {
            out.push(format!(
                "  «{}» {}: last import {}, {} imported ({}), {} damaged{}",
                r.name,
                r.location,
                varsto_core::util::format_date(r.last_utc),
                r.imported,
                fmt_bytes(r.imported_bytes),
                r.damaged,
                if r.complete {
                    ", everything it held is in"
                } else {
                    ""
                }
            ));
        }
        for (i, h) in s.holders.iter().take(5).enumerate() {
            out.push(format!(
                "  {} «{}» (has {} of the missing {unit}, {})",
                if i == 0 {
                    "Insert next:"
                } else {
                    "        then:"
                },
                h.name,
                h.items,
                fmt_bytes(h.bytes)
            ));
        }
        if s.removed_files > 0 {
            out.push(format!(
                "  removed from the source: {}, {}",
                plural(s.removed_files, "file", "files"),
                fmt_bytes(s.removed_bytes)
            ));
        }
    }
    out.join("\n")
}

fn describe_missing(list: &[MissingFile]) -> String {
    if list.is_empty() {
        return "Nothing is awaiting import.".into();
    }
    list.iter()
        .map(|m| {
            format!(
                "{}  {}  {}",
                show(&m.path),
                fmt_bytes(m.size),
                if m.holders.is_empty() {
                    "(no copy claims it)".to_string()
                } else {
                    format!("on: {}", m.holders.join(", "))
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn describe_verify(v: &ImportVerify) -> String {
    let mut out = vec![if v.complete {
        format!(
            "{}: complete. All {} are imported, on storages, and the policy is met; the source is no longer needed by Varsto.",
            v.folder,
            plural(v.files_total, "file", "files")
        )
    } else {
        format!(
            "{}: not complete yet ({} of {} imported and unchanged).",
            v.folder,
            v.files_ok,
            plural(v.files_total, "file", "files")
        )
    }];
    for r in &v.reasons {
        out.push(format!("  {r}"));
    }
    for (name, loc, all) in &v.copies {
        out.push(format!(
            "  «{name}» {loc}: {}",
            if *all {
                "everything it held is imported"
            } else {
                "not everything it held is imported"
            }
        ));
    }
    out.join("\n")
}
