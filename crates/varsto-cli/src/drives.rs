// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Whole drives of disk pools on Linux: `varsto disk init` (partition,
//! format, mount and fill a drive), `varsto disk insert` (mount a known
//! drive and bring it up to date) and `varsto disk unmount` (sync, unmount,
//! power off). The device work is in `varsto_core::blockdev`; the drive
//! names live in `<home>/disks.conf` (`varsto_core::diskconf`).

use crate::{fmt_bytes, Cli};
use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use varsto_core::blockdev::{self, SystemRunner};
use varsto_core::diskconf::{DiskConf, Drive};
use varsto_core::engine::{DiskProgress, InsertOptions};
use varsto_core::Engine;

/// Progress lines on stderr (only on a terminal): counts, bytes, rate, ETA.
pub struct ProgressLine {
    on: bool,
    phase: &'static str,
    started: Instant,
    last: Option<Instant>,
}

impl ProgressLine {
    pub fn new(json: bool) -> ProgressLine {
        ProgressLine {
            on: !json && std::io::stderr().is_terminal(),
            phase: "",
            started: Instant::now(),
            last: None,
        }
    }

    pub fn update(&mut self, p: &DiskProgress) {
        if !self.on {
            return;
        }
        if p.phase != self.phase {
            if !self.phase.is_empty() {
                eprintln!();
            }
            self.phase = p.phase;
            self.started = Instant::now();
            self.last = None;
        }
        let done = p.objects_done >= p.objects_total;
        if !done && self.last.is_some_and(|t| t.elapsed().as_millis() < 250) {
            return;
        }
        self.last = Some(Instant::now());
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = p.bytes_done as f64 / secs;
        let eta = if rate > 0.0 && p.bytes_total > p.bytes_done {
            let left = ((p.bytes_total - p.bytes_done) as f64 / rate) as u64;
            format!(
                ", {}:{:02}:{:02} left",
                left / 3600,
                left / 60 % 60,
                left % 60
            )
        } else {
            String::new()
        };
        let what = match p.phase {
            "tidy" => "tidying (listings only)".to_string(),
            "verify" => "verifying old copies".to_string(),
            "fill" => "writing and reading back".to_string(),
            other => other.to_string(),
        };
        if p.objects_total == 0 && p.phase == "tidy" {
            eprint!("\r{what}...");
        } else {
            eprint!(
                "\r{what}: {}/{} blocks, {} of {}, {}/s{eta}   ",
                p.objects_done,
                p.objects_total,
                fmt_bytes(p.bytes_done),
                fmt_bytes(p.bytes_total),
                fmt_bytes(rate as u64)
            );
        }
        let _ = std::io::stderr().flush();
    }

    pub fn finish(&mut self) {
        if self.on && !self.phase.is_empty() {
            eprintln!();
        }
        self.phase = "";
    }
}

fn linux_only(what: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("`varsto disk {what}` works on Linux only; elsewhere format and mount the drive yourself and use `varsto disk add <mount>`");
    }
    Ok(())
}

/// While this lives, the background service (if it runs) takes no new
/// sync: pausing waits for a running one to finish, because the service
/// answers only between syncs. The previous state is put back on drop.
pub struct ServicePause {
    target: Option<(crate::service::ServiceFile, bool)>,
}

impl ServicePause {
    pub fn new(home: &Path) -> ServicePause {
        let Some((sf, summary)) = crate::service::status(home) else {
            return ServicePause { target: None };
        };
        let was = summary
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false);
        let url = format!("http://127.0.0.1:{}/api/service/pause", sf.port);
        match crate::service::http_post(&url, &sf.token, &json!({"paused": true}).to_string()) {
            Ok(_) => ServicePause {
                target: Some((sf, was)),
            },
            Err(e) => {
                eprintln!("warning: could not pause the background service ({e:#}); it may write to the drive meanwhile");
                ServicePause { target: None }
            }
        }
    }
}

impl Drop for ServicePause {
    fn drop(&mut self) {
        if let Some((sf, was)) = self.target.take() {
            if !was {
                let url = format!("http://127.0.0.1:{}/api/service/pause", sf.port);
                let _ = crate::service::http_post(
                    &url,
                    &sf.token,
                    &json!({"paused": false}).to_string(),
                );
            }
        }
    }
}

/// Remember which partition holds a drive, under its sticker name.
fn remember(home: &Path, partuuid: &str, pool: &str, label: &str) -> Result<()> {
    let mut conf = DiskConf::load(home)?;
    conf.upsert(Drive {
        partuuid: partuuid.to_string(),
        pool: pool.to_string(),
        label: label.to_string(),
    })?;
    conf.save(home)
}

/// After `disk add` of a mounted directory: on Linux, when the directory is
/// the mount point of a partition, record it in disks.conf (best effort).
pub fn remember_mount(home: &Path, mount: &Path, pool: &str, label: &str) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let mount = mount.canonicalize().unwrap_or_else(|_| mount.to_path_buf());
    let Ok(devs) = blockdev::lsblk(&mut SystemRunner) else {
        return;
    };
    if let Some((part, _)) = blockdev::partition_at(&devs, &mount) {
        if !part.partuuid.is_empty() {
            if let Err(e) = remember(home, &part.partuuid, pool, label) {
                eprintln!("note: {} not recorded in disks.conf: {e:#}", part.path);
            }
        }
    }
}

/// Ask for the device path to be typed back exactly, or take `--confirm`.
fn confirmed(device: &str, given: &Option<String>, description: &str) -> Result<()> {
    if let Some(c) = given {
        if c != device {
            bail!("--confirm {c} does not match {device}; nothing was changed");
        }
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("refusing to erase {device} without a terminal: pass --confirm {device} to say you mean it");
    }
    eprintln!("\nThis ERASES EVERYTHING on:\n{description}");
    eprint!("Type the device path ({device}) to erase it, anything else to stop: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim() != device {
        bail!("not confirmed; nothing was changed");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn init(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    device: &Path,
    pool: &str,
    label: &str,
    place: &str,
    confirm: &Option<String>,
) -> Result<()> {
    linux_only("init")?;
    engine.check_new_disk(pool, label)?;
    let device_s = device.display().to_string();
    // /dev/disk/by-id/... names resolve to the kernel's /dev/sdX.
    let real = device
        .canonicalize()
        .map_err(|e| anyhow!("{device_s}: {e}"))?
        .display()
        .to_string();
    let mut r = SystemRunner;
    let devs = blockdev::lsblk(&mut r)?;
    let facts = blockdev::SystemFacts::gather(home);
    let dev = blockdev::check_whole_device(&devs, &real, &facts)?;
    let description = blockdev::describe(dev);
    confirmed(&device_s, confirm, &description)?;
    let how = blockdev::privilege(&r)?;
    eprintln!(
        "preparing {real} as \"{label}\" of pool {pool} ({})",
        match how.first().map(String::as_str) {
            Some("sudo") => "running wipefs, sgdisk and mkfs.ext4 through sudo",
            Some("pkexec") => "sudo is missing: running wipefs, sgdisk and mkfs.ext4 through pkexec (one password prompt)",
            _ => "running as root",
        }
    );
    let task = varsto_core::activity::start(
        varsto_core::activity::DISK_INIT,
        label,
        0,
        varsto_core::activity::Unit::Items,
    );
    let prepared = blockdev::prepare_drive(&mut r, &real, label, blockdev::current_owner())?;
    drop(task);
    for s in &prepared.steps {
        eprintln!("  {s}");
    }
    remember(home, &prepared.partuuid, pool, label)?;
    let (mount, method) = blockdev::mount_partition(&mut r, &prepared.partuuid, label)?;
    eprintln!("  mounted at {} ({method:?})", mount.display());
    let mut progress = ProgressLine::new(cli.json);
    let _pause = ServicePause::new(home);
    let (report, fill) =
        engine.disk_add_with(&mount, pool, label, place, &mut |p| progress.update(p))?;
    progress.finish();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "device": prepared,
                "mount": mount,
                "mount_method": method,
                "disk": report,
                "fill": fill,
            }))?
        );
    } else {
        println!(
            "{label}: {} on {real} (partition {}, PARTUUID {}), mounted at {}; {} written and read back ({} blocks)",
            prepared.fs_label,
            prepared.partition,
            prepared.partuuid,
            mount.display(),
            fmt_bytes(fill.bytes),
            fill.objects
        );
        if let Some(w) = &report.warning {
            println!("warning: {w}");
        }
        println!("Recorded in {}. Next time plug it in and run `varsto disk insert \"{label}\"`; unplug after `varsto disk unmount \"{label}\"`.", DiskConf::path(home).display());
    }
    if let Some(why) = fill.failed {
        bail!("{why}");
    }
    Ok(())
}

/// Which known drives are plugged in: (drive, partition path, mount if any).
fn plugged_in(
    conf: &DiskConf,
    devs: &[blockdev::BlockDev],
) -> Vec<(Drive, String, Option<PathBuf>)> {
    conf.drives()
        .filter_map(|d| {
            let (p, _) = blockdev::find_partition(devs, &d.partuuid)?;
            Some((
                d.clone(),
                p.path.clone(),
                p.mountpoints
                    .iter()
                    .find(|m| !m.is_empty())
                    .map(PathBuf::from),
            ))
        })
        .collect()
}

pub fn insert(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    label: Option<&str>,
    opts: InsertOptions,
) -> Result<()> {
    linux_only("insert")?;
    let conf = DiskConf::load(home)?;
    if conf.drives().next().is_none() {
        bail!("{} lists no drives: prepare one with `varsto disk init` (or `varsto disk add` a mounted partition)", DiskConf::path(home).display());
    }
    let mut r = SystemRunner;
    let devs = blockdev::lsblk(&mut r)?;
    let mut present = plugged_in(&conf, &devs);
    if let Some(l) = label {
        if conf.by_label(l).is_none() {
            bail!(
                "{} has no drive named \"{l}\"",
                DiskConf::path(home).display()
            );
        }
        present.retain(|(d, _, _)| d.label == l);
        if present.is_empty() {
            bail!("\"{l}\" is not plugged in");
        }
    } else if present.is_empty() {
        let names: Vec<String> = conf.drives().map(|d| format!("\"{}\"", d.label)).collect();
        bail!(
            "none of the known drives is plugged in ({})",
            names.join(", ")
        );
    }
    let _pause = ServicePause::new(home);
    let mut reports = Vec::new();
    for (drive, part, _) in present {
        let (mount, method, fsck) = crate::drive_mount::mount_checked(home, cli.json, &drive)?;
        if !cli.json {
            eprintln!(
                "{}: {part} {}",
                drive.label,
                if method == blockdev::Method::None {
                    format!("is mounted at {}", mount.display())
                } else {
                    format!("mounted at {} ({method:?})", mount.display())
                }
            );
        }
        let mut progress = ProgressLine::new(cli.json);
        let rep = engine.disk_insert(&drive.label, opts, &mut |p| progress.update(p));
        progress.finish();
        let rep = rep?;
        let msg = format!(
            "{} is up to date: run `varsto disk unmount \"{}\"` before unplugging it",
            drive.label, drive.label
        );
        if !cli.json {
            println!(
                "{}: removed {} ({} queued, {} unneeded, {} leftovers); re-hashed {} copies older than {} days ({}), {} bad{}; wrote and read back {} ({} blocks, {} files whole, {} split){}",
                drive.label,
                fmt_bytes(rep.tidy.pending_bytes + rep.tidy.unneeded_bytes),
                rep.tidy.pending_removed,
                rep.tidy.unneeded_removed,
                rep.tidy.temp_removed,
                rep.verified_objects,
                rep.verify_after_days,
                fmt_bytes(rep.verified_bytes),
                rep.bad.len() + rep.tidy.bad.len(),
                if rep.missing.len() + rep.tidy.missing.len() > 0 {
                    format!(", {} missing", rep.missing.len() + rep.tidy.missing.len())
                } else {
                    String::new()
                },
                fmt_bytes(rep.fill.bytes),
                rep.fill.objects,
                rep.fill.files_whole,
                rep.fill.files_split,
                if rep.group_short > 0 {
                    format!("; {} blocks still have fewer than {} copies in different places", rep.group_short, rep.group_copies)
                } else {
                    String::new()
                }
            );
            if let Some(n) = &rep.ledger_note {
                println!("note: {n}; files on the drive that this device does not know were kept");
            }
            if let Some(f) = &rep.fill.failed {
                println!("WARNING: {f}");
            } else {
                println!("{msg}");
            }
        }
        if rep.fill.failed.is_none() {
            crate::service::notify("Varsto disk", &msg);
        }
        reports.push(json!({"drive": drive.label, "partuuid": drive.partuuid, "mount": mount, "mount_method": method, "fsck": fsck, "report": rep, "message": msg}));
    }
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }
    Ok(())
}

pub fn unmount(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    label: &str,
    power_off: bool,
) -> Result<()> {
    linux_only("unmount")?;
    let _pause = ServicePause::new(home);
    let _task = varsto_core::activity::start(
        varsto_core::activity::DISK_UNMOUNT,
        label,
        0,
        varsto_core::activity::Unit::Items,
    );
    let mount = engine.disk_eject(label)?;
    let mut steps = vec![blockdev::Step {
        step: format!("write the disk index and sync {}", mount.display()),
        ok: true,
        note: String::new(),
    }];
    steps.extend(blockdev::unmount_partition(
        &mut SystemRunner,
        &mount,
        power_off,
    )?);
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"label": label, "mount": mount, "steps": steps, "safe_to_remove": true})
            )?
        );
    } else {
        for s in &steps {
            println!(
                "  {} {}{}",
                if s.ok { "ok  " } else { "note" },
                s.step,
                if s.note.is_empty() {
                    String::new()
                } else {
                    format!(": {}", s.note)
                }
            );
        }
        println!("{label} is unmounted: you can unplug it now");
    }
    Ok(())
}

/// For `varsto disk list`: the drives of disks.conf, plugged in or not.
/// A drive of disks.conf and, when plugged in, its partition and mount.
pub type KnownDrive = (Drive, Option<(String, Option<PathBuf>)>);

pub fn known_drives(home: &Path) -> Vec<KnownDrive> {
    let Ok(conf) = DiskConf::load(home) else {
        return Vec::new();
    };
    let devs = if cfg!(target_os = "linux") {
        blockdev::lsblk(&mut SystemRunner).unwrap_or_default()
    } else {
        Vec::new()
    };
    conf.drives()
        .map(|d| {
            let at = blockdev::find_partition(&devs, &d.partuuid).map(|(p, _)| {
                (
                    p.path.clone(),
                    p.mountpoints
                        .iter()
                        .find(|m| !m.is_empty())
                        .map(PathBuf::from),
                )
            });
            (d.clone(), at)
        })
        .collect()
}

// ----- fetching from pool disks ------------------------------------------------------------

fn duration(secs: f64) -> String {
    let s = secs.round() as u64;
    if s >= 3600 {
        format!("{} h {} min", s / 3600, s / 60 % 60)
    } else if s >= 60 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{s} s")
    }
}

fn money(cost: Option<f64>, currency: &str) -> String {
    match cost {
        Some(c) => format!(
            "{c:.2} {}",
            if currency.is_empty() {
                "(currency unknown)"
            } else {
                currency
            }
        ),
        None => "price unknown".into(),
    }
}

/// The plan as text.
pub fn plan_text(plan: &varsto_core::engine::FetchPlan) -> String {
    let mut out = format!(
        "{} file{}, {}: fetch from {} ({})\n",
        plan.files.len(),
        if plan.files.len() == 1 { "" } else { "s" },
        fmt_bytes(plan.total_bytes),
        if plan.recommend == "disks" {
            "disks"
        } else {
            "the network"
        },
        plan.reason
    );
    for (i, s) in plan.steps.iter().enumerate() {
        out.push_str(&format!(
            "  {}. \"{}\" ({}): {}{}{}\n",
            i + 1,
            s.label,
            s.place,
            fmt_bytes(s.bytes),
            if s.attached { ", attached now" } else { "" },
            if s.state != "pending" {
                format!(", {}", s.state)
            } else {
                String::new()
            }
        ));
    }
    if !plan.steps.is_empty() {
        out.push_str(&format!(
            "  with the disks: about {}{}\n",
            duration(plan.disks_secs),
            if plan.remote_part_bytes > 0 {
                format!(
                    ", plus {} from the network ({})",
                    fmt_bytes(plan.remote_part_bytes),
                    money(plan.remote_part_cost, &plan.remote.currency)
                )
            } else {
                String::new()
            }
        ));
    }
    let r = &plan.remote;
    if r.possible {
        out.push_str(&format!(
            "  from the network instead: {} from {}, {}, about {}{}\n",
            fmt_bytes(r.bytes),
            r.storages.join(", "),
            money(r.cost, &r.currency),
            duration(r.secs),
            if r.cold {
                " (cold storage: retrieval fees and delays)"
            } else {
                ""
            }
        ));
    } else {
        out.push_str("  the network does not have every block: the disks are needed\n");
    }
    out
}

/// Runs a plan on the terminal: asks for each disk, mounts, unmounts.
struct CliDriver<'a> {
    home: &'a Path,
    json: bool,
}

impl varsto_core::engine::PlanDriver for CliDriver<'_> {
    fn ask(
        &mut self,
        plan: &varsto_core::engine::FetchPlan,
        k: usize,
    ) -> Result<varsto_core::engine::InsertAnswer> {
        use varsto_core::engine::InsertAnswer;
        let s = &plan.steps[k];
        eprint!(
            "Insert disk \"{}\" ({}) into the dock and press Enter (s = skip, use the network; q = stop): ",
            s.label, s.place
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok(InsertAnswer::Stop);
        }
        Ok(match line.trim() {
            "s" | "S" => InsertAnswer::Skip,
            "q" | "Q" => InsertAnswer::Stop,
            _ => InsertAnswer::Inserted,
        })
    }
    fn attach(&mut self, step: &varsto_core::engine::DiskStep) -> Result<bool> {
        match crate::drive_mount::mount_known(self.home, &step.label) {
            Ok(found) => Ok(found),
            // A file system that failed its check stops the whole run.
            Err(e) if e.downcast_ref::<blockdev::FsckStopped>().is_some() => Err(e),
            Err(e) => {
                eprintln!("{}: {e:#}", step.label);
                Ok(false)
            }
        }
    }
    fn release(&mut self, step: &varsto_core::engine::DiskStep, mount: &Path) -> Result<()> {
        for s in crate::drive_mount::release_mount(mount)? {
            if !self.json {
                eprintln!(
                    "  {}: {}{}",
                    step.label,
                    s.step,
                    if s.note.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", s.note)
                    }
                );
            }
        }
        Ok(())
    }
    fn say(&mut self, message: &str) {
        if !self.json {
            println!("{message}");
        }
    }
}

/// How `varsto folder fetch` uses pool disks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum FromDisks {
    /// Propose the disks when the plan recommends them and ask.
    Ask,
    /// Use the disks whenever they hold blocks, without asking first.
    Always,
    /// Never: the network only (as before).
    Never,
}

/// Fetch files, from pool disks when the plan says so (and the user agrees).
/// Returns false when the fetch did not complete.
pub fn fetch_with_plan(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    folder: &str,
    paths: &[String],
    mode: FromDisks,
) -> Result<bool> {
    let mut plan = engine.fetch_plan(folder, paths)?;
    let use_disks = match mode {
        FromDisks::Never => false,
        FromDisks::Always => !plan.steps.is_empty(),
        FromDisks::Ask => {
            plan.recommend == "disks"
                && {
                    if !cli.json {
                        print!("{}", plan_text(&plan));
                    }
                    if !std::io::stdin().is_terminal() {
                        if !plan.remote.possible {
                            bail!("these blocks are on pool disks only: run on a terminal, or with --from-disks always");
                        }
                        false
                    } else {
                        crate::confirm(if plan.remote.possible {
                            "Fetch from the disks (no = from the network)?"
                        } else {
                            "Fetch from the disks?"
                        })?
                    }
                }
        }
    };
    if !use_disks {
        engine.cancel_fetch_plan()?;
        return Ok(false);
    }
    if mode == FromDisks::Always && !cli.json {
        print!("{}", plan_text(&plan));
    }
    let _pause = ServicePause::new(home);
    let mut driver = CliDriver {
        home,
        json: cli.json,
    };
    let r = engine.run_fetch_plan(&mut plan, &mut driver)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"plan": plan, "report": r}))?
        );
    } else {
        for (p, why) in &r.files_failed {
            println!("{p}: not fetched: {why}");
        }
        if r.stopped {
            println!("stopped; the plan is kept: run the same fetch again to go on");
        } else if r.files_failed.is_empty() {
            println!(
                "fetched {} file{}",
                r.files_done.len(),
                if r.files_done.len() == 1 { "" } else { "s" }
            );
        }
    }
    Ok(!r.stopped && r.files_failed.is_empty())
}
