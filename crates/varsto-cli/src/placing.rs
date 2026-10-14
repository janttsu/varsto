// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto folder placement`, `varsto move` and the disk group commands:
//! where a folder's blocks are written, moving them between storages, and
//! keeping copies on disks in different places.

use crate::upkeep::ask;
use crate::{fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use std::path::Path;
use varsto_core::engine::{JobRunLimits, MoveJobRequest, MoveJobRun};
use varsto_core::placement::{MoveReport, MoveRequest, Placement, PlacementInfo};
use varsto_core::staged_move::{self, JobState, MoveJob};
use varsto_core::Engine;

fn describe_info(i: &PlacementInfo) -> String {
    let mut out = format!(
        "{}: {} (here: {})",
        i.folder,
        i.description,
        if i.targets.is_empty() {
            "no storage".to_string()
        } else {
            i.targets.join(", ")
        }
    );
    for w in &i.warnings {
        out += &format!("\n  note: {w}");
    }
    out
}

/// `varsto folder placement <folder> [--storage X]... [--place P]... [--every]`.
pub fn folder_placement(
    cli: &Cli,
    engine: &mut Engine,
    folder: &str,
    storages: &[String],
    places: &[String],
    every: bool,
) -> Result<()> {
    let info = if every {
        engine.set_placement(folder, None)?
    } else if !storages.is_empty() || !places.is_empty() {
        engine.set_placement(
            folder,
            Some(Placement {
                storages: storages.to_vec(),
                places: places.to_vec(),
                ..Default::default()
            }),
        )?
    } else {
        engine.placement(folder)?
    };
    print(cli, &info, |i| {
        let mut s = describe_info(i);
        if every || !storages.is_empty() || !places.is_empty() {
            s += "\nNew blocks go there; blocks already stored stay where they are (move them with `varsto move`).";
        }
        s
    })
}

fn describe_move(r: &MoveReport) -> String {
    let mut out = r.summary.clone();
    if !r.dry_run {
        out += &format!(
            "\n{} copied ({}), {} checked, {} removed from {} ({})",
            r.blocks_copied,
            fmt_bytes(r.bytes_copied),
            r.blocks_verified,
            r.blocks_dropped,
            r.from,
            fmt_bytes(r.bytes_dropped)
        );
        if r.leftovers_removed > 0 {
            out += &format!(
                "; {} left over from an earlier run removed",
                r.leftovers_removed
            );
        }
    }
    for (block, why) in &r.kept {
        out += &format!("\n  kept {block}: {why}");
    }
    out
}

/// Options of `varsto move`.
pub struct MoveArgs<'a> {
    pub folder: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub idle_days: Option<i64>,
    pub dry_run: bool,
    pub confirm_cold_read: bool,
    pub yes: bool,
}

/// `varsto move <folder> --from A --to B [--idle-days N] [--dry-run]`.
pub fn move_data(cli: &Cli, engine: &mut Engine, a: MoveArgs) -> Result<()> {
    let req = MoveRequest {
        folder: a.folder.to_string(),
        from: a.from.to_string(),
        to: a.to.to_string(),
        idle_days: a.idle_days,
        dry_run: true,
        confirm_cold_read: a.confirm_cold_read,
    };
    let plan = engine.move_data(&req)?;
    if a.dry_run {
        return print(cli, &plan, describe_move);
    }
    if plan.blocks == 0 && plan.already_moved == 0 {
        return print(cli, &plan, describe_move);
    }
    if !a.yes {
        eprintln!("{}", plan.summary);
        if !ask("Proceed?")? {
            bail!("cancelled");
        }
    }
    let r = engine.move_data(&MoveRequest {
        dry_run: false,
        ..req
    })?;
    print(cli, &r, describe_move)?;
    if r.blocks_kept > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `varsto move status|pause|resume|cancel`.
#[derive(clap::Subcommand, Debug)]
pub enum MoveCmd {
    /// Open and paused move jobs (all jobs with an id), with what is left and the disk each waits for.
    Status { id: Option<String> },
    /// Keep a job but do not run it.
    Pause { id: String },
    /// Open a paused job again and run it now with the disks attached.
    Resume { id: String },
    /// Stop a job for good. Nothing is deleted: what was moved stays moved.
    Cancel { id: String },
}

fn job_text(j: &MoveJob) -> String {
    let mut out = j.line();
    out += &format!(
        "\n  folder {}, from {} to {}; started {}{}",
        j.folder,
        j.from,
        j.to,
        varsto_core::util::format_date(j.started_utc),
        if j.disks_used.is_empty() {
            String::new()
        } else {
            format!("; disks used: {}", j.disks_used.join(", "))
        }
    );
    if !j.policy.is_empty() {
        out += &format!("\n  policy when it started: {}", j.policy);
    }
    if j.blocks_total > 0 {
        out += &format!("\n  blocks: {} of {} moved", j.blocks_done, j.blocks_total);
    }
    for e in &j.errors {
        out += &format!("\n  note: {e}");
    }
    out
}

/// The open jobs as lines for `varsto status` (empty when there are none).
pub fn status_lines(home: &Path) -> Vec<String> {
    staged_move::list_active(home)
        .iter()
        .map(|j| format!("move {}", j.line()))
        .collect()
}

pub fn move_cmd(cli: &Cli, home: &Path, cmd: &MoveCmd) -> Result<()> {
    match cmd {
        MoveCmd::Status { id } => {
            let jobs: Vec<MoveJob> = match id {
                Some(id) => vec![staged_move::find(home, id)?],
                None => staged_move::list_active(home),
            };
            print(cli, &jobs, |jobs| {
                if jobs.is_empty() {
                    return "no open move jobs".to_string();
                }
                jobs.iter().map(job_text).collect::<Vec<_>>().join("\n")
            })
        }
        MoveCmd::Pause { id } => {
            let j = staged_move::set_state(home, id, JobState::Paused)?;
            print(cli, &j, |j| format!("paused: {}", j.line()))
        }
        MoveCmd::Cancel { id } => {
            let j = staged_move::set_state(home, id, JobState::Cancelled)?;
            print(cli, &j, |j| {
                format!(
                    "cancelled: {}\nNothing was deleted: the {} moved so far stay on {}.",
                    j.line(),
                    varsto_core::util::human_bytes(j.bytes_done),
                    j.to
                )
            })
        }
        MoveCmd::Resume { id } => {
            staged_move::set_state(home, id, JobState::Open)?;
            let mut engine = crate::open_engine(home)?;
            let run = engine.move_job_run(id, &JobRunLimits::default())?;
            print_run(cli, &run)
        }
    }
}

fn print_run(cli: &Cli, run: &MoveJobRun) -> Result<()> {
    print(cli, run, |r| {
        let mut out = String::new();
        if !r.ran {
            return r.note.clone().unwrap_or_default();
        }
        out += &format!(
            "{} copied ({}), {} checked, {} moved ({}) in this run",
            r.report.blocks_copied,
            fmt_bytes(r.report.bytes_copied),
            r.report.blocks_verified,
            r.report.blocks_done,
            fmt_bytes(r.report.bytes_done)
        );
        if !r.report.disks_used.is_empty() {
            out += &format!(", on disk {}", r.report.disks_used.join(", "));
        }
        out += &format!("\n{}", job_text(&r.job));
        match r.job.state {
            JobState::Done => out += "\nDone.",
            JobState::Open if r.job.waiting.is_none() => {
                out += "\nThere is more to move; run `varsto move resume <id>` or let the service carry on."
            }
            _ => {}
        }
        for (block, why) in &r.report.kept {
            out += &format!("\n  kept {block}: {why}");
        }
        out
    })
}

/// `varsto move` as a job: record it (or find the open one that is the
/// same move) and run it with the disks attached now.
pub fn move_job(
    cli: &Cli,
    engine: &mut Engine,
    a: MoveArgs,
    paths: &[String],
    keep_source: bool,
) -> Result<()> {
    let req = MoveJobRequest {
        folder: a.folder.to_string(),
        paths: paths.to_vec(),
        from: a.from.to_string(),
        to: a.to.to_string(),
        idle_days: a.idle_days,
        keep_source,
        confirm_cold_read: a.confirm_cold_read,
    };
    let plan = engine.move_job_plan(&req)?;
    if a.dry_run || (plan.blocks == 0 && plan.already_moved == 0) {
        return print(cli, &plan, describe_move);
    }
    if !a.yes {
        eprintln!("{}", plan.summary);
        eprintln!("This is recorded as a move job: it moves what fits on the disks attached now, waits for the next disk and goes on when one is attached.");
        if !ask("Proceed?")? {
            bail!("cancelled");
        }
    }
    let (job, existing) = engine.move_job_start(&req)?;
    if existing && !cli.json {
        eprintln!("continuing the open move job {}", job.id);
    }
    let run = engine.move_job_run(&job.id, &JobRunLimits::default())?;
    print_run(cli, &run)?;
    if run.job.state == JobState::Done && run.job.kept_blocks > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// After a disk was added, checked or inserted: say which open move jobs
/// can continue with it. The background service does that by itself within
/// half a minute.
pub fn continue_hint(engine: &Engine) {
    for id in engine.move_jobs_ready(false) {
        eprintln!("The move job {id} can continue with the disks attached now: the background service does it shortly, or run `varsto move resume {id}`.");
    }
}

/// `varsto disk place <label> <place>`.
pub fn disk_place(cli: &Cli, engine: &mut Engine, label: &str, place: &str) -> Result<()> {
    engine.set_disk_place(label, place)?;
    let groups = engine.disk_groups()?;
    print(cli, &groups, |_| {
        if place.is_empty() {
            format!("{label} is kept at its pool's place again")
        } else {
            format!("{label} is kept at {place}; run `varsto disk check {label}` when it is attached to fill it to the pool's disk group rule")
        }
    })
}

/// `varsto disk group [<pool> --copies N]`.
pub fn disk_group(
    cli: &Cli,
    engine: &mut Engine,
    pool: Option<&str>,
    copies: Option<u32>,
) -> Result<()> {
    if let Some(n) = copies {
        let Some(pool) = pool else {
            bail!("name the pool: varsto disk group <pool> --copies {n}");
        };
        engine.set_pool_copies(pool, n)?;
    }
    let groups: Vec<_> = engine
        .disk_groups()?
        .into_iter()
        .filter(|g| pool.is_none_or(|p| g.pool == p))
        .collect();
    print(cli, &groups, |groups| {
        if groups.is_empty() {
            return "no disk pools".to_string();
        }
        groups
            .iter()
            .map(|g| {
                let mut s = format!(
                    "pool {}: {} cop{} on disks in different places; places: {}",
                    g.pool,
                    g.copies,
                    if g.copies == 1 { "y" } else { "ies" },
                    g.places
                        .iter()
                        .map(|(p, d)| format!("{p} ({})", d.join(", ")))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if g.objects_short > 0 {
                    s += &format!(
                        "\n  {} objects ({}) are short of the rule: attach a disk kept elsewhere and run `varsto disk check <label>`",
                        g.objects_short,
                        fmt_bytes(g.bytes_short)
                    );
                }
                for w in &g.warnings {
                    s += &format!("\n  note: {w}");
                }
                s
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}
