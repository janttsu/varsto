// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto verify`, `varsto repair`, `varsto scrub`, `varsto advice` and
//! `varsto storage price|quota|drain`: automatic verification and repair,
//! bit-rot checks, placement suggestions, storage prices, quotas and
//! draining on the command line.

use crate::{fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use clap::Subcommand;
use std::path::Path;
use varsto_core::autoverify::VerifySchedule;
use varsto_core::engine::{
    DrainOptions, DrainRunLimits, DrainStatus, QuotaStatus, RepairOptions, RepairReport,
    ScrubOptions,
};
use varsto_core::price::StoragePrice;
use varsto_core::scrub::{ScrubReport, ScrubStatus};
use varsto_core::Engine;

#[derive(Subcommand)]
pub enum VerifyCmd {
    /// Show the schedule, the last run and the next one (the default).
    Show,
    /// Verify now, within the budget, whatever the schedule says.
    Run,
    /// Change the schedule or the budget (only the options given change).
    Set {
        /// Turn automatic verification on.
        #[arg(long, conflicts_with = "off")]
        on: bool,
        /// Turn automatic verification off.
        #[arg(long)]
        off: bool,
        /// Hours between runs.
        #[arg(long)]
        interval_hours: Option<u32>,
        /// Most MiB downloaded per run.
        #[arg(long)]
        max_mib: Option<u64>,
        /// Most blocks checked per run.
        #[arg(long)]
        max_blocks: Option<u64>,
        /// Days after which copies in folders without a verification window are checked again.
        #[arg(long)]
        reverify_days: Option<u32>,
    },
}

/// `varsto scrub` without a subcommand: one run now.
#[derive(clap::Args)]
pub struct ScrubRunArgs {
    /// Only this storage (repeat for more).
    #[arg(long = "storage", value_name = "NAME")]
    pub storages: Vec<String>,
    /// The synced files on this device and its block cache (only those,
    /// unless storages are named too).
    #[arg(long)]
    pub local: bool,
    /// Everything selected, from the start, whatever the schedule and the budgets.
    #[arg(long)]
    pub full: bool,
    /// Also read cold storages in this run (retrieval fees may apply; needs --confirm-cold-read).
    #[arg(long, requires = "confirm_cold_read")]
    pub include_cold: bool,
    /// Confirm that reading cold storage may start retrievals your provider bills.
    #[arg(long)]
    pub confirm_cold_read: bool,
    /// Leave damaged copies in the repair queue for the service instead of repairing them now.
    #[arg(long)]
    pub no_repair: bool,
}

#[derive(Subcommand)]
pub enum ScrubCmd {
    /// Show the schedule, the last run, every target's pass and damaged files waiting.
    Status,
    /// Change the schedule or the budgets (only the options given change).
    Set {
        /// Turn the scheduled bit-rot check on.
        #[arg(long, conflicts_with = "off")]
        on: bool,
        /// Turn the scheduled bit-rot check off.
        #[arg(long)]
        off: bool,
        /// Hours between runs.
        #[arg(long)]
        interval_hours: Option<u32>,
        /// Every copy and file is re-hashed at least once in this many days.
        #[arg(long)]
        days: Option<u32>,
        /// Most MiB read per run from this device's disks (files, block cache, directories, pool disks).
        #[arg(long)]
        local_mib: Option<u64>,
        /// Most MiB downloaded per run from S3 and rclone storages.
        #[arg(long)]
        remote_mib: Option<u64>,
        /// Include this cold storage in scheduled runs (needs --confirm-cold-read).
        #[arg(long, value_name = "NAME", requires = "confirm_cold_read")]
        cold: Vec<String>,
        /// Leave this cold storage out of scheduled runs again.
        #[arg(long, value_name = "NAME")]
        no_cold: Vec<String>,
        /// Confirm that reading cold storage may start retrievals your provider bills.
        #[arg(long)]
        confirm_cold_read: bool,
    },
}

#[derive(Subcommand)]
pub enum AdviceCmd {
    /// Show idle files, storage prices, monthly costs and suggestions (the default).
    Show,
    /// Carry out a suggestion, e.g. `varsto advice apply free-idle:photos`.
    Apply {
        /// Suggestion id from `varsto advice`, or a folder name.
        id: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Options of `varsto storage price`.
pub struct PriceArgs<'a> {
    pub name: &'a str,
    pub gb_month: Option<f64>,
    pub egress: Option<f64>,
    pub retrieval: Option<f64>,
    pub min_days: Option<u32>,
    pub currency: Option<&'a str>,
    pub clear: bool,
}

pub fn verify(cli: &Cli, home: &Path, cmd: &Option<VerifyCmd>) -> Result<()> {
    let mut engine = crate::open_engine(home)?;
    match cmd.as_ref().unwrap_or(&VerifyCmd::Show) {
        VerifyCmd::Show => {
            let st = engine.verify_status();
            print(cli, &st, |s| s.describe())?;
        }
        VerifyCmd::Run => {
            let r = engine.auto_verify()?;
            print(cli, &r, |r| {
                format!(
                    "{} blocks verified of {} due ({} checked, {} downloaded), {} left for the next run{}{}{}",
                    r.blocks_verified,
                    r.due,
                    r.blocks_checked,
                    fmt_bytes(r.bytes_downloaded),
                    r.left_for_next_run,
                    if r.storages_skipped.is_empty() {
                        String::new()
                    } else {
                        format!("; not read: {}", r.storages_skipped.join(", "))
                    },
                    if r.corrupt.is_empty() {
                        String::new()
                    } else {
                        format!("; CORRUPT: {}", r.corrupt.join(", "))
                    },
                    if r.missing.is_empty() {
                        String::new()
                    } else {
                        format!("; MISSING: {}", r.missing.join(", "))
                    }
                )
            })?;
            if !r.corrupt.is_empty() || !r.missing.is_empty() {
                std::process::exit(1);
            }
        }
        VerifyCmd::Set {
            on,
            off,
            interval_hours,
            max_mib,
            max_blocks,
            reverify_days,
        } => {
            let mut s: VerifySchedule = engine.verify_schedule().clone();
            if *on {
                s.enabled = true;
            }
            if *off {
                s.enabled = false;
            }
            if let Some(h) = interval_hours {
                s.interval_hours = *h;
            }
            if let Some(m) = max_mib {
                s.max_bytes = m.saturating_mul(1024 * 1024);
            }
            if let Some(b) = max_blocks {
                s.max_blocks = *b;
            }
            if let Some(d) = reverify_days {
                s.reverify_days = *d;
            }
            engine.set_verify_schedule(s)?;
            let st = engine.verify_status();
            print(cli, &st, |s| s.describe())?;
        }
    }
    Ok(())
}

/// What `varsto scrub` did, with the repair of what it found.
#[derive(serde::Serialize)]
struct ScrubRun {
    scrub: ScrubReport,
    repair: Option<RepairReport>,
}

/// "120 objects and 40 files checked (1.2 GiB), 1 problem: ...".
pub fn describe_scrub(r: &ScrubReport) -> String {
    let mut out = format!(
        "{} objects, {} files and {} cached blocks checked ({} from storages, {} of files), {} problem{}",
        r.objects_checked,
        r.files_checked,
        r.cache_checked,
        fmt_bytes(r.object_bytes),
        fmt_bytes(r.file_bytes),
        r.problems(),
        if r.problems() == 1 { "" } else { "s" }
    );
    if r.queued_for_repair > 0 {
        out += &format!(
            ", {} cop{} queued for repair",
            r.queued_for_repair,
            if r.queued_for_repair == 1 { "y" } else { "ies" }
        );
    }
    for t in &r.targets {
        out += &format!(
            "\n  {}: {} checked, {} left in this pass{}{}",
            t.label,
            t.checked,
            t.left_in_pass,
            if t.pass_done { ", pass complete" } else { "" },
            if t.behind {
                ", BEHIND: raise the budget or the period"
            } else {
                ""
            }
        );
    }
    for c in &r.corrupt {
        out += &format!("\n  CORRUPT {c}");
    }
    for m in &r.missing {
        out += &format!("\n  MISSING {m}");
    }
    for d in &r.damaged_files {
        out += &match (&d.moved_to, d.restored) {
            (Some(to), true) => format!(
                "\n  DAMAGED FILE {} ({}): moved to {to}, the recorded version restored",
                d.path, d.folder
            ),
            _ => format!(
                "\n  DAMAGED FILE {} ({}): left in place, not restored: {}",
                d.path,
                d.folder,
                d.reason.clone().unwrap_or_default()
            ),
        };
    }
    if r.offline > 0 {
        out += &format!(
            "\n  {} copies on pool disks that are not attached",
            r.offline
        );
    }
    for d in &r.disks_away {
        out += &format!("\n  disk away for long: {d}");
    }
    for s in &r.skipped {
        out += &format!("\n  not read: {s}");
    }
    out
}

fn describe_scrub_status(s: &ScrubStatus) -> String {
    let mut out = s.describe();
    for (key, t) in &s.targets {
        let _ = key;
        out += &format!(
            "\n  {}: pass started {}, {} checked in it, last complete pass {}",
            t.label,
            if t.pass_started_utc > 0 {
                varsto_core::util::format_date(t.pass_started_utc)
            } else {
                "-".to_string()
            },
            t.checked_in_pass,
            t.last_pass_done_utc
                .map(varsto_core::util::format_date)
                .unwrap_or_else(|| "never".to_string())
        );
    }
    for d in &s.unrestored {
        out += &format!(
            "\n  DAMAGED FILE {} ({}): waiting for a good copy: {}",
            d.path,
            d.folder,
            d.reason.clone().unwrap_or_default()
        );
    }
    out
}

pub fn scrub(cli: &Cli, home: &Path, cmd: &Option<ScrubCmd>, run: &ScrubRunArgs) -> Result<()> {
    let mut engine = crate::open_engine(home)?;
    match cmd {
        Some(ScrubCmd::Status) => {
            print(cli, &engine.scrub_status(), describe_scrub_status)?;
        }
        Some(ScrubCmd::Set {
            on,
            off,
            interval_hours,
            days,
            local_mib,
            remote_mib,
            cold,
            no_cold,
            confirm_cold_read,
        }) => {
            let mut s = engine.scrub_schedule().clone();
            if *on {
                s.enabled = true;
            }
            if *off {
                s.enabled = false;
            }
            if let Some(h) = interval_hours {
                s.interval_hours = *h;
            }
            if let Some(d) = days {
                s.scrub_days = *d;
            }
            if let Some(m) = local_mib {
                s.max_local_bytes = m.saturating_mul(1024 * 1024);
            }
            if let Some(m) = remote_mib {
                s.max_remote_bytes = m.saturating_mul(1024 * 1024);
            }
            engine.set_scrub_schedule(s)?;
            for n in cold {
                engine.set_scrub_cold(n, true, *confirm_cold_read)?;
            }
            for n in no_cold {
                engine.set_scrub_cold(n, false, false)?;
            }
            print(cli, &engine.scrub_status(), describe_scrub_status)?;
        }
        None => {
            let opts = ScrubOptions {
                storages: run.storages.clone(),
                local: run.local,
                full: run.full,
                include_cold: run.include_cold && run.confirm_cold_read,
                scheduled: false,
            };
            let r = engine.scrub(&opts)?;
            let repair = if !run.no_repair && r.queued_for_repair > 0 {
                let mut o = RepairOptions::manual();
                o.scan = false;
                Some(engine.repair(&o)?)
            } else {
                None
            };
            let out = ScrubRun { scrub: r, repair };
            print(cli, &out, |o| {
                let mut s = describe_scrub(&o.scrub);
                if let Some(rep) = &o.repair {
                    s += "\n";
                    s += &describe_repair(rep);
                }
                s
            })?;
            let copies_left = out.scrub.queued_for_repair > 0
                && out
                    .repair
                    .as_ref()
                    .is_none_or(|rep| !rep.unrepairable.is_empty() || rep.left_for_next_run > 0);
            let files_left = out.scrub.damaged_files.iter().any(|d| !d.restored);
            if copies_left || files_left {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Options of `varsto repair`.
pub struct RepairArgs {
    pub dry_run: bool,
    pub from_cold: bool,
    pub scan: bool,
    pub max_mib: Option<u64>,
    pub max_blocks: Option<u64>,
}

/// "2 copies repaired (from storage box), 1 could not be repaired: why".
pub fn describe_repair(r: &RepairReport) -> String {
    let mut out = if r.dry_run {
        format!(
            "dry run: {} of {} damaged cop{} would be repaired",
            r.repaired.len(),
            r.found,
            if r.found == 1 { "y" } else { "ies" }
        )
    } else {
        format!(
            "{} of {} damaged cop{} repaired ({} written)",
            r.repaired.len(),
            r.found,
            if r.found == 1 { "y" } else { "ies" },
            fmt_bytes(r.bytes_written)
        )
    };
    if r.already_intact > 0 {
        out += &format!(", {} already intact", r.already_intact);
    }
    if r.not_needed > 0 {
        out += &format!(", {} no longer needed", r.not_needed);
    }
    if r.left_for_next_run > 0 {
        out += &format!(", {} left for later", r.left_for_next_run);
    }
    for c in &r.repaired {
        out += &format!(
            "\n  {} {} on {} ({}): from {}",
            if r.dry_run {
                "would rewrite"
            } else {
                "rewrote"
            },
            c.object,
            c.storage,
            c.folder,
            c.source
        );
    }
    for u in &r.unrepairable {
        out += &format!(
            "\n  NOT REPAIRED {} on {} ({}): {}",
            u.object, u.storage, u.folder, u.reason
        );
    }
    if !r.unreachable.is_empty() {
        out += &format!("\n  not reachable: {}", r.unreachable.join(", "));
    }
    out
}

pub fn repair(cli: &Cli, home: &Path, args: RepairArgs) -> Result<()> {
    let mut engine = crate::open_engine(home)?;
    let mut opts = RepairOptions::manual();
    opts.dry_run = args.dry_run;
    opts.from_cold = args.from_cold;
    opts.scan = args.scan;
    if let Some(m) = args.max_mib {
        opts.max_bytes = m.saturating_mul(1024 * 1024).max(1);
    }
    if let Some(b) = args.max_blocks {
        opts.max_blocks = b.max(1);
    }
    let r = engine.repair(&opts)?;
    print(cli, &r, describe_repair)?;
    if !r.unrepairable.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

pub(crate) fn ask(question: &str) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        bail!("confirmation needed: run from a terminal or pass --yes");
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

pub fn advice(cli: &Cli, home: &Path, idle_days: i64, cmd: &Option<AdviceCmd>) -> Result<()> {
    let mut engine = crate::open_engine(home)?;
    let now = varsto_core::util::now_utc();
    match cmd.as_ref().unwrap_or(&AdviceCmd::Show) {
        AdviceCmd::Show => {
            let a = engine.placement_advice(idle_days, now)?;
            print(cli, &a, |a| {
                let mut out = format!(
                    "{} files ({}) not used in {} days.\n",
                    a.idle_files.len(),
                    fmt_bytes(a.idle_bytes),
                    a.idle_days_threshold
                );
                if let Some(best) = a.estimates.first() {
                    out += &format!(
                        "Cheapest known class for them: {} {} at about {:.2} {} a month (source verified {}).\n",
                        best.provider, best.class, best.monthly_cost, best.currency, best.last_verified
                    );
                }
                for s in &a.storages {
                    out += &format!(
                        "storage {}: {} stored, {}{}\n",
                        s.name,
                        fmt_bytes(s.bytes),
                        s.price
                            .as_ref()
                            .map(|p| p.describe())
                            .unwrap_or_else(|| "no price set".to_string()),
                        s.monthly_cost
                            .map(|c| format!(", about {c:.2} {} a month", s.currency))
                            .unwrap_or_default()
                    );
                }
                for f in &a.folders {
                    out += &format!(
                        "folder {}: {} ({} idle){}{}\n",
                        f.folder,
                        fmt_bytes(f.bytes),
                        fmt_bytes(f.idle_bytes),
                        if f.monthly.is_empty() {
                            String::new()
                        } else {
                            format!(
                                ", about {} a month",
                                f.monthly
                                    .iter()
                                    .map(|(c, v)| format!("{v:.2} {c}"))
                                    .collect::<Vec<_>>()
                                    .join(" + ")
                            )
                        },
                        if f.unpriced_storages.is_empty() {
                            String::new()
                        } else {
                            format!(" (no price for {})", f.unpriced_storages.join(", "))
                        }
                    );
                }
                for s in &a.suggestions {
                    out += &format!("\nsuggestion {}: {}\n", s.id, s.summary);
                    for w in &s.warnings {
                        out += &format!("  note: {w}\n");
                    }
                    out += &format!("  apply with: varsto advice apply {}\n", s.id);
                }
                out.trim_end().to_string()
            })?;
        }
        AdviceCmd::Apply { id, yes } => {
            let a = engine.placement_advice(idle_days, now)?;
            let folder = id
                .strip_prefix(varsto_core::advice::FREE_IDLE_PREFIX)
                .unwrap_or(id);
            let Some(s) = a
                .suggestions
                .iter()
                .find(|s| s.id == *id || s.folder == folder)
            else {
                bail!("no suggestion {id} right now; see `varsto advice`");
            };
            if !yes {
                eprintln!("{}", s.summary);
                if !ask("Proceed?")? {
                    bail!("cancelled");
                }
            }
            let r = engine.apply_suggestion(&s.id, idle_days)?;
            print(cli, &r, |r| {
                if let Some(m) = &r.moved {
                    let mut out = m.summary.clone();
                    for (block, why) in &m.kept {
                        out += &format!("\n  kept {block}: {why}");
                    }
                    return out;
                }
                let mut out = format!(
                    "{}: {} files freed ({}) on this device{}",
                    r.folder,
                    r.files_freed,
                    fmt_bytes(r.bytes_freed),
                    if r.blocks_verified > 0 {
                        format!(", {} blocks verified first", r.blocks_verified)
                    } else {
                        String::new()
                    }
                );
                for (p, why) in &r.skipped {
                    out += &format!("\n  kept {p}: {why}");
                }
                out
            })?;
        }
    }
    Ok(())
}

pub fn price(cli: &Cli, engine: &mut Engine, a: PriceArgs) -> Result<()> {
    if a.clear {
        engine.set_storage_price(a.name, None)?;
    } else if a.gb_month.is_some()
        || a.egress.is_some()
        || a.retrieval.is_some()
        || a.min_days.is_some()
        || a.currency.is_some()
    {
        // Figures not given keep what the user set before.
        let before = engine.storage_prices_set_by_user(a.name);
        engine.set_storage_price(
            a.name,
            Some(StoragePrice {
                storage_per_gb_month: a.gb_month.or(before.storage_per_gb_month),
                egress_per_gb: a.egress.or(before.egress_per_gb),
                retrieval_per_gb: a.retrieval.or(before.retrieval_per_gb),
                minimum_storage_days: a.min_days.or(before.minimum_storage_days),
                currency: a.currency.map(str::to_string).unwrap_or(before.currency),
                source: String::new(),
            }),
        )?;
    }
    let p = engine.storage_price(a.name);
    print(cli, &p, |p| {
        match p {
        Some(p) => format!("{}: {} ({})", a.name, p.describe(), p.source),
        None => format!(
            "{}: no price set; set one with --gb-month (and --egress, --retrieval, --min-days, --currency)",
            a.name
        ),
    }
    })
}

pub struct DrainArgs<'a> {
    pub name: &'a str,
    pub stop: bool,
    pub plan: bool,
    pub remove_when_empty: bool,
    pub budget_gb_per_day: Option<f64>,
    pub confirm_cold_read: bool,
    pub background: bool,
}

fn drain_status_lines(list: &[DrainStatus]) -> String {
    if list.is_empty() {
        return "no storage is being drained".to_string();
    }
    list.iter()
        .map(|d| {
            let mut line = d.summary.clone();
            if let Some(eta) = d.eta_utc {
                line += &format!("; finishes about {}", crate::backup::fmt_utc(eta));
            }
            if let Some(b) = d.budget_bytes_per_day {
                line += &format!(
                    "; budget {} a day ({} used today)",
                    fmt_bytes(b),
                    fmt_bytes(d.bytes_today)
                );
            }
            if d.remove_when_empty {
                line += "; removed when empty";
            }
            if let Some(e) = &d.last_error {
                line += &format!("; last run failed: {e}");
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `varsto storage drain`: plan, start (and run now), stop, or show progress.
pub fn drain(cli: &Cli, engine: &mut Engine, a: DrainArgs) -> Result<()> {
    if a.name == "status" && !engine.storages().iter().any(|s| s.name() == "status") {
        let list = engine.drain_statuses()?;
        return print(cli, &list, |l| drain_status_lines(l));
    }
    if a.stop {
        engine.drain_stop(a.name)?;
        return print(
            cli,
            &serde_json::json!({"storage": a.name, "stopped": true}),
            |_| {
                format!("{}: draining stopped; it takes new blocks again (blocks already moved stay where they are)", a.name)
            },
        );
    }
    if a.budget_gb_per_day
        .is_some_and(|g| !g.is_finite() || g <= 0.0)
    {
        bail!("the daily budget must be more than zero GB");
    }
    // Options not given keep what an ongoing drain has.
    let current = engine.storage_settings(a.name).drain;
    let opts = DrainOptions {
        remove_when_empty: a.remove_when_empty
            || current.as_ref().is_some_and(|d| d.remove_when_empty),
        budget_bytes_per_day: a
            .budget_gb_per_day
            .map(|g| (g * 1e9) as u64)
            .or(current.as_ref().and_then(|d| d.budget_bytes_per_day)),
        confirm_cold_read: a.confirm_cold_read
            || current.as_ref().is_some_and(|d| d.confirm_cold_read),
    };
    if a.plan {
        let p = engine.drain_plan(a.name, &opts)?;
        return print(cli, &p, |p| {
            let mut out = p.summary.clone();
            for n in &p.notes {
                out += &format!("\nnote: {n}");
            }
            out
        });
    }
    let plan = engine.drain_start(a.name, &opts)?;
    if !cli.json {
        println!("{}", plan.summary);
        for n in &plan.notes {
            println!("note: {n}");
        }
    }
    let run = if a.background {
        None
    } else {
        Some(engine.drain_run(a.name, &DrainRunLimits::default())?)
    };
    let status = engine.drain_statuses()?;
    let mine: Vec<&DrainStatus> = status.iter().filter(|d| d.storage == a.name).collect();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "plan": plan,
                "run": run,
                "status": mine,
            }))?
        );
        return Ok(());
    }
    match &run {
        Some(r) => println!("{}", r.summary),
        None => println!(
            "{}: the background service drains it after its next sync (varsto storage drain status)",
            a.name
        ),
    }
    if let Some(r) = &run {
        if !r.removed && !r.drained {
            println!(
                "{}",
                drain_status_lines(&mine.into_iter().cloned().collect::<Vec<_>>())
            );
        }
    }
    Ok(())
}

/// `varsto storage quota`: show, set or clear a storage's quota.
pub fn quota(
    cli: &Cli,
    engine: &mut Engine,
    name: &str,
    bytes: Option<&str>,
    objects: Option<u64>,
    clear: bool,
    measure: bool,
) -> Result<()> {
    let mut status = if clear {
        engine.set_storage_quota(name, Some(None), Some(None))?
    } else if bytes.is_some() || objects.is_some() {
        let b = bytes
            .map(varsto_core::storage_settings::parse_size)
            .transpose()?;
        engine.set_storage_quota(name, b.map(Some), objects.map(Some))?
    } else {
        engine.quota_status(name)?
    };
    if measure {
        status = engine.measure_storage(name)?;
    }
    print(cli, &status, quota_line)
}

fn quota_line(q: &QuotaStatus) -> String {
    let used = format!(
        "{} in {} objects{}",
        fmt_bytes(q.used_bytes),
        q.used_objects,
        match q.measured_utc {
            Some(t) => format!(", records measured {}", crate::backup::fmt_utc(t)),
            None => ", records estimated".to_string(),
        }
    );
    let mut out = match (q.quota_bytes, q.quota_objects) {
        (None, None) => format!("{}: no quota; {used}", q.storage),
        (b, o) => format!(
            "{}: quota {}{}; {used} ({} %)",
            q.storage,
            b.map(fmt_bytes).unwrap_or_default(),
            o.map(|o| format!("{}{o} objects", if b.is_some() { ", " } else { "" }))
                .unwrap_or_default(),
            q.percent.unwrap_or(0)
        ),
    };
    if let Some(m) = &q.message {
        out += &format!("\n{m}");
    }
    out
}
