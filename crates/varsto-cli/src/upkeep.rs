// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto verify`, `varsto repair`, `varsto advice` and `varsto storage
//! price`: automatic verification and repair, placement suggestions and
//! storage prices on the command line.

use crate::{fmt_bytes, passphrase, print, Cli};
use anyhow::{bail, Result};
use clap::Subcommand;
use std::path::Path;
use varsto_core::autoverify::VerifySchedule;
use varsto_core::engine::{RepairOptions, RepairReport};
use varsto_core::price::StoragePrice;
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
    let mut engine = Engine::open(home, &passphrase()?)?;
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
    let mut engine = Engine::open(home, &passphrase()?)?;
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

fn ask(question: &str) -> Result<bool> {
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
    let mut engine = Engine::open(home, &passphrase()?)?;
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
