// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto folder placement`, `varsto move` and the disk group commands:
//! where a folder's blocks are written, moving them between storages, and
//! keeping copies on disks in different places.

use crate::upkeep::ask;
use crate::{fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use varsto_core::placement::{MoveReport, MoveRequest, Placement, PlacementInfo};
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
