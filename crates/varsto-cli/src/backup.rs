// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto backup`: read-only snapshots of a directory of this device, kept
//! on the storages only (never on the vault's other devices), with a
//! retention in days; restored only into a directory named here.

use crate::{confirm, fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use varsto_core::engine::{BackupOptions, SnapshotPick};
use varsto_core::placement::Placement;
use varsto_core::vault::{BackupSchedule, DEFAULT_BACKUP_RETENTION_DAYS};
use varsto_core::Engine;

#[derive(Subcommand)]
pub enum BackupCmd {
    /// Back up a directory of this device to the storages (never to other
    /// devices or transferrers). The directory is only ever read.
    Add {
        name: String,
        dir: PathBuf,
        /// Keep each snapshot this many days; expired ones are deleted from the storages.
        #[arg(long, default_value_t = DEFAULT_BACKUP_RETENTION_DAYS)]
        retention_days: u32,
        /// Take a snapshot when this many hours have passed (default 24: daily).
        #[arg(long, conflicts_with = "manual")]
        every_hours: Option<u32>,
        /// Take snapshots only when asked (`varsto backup take`).
        #[arg(long)]
        manual: bool,
        /// Keep it on this storage only (repeatable; default: every storage).
        #[arg(long)]
        storage: Vec<String>,
        /// Keep it on the storages at this place (repeatable).
        #[arg(long)]
        place: Vec<String>,
        /// Do not take the first snapshot now.
        #[arg(long)]
        no_initial: bool,
    },
    /// List the vault's backups.
    List,
    /// List the snapshots of a backup that can be restored.
    Snapshots { backup: String },
    /// Take a snapshot now.
    Take { backup: String },
    /// Restore a snapshot into a directory: SNAPSHOT is a number, "latest"
    /// (the default) or a day YYYY-MM-DD (the newest snapshot by its end, UTC).
    Restore {
        backup: String,
        snapshot: Option<String>,
        /// Directory to restore into; it must be empty unless --overwrite.
        #[arg(long)]
        to: PathBuf,
        /// Only this file or directory of the snapshot (repeatable).
        #[arg(long)]
        path: Vec<String>,
        /// Write into a directory that is not empty, replacing files of the same name.
        #[arg(long)]
        overwrite: bool,
        /// Also read cold storages (retrieval fees may apply).
        #[arg(long)]
        confirm_cold_read: bool,
    },
    /// Change the retention or the schedule; the retention applies to
    /// snapshots taken from now on.
    Set {
        backup: String,
        #[arg(long)]
        retention_days: Option<u32>,
        #[arg(long, conflicts_with = "manual")]
        every_hours: Option<u32>,
        #[arg(long)]
        manual: bool,
    },
    /// Take no more snapshots. Those kept expire as they would, and the
    /// backup goes with the last of them.
    Stop {
        backup: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Expire the snapshots past their retention now and delete from the
    /// storages what only they used (the background service does this too).
    Expire,
}

/// Seconds since the epoch as "2026-10-12 14:03 UTC".
pub fn fmt_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn schedule(every_hours: Option<u32>, manual: bool) -> Option<BackupSchedule> {
    match (every_hours, manual) {
        (_, true) => Some(BackupSchedule::Manual),
        (Some(h), false) => Some(BackupSchedule::EveryHours(h)),
        (None, false) => None,
    }
}

fn describe_list(v: &Value) -> String {
    let Some(list) = v.as_array().filter(|l| !l.is_empty()) else {
        return "no backups (add one with `varsto backup add <name> <dir>`)".to_string();
    };
    list.iter()
        .map(|b| {
            let mut s = format!(
                "{}  from {} on {}  {} snapshot{}, kept {} days{}",
                b["name"].as_str().unwrap_or(""),
                b["source_path"].as_str().unwrap_or(""),
                b["source_device"].as_str().unwrap_or(""),
                b["snapshots"].as_u64().unwrap_or(0),
                if b["snapshots"].as_u64() == Some(1) {
                    ""
                } else {
                    "s"
                },
                b["retention_days"].as_u64().unwrap_or(0),
                if b["stopped"].as_bool().unwrap_or(false) {
                    ", stopped"
                } else {
                    ""
                }
            );
            if let Some(t) = b["latest_utc"].as_i64() {
                s += &format!(
                    "\n  latest: {} ({} files, {})",
                    fmt_utc(t),
                    b["latest_files"].as_u64().unwrap_or(0),
                    fmt_bytes(b["latest_bytes"].as_u64().unwrap_or(0))
                );
            }
            if let Some(sch) = b["schedule"].as_str() {
                s += &format!("\n  schedule: {sch}");
                if let Some(t) = b["next_due_utc"].as_i64() {
                    s += &format!(", next {}", fmt_utc(t));
                }
            }
            let storages: Vec<&str> = b["storages"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            s += &format!("\n  storages: {}", storages.join(", "));
            s
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn describe_snapshots(v: &Value) -> String {
    let Some(list) = v.as_array().filter(|l| !l.is_empty()) else {
        return "no snapshots yet".to_string();
    };
    list.iter()
        .map(|s| {
            format!(
                "{:>5}  {}  {} files  {}  expires {}",
                s["seq"].as_u64().unwrap_or(0),
                fmt_utc(s["taken_utc"].as_i64().unwrap_or(0)),
                s["files"].as_u64().unwrap_or(0),
                fmt_bytes(s["bytes"].as_u64().unwrap_or(0)),
                fmt_utc(s["expires_utc"].as_i64().unwrap_or(0))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn describe_snapshot(r: &Value) -> String {
    let mut s = format!(
        "snapshot {} of {}: {} files ({}), {} changed, {} blocks uploaded ({}); kept until {}",
        r["seq"].as_u64().unwrap_or(0),
        r["backup"].as_str().unwrap_or(""),
        r["files"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes"].as_u64().unwrap_or(0)),
        r["files_changed"].as_u64().unwrap_or(0),
        r["chunks_uploaded"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes_uploaded"].as_u64().unwrap_or(0)),
        fmt_utc(r["expires_utc"].as_i64().unwrap_or(0))
    );
    if let Some(skipped) = r["skipped"].as_array().filter(|a| !a.is_empty()) {
        s += &format!(
            "\n{} file{} left out (unreadable or not stored completely):",
            skipped.len(),
            if skipped.len() == 1 { "" } else { "s" }
        );
        for p in skipped.iter().take(20) {
            s += &format!("\n  {}", p.as_str().unwrap_or(""));
        }
    }
    s
}

fn describe_restore(r: &Value) -> String {
    let mut s = format!(
        "restored {} files ({}) of snapshot {} of {} ({}) into {}",
        r["files_restored"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes_restored"].as_u64().unwrap_or(0)),
        r["seq"].as_u64().unwrap_or(0),
        r["backup"].as_str().unwrap_or(""),
        fmt_utc(r["taken_utc"].as_i64().unwrap_or(0)),
        r["to"].as_str().unwrap_or("")
    );
    if let Some(u) = r["unavailable"].as_array().filter(|a| !a.is_empty()) {
        s += &format!("\n{} files could not be restored:", u.len());
        for p in u.iter().take(20) {
            s += &format!("\n  {}", p.as_str().unwrap_or(""));
        }
    }
    s
}

fn describe_expire(r: &Value) -> String {
    let mut s = format!(
        "{} snapshots expired; {} snapshot objects and {} blocks deleted from the storages",
        r["snapshots_expired"].as_u64().unwrap_or(0),
        r["snapshots_deleted"].as_u64().unwrap_or(0),
        r["objects_deleted"].as_u64().unwrap_or(0)
    );
    for b in r["backups_removed"].as_array().into_iter().flatten() {
        s += &format!(
            "\n{}: stopped and its last snapshot expired, so it was removed",
            b.as_str().unwrap_or("")
        );
    }
    for b in r["waiting"].as_array().into_iter().flatten() {
        s += &format!(
            "\n{}: a snapshot could not be read, so nothing was deleted yet",
            b.as_str().unwrap_or("")
        );
    }
    s
}

/// Through the running background service when there is one (it owns the
/// engine), otherwise with the engine opened here.
fn via_service(home: &Path, path: &str, body: Value) -> Result<Option<Value>> {
    crate::call_service(home, path, body)
}

fn open(home: &Path) -> Result<Engine> {
    Engine::open(home, &crate::passphrase()?)
}

pub fn run(cli: &Cli, home: &Path, cmd: &BackupCmd) -> Result<()> {
    let abs = |p: &Path| -> Result<String> { Ok(std::path::absolute(p)?.display().to_string()) };
    match cmd {
        BackupCmd::Add {
            name,
            dir,
            retention_days,
            every_hours,
            manual,
            storage,
            place,
            no_initial,
        } => {
            let sched = schedule(*every_hours, *manual).unwrap_or_default();
            let placement = (!storage.is_empty() || !place.is_empty()).then(|| Placement {
                storages: storage.clone(),
                places: place.clone(),
                ..Default::default()
            });
            let body = json!({
                "name": name,
                "path": abs(dir)?,
                "retention_days": retention_days,
                "schedule": sched,
                "placement": placement,
                "initial": !no_initial,
            });
            let r = match via_service(home, "/api/backup", body)? {
                Some(r) => r,
                None => {
                    let mut engine = open(home)?;
                    let id = engine.add_backup(
                        name,
                        dir,
                        BackupOptions {
                            retention_days: *retention_days,
                            schedule: sched,
                            placement,
                        },
                    )?;
                    let snapshot = if *no_initial {
                        None
                    } else {
                        Some(engine.take_snapshot(id.as_str())?)
                    };
                    json!({"id": id.to_string(), "snapshot": snapshot})
                }
            };
            print(cli, &r, |r| {
                let mut s = format!(
                    "backup {name} ({}) of {} created: kept {retention_days} days, {}",
                    r["id"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(8)
                        .collect::<String>(),
                    dir.display(),
                    sched.describe()
                );
                if !r["snapshot"].is_null() {
                    s += "\n";
                    s += &describe_snapshot(&r["snapshot"]);
                }
                s
            })
        }
        BackupCmd::List => {
            let v = match crate::service::status(home) {
                Some(_) => via_service_get(home, "/api/backups")?,
                None => serde_json::to_value(open(home)?.backups()?)?,
            };
            print(cli, &v, describe_list)
        }
        BackupCmd::Snapshots { backup } => {
            let v = match crate::service::status(home) {
                Some(_) => via_service_get(
                    home,
                    &format!("/api/backup/snapshots?backup={}", crate::url_escape(backup)),
                )?,
                None => serde_json::to_value(open(home)?.backup_snapshots(backup)?)?,
            };
            print(cli, &v, describe_snapshots)
        }
        BackupCmd::Take { backup } => {
            let r = match via_service(home, "/api/backup/take", json!({"backup": backup}))? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.take_snapshot(backup)?)?,
            };
            print(cli, &r, describe_snapshot)
        }
        BackupCmd::Restore {
            backup,
            snapshot,
            to,
            path,
            overwrite,
            confirm_cold_read,
        } => {
            let which = snapshot.clone().unwrap_or_else(|| "latest".to_string());
            let pick = SnapshotPick::parse(&which)?;
            let body = json!({
                "backup": backup,
                "snapshot": which,
                "to": abs(to)?,
                "paths": path,
                "overwrite": overwrite,
                "confirm_cold_read": confirm_cold_read,
            });
            let r = match via_service(home, "/api/backup/restore", body)? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.restore_snapshot(
                    backup,
                    pick,
                    to,
                    path,
                    *overwrite,
                    *confirm_cold_read,
                )?)?,
            };
            print(cli, &r, describe_restore)?;
            if r["unavailable"].as_array().is_some_and(|a| !a.is_empty()) {
                std::process::exit(1);
            }
            Ok(())
        }
        BackupCmd::Set {
            backup,
            retention_days,
            every_hours,
            manual,
        } => {
            let sched = schedule(*every_hours, *manual);
            if retention_days.is_none() && sched.is_none() {
                bail!("give --retention-days, --every-hours or --manual");
            }
            let body =
                json!({"backup": backup, "retention_days": retention_days, "schedule": sched});
            if via_service(home, "/api/backup/set", body)?.is_none() {
                open(home)?.set_backup(backup, *retention_days, sched)?;
            }
            print(
                cli,
                &json!({"backup": backup, "retention_days": retention_days, "schedule": sched}),
                |_| {
                    format!(
                        "{backup} changed; a new retention applies to snapshots taken from now on"
                    )
                },
            )
        }
        BackupCmd::Stop { backup, yes } => {
            if !*yes
                && !confirm(&format!(
                    "Stop {backup}? No more snapshots are taken; the ones kept expire as they would, and then the backup goes."
                ))?
            {
                bail!("cancelled");
            }
            if via_service(home, "/api/backup/stop", json!({"backup": backup}))?.is_none() {
                open(home)?.stop_backup(backup)?;
            }
            print(cli, &json!({"backup": backup, "stopped": true}), |_| {
                format!("{backup} stopped: no more snapshots; the ones kept expire as they would")
            })
        }
        BackupCmd::Expire => {
            let r = match via_service(home, "/api/backup/expire", json!({}))? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.backup_upkeep()?)?,
            };
            print(cli, &r, describe_expire)
        }
    }
}

fn via_service_get(home: &Path, path: &str) -> Result<Value> {
    let Some((sf, _)) = crate::service::status(home) else {
        bail!("the background service stopped");
    };
    let text = crate::service::http_get(&format!("http://127.0.0.1:{}{path}", sf.port), &sf.token)?;
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::fmt_utc;

    #[test]
    fn utc_times_read_as_dates() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_791_849_599), "2026-10-12 23:59 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
