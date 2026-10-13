// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto trash`: files deleted on any device of the vault, kept for the
//! trash days (30 by default) and restorable from the storages on every
//! device; settings, restore, delete for good.

use crate::backup::fmt_utc;
use crate::{confirm, fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};
use std::path::Path;
use varsto_core::Engine;

#[derive(Subcommand)]
pub enum TrashCmd {
    /// List what is in the trash: path, size, when and on which device it
    /// was deleted, and when it expires.
    List {
        /// Only this folder.
        #[arg(long)]
        folder: Option<String>,
    },
    /// Restore files or whole directories from the trash. A file goes back
    /// to its path, or to "name (restored).ext" when the path is taken;
    /// nothing is overwritten.
    Restore {
        folder: String,
        #[arg(required = true)]
        paths: Vec<String>,
        /// Restore under this directory of the folder instead.
        #[arg(long)]
        to: Option<String>,
        /// Read blocks kept only on cold storage (retrieval fees may apply).
        #[arg(long)]
        confirm_cold_read: bool,
    },
    /// Delete files from the trash for good, or empty it with --all.
    Purge {
        folder: Option<String>,
        paths: Vec<String>,
        /// Everything in the trash (of FOLDER, or of every folder).
        #[arg(long)]
        all: bool,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Change how long files are kept and where the trash is stored.
    Set {
        /// Days files are kept: for the vault, or with --folder for one
        /// folder (0 there returns it to the vault's days).
        #[arg(long)]
        days: Option<u32>,
        #[arg(long)]
        folder: Option<String>,
        /// Keep trashed blocks on this storage only (e.g. a cold storage):
        /// they leave the other warm storages.
        #[arg(long, conflicts_with = "no_storage")]
        storage: Option<String>,
        /// No trash storage: trashed blocks stay where they are.
        #[arg(long)]
        no_storage: bool,
    },
    /// Settings, totals and the bytes of the trash on each storage.
    Status,
    /// Expire old entries now, move trashed blocks to the trash storage and
    /// drop what nothing uses any more (the background service does this daily).
    Upkeep,
}

fn open(home: &Path) -> Result<Engine> {
    Engine::open(home, &crate::passphrase()?)
}

fn via_service_get(home: &Path, path: &str) -> Result<Option<Value>> {
    let Some((sf, _)) = crate::service::status(home) else {
        return Ok(None);
    };
    let text = crate::service::http_get(&format!("http://127.0.0.1:{}{path}", sf.port), &sf.token)?;
    Ok(Some(serde_json::from_str(&text)?))
}

fn describe_list(v: &Value) -> String {
    let Some(list) = v.as_array().filter(|l| !l.is_empty()) else {
        return "the trash is empty".to_string();
    };
    let mut out = Vec::new();
    for i in list {
        out.push(format!(
            "{}/{}  {}  deleted {} on {}, expires {}{}",
            i["folder"].as_str().unwrap_or(""),
            i["path"].as_str().unwrap_or(""),
            fmt_bytes(i["size"].as_u64().unwrap_or(0)),
            fmt_utc(i["deleted_utc"].as_i64().unwrap_or(0)),
            i["deleted_by"].as_str().unwrap_or(""),
            fmt_utc(i["expires_utc"].as_i64().unwrap_or(0)),
            if i["cold_only"].as_bool().unwrap_or(false) {
                " (cold storage: restoring needs --confirm-cold-read)"
            } else {
                ""
            }
        ));
    }
    out.join("\n")
}

fn describe_status(v: &Value) -> String {
    let mut s = format!("files are kept {} days", v["days"].as_u64().unwrap_or(30));
    if let Some(m) = v["folder_days"].as_object().filter(|m| !m.is_empty()) {
        let parts: Vec<String> = m
            .iter()
            .map(|(f, d)| format!("{f} {} days", d.as_u64().unwrap_or(0)))
            .collect();
        s += &format!(" ({})", parts.join(", "));
    }
    match v["storage"].as_str() {
        Some(n) => {
            s += &format!("\ntrash storage: {n}");
            if v["storage_cold"].as_bool().unwrap_or(false) {
                s += " (cold)";
            }
        }
        None => s += "\nno trash storage: trashed blocks stay where they are",
    }
    s += &format!(
        "\n{} files in the trash, {}",
        v["entries"].as_u64().unwrap_or(0),
        fmt_bytes(v["bytes"].as_u64().unwrap_or(0))
    );
    if let Some(m) = v["by_storage"].as_object().filter(|m| !m.is_empty()) {
        for (n, b) in m {
            s += &format!("\n  on {n}: {}", fmt_bytes(b.as_u64().unwrap_or(0)));
        }
    }
    if v["local_copies"].as_u64().unwrap_or(0) > 0 {
        s += &format!(
            "\nlocal trash on this device: {} files, {}",
            v["local_copies"].as_u64().unwrap_or(0),
            fmt_bytes(v["local_copy_bytes"].as_u64().unwrap_or(0))
        );
    }
    if let Some(t) = v["next_expiry_utc"].as_i64() {
        s += &format!("\nnext expiry: {}", fmt_utc(t));
    }
    if let Some(t) = v["last_upkeep_utc"].as_i64() {
        s += &format!("\nlast upkeep: {}", fmt_utc(t));
    }
    if v["drops_waiting"].as_u64().unwrap_or(0) > 0 {
        s += &format!(
            "\n{} blocks wait to be deleted (cold storage minimum duration)",
            v["drops_waiting"].as_u64().unwrap_or(0)
        );
    }
    for n in v["notes"].as_array().into_iter().flatten() {
        s += &format!("\nnote: {}", n.as_str().unwrap_or(""));
    }
    s
}

fn describe_restore(r: &Value) -> String {
    let mut s = format!(
        "restored {} files ({}) of {}",
        r["restored"].as_array().map(|a| a.len()).unwrap_or(0),
        fmt_bytes(r["bytes"].as_u64().unwrap_or(0)),
        r["folder"].as_str().unwrap_or("")
    );
    for f in r["restored"].as_array().into_iter().flatten() {
        let (from, to) = (
            f["from"].as_str().unwrap_or(""),
            f["to"].as_str().unwrap_or(""),
        );
        if from == to {
            s += &format!("\n  {to}");
        } else {
            s += &format!("\n  {from} -> {to}");
        }
    }
    if let Some(u) = r["unavailable"].as_array().filter(|a| !a.is_empty()) {
        s += &format!("\n{} files could not be restored:", u.len());
        for p in u.iter().take(20) {
            s += &format!("\n  {}", p.as_str().unwrap_or(""));
        }
    }
    s
}

fn describe_purge(r: &Value) -> String {
    let mut s = format!(
        "deleted {} files ({}) for good; {} blocks ({}) deleted from this device's storages",
        r["entries"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes"].as_u64().unwrap_or(0)),
        r["blocks_dropped"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes_dropped"].as_u64().unwrap_or(0))
    );
    let waiting = r["blocks_waiting"].as_u64().unwrap_or(0);
    if waiting > 0 {
        s += &format!("\n{waiting} block copies on cold storage are deleted once its minimum storage duration has passed");
    }
    s
}

fn describe_upkeep(r: &Value) -> String {
    let mut s = format!(
        "{} files expired, {} earlier versions let go; {} blocks ({}) deleted, {} blocks ({}) moved to the trash storage, {} local trash copies removed",
        r["expired"].as_u64().unwrap_or(0),
        r["versions_dropped"].as_u64().unwrap_or(0),
        r["blocks_dropped"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes_dropped"].as_u64().unwrap_or(0)),
        r["blocks_moved"].as_u64().unwrap_or(0),
        fmt_bytes(r["bytes_moved"].as_u64().unwrap_or(0)),
        r["local_copies_removed"].as_u64().unwrap_or(0)
    );
    for n in r["notes"].as_array().into_iter().flatten() {
        s += &format!("\nnote: {}", n.as_str().unwrap_or(""));
    }
    s
}

pub fn run(cli: &Cli, home: &Path, cmd: &TrashCmd) -> Result<()> {
    match cmd {
        TrashCmd::List { folder } => {
            let q = folder
                .as_ref()
                .map(|f| format!("?folder={}", crate::url_escape(f)))
                .unwrap_or_default();
            let v = match via_service_get(home, &format!("/api/trash{q}"))? {
                Some(v) => v,
                None => serde_json::to_value(open(home)?.trash_list(folder.as_deref())?)?,
            };
            print(cli, &v, describe_list)
        }
        TrashCmd::Status => {
            let v = match via_service_get(home, "/api/trash/status")? {
                Some(v) => v,
                None => serde_json::to_value(open(home)?.trash_status()?)?,
            };
            print(cli, &v, describe_status)
        }
        TrashCmd::Restore {
            folder,
            paths,
            to,
            confirm_cold_read,
        } => {
            let body = json!({
                "folder": folder,
                "paths": paths,
                "to": to,
                "confirm_cold_read": confirm_cold_read,
            });
            let r = match crate::call_service(home, "/api/trash/restore", body)? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.trash_restore(
                    folder,
                    paths,
                    to.as_deref(),
                    *confirm_cold_read,
                )?)?,
            };
            print(cli, &r, describe_restore)?;
            if r["unavailable"].as_array().is_some_and(|a| !a.is_empty()) {
                std::process::exit(1);
            }
            Ok(())
        }
        TrashCmd::Purge {
            folder,
            paths,
            all,
            yes,
        } => {
            if !*all && (folder.is_none() || paths.is_empty()) {
                bail!("name a folder and the files to delete for good, or use --all");
            }
            if *all && !paths.is_empty() {
                bail!("--all takes no paths");
            }
            let question = if *all {
                match folder {
                    Some(f) => {
                        format!("Empty the trash of {f}? The files cannot be restored afterwards.")
                    }
                    None => "Empty the whole trash? The files cannot be restored afterwards."
                        .to_string(),
                }
            } else {
                format!(
                    "Delete {} from the trash of {} for good? They cannot be restored afterwards.",
                    paths.join(", "),
                    folder.as_deref().unwrap_or("")
                )
            };
            if !*yes && !confirm(&question)? {
                bail!("cancelled");
            }
            let body = json!({"folder": folder, "paths": paths, "all": all});
            let r = match crate::call_service(home, "/api/trash/purge", body)? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.trash_purge(
                    folder.as_deref(),
                    paths,
                    *all,
                )?)?,
            };
            print(cli, &r, describe_purge)
        }
        TrashCmd::Set {
            days,
            folder,
            storage,
            no_storage,
        } => {
            if days.is_none() && storage.is_none() && !no_storage {
                bail!("give --days, --storage or --no-storage");
            }
            if folder.is_some() && days.is_none() {
                bail!("give --days with --folder");
            }
            let choice: Option<Option<String>> = if *no_storage {
                Some(None)
            } else {
                storage.clone().map(Some)
            };
            let body = json!({
                "days": days,
                "folder": folder,
                "storage": storage,
                "no_storage": no_storage,
            });
            let v = match crate::call_service(home, "/api/trash/set", body)? {
                Some(v) => v,
                None => {
                    let mut engine = open(home)?;
                    let st = engine.trash_set(*days, folder.as_deref(), choice)?;
                    if storage.is_some() {
                        // Move what is in the trash now.
                        engine.trash_upkeep()?;
                    }
                    serde_json::to_value(st)?
                }
            };
            print(cli, &v, describe_status)
        }
        TrashCmd::Upkeep => {
            let r = match crate::call_service(home, "/api/trash/upkeep", json!({}))? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.trash_upkeep()?)?,
            };
            print(cli, &r, describe_upkeep)
        }
    }
}
