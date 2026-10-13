// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto history`: earlier versions of overwritten files, kept on a
//! thinning schedule for the history days (90 by default) and restorable on
//! every device.

use crate::backup::fmt_utc;
use crate::{fmt_bytes, print, Cli};
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::Path;
use varsto_core::engine::HistoryTarget;
use varsto_core::Engine;

/// `varsto history <folder> <path>` lists the versions of a file; the
/// subcommands restore, change the settings and show what is kept.
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct HistoryArgs {
    #[command(subcommand)]
    pub cmd: Option<HistoryCmd>,
    /// The folder.
    pub folder: Option<String>,
    /// The file (path inside the folder).
    pub path: Option<String>,
}

#[derive(Subcommand)]
pub enum HistoryCmd {
    /// Restore a version: over the current file (which is kept as a version
    /// itself), or with --to/--as to another path. Nothing is overwritten
    /// without being kept.
    Restore {
        folder: String,
        path: String,
        /// A version id from `varsto history` (6 or more characters), or a
        /// time in UTC (YYYY-MM-DD for the end of that day, or YYYY-MM-DD
        /// HH:MM): the version that was current then.
        version: String,
        /// Restore under this directory of the folder ("name (restored).ext"
        /// when the name is taken there).
        #[arg(long, conflicts_with = "as_name")]
        to: Option<String>,
        /// Restore as this name beside the file (or this path of the
        /// folder); refused when it exists.
        #[arg(long = "as")]
        as_name: Option<String>,
        /// Read blocks kept only on cold storage (retrieval fees may apply).
        #[arg(long)]
        confirm_cold_read: bool,
    },
    /// Change how long versions are kept: for the vault, or with --folder
    /// for one folder (--days 0 there follows the vault again).
    Set {
        #[arg(long, conflicts_with = "off")]
        days: Option<u32>,
        /// Keep no new versions (versions kept so far age out as before).
        #[arg(long)]
        off: bool,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Settings, versions and the bytes they really take per folder and storage.
    Status,
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
    let mut s = format!(
        "{}/{}",
        v["folder"].as_str().unwrap_or(""),
        v["path"].as_str().unwrap_or("")
    );
    match v["current_size"].as_u64() {
        Some(n) => s += &format!("  now {}", fmt_bytes(n)),
        None => s += "  (no current file)",
    }
    if v["days"].is_null() {
        s += "\nthe history of this folder is off: no new versions are kept";
    }
    let list = v["versions"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        s += "\nno earlier versions";
        return s;
    }
    for i in &list {
        let id: String = i["id"].as_str().unwrap_or("").chars().take(8).collect();
        let by = i["author"]
            .as_str()
            .unwrap_or(i["replaced_by"].as_str().unwrap_or(""));
        s += &format!(
            "\n  {}  {}  {} (new {}), by {}, replaced on {}{}",
            id,
            fmt_utc(i["replaced_utc"].as_i64().unwrap_or(0)),
            fmt_bytes(i["size"].as_u64().unwrap_or(0)),
            fmt_bytes(i["new_bytes"].as_u64().unwrap_or(0)),
            by,
            i["replaced_by"].as_str().unwrap_or(""),
            if i["cold_only"].as_bool().unwrap_or(false) {
                " (cold storage: restoring needs --confirm-cold-read)"
            } else {
                ""
            }
        );
    }
    s
}

fn days_word(d: u64) -> String {
    if d == 0 {
        "off".to_string()
    } else {
        format!("{d} days")
    }
}

fn describe_status(v: &Value) -> String {
    let mut s = format!(
        "versions are kept: {}",
        days_word(v["days"].as_u64().unwrap_or(0))
    );
    if let Some(m) = v["folder_days"].as_object().filter(|m| !m.is_empty()) {
        let parts: Vec<String> = m
            .iter()
            .map(|(f, d)| format!("{f} {}", days_word(d.as_u64().unwrap_or(0))))
            .collect();
        s += &format!(" ({})", parts.join(", "));
    }
    let words: Vec<&str> = v["schedule"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w.as_str())
        .collect();
    if !words.is_empty() {
        s += &format!("\nschedule: {}", words.join(", "));
    }
    if let Some(n) = v["storage"].as_str() {
        s += &format!(
            "\nblocks only versions use go to the trash storage {n}{}",
            if v["storage_cold"].as_bool().unwrap_or(false) {
                " (cold)"
            } else {
                ""
            }
        );
    }
    s += &format!(
        "\n{} versions, {} of blocks only they use",
        v["versions"].as_u64().unwrap_or(0),
        fmt_bytes(v["extra_bytes"].as_u64().unwrap_or(0))
    );
    for f in v["folders"].as_array().into_iter().flatten() {
        s += &format!(
            "\n  {}: {} versions of {} files ({}), {} extra",
            f["folder"].as_str().unwrap_or(""),
            f["versions"].as_u64().unwrap_or(0),
            f["files"].as_u64().unwrap_or(0),
            fmt_bytes(f["bytes"].as_u64().unwrap_or(0)),
            fmt_bytes(f["extra_bytes"].as_u64().unwrap_or(0))
        );
        if f["days"].is_null() {
            s += " (off)";
        }
        if let Some(m) = f["by_storage"].as_object().filter(|m| !m.is_empty()) {
            let parts: Vec<String> = m
                .iter()
                .map(|(n, b)| format!("{n} {}", fmt_bytes(b.as_u64().unwrap_or(0))))
                .collect();
            s += &format!(" [{}]", parts.join(", "));
        }
    }
    s
}

fn describe_restore(r: &Value) -> String {
    let mut s = format!(
        "restored the version of {} replaced {} ({}) to {}",
        r["path"].as_str().unwrap_or(""),
        fmt_utc(r["replaced_utc"].as_i64().unwrap_or(0)),
        fmt_bytes(r["size"].as_u64().unwrap_or(0)),
        r["to"].as_str().unwrap_or("")
    );
    if r["replaced_current"].as_bool().unwrap_or(false) {
        s += "\nthe version it replaced is kept in the history";
    }
    s
}

pub fn run(cli: &Cli, home: &Path, args: &HistoryArgs) -> Result<()> {
    let Some(cmd) = &args.cmd else {
        let (Some(folder), Some(path)) = (&args.folder, &args.path) else {
            bail!("give the folder and the file: varsto history <folder> <path>");
        };
        let q = format!(
            "/api/history?folder={}&path={}",
            crate::url_escape(folder),
            crate::url_escape(path)
        );
        let v = match via_service_get(home, &q)? {
            Some(v) => v,
            None => serde_json::to_value(open(home)?.history_list(folder, path)?)?,
        };
        return print(cli, &v, describe_list);
    };
    match cmd {
        HistoryCmd::Status => {
            let v = match via_service_get(home, "/api/history/status")? {
                Some(v) => v,
                None => serde_json::to_value(open(home)?.history_status()?)?,
            };
            print(cli, &v, describe_status)
        }
        HistoryCmd::Restore {
            folder,
            path,
            version,
            to,
            as_name,
            confirm_cold_read,
        } => {
            let body = json!({
                "folder": folder,
                "path": path,
                "version": version,
                "to": to,
                "as": as_name,
                "confirm_cold_read": confirm_cold_read,
            });
            let r = match crate::call_service(home, "/api/history/restore", body)? {
                Some(r) => r,
                None => serde_json::to_value(open(home)?.history_restore(
                    folder,
                    path,
                    version,
                    &HistoryTarget {
                        to: to.clone(),
                        as_name: as_name.clone(),
                    },
                    *confirm_cold_read,
                )?)?,
            };
            print(cli, &r, describe_restore)
        }
        HistoryCmd::Set { days, off, folder } => {
            if days.is_none() && !off {
                bail!("give --days or --off");
            }
            let body = json!({"days": days, "off": off, "folder": folder});
            let v = match crate::call_service(home, "/api/history/set", body)? {
                Some(v) => v,
                None => serde_json::to_value(open(home)?.history_set(
                    *days,
                    folder.as_deref(),
                    *off,
                )?)?,
            };
            print(cli, &v, describe_status)
        }
    }
}
