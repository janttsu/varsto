// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto import torrent`: download a
//! torrent larger than the local disk straight into a Varsto folder through
//! a local transmission-daemon, in batches that fit above a free-space
//! reserve (`docs/torrents.md`). Linux only.

use crate::{fmt_bytes, passphrase, print, Cli};
use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};
use varsto_core::engine::{
    torrent_jobs_at, FileOutcome, JobState, TorrentAddOptions, TorrentEnv, TorrentJob,
};
use varsto_core::freespace::MinFree;
use varsto_core::transmission::{self, AddSource, Rpc, RpcSettings};
use varsto_core::Engine;

#[derive(Args, Clone, Default)]
pub struct RpcArgs {
    /// transmission-daemon's RPC address (default
    /// http://127.0.0.1:9091/transmission/rpc, or VARSTO_TRANSMISSION_URL).
    #[arg(long)]
    rpc_url: Option<String>,
    /// RPC user name (or VARSTO_TRANSMISSION_USER).
    #[arg(long)]
    rpc_user: Option<String>,
    /// RPC password (or VARSTO_TRANSMISSION_PASSWORD); a job keeps it in
    /// the device's encrypted secret store.
    #[arg(long)]
    rpc_password: Option<String>,
}

impl RpcArgs {
    /// Only what was given on the command line (a job's own settings and
    /// the environment fill the rest).
    pub(crate) fn given(&self) -> RpcSettings {
        RpcSettings {
            url: self.rpc_url.clone().unwrap_or_default(),
            user: self.rpc_user.clone(),
            password: self.rpc_password.clone(),
        }
    }
}

/// `varsto import torrent`: register a job. The torrent is added to
/// transmission stopped with every file unwanted; `import jobs run`
/// (or the background service) downloads it batch by batch into the folder.
#[derive(Args, Clone)]
pub struct TorrentAddArgs {
    /// A .torrent file or a magnet link.
    source: String,
    /// The Varsto folder for the torrent's files (default: named after the
    /// torrent): a new one, or an existing folder. Files an existing folder
    /// holds at the same path with the same size are not downloaded.
    #[arg(long)]
    folder: Option<String>,
    /// Write the new folder's blocks only to these storages (its
    /// placement). `cheapest`: the storages with the lowest price per
    /// GB-month (`varsto storage price`), as many as --min-copies.
    #[arg(long = "storage", value_name = "NAME")]
    storages: Vec<String>,
    /// Free space to keep on the download disk: a share ("15%") or an
    /// amount ("20GB"). Never less than Varsto's own minimum (5 %).
    #[arg(long, default_value = "15%")]
    free_min: String,
    /// Where transmission downloads (a directory per torrent is made
    /// inside). Default: transmission's own download directory.
    #[arg(long, value_name = "DIR")]
    download_dir: Option<PathBuf>,
    /// Copies on storages the new folder's policy asks for before a
    /// downloaded file is removed from the disk.
    #[arg(long, default_value_t = 1)]
    min_copies: u32,
    /// Keep the default durability policy (it asks for a copy on your own
    /// devices or disks checked by another device, so files leave the
    /// download disk only once that holds).
    #[arg(long)]
    keep_policy: bool,
    /// Download files the folder holds at the same path with the same
    /// size too, and compare them: identical ones are not stored again,
    /// different ones stay in the download directory as conflicts.
    #[arg(long)]
    verify_existing: bool,
    /// Start downloading in this terminal right away (as
    /// `import jobs run`).
    #[arg(long)]
    run: bool,
    #[command(flatten)]
    rpc: RpcArgs,
}

pub(crate) fn linux_only() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("torrent imports run on Linux only (they drive a local transmission-daemon)");
    }
    Ok(())
}

/// The command line holds the background service while it imports.
struct CliEnv {
    home: PathBuf,
}

impl TorrentEnv for CliEnv {
    fn before_import(&mut self) -> Option<Box<dyn std::any::Any>> {
        Some(Box::new(crate::drives::ServicePause::new(&self.home)))
    }
}

/// `varsto import torrent`.
pub fn add(cli: &Cli, home: &Path, a: &TorrentAddArgs) -> Result<()> {
    linux_only()?;
    let free_min = MinFree::parse(&a.free_min)?;
    let (src, name) = if a.source.starts_with("magnet:") {
        let (hash, name) = transmission::parse_magnet(&a.source)?;
        (AddSource::Magnet(a.source.clone()), name.unwrap_or(hash))
    } else {
        let bytes = std::fs::read(&a.source).with_context(|| format!("read {}", a.source))?;
        let name = transmission::parse_metainfo(&bytes)?.name;
        (AddSource::Metainfo(bytes), name)
    };
    let folder = match &a.folder {
        Some(f) => f.clone(),
        None => varsto_core::import::folder_name_from(&name),
    };
    let settings = RpcSettings::resolve(
        a.rpc.rpc_url.as_deref(),
        a.rpc.rpc_user.as_deref(),
        a.rpc.rpc_password.as_deref(),
    );
    let client = Rpc::new(settings.clone());
    let mut engine = Engine::open(home, &passphrase()?)?;
    let job = {
        let _pause = crate::drives::ServicePause::new(home);
        engine.torrent_add(
            &TorrentAddOptions {
                source: src,
                folder,
                storages: a.storages.clone(),
                free_min,
                download_dir: a.download_dir.clone(),
                folder_parent: crate::desktop::folder_root(home),
                min_copies: (!a.keep_policy).then_some(a.min_copies),
                verify_existing: a.verify_existing,
                rpc: settings,
            },
            &client,
        )?
    };
    if a.run {
        let j = drive(cli, home, &mut engine, &job.hash, &client, 5, false)?;
        return print(cli, &j, describe);
    }
    print(cli, &job, |j| {
        format!(
            "{}\nIt downloads while the background service runs, or now with: varsto import jobs run torrent:{}",
            describe(j),
            j.short()
        )
    })
}

/// Step a job until it is complete (or once); the job as it is then.
pub(crate) fn drive(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    hash: &str,
    rpc: &Rpc,
    interval: u64,
    once: bool,
) -> Result<TorrentJob> {
    let mut env = CliEnv {
        home: home.to_path_buf(),
    };
    let mut last = String::new();
    loop {
        match engine.torrent_tick(hash, rpc, &mut env as &mut dyn TorrentEnv, true) {
            Ok(Some(j)) => {
                let line = j.line();
                if line != last && !cli.json {
                    println!("{line}");
                    last = line;
                }
                if once || j.state == JobState::Complete {
                    return Ok(j);
                }
                if j.user_paused {
                    bail!(
                        "the job is paused: varsto import jobs resume torrent:{}",
                        j.short()
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("torrent {}: {e:#} (trying again)", &hash[..8]);
                if once {
                    return Err(e);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    }
}

pub(crate) fn describe(j: &TorrentJob) -> String {
    let mut out = j.line();
    out += &format!(
        "\n  info hash {}\n  download directory {}\n  reserve {} ({}){}",
        j.hash,
        j.download_dir.display(),
        j.free_min,
        fmt_bytes(j.reserve_bytes),
        j.free_bytes
            .map(|f| format!(", {} free at the last step", fmt_bytes(f)))
            .unwrap_or_default()
    );
    if !j.storages.is_empty() {
        out += &format!("\n  written to {}", j.storages.join(", "));
    }
    if j.existing_folder {
        out += &format!(
            "\n  an existing folder: files it holds at the same path {}",
            if j.verify_existing {
                "are downloaded and compared"
            } else {
                "with the same size are not downloaded"
            }
        );
    }
    for (o, what) in [
        (
            FileOutcome::Present,
            "already in the folder, not downloaded",
        ),
        (FileOutcome::Identical, "identical to the folder's copy"),
        (
            FileOutcome::Conflict,
            "differ from the folder's file at the same path, kept in the download directory",
        ),
    ] {
        let paths: Vec<&str> = j
            .files
            .iter()
            .filter(|f| f.done && f.outcome == o)
            .map(|f| f.path.as_str())
            .collect();
        if !paths.is_empty() {
            let more = paths.len().saturating_sub(5);
            out += &format!(
                "\n  {} {what}: {}{}",
                paths.len(),
                paths[..paths.len().min(5)].join(", "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            );
        }
    }
    if !j.batch.is_empty() {
        out += &format!(
            "\n  batch {}: {}",
            j.batches,
            j.batch
                .iter()
                .filter_map(|i| j.files.get(*i).map(|f| f.path.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for e in j.errors.iter().rev().take(5) {
        out += &format!("\n  error {}: {}", when(e.utc), e.text);
    }
    out
}

fn when(t: i64) -> String {
    format!(
        "{} {:02}:{:02} UTC",
        varsto_core::util::format_date(t),
        t.rem_euclid(86_400) / 3600,
        t.rem_euclid(3600) / 60
    )
}

/// Lines for `varsto status`: the jobs that are not complete.
pub fn status_lines(home: &Path) -> Vec<String> {
    torrent_jobs_at(home)
        .iter()
        .filter(|j| j.state != JobState::Complete)
        .map(TorrentJob::line)
        .collect()
}
