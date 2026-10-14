// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto torrent`: download a torrent larger than the local disk straight
//! into a Varsto folder through a local transmission-daemon, in batches
//! that fit above a free-space reserve (`docs/torrents.md`). Linux only.

use crate::{fmt_bytes, passphrase, print, Cli};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use varsto_core::engine::{
    find_job, torrent_jobs_at, JobState, TorrentAddOptions, TorrentEnv, TorrentJob,
};
use varsto_core::freespace::MinFree;
use varsto_core::transmission::{AddSource, Rpc, RpcSettings};
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
    fn given(&self) -> RpcSettings {
        RpcSettings {
            url: self.rpc_url.clone().unwrap_or_default(),
            user: self.rpc_user.clone(),
            password: self.rpc_password.clone(),
        }
    }
}

#[derive(Subcommand)]
pub enum TorrentCmd {
    /// Register a job: the torrent is added to transmission stopped with
    /// every file unwanted; `torrent run` (or the background service)
    /// downloads it batch by batch into the folder.
    Add {
        /// A .torrent file or a magnet link.
        source: String,
        /// The Varsto folder to create for the torrent's files.
        #[arg(long)]
        folder: String,
        /// Write the folder's blocks only to these storages (its placement).
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
        /// Start downloading in this terminal right away (as `torrent run`).
        #[arg(long)]
        run: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Drive a job until it is complete: download a batch, import it, remove
    /// it from the disk, then the next batch. Stop with Ctrl-C; running it
    /// again carries on.
    Run {
        job: String,
        /// Seconds between checks.
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// One step only.
        #[arg(long)]
        once: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// A job's state, files and errors (every job without a name).
    Status { job: Option<String> },
    /// Every torrent job of this device.
    List,
    /// Stop downloading; the job stays.
    Pause {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Go on downloading.
    Resume {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Forget a job. The folder stays; files in the download directory that
    /// were not stored yet stay there too.
    Remove {
        job: String,
        /// Leave the torrent in transmission.
        #[arg(long)]
        keep_in_transmission: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
}

fn linux_only() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("torrent jobs run on Linux only (they drive a local transmission-daemon)");
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

pub fn run(cli: &Cli, home: &Path, cmd: &TorrentCmd) -> Result<()> {
    match cmd {
        TorrentCmd::List => {
            let jobs = torrent_jobs_at(home);
            print(cli, &jobs, |j| {
                if j.is_empty() {
                    "no torrent jobs".to_string()
                } else {
                    j.iter()
                        .map(TorrentJob::line)
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            })
        }
        TorrentCmd::Status { job } => match job {
            Some(k) => {
                let j = find_job(home, k)?;
                print(cli, &j, describe)
            }
            None => {
                let jobs = torrent_jobs_at(home);
                print(cli, &jobs, |j| {
                    if j.is_empty() {
                        "no torrent jobs".to_string()
                    } else {
                        j.iter().map(describe).collect::<Vec<_>>().join("\n\n")
                    }
                })
            }
        },
        TorrentCmd::Add {
            source,
            folder,
            storages,
            free_min,
            download_dir,
            min_copies,
            keep_policy,
            run: run_now,
            rpc,
        } => {
            linux_only()?;
            let free_min = MinFree::parse(free_min)?;
            let src = if source.starts_with("magnet:") {
                AddSource::Magnet(source.clone())
            } else {
                AddSource::Metainfo(
                    std::fs::read(source).with_context(|| format!("read {source}"))?,
                )
            };
            let settings = RpcSettings::resolve(
                rpc.rpc_url.as_deref(),
                rpc.rpc_user.as_deref(),
                rpc.rpc_password.as_deref(),
            );
            let client = Rpc::new(settings.clone());
            let mut engine = Engine::open(home, &passphrase()?)?;
            let job = {
                let _pause = crate::drives::ServicePause::new(home);
                engine.torrent_add(
                    &TorrentAddOptions {
                        source: src,
                        folder: folder.clone(),
                        storages: storages.clone(),
                        free_min,
                        download_dir: download_dir.clone(),
                        folder_parent: crate::desktop::folder_root(home),
                        min_copies: (!keep_policy).then_some(*min_copies),
                        rpc: settings,
                    },
                    &client,
                )?
            };
            if *run_now {
                return drive(cli, home, &mut engine, &job.hash, &client, 5, false);
            }
            print(cli, &job, |j| {
                format!(
                    "{}\nIt downloads while the background service runs, or now with: varsto torrent run {}",
                    describe(j),
                    j.short()
                )
            })
        }
        TorrentCmd::Run {
            job,
            interval,
            once,
            rpc,
        } => {
            linux_only()?;
            let mut engine = Engine::open(home, &passphrase()?)?;
            let j = find_job(home, job)?;
            let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
            drive(cli, home, &mut engine, &j.hash, &client, *interval, *once)
        }
        TorrentCmd::Pause { job, rpc } | TorrentCmd::Resume { job, rpc } => {
            linux_only()?;
            let paused = matches!(cmd, TorrentCmd::Pause { .. });
            let mut engine = Engine::open(home, &passphrase()?)?;
            let j = find_job(home, job)?;
            let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
            let j = engine.torrent_set_paused(&j.hash, paused, &client)?;
            print(cli, &j, TorrentJob::line)
        }
        TorrentCmd::Remove {
            job,
            keep_in_transmission,
            rpc,
        } => {
            linux_only()?;
            let mut engine = Engine::open(home, &passphrase()?)?;
            let j = find_job(home, job)?;
            let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
            let j = engine.torrent_remove(&j.hash, *keep_in_transmission, Some(&client))?;
            print(cli, &j, |j| {
                let left = std::fs::read_dir(&j.download_dir)
                    .map(|d| d.count())
                    .unwrap_or(0);
                format!(
                    "removed torrent job {} ({}); folder {} stays{}{}",
                    j.short(),
                    j.name,
                    j.folder,
                    if *keep_in_transmission {
                        "; the torrent stays in transmission"
                    } else {
                        ""
                    },
                    if left > 0 {
                        format!(
                            "; {} holds files that were not stored yet",
                            j.download_dir.display()
                        )
                    } else {
                        String::new()
                    }
                )
            })
        }
    }
}

/// Step a job until it is complete (or once).
fn drive(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    hash: &str,
    rpc: &Rpc,
    interval: u64,
    once: bool,
) -> Result<()> {
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
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&j)?);
                    }
                    return Ok(());
                }
                if j.user_paused {
                    bail!("the job is paused: varsto torrent resume {}", j.short());
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

fn describe(j: &TorrentJob) -> String {
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
