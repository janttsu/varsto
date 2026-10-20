// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto import jobs`: the torrent and YouTube imports of this device on
//! the command line. The list and the Import page's API are in
//! `import_jobs` (shared with the mobile apps).

use crate::import_jobs::{all_jobs, find, job_rows, JobRef};
use crate::torrent::RpcArgs;
use crate::{print, Cli};
use anyhow::{bail, Result};
use clap::Subcommand;
use std::path::Path;
use varsto_core::transmission::Rpc;
use varsto_core::Engine;

/// `varsto import jobs`: the torrent and YouTube imports of this device.
#[derive(Subcommand)]
pub enum JobsCmd {
    /// Every import job of this device (torrents and YouTube), one line
    /// each with its kind.
    List,
    /// A job's state, files or videos and errors (every job without a name).
    Status {
        job: Option<String>,
        /// List every video of a YouTube job with its state.
        #[arg(long)]
        videos: bool,
    },
    /// Work on a job in this terminal: a torrent job until it is complete
    /// (download a batch, import it, remove it from the disk, the next
    /// batch), a YouTube job until it waits (for space, the policy, a retry,
    /// the next listing). Without a job: every YouTube job until it waits
    /// and one step of every torrent job. Stop with Ctrl-C; running it again
    /// carries on.
    Run {
        job: Option<String>,
        /// Seconds between the steps of a torrent job.
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// One step only.
        #[arg(long)]
        once: bool,
        /// YouTube: try failed and given-up videos again now, and list again.
        #[arg(long)]
        retry_failed: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Stop a job's downloads; the job stays.
    Pause {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Carry on (YouTube: videos that were given up are tried again).
    Resume {
        job: String,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Forget a job. The folder stays; files in the download directory that
    /// were not stored yet stay there too.
    Remove {
        job: String,
        /// Torrent: leave the torrent in transmission.
        #[arg(long)]
        keep_in_transmission: bool,
        #[command(flatten)]
        rpc: RpcArgs,
    },
}

fn describe(job: &JobRef, videos: bool) -> String {
    match job {
        JobRef::Torrent(j) => crate::torrent::describe(j),
        JobRef::Youtube(j) => crate::youtube::describe_jobs(std::slice::from_ref(j), videos),
    }
}

/// `varsto import jobs ...`.
pub fn jobs(cli: &Cli, home: &Path, cmd: &JobsCmd) -> Result<()> {
    match cmd {
        JobsCmd::List => {
            let rows = job_rows(home);
            let lines: Vec<String> = all_jobs(home).iter().map(JobRef::line).collect();
            print(cli, &rows, |_| {
                if lines.is_empty() {
                    "no import jobs (varsto import torrent ..., varsto import youtube ...)".into()
                } else {
                    lines.join("\n")
                }
            })
        }
        JobsCmd::Status { job, videos } => match job {
            Some(k) => {
                let j = find(home, k)?;
                let text = describe(&j, *videos);
                print(cli, &j.value()?, |_| text)
            }
            None => {
                let list = all_jobs(home);
                let values = list.iter().map(JobRef::value).collect::<Result<Vec<_>>>()?;
                let text = if list.is_empty() {
                    "no import jobs (varsto import torrent ..., varsto import youtube ...)"
                        .to_string()
                } else {
                    list.iter()
                        .map(|j| describe(j, *videos))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                };
                print(cli, &values, |_| text)
            }
        },
        JobsCmd::Run {
            job,
            interval,
            once,
            retry_failed,
            rpc,
        } => {
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            match job {
                Some(k) => {
                    let after = run_one(
                        cli,
                        home,
                        &mut engine,
                        find(home, k)?,
                        *interval,
                        *once,
                        *retry_failed,
                        rpc,
                    )?;
                    let text = describe(&after, false);
                    print(cli, &after.value()?, |_| text)
                }
                None => {
                    let mut out = Vec::new();
                    for j in engine.youtube_to_run() {
                        out.push(run_one(
                            cli,
                            home,
                            &mut engine,
                            JobRef::Youtube(j),
                            *interval,
                            true,
                            *retry_failed,
                            rpc,
                        )?);
                    }
                    if cfg!(target_os = "linux") {
                        for j in engine.torrents_to_run() {
                            out.push(run_one(
                                cli,
                                home,
                                &mut engine,
                                JobRef::Torrent(j),
                                *interval,
                                true,
                                false,
                                rpc,
                            )?);
                        }
                    }
                    let values = out.iter().map(JobRef::value).collect::<Result<Vec<_>>>()?;
                    let text = if out.is_empty() {
                        "no import job to run".to_string()
                    } else {
                        out.iter().map(JobRef::line).collect::<Vec<_>>().join("\n")
                    };
                    print(cli, &values, |_| text)
                }
            }
        }
        JobsCmd::Pause { job, rpc } | JobsCmd::Resume { job, rpc } => {
            let paused = matches!(cmd, JobsCmd::Pause { .. });
            let j = find(home, job)?;
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            let after = match j {
                JobRef::Torrent(j) => {
                    crate::torrent::linux_only()?;
                    let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
                    JobRef::Torrent(engine.torrent_set_paused(&j.hash, paused, &client)?)
                }
                JobRef::Youtube(j) => JobRef::Youtube(engine.youtube_set_paused(&j.id, paused)?),
            };
            let text = after.line();
            print(cli, &after.value()?, |_| text)
        }
        JobsCmd::Remove {
            job,
            keep_in_transmission,
            rpc,
        } => {
            let j = find(home, job)?;
            let mut engine = Engine::open(home, &crate::passphrase()?)?;
            match j {
                JobRef::Torrent(j) => {
                    crate::torrent::linux_only()?;
                    let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
                    let j = engine.torrent_remove(&j.hash, *keep_in_transmission, Some(&client))?;
                    let left = std::fs::read_dir(&j.download_dir)
                        .map(|d| d.count())
                        .unwrap_or(0);
                    let text = format!(
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
                    );
                    print(cli, &JobRef::Torrent(j).value()?, |_| text)
                }
                JobRef::Youtube(j) => {
                    if *keep_in_transmission {
                        bail!("--keep-in-transmission is for torrent jobs");
                    }
                    let j = engine.youtube_remove(&j.id)?;
                    let mut text = format!(
                        "YouTube job {} removed; folder {} keeps its videos.",
                        j.short(),
                        j.folder
                    );
                    if j.spool_dir.exists() {
                        text += &format!(
                            "\nFiles not stored yet stay in {} (remove them yourself when you no longer need them).",
                            j.spool_dir.display()
                        );
                    }
                    print(cli, &JobRef::Youtube(j).value()?, |_| text)
                }
            }
        }
    }
}

/// Work on one job in this terminal (see [`JobsCmd::Run`]).
#[allow(clippy::too_many_arguments)]
fn run_one(
    cli: &Cli,
    home: &Path,
    engine: &mut Engine,
    job: JobRef,
    interval: u64,
    once: bool,
    retry_failed: bool,
    rpc: &RpcArgs,
) -> Result<JobRef> {
    match job {
        JobRef::Torrent(j) => {
            crate::torrent::linux_only()?;
            let client = Rpc::new(engine.torrent_rpc(&j, &rpc.given()));
            let after = crate::torrent::drive(cli, home, engine, &j.hash, &client, interval, once)?;
            Ok(JobRef::Torrent(after))
        }
        JobRef::Youtube(j) => {
            if retry_failed {
                engine.youtube_retry_failed(&j.id)?;
            }
            let after = crate::youtube::run_job(engine, home, &j.id, !cli.json)?;
            Ok(JobRef::Youtube(after))
        }
    }
}
