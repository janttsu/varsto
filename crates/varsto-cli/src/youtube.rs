// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto import youtube`: archive a YouTube
//! channel, playlist or video into a folder with the local yt-dlp, one
//! video at a time and politely; see `docs/youtube.md`. Only for content
//! you may keep a copy of.

use crate::{fmt_bytes, passphrase, print, Cli};
use anyhow::{bail, Result};
use clap::Args;
use std::path::{Path, PathBuf};
use varsto_core::engine::{
    youtube_jobs_at, VideoStatus, YoutubeAddOptions, YoutubeEnv, YoutubeJob, YoutubeScanReport,
    YtState, DEFAULT_REFRESH_HOURS,
};
use varsto_core::freespace::MinFree;
use varsto_core::youtube::{self as yt, Throttle};
use varsto_core::Engine;

#[derive(Args)]
pub struct AddArgs {
    /// A channel, playlist or video address.
    url: String,
    /// The folder (default: named after the channel). An existing folder
    /// can be used when `import youtube-scan` registered it.
    #[arg(long)]
    folder: Option<String>,
    /// Store the videos on this storage (repeat for more); `cheapest`: the
    /// storage(s) with the lowest price per GB-month (`varsto storage price`).
    /// Default: the folder's normal placement.
    #[arg(long = "storage", value_name = "NAME")]
    storages: Vec<String>,
    /// Free space the download disk always keeps: a share (15%) or an
    /// amount (20GB). A video waits until it fits above it.
    #[arg(long, default_value = "15%")]
    free_min: String,
    /// Where the spool directory goes (`<dir>/<job id>`; default
    /// ~/Downloads/varsto-youtube). Not inside a Varsto folder.
    #[arg(long, value_name = "DIR")]
    download_dir: Option<PathBuf>,
    /// The download rate limit (yt-dlp --limit-rate; `none` for no limit).
    #[arg(long, default_value = "600K")]
    rate: String,
    /// Seconds between two videos, chosen at random in this range.
    #[arg(long, value_name = "MIN-MAX", default_value = "25-65")]
    sleep: String,
    /// Seconds between two requests to YouTube.
    #[arg(long, default_value_t = 2)]
    sleep_requests: u32,
    /// Fragments downloaded at a time.
    #[arg(long, default_value_t = 1)]
    concurrent_fragments: u32,
    /// yt-dlp's --format (default: yt-dlp's best).
    #[arg(long)]
    format: Option<String>,
    /// yt-dlp's --cookies-from-browser, for videos that need a login you have.
    #[arg(long, value_name = "BROWSER")]
    cookies_from_browser: Option<String>,
    /// One more yt-dlp argument (repeat for more), e.g. --extra-arg=--embed-metadata.
    #[arg(long = "extra-arg", value_name = "ARG", allow_hyphen_values = true)]
    extra: Vec<String>,
    /// Also keep the thumbnail.
    #[arg(long)]
    thumbnails: bool,
    /// Also keep subtitles in these languages (en,fi).
    #[arg(long, value_name = "LANGS")]
    subs: Option<String>,
    /// The policy a new folder gets: every block on this many storages
    /// before a video leaves the spool.
    #[arg(long, default_value_t = 1)]
    min_copies: u32,
    /// Keep the vault's default policy for a new folder instead.
    #[arg(long)]
    keep_policy: bool,
    /// List the channel again this often for new videos (0: once).
    #[arg(long, default_value_t = DEFAULT_REFRESH_HOURS)]
    refresh_hours: u32,
    /// The yt-dlp program (default: VARSTO_YTDLP, else yt-dlp from the PATH).
    #[arg(long, value_name = "PATH")]
    ytdlp_path: Option<PathBuf>,
    /// Only register the job; the background service starts it.
    #[arg(long)]
    no_run: bool,
}

/// The default spool parent.
pub(crate) fn default_download_dir() -> Result<PathBuf> {
    crate::import_jobs::default_youtube_download_dir()
}

fn throttle(a: &AddArgs) -> Result<Throttle> {
    let (sleep_min, sleep_max) = yt::parse_sleep(&a.sleep)?;
    for x in &a.extra {
        yt::check_extra_arg(x)?;
    }
    Ok(Throttle {
        sleep_min,
        sleep_max,
        sleep_requests: a.sleep_requests,
        rate: yt::parse_rate(&a.rate)?,
        concurrent_fragments: a.concurrent_fragments.max(1),
        format: a.format.clone().unwrap_or_default(),
        cookies_from_browser: a.cookies_from_browser.clone().unwrap_or_default(),
        extra: a.extra.clone(),
    })
}

/// The command line's steps: yt-dlp is waited for, and the background
/// service is paused while a video is imported.
struct Terminal {
    home: PathBuf,
}

impl YoutubeEnv for Terminal {
    fn before_import(&mut self) -> Option<Box<dyn std::any::Any>> {
        Some(Box::new(crate::drives::ServicePause::new(&self.home)))
    }
    fn blocking(&self) -> bool {
        true
    }
}

/// Step a job until it waits; its last state.
pub(crate) fn run_job(
    engine: &mut Engine,
    home: &Path,
    id: &str,
    progress: bool,
) -> Result<YoutubeJob> {
    let mut env = Terminal {
        home: home.to_path_buf(),
    };
    let mut last_text = String::new();
    loop {
        let Some(j) = engine.youtube_tick(id, &mut env, false)? else {
            bail!("another Varsto process is working on this job right now");
        };
        if progress && j.text != last_text {
            eprintln!("{}: {}", j.short(), j.text);
            last_text = j.text.clone();
        }
        let elsewhere = j.running.is_some();
        let waits = matches!(
            j.state,
            YtState::WaitingSpace
                | YtState::WaitingPolicy
                | YtState::WaitingRetry
                | YtState::Paused
                | YtState::UpToDate
                | YtState::Complete
        );
        // A yt-dlp run left by the background service carries on there.
        if waits || elsewhere {
            return Ok(j);
        }
    }
}

/// `varsto import youtube`: register the job, then work on it until it waits.
pub fn add(cli: &Cli, home: &Path, a: &AddArgs) -> Result<()> {
    let mut engine = Engine::open(home, &passphrase()?)?;
    let progress = !cli.json;
    {
        {
            let opts = YoutubeAddOptions {
                url: a.url.clone(),
                folder: a.folder.clone(),
                storages: a.storages.clone(),
                free_min: MinFree::parse(&a.free_min)?,
                download_dir: match &a.download_dir {
                    Some(d) => d.clone(),
                    None => default_download_dir()?,
                },
                folder_parent: crate::desktop::folder_root(home),
                min_copies: (!a.keep_policy).then_some(a.min_copies.max(1)),
                throttle: throttle(a)?,
                thumbnails: a.thumbnails,
                subtitles: a.subs.clone().unwrap_or_default(),
                refresh_hours: a.refresh_hours,
                ytdlp: a.ytdlp_path.clone(),
            };
            let job = {
                let _pause = crate::drives::ServicePause::new(home);
                engine.youtube_add(&opts)?
            };
            if !cli.json {
                println!(
                    "YouTube job {} for {} into folder {} (spool {})",
                    job.short(),
                    job.url,
                    job.folder,
                    job.spool_dir.display()
                );
                println!("  downloads: {}", job.throttle.describe());
                if !job.storages.is_empty() {
                    println!("  storages: {}", job.storages.join(", "));
                }
            }
            let job = if a.no_run {
                job
            } else {
                run_job(&mut engine, home, &job.id, progress)?
            };
            print(cli, &job, |j| {
                format!(
                    "{}\nThe background service carries on (varsto import jobs status {}).",
                    j.line(),
                    j.short()
                )
            })?;
        }
    }
    Ok(())
}

/// `varsto import youtube-scan`: register videos by the ids in file names.
pub fn scan(cli: &Cli, home: &Path, target: &str) -> Result<()> {
    let mut engine = Engine::open(home, &passphrase()?)?;
    let r = engine.youtube_scan(target)?;
    print(cli, &r, describe_scan)
}

fn describe_scan(r: &YoutubeScanReport) -> String {
    format!(
        "{} {}: {} file(s) named with a video id, {} video(s), {} new to the index{}",
        r.kind,
        r.target,
        r.files_with_id,
        r.videos,
        r.new_videos,
        if r.kind == "directory" {
            " (recorded on this device only)"
        } else {
            " (recorded with the folder, for every device)"
        }
    )
}

pub(crate) fn describe_jobs(list: &[YoutubeJob], videos: bool) -> String {
    if list.is_empty() {
        return "no YouTube jobs (varsto import youtube <channel address> --folder <name>)".into();
    }
    let mut out = Vec::new();
    for j in list {
        out.push(j.line());
        let c = j.counts();
        out.push(format!(
            "  {} listed: {} stored ({}), {} already stored, {} downloaded waiting, {} to download, {} failed, {} given up",
            c.listed,
            c.stored,
            fmt_bytes(c.stored_bytes),
            c.already_stored,
            c.downloaded,
            c.pending,
            c.failed,
            c.gave_up
        ));
        out.push(format!(
            "  source {}, spool {}",
            j.url,
            j.spool_dir.display()
        ));
        if let Some(e) = &j.last_error {
            out.push(format!("  last error: {e}"));
        }
        for v in &j.videos {
            let show = videos || matches!(v.status, VideoStatus::Failed | VideoStatus::GaveUp);
            if !show {
                continue;
            }
            let extra = match (&v.last_error, &v.found_in) {
                (Some(e), _) if !matches!(v.status, VideoStatus::Stored) => {
                    format!(" ({} attempt(s)): {e}", v.attempts)
                }
                (_, Some(at)) => format!(": {at}"),
                _ => String::new(),
            };
            out.push(format!(
                "    {} {} [{}]{extra}",
                v.status.as_str().replace('_', " "),
                v.title,
                v.id
            ));
        }
    }
    out.join("\n")
}

/// Lines for `varsto status` (read without the passphrase).
pub fn status_lines(home: &Path) -> Vec<String> {
    youtube_jobs_at(home)
        .into_iter()
        .filter(|j| j.state != YtState::Complete)
        .map(|j| j.line())
        .collect()
}
