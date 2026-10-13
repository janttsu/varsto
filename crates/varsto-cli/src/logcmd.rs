// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto log`: where the local debug log is, follow it, and pack it into a
//! diagnostics bundle for a bug report. Also sets up this process's log.

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use varsto_core::logging;

#[derive(Subcommand)]
pub enum LogCmd {
    /// Print the log directory.
    Path,
    /// Print the end of a log file; with -f keep printing new lines.
    Tail {
        /// Component: service, cli, tray, desktop-app, mcp, app, …
        #[arg(long, default_value = "service")]
        component: String,
        /// Lines to show.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Follow the file as it grows (also across rotations).
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Pack the logs, the service's status and version details into a
    /// .tar.zst for a bug report. Check it before sharing it.
    Bundle {
        /// Output file (default: varsto-logs-<time>.tar.zst here).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

/// Which component a command logs as.
pub fn component_for(service_run: bool, desktop: bool, tray: bool, mcp: bool) -> &'static str {
    if service_run {
        "service"
    } else if desktop {
        "desktop-app"
    } else if tray {
        "tray"
    } else if mcp {
        "mcp"
    } else {
        "cli"
    }
}

/// Start this process's log. A bad `--log-level` is a usage error; any
/// other problem (no home yet, a read-only disk) leaves logging off.
pub fn init(home: &Path, component: &str, level: Option<&str>, echo_stderr: bool) -> Result<()> {
    let mut o = logging::Options::new(home, component);
    o.level = level.map(str::to_string);
    if echo_stderr {
        o.stderr = Some(log::LevelFilter::Info);
    }
    logging::init(o).map_err(|e| anyhow!("--log-level: {e}"))
}

pub fn run(home: &Path, cmd: &LogCmd, json: bool) -> Result<()> {
    let dir = logging::dir(home);
    match cmd {
        LogCmd::Path => {
            if json {
                let (bytes, files) = logging::usage(home);
                println!(
                    "{}",
                    serde_json::json!({"dir": dir, "bytes": bytes, "files": files})
                );
            } else {
                println!("{}", dir.display());
            }
        }
        LogCmd::Tail {
            component,
            lines,
            follow,
        } => tail(&dir, component, *lines, *follow)?,
        LogCmd::Bundle { output } => {
            let out = output
                .clone()
                .unwrap_or_else(|| PathBuf::from(format!("varsto-logs-{}.tar.zst", crate::desktop::log_stamp())));
            let state = crate::service::read_service_file(home).and_then(|f| {
                crate::service::http_get(&format!("http://127.0.0.1:{}/api/state", f.port), &f.token).ok()
            });
            let file = std::fs::File::create(&out).with_context(|| format!("create {}", out.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            let mut file = logging::bundle(home, &crate::desktop::bundle_extras(home, state), file)?;
            file.flush()?;
            log::info!(path = out.display().to_string(); "log bundle written");
            if json {
                println!("{}", serde_json::json!({"bundle": out, "note": crate::desktop::BUNDLE_REMINDER}));
            } else {
                println!("Wrote {}", out.display());
                println!("{}", crate::desktop::BUNDLE_REMINDER);
            }
        }
    }
    Ok(())
}

fn tail(dir: &Path, component: &str, lines: usize, follow: bool) -> Result<()> {
    let path = logging::files::active_path(dir, component);
    let mut f = std::fs::File::open(&path).with_context(|| {
        format!(
            "no log at {} (components: {})",
            path.display(),
            components(dir).join(", ")
        )
    })?;
    // The last `lines` lines: read the end of the file.
    let len = f.metadata()?.len();
    let from = len.saturating_sub((lines as u64 + 1) * 400);
    f.seek(SeekFrom::Start(from))?;
    let mut text = String::new();
    f.read_to_string(&mut text).ok();
    let mut all: Vec<&str> = text.lines().collect();
    if from > 0 && !all.is_empty() {
        // The first line read is cut.
        all.remove(0);
    }
    let start = all.len().saturating_sub(lines);
    let stdout = std::io::stdout();
    let mut o = stdout.lock();
    for l in &all[start..] {
        writeln!(o, "{l}")?;
    }
    o.flush()?;
    drop(o);
    if !follow {
        return Ok(());
    }
    let mut pos = len;
    let mut reader = std::io::BufReader::new(f);
    reader.seek(SeekFrom::Start(pos))?;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n > 0 {
            pos += n as u64;
            print!("{line}");
            std::io::stdout().flush()?;
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Rotated: start over at the new file.
        let now = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if now < pos {
            if let Ok(f) = std::fs::File::open(&path) {
                reader = std::io::BufReader::new(f);
                pos = 0;
            }
        }
    }
}

fn components(dir: &Path) -> Vec<String> {
    logging::files::list(dir)
        .into_iter()
        .filter(|f| f.active)
        .filter_map(|f| {
            f.path
                .file_name()?
                .to_str()?
                .strip_prefix("varsto-")?
                .strip_suffix(".log")
                .map(str::to_string)
        })
        .collect()
}
