// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Self-update from the project download page.
//!
//! `varsto update` fetches `manifest.json` and `SHA256SUMS`, downloads the
//! archive for this platform, verifies its SHA-256, and replaces the running
//! binary. Downloads use the system `curl` so that the binary carries no TLS
//! stack of its own. Limitation, stated on the download page: the checksum
//! comes from the same site as the archive, so it protects against a corrupt
//! download, not against a compromised site; signed releases are planned.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const DOWNLOAD_BASE: &str = "https://varsto.net/downloads/";

pub fn target_triple() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-gnu"
    } else {
        "unsupported"
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Check {
    pub current: String,
    pub latest: String,
    pub available: bool,
    pub archive: Option<String>,
    pub target: String,
}

/// Parse "0.0.1-alpha.3" into a comparable tuple.
fn version_key(v: &str) -> (u64, u64, u64, u8, u64) {
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut nums = core.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    let (a, b, c) = (
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
    );
    // No pre-release ranks above any pre-release; alpha < beta < rc.
    let (tag, n) = if pre.is_empty() {
        (9, 0)
    } else {
        let (t, n) = pre.split_once('.').unwrap_or((pre, "0"));
        let rank = match t {
            "alpha" => 1,
            "beta" => 2,
            "rc" => 3,
            _ => 0,
        };
        (rank, n.parse().unwrap_or(0))
    };
    (a, b, c, tag, n)
}

fn curl(args: &[&str]) -> Result<Vec<u8>> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "600",
            "-A",
            &format!("varsto/{}", env!("CARGO_PKG_VERSION")),
        ])
        .args(args)
        .output()
        .context("curl is required for updates (install it or download by hand)")?;
    if !out.status.success() {
        bail!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

pub fn check() -> Result<Check> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&curl(&[&format!("{DOWNLOAD_BASE}manifest.json")])?)?;
    let latest = manifest
        .get("_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest has no version"))?
        .to_string();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let target = target_triple().to_string();
    let archive = manifest.as_object().and_then(|m| {
        m.keys()
            .find(|k| k.contains(&target) && (k.ends_with(".tar.gz") || k.ends_with(".zip")))
            .cloned()
    });
    Ok(Check {
        available: version_key(&latest) > version_key(&current) && archive.is_some(),
        current,
        latest,
        archive,
        target,
    })
}

/// Download, verify and install the latest release over the running binary.
/// Returns a human-readable message. The caller restarts the service.
pub fn apply(check: &Check) -> Result<String> {
    if !check.available {
        return Ok(format!("already up to date ({})", check.current));
    }
    let archive = check
        .archive
        .clone()
        .ok_or_else(|| anyhow!("no archive for {}", check.target))?;
    let sums = String::from_utf8(curl(&[&format!("{DOWNLOAD_BASE}SHA256SUMS")])?)?;
    let expected = sums
        .lines()
        .filter_map(|l| l.split_once("  "))
        .find(|(_, name)| name.trim() == archive)
        .map(|(h, _)| h.trim().to_lowercase())
        .ok_or_else(|| anyhow!("{archive} is not listed in SHA256SUMS"))?;
    let tmp = tempdir()?;
    let archive_path = tmp.join(&archive);
    curl(&[
        "-o",
        &archive_path.display().to_string(),
        &format!("{DOWNLOAD_BASE}{archive}"),
    ])?;
    let data = fs::read(&archive_path)?;
    let actual = hex::encode(Sha256::digest(&data));
    if actual != expected {
        bail!("checksum mismatch for {archive}: expected {expected}, got {actual}");
    }
    let extract = tmp.join("x");
    fs::create_dir_all(&extract)?;
    let tar = std::process::Command::new("tar")
        .args([
            "-xf",
            &archive_path.display().to_string(),
            "-C",
            &extract.display().to_string(),
        ])
        .output()
        .context("tar is required to unpack the update")?;
    if !tar.status.success() {
        bail!(
            "unpack failed: {}",
            String::from_utf8_lossy(&tar.stderr).trim()
        );
    }
    let bin_name = if cfg!(windows) {
        "varsto.exe"
    } else {
        "varsto"
    };
    let new_bin = walkdir::WalkDir::new(&extract)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().is_file() && e.file_name() == bin_name)
        .map(|e| e.into_path())
        .ok_or_else(|| anyhow!("archive does not contain {bin_name}"))?;
    let exe = std::env::current_exe()?;
    replace_binary(&new_bin, &exe)?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "updated {} -> {} ({}); restart the service or app to use it",
        check.current,
        check.latest,
        exe.display()
    ))
}

fn replace_binary(new_bin: &Path, exe: &Path) -> Result<()> {
    let staged = exe.with_extension("new");
    fs::copy(new_bin, &staged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        fs::rename(&staged, exe)?;
    }
    #[cfg(windows)]
    {
        // A running executable cannot be overwritten but can be renamed.
        let old = exe.with_extension("old");
        let _ = fs::remove_file(&old);
        fs::rename(exe, &old)?;
        if let Err(e) = fs::rename(&staged, exe) {
            let _ = fs::rename(&old, exe);
            return Err(e.into());
        }
    }
    Ok(())
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("varsto-update-{}", std::process::id()));
    fs::create_dir_all(&base)?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_order() {
        assert!(version_key("0.0.1-alpha.2") > version_key("0.0.1-alpha.1"));
        assert!(version_key("0.0.1-beta.1") > version_key("0.0.1-alpha.9"));
        assert!(version_key("0.0.1") > version_key("0.0.1-rc.1"));
        assert!(version_key("0.1.0-alpha.1") > version_key("0.0.9"));
    }
}
