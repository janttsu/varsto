// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Small helpers: JSON files, atomic writes, time.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Seconds since the Unix epoch. Only used for display and for ordering hints;
/// ordering between devices uses logical clocks (see `ledger`).
pub fn now_utc() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD` of a Unix time (UTC), for messages.
pub fn format_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // Civil-from-days (Howard Hinnant), valid for the range we care about.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Write `data` to `path` atomically: temporary file in the same directory,
/// fsync, rename. The parent directory is created if needed.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("object");
    let tmp = dir.join(format!(".{}.tmp-{}", file_name, std::process::id()));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("create temporary file {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub fn read_json_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if path.exists() {
        read_json(path)
    } else {
        Ok(T::default())
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &bytes)
}

/// Normalise a relative path to the manifest form: forward slashes, no leading
/// `./`. Returns `None` for paths that escape the folder.
/// Whether `path` (slashes as separators) names a file strictly inside a
/// root: relative, every component a plain name, no `..`, `.`, empty
/// components, backslashes, drive letters, NUL or other control
/// characters, and no Windows reserved device names. Paths from other
/// devices (manifests) and object keys from storages go through this
/// before they touch a file system.
pub fn check_rel_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 {
        anyhow::bail!("path must be relative to the folder and must not contain '..': {path:?}");
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) || path.contains('\\') {
        anyhow::bail!("path contains a control character or a backslash: {path:?}");
    }
    if Path::new(path).is_absolute() || path.starts_with('/') {
        anyhow::bail!("path must be relative to the folder: {path:?}");
    }
    for c in path.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.contains(':') {
            anyhow::bail!(
                "path must be relative to the folder and must not contain '..': {path:?}"
            );
        }
        let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            anyhow::bail!("path uses a name that is reserved on Windows: {path:?}");
        }
    }
    Ok(())
}

/// `root/rel` for writing: the relative path is checked, and no component
/// of the existing part of the path may be a symbolic link (a link inside
/// the folder would otherwise let another device write outside it).
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    check_rel_path(rel)?;
    let mut p = root.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
        if let Ok(md) = std::fs::symlink_metadata(&p) {
            if md.file_type().is_symlink() {
                anyhow::bail!(
                    "{} is a symbolic link; files are not written through links",
                    p.display()
                );
            }
        }
    }
    Ok(p)
}

pub fn manifest_path(rel: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            std::path::Component::Normal(s) => parts.push(s.to_str()?.to_string()),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_stay_inside_the_folder() {
        for ok in [
            "a.txt",
            "dir/sub/file",
            "spaces in name/x.y",
            "ünïcode/ä.txt",
        ] {
            check_rel_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a/./b",
            "a//b",
            "a/",
            "C:/x",
            "c:x",
            "a\\b",
            "nul",
            "con.txt",
            "dir/LPT1",
            "a\u{0}b",
            "a\nb",
            "..",
        ] {
            assert!(check_rel_path(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[cfg(unix)]
    #[test]
    fn writes_do_not_follow_links() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(tmp.path(), root.join("link")).unwrap();
        assert!(safe_join(&root, "real/a.txt").is_ok());
        assert!(safe_join(&root, "link/escape.txt").is_err());
        assert!(
            safe_join(&root, "new/dir/file").is_ok(),
            "missing parents are fine"
        );
    }
}
