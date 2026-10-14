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
///
/// The temporary file is created new (never an existing file someone else
/// planted) and, on Unix, readable by this user only from its first byte:
/// most of what goes through here is key material or encrypted state, and
/// the umask (usually 022) would otherwise leave it world-readable until a
/// later `chmod`.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("object");
    // Unique per write, not only per process: uploader threads may write the
    // same object (a block two files share) at the same moment, and a name
    // another process could guess from the pid alone must not be enough to
    // place a file there first.
    let mut tmp = temp_name(dir, file_name);
    let mut f = loop {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&tmp) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                tmp = temp_name(dir, file_name);
            }
            Err(e) => {
                return Err(e).with_context(|| format!("create temporary file {}", tmp.display()))
            }
        }
    };
    let written = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", tmp.display()));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename into {}", path.display()));
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn temp_name(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(format!(".{file_name}.tmp-{:016x}", rand::random::<u64>()))
}

/// Create `dir` readable by this user only (mode 0700 on Unix; parents that
/// are missing are created with the umask). When it already exists and the
/// group or others can reach it, its mode is set to 0700 and a warning is
/// logged: the device directory holds keys, and a directory someone else
/// can list or read must not stay that way.
pub fn private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match fs::metadata(dir) {
            Ok(m) if m.is_dir() => {
                let mode = m.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                        .with_context(|| format!("restrict {}", dir.display()))?;
                    log::warn!(
                        "{} was reachable by other users (mode {mode:o}); set to 0700",
                        dir.display()
                    );
                }
                return Ok(());
            }
            Ok(_) => anyhow::bail!("{} is not a directory", dir.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("stat {}", dir.display())),
        }
        if let Some(parent) = dir.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => Ok(()),
            // Another thread or process made it meanwhile: check its mode.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => private_dir(dir),
            Err(e) => Err(e).with_context(|| format!("create {}", dir.display())),
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))
    }
}

/// The subdirectories of a device directory that hold plaintext of the
/// user's files (trash copies, exports) or local sync state.
pub const PRIVATE_SUBDIRS: [&str; 3] = ["state", "trash", "exports"];

/// Create a device directory readable by this user only, with its `state/`
/// directory, and tighten `trash/` and `exports/` when they exist. Called
/// whenever a device directory is created or opened.
pub fn private_home(home: &Path) -> Result<()> {
    private_dir(home)?;
    for sub in PRIVATE_SUBDIRS {
        let p = home.join(sub);
        if sub == "state" || p.is_dir() {
            private_dir(&p)?;
        }
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

/// Whether `path` is a valid vault path (see [`crate::names`]): relative,
/// `/` as the separator, no empty, `.` or `..` component, no NUL. Any
/// other name is kept as it is; a device whose filesystem does not take
/// it writes it under a mapped local name (`names::LocalNames`).
pub fn check_rel_path(path: &str) -> Result<()> {
    crate::names::check_vault_path(path)
}

/// The stricter rule for object keys on storages, which every platform
/// must be able to write as they are: [`check_rel_path`], and no
/// backslash, `:`, control character or Windows device name.
pub fn check_portable_rel_path(path: &str) -> Result<()> {
    check_rel_path(path)?;
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) || path.contains('\\') || path.contains(':') {
        anyhow::bail!("path contains a control character, a backslash or ':': {path:?}");
    }
    if path.split('/').any(crate::names::mapped_on_windows) {
        anyhow::bail!("path uses a name Windows does not allow: {path:?}");
    }
    Ok(())
}

/// 16 random hex digits, for names nobody should be able to guess.
pub fn random_suffix() -> String {
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

/// Create a file that must not exist yet (`O_EXCL`: a planted file or link
/// of that name is an error, never followed), readable by the owner only.
pub fn create_new_private(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// A new temporary file next to `target`: `.varsto-<kind>-<pid>-<random>`,
/// created exclusively with mode 0600, so that nothing another local user
/// plants or guesses under a predictable name is ever written through, and
/// what is written is private until the final mode is set.
pub fn temp_beside(target: &Path, kind: &str) -> std::io::Result<(PathBuf, fs::File)> {
    let mut last = None;
    for _ in 0..16 {
        let tmp = target.with_file_name(format!(
            ".varsto-{kind}-{}-{}",
            std::process::id(),
            random_suffix()
        ));
        match create_new_private(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no free temporary name")))
}

/// What a file created without a mode of its own gets here: `0666` less the
/// umask.
#[cfg(unix)]
pub fn default_file_mode() -> u32 {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    static MODE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        let dir = std::env::temp_dir();
        for _ in 0..8 {
            let p = dir.join(format!(".varsto-umask-{}", random_suffix()));
            let made = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o666)
                .open(&p);
            if let Ok(f) = made {
                let m = f.metadata().map(|m| m.mode() & 0o777).unwrap_or(0o644);
                drop(f);
                let _ = fs::remove_file(&p);
                return m;
            }
        }
        0o644
    })
}

/// Give an open file its final mode before it is renamed into place
/// (`fchmod`): `mode` when the folder records one, else the default a new
/// file gets here. Best effort: the metadata step after the rename sets it
/// again and reports a failure.
pub fn set_final_mode(file: &fs::File, mode: Option<u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = mode.map(|m| m & 0o777).unwrap_or_else(default_file_mode);
        let _ = file.set_permissions(fs::Permissions::from_mode(m));
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
    }
}

/// `root/rel` for writing, where `rel` is the local path (already mapped
/// for this device's filesystem, see `names::LocalNames`): the path is
/// checked, and no component of the existing part of the path may be a
/// symbolic link (a link inside the folder would otherwise let another
/// device write outside it).
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    crate::names::checked_join(root, rel)
}

/// Decimal sizes for messages ("3.2 GB", "410 MB").
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Normalise a relative path to the manifest form: forward slashes, no
/// leading `./`. Returns `None` for paths that escape the folder and for
/// names that are not UTF-8 (those are not synced).
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
            // Original names are kept (spec: "Paths").
            "C:/x",
            "c:x",
            "a\\b",
            "nul",
            "con.txt",
            "dir/LPT1",
            "a\nb",
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
            "a\u{0}b",
            "..",
        ] {
            assert!(check_rel_path(bad).is_err(), "{bad:?} must be refused");
            assert!(
                check_portable_rel_path(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        for bad in [
            "C:/x", "c:x", "a\\b", "nul", "con.txt", "dir/LPT1", "a\nb", "x.",
        ] {
            assert!(
                check_portable_rel_path(bad).is_err(),
                "{bad:?} is not a portable key"
            );
        }
        check_portable_rel_path("chunks/ab/abcdef").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_and_device_directories_are_private_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // The usual umask would leave a plain `File::create` at 0644.
        let old = unsafe { libc::umask(0o022) };
        let result = std::panic::catch_unwind(|| {
            let file = tmp.path().join("dir").join("keys.enc");
            write_atomic(&file, b"secret").unwrap();
            assert_eq!(fs::read(&file).unwrap(), b"secret");
            let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
            // Overwriting keeps it private and leaves no temporary file behind.
            write_atomic(&file, b"other").unwrap();
            assert_eq!(fs::read(&file).unwrap(), b"other");
            let names: Vec<_> = fs::read_dir(file.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec!["keys.enc".to_string()], "{names:?}");

            let home = tmp.path().join("home");
            private_home(&home).unwrap();
            for p in [home.clone(), home.join("state")] {
                let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{}: mode {mode:o}", p.display());
            }
            // An existing directory that others can read is tightened.
            let open = home.join("trash");
            fs::create_dir(&open).unwrap();
            fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
            private_home(&home).unwrap();
            let mode = fs::metadata(&open).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "mode {mode:o}");
            // A missing optional subdirectory is not created.
            assert!(!home.join("exports").exists());
        });
        unsafe { libc::umask(old) };
        result.unwrap();
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

/// For `skip_serializing_if` on counters.
pub fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
