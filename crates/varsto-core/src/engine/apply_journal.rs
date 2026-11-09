// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One durability record for a run of new small files.
//!
//! Syncing every temp file on a cloud block volume dominated a pull of
//! thousands of files, and a wider parallel wave was slower still. The
//! bytes go into one journal, that journal is synced once, and only then
//! are the files renamed into place. A crash before those files are synced
//! restores them from the journal the next time the vault is opened.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static JOURNAL_SEQ: AtomicU64 = AtomicU64::new(0);

const MAGIC: &[u8; 8] = b"VARSTOJ1";
/// A file whose mtime is this far past the journal was edited after the
/// pull published it. Replay leaves that file alone.
const EDITED_AFTER: u128 = 2_000_000_000;

pub(super) struct OpenJournal {
    pub path: PathBuf,
    file: File,
    dir: File,
}

impl OpenJournal {
    pub(super) fn sync(self) -> io::Result<()> {
        self.file.sync_all()?;
        self.dir.sync_all()?;
        // The directory entry of `apply-journal` itself lives in `state`.
        if let Some(parent) = self.path.parent().and_then(|dir| dir.parent()) {
            if let Ok(parent) = File::open(parent) {
                parent.sync_all()?;
            }
        }
        Ok(())
    }
}

/// Write the journal and sync it. The path is removed if either step fails.
pub(super) fn commit(home: &Path, files: &[Planned]) -> io::Result<PathBuf> {
    let journal = write(home, files)?;
    let path = journal.path.clone();
    if let Err(err) = journal.sync() {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    Ok(path)
}

pub(super) struct Planned {
    pub dest: PathBuf,
    pub src: PathBuf,
    pub mtime_ns: i64,
    pub mode: Option<u32>,
}

/// Write `files` into a new journal under `home/state/apply-journal`.
/// The caller syncs the returned file before renaming anything into place.
pub(super) fn write(home: &Path, files: &[Planned]) -> io::Result<OpenJournal> {
    let dir_path = home.join("state").join("apply-journal");
    fs::create_dir_all(&dir_path)?;
    let created = now_ns();
    let seq = JOURNAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("{created:016x}-{:x}-{seq:x}.jnl", std::process::id());
    let path = dir_path.join(name);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    let mut unfinished = Unfinished {
        path: path.clone(),
        keep: false,
    };
    file.write_all(MAGIC)?;
    file.write_all(&created.to_le_bytes())?;
    file.write_all(&(files.len() as u32).to_le_bytes())?;
    for item in files {
        let dest = item.dest.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "journal path is not utf-8")
        })?;
        if dest.is_empty() || dest.len() > 4096 || dest.contains('\0') || !item.dest.is_absolute()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal path must be absolute",
            ));
        }
        let mut src = File::open(&item.src)?;
        let bytes = {
            let mut buf = Vec::new();
            src.read_to_end(&mut buf)?;
            buf
        };
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal record too large",
            ));
        }
        let mode = item.mode.map(|m| m as i32).unwrap_or(-1);
        write_u32(&mut file, dest.len() as u32)?;
        file.write_all(dest.as_bytes())?;
        file.write_all(&item.mtime_ns.to_le_bytes())?;
        file.write_all(&mode.to_le_bytes())?;
        write_u64(&mut file, bytes.len() as u64)?;
        file.write_all(&bytes)?;
    }
    file.seek(SeekFrom::Start(0))?;
    let dir = File::open(&dir_path)?;
    unfinished.keep = true;
    Ok(OpenJournal { path, file, dir })
}

/// Removes a journal that `write` did not finish.
struct Unfinished {
    path: PathBuf,
    keep: bool,
}

impl Drop for Unfinished {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Runs [`replay`] after a pull returns, so the pull does not wait for
/// every published file to be synced.
pub(super) struct FinishJournals {
    home: PathBuf,
}

impl FinishJournals {
    pub(super) fn arm(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
        }
    }
}

impl Drop for FinishJournals {
    fn drop(&mut self) {
        let home = self.home.clone();
        // Sync the names that already match. Do not rewrite a file here:
        // the user may have edited it while the pull was finishing, and a
        // crash still has the journal for the next open.
        drop(std::thread::spawn(move || seal_live(&home)));
    }
}

/// Sync journals whose files already hold the journaled bytes, then remove
/// those journals. A file that is missing or different is left alone and
/// its journal stays.
fn seal_live(home: &Path) {
    let dir_path = home.join("state").join("apply-journal");
    let Ok(entries) = fs::read_dir(&dir_path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jnl") {
            continue;
        }
        if let Err(err) = seal_one(&path) {
            log::warn!("apply journal {} left in place: {err}", path.display());
        }
    }
}

fn seal_one(path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad journal magic"));
    }
    let _created = read_u64(&mut file)?;
    let count = read_u32(&mut file)?;
    for _ in 0..count {
        let dest_len = read_u32(&mut file)? as usize;
        if dest_len == 0 || dest_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad journal path"));
        }
        let mut dest_buf = vec![0u8; dest_len];
        file.read_exact(&mut dest_buf)?;
        let dest = String::from_utf8(dest_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "journal path"))?;
        let _mtime_ns = read_u64(&mut file)?;
        let _mode = read_u32(&mut file)?;
        let len = read_u64(&mut file)? as usize;
        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record too large",
            ));
        }
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes)?;
        let dest = PathBuf::from(&dest);
        if !synced_match(&dest, &bytes)? {
            return Err(io::Error::other("journal file is missing or was edited"));
        }
    }
    fs::remove_file(path)
}

fn synced_match(dest: &Path, bytes: &[u8]) -> io::Result<bool> {
    let found = match fs::read(dest) {
        Ok(found) => found,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if found != bytes {
        return Ok(false);
    }
    let file = File::open(dest)?;
    file.sync_all()?;
    Ok(true)
}

/// Restore any journal left by a crash. A file edited after the journal
/// was written is left as it is. A journal is removed once every record
/// has been applied or deliberately skipped.
pub(super) fn replay(home: &Path) {
    let dir_path = home.join("state").join("apply-journal");
    let Ok(entries) = fs::read_dir(&dir_path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jnl") {
            continue;
        }
        match replay_one(&path) {
            Ok(()) => {}
            Err(e) => log::warn!("apply journal {} left in place: {e}", path.display()),
        }
    }
}

fn replay_one(path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad journal magic"));
    }
    let created = read_u64(&mut file)? as u128;
    let count = read_u32(&mut file)?;
    for _ in 0..count {
        let dest_len = read_u32(&mut file)? as usize;
        if dest_len == 0 || dest_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad journal path"));
        }
        let mut dest_buf = vec![0u8; dest_len];
        file.read_exact(&mut dest_buf)?;
        let dest = String::from_utf8(dest_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "journal path"))?;
        let mtime_ns = read_u64(&mut file)? as i64;
        let mode = read_u32(&mut file)? as i32;
        let len = read_u64(&mut file)? as usize;
        if len > 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "journal record too large"));
        }
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes)?;
        if dest.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "journal path"));
        }
        let dest = PathBuf::from(&dest);
        if !dest.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "journal path"));
        }
        if !already_good(&dest, &bytes, created)? {
            restore(&dest, &bytes, mtime_ns, mode)?;
        }
    }
    fs::remove_file(path)
}

fn already_good(dest: &Path, bytes: &[u8], created_ns: u128) -> io::Result<bool> {
    let found = match fs::read(dest) {
        Ok(found) => found,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if found == bytes {
        // The bytes may still be only in the page cache. Sync them before
        // the journal is allowed to disappear.
        let file = File::open(dest)?;
        file.sync_all()?;
        return Ok(true);
    }
    let meta = fs::metadata(dest)?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(mtime > created_ns.saturating_add(EDITED_AFTER))
}

fn restore(dest: &Path, bytes: &[u8], mtime_ns: i64, mode: i32) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("apply-tmp");
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        if mtime_ns > 0 {
            let t = UNIX_EPOCH + std::time::Duration::from_nanos(mtime_ns as u64);
            let _ = file.set_modified(t);
        }
        if mode >= 0 {
            crate::util::set_final_mode(&file, Some(mode as u32));
        }
        file.sync_all()?;
    }
    fs::rename(&tmp, dest)?;
    Ok(())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn write_u32(file: &mut File, n: u32) -> io::Result<()> {
    file.write_all(&n.to_le_bytes())
}

fn write_u64(file: &mut File, n: u64) -> io::Result<()> {
    file.write_all(&n.to_le_bytes())
}

fn read_u32(file: &mut File) -> io::Result<u32> {
    let mut b = [0u8; 4];
    file.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(file: &mut File) -> io::Result<u64> {
    let mut b = [0u8; 8];
    file.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned(dir: &Path, name: &str, bytes: &[u8], mtime_ns: i64) -> Planned {
        let src = dir.join(format!("{name}.src"));
        let dest = dir.join(name);
        fs::write(&src, bytes).unwrap();
        Planned {
            dest,
            src,
            mtime_ns,
            mode: None,
        }
    }

    #[test]
    fn a_crash_before_rename_is_restored_from_the_journal() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("folder");
        fs::create_dir_all(&folder).unwrap();
        let files = vec![
            planned(&folder, "a.txt", b"alpha", 1_700_000_000_000_000_000),
            planned(&folder, "b.txt", b"beta", 1_700_000_000_000_000_000),
        ];
        let journal = write(home.path(), &files).unwrap();
        journal.sync().unwrap();
        assert!(!files[0].dest.exists());
        replay(home.path());
        assert_eq!(fs::read(&files[0].dest).unwrap(), b"alpha");
        assert_eq!(fs::read(&files[1].dest).unwrap(), b"beta");
        let left = fs::read_dir(home.path().join("state/apply-journal"))
            .unwrap()
            .count();
        assert_eq!(left, 0);
    }

    #[test]
    fn a_short_file_is_replaced_from_the_journal() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("folder");
        fs::create_dir_all(&folder).unwrap();
        let files = vec![planned(&folder, "a.txt", b"alpha", 1)];
        let journal = write(home.path(), &files).unwrap();
        journal.sync().unwrap();
        fs::write(&files[0].dest, b"al").unwrap();
        replay(home.path());
        assert_eq!(fs::read(&files[0].dest).unwrap(), b"alpha");
    }

    #[test]
    fn a_file_edited_after_the_pull_is_not_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("folder");
        fs::create_dir_all(&folder).unwrap();
        let files = vec![planned(&folder, "a.txt", b"alpha", 1)];
        let journal = write(home.path(), &files).unwrap();
        journal.sync().unwrap();
        fs::write(&files[0].dest, b"user").unwrap();
        // The edit is newer than the journal by more than the grace period.
        let later = SystemTime::now() + std::time::Duration::from_secs(5);
        fs::File::open(&files[0].dest)
            .unwrap()
            .set_modified(later)
            .unwrap();
        replay(home.path());
        assert_eq!(fs::read(&files[0].dest).unwrap(), b"user");
    }

    #[test]
    fn a_live_seal_does_not_overwrite_an_edit() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("folder");
        fs::create_dir_all(&folder).unwrap();
        let files = vec![planned(&folder, "a.txt", b"alpha", 1)];
        let journal = write(home.path(), &files).unwrap();
        journal.sync().unwrap();
        fs::write(&files[0].dest, b"user").unwrap();
        seal_live(home.path());
        assert_eq!(fs::read(&files[0].dest).unwrap(), b"user");
        let left = fs::read_dir(home.path().join("state/apply-journal"))
            .unwrap()
            .count();
        assert_eq!(left, 1);
    }

    #[test]
    fn a_live_seal_drops_the_journal_when_the_file_matches() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("folder");
        fs::create_dir_all(&folder).unwrap();
        let files = vec![planned(&folder, "a.txt", b"alpha", 1)];
        let journal = write(home.path(), &files).unwrap();
        journal.sync().unwrap();
        fs::copy(&files[0].src, &files[0].dest).unwrap();
        seal_live(home.path());
        assert_eq!(fs::read(&files[0].dest).unwrap(), b"alpha");
        let left = fs::read_dir(home.path().join("state/apply-journal"))
            .unwrap()
            .count();
        assert_eq!(left, 0);
    }
}
