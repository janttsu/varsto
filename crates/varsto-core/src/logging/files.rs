// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Log files: `<home>/logs/varsto-<component>.log`, rotated by size into
//! zstd-compressed `varsto-<component>.<n>.log.zst`, with a cap on the whole
//! directory. Several processes may write the same component's file (two
//! command-line runs at once): writes are whole lines in one `write` on a file
//! opened for appending, and a process notices when another one rotated the
//! file under it and reopens it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Size limits of the log files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The active file is rotated once it grows past this.
    pub max_file_bytes: u64,
    /// Rotated files kept per component (besides the active one).
    pub keep: usize,
    /// Upper bound for the whole log directory: the oldest rotated files
    /// (of any component) go first. Active files are never removed.
    pub total_cap_bytes: u64,
    /// Compress rotated files with zstd.
    pub compress: bool,
}

impl Rotation {
    /// Computers: 10 MiB per file, 5 files per component, 64 MiB in all.
    pub const DESKTOP: Rotation = Rotation {
        max_file_bytes: 10 << 20,
        keep: 4,
        total_cap_bytes: 64 << 20,
        compress: true,
    };
    /// Phones: 4 MiB per file, 4 files per component, 24 MiB in all.
    pub const MOBILE: Rotation = Rotation {
        max_file_bytes: 4 << 20,
        keep: 3,
        total_cap_bytes: 24 << 20,
        compress: true,
    };
}

impl Default for Rotation {
    fn default() -> Self {
        Rotation::DESKTOP
    }
}

/// Buffered lines are written once this much has gathered (or on a timer,
/// a warning or an error).
const BUFFER_BYTES: usize = 64 << 10;
/// With no file to write to, at most this much waits in memory.
const MAX_PENDING: usize = 1 << 20;

/// The active file of a component.
pub fn active_path(dir: &Path, component: &str) -> PathBuf {
    dir.join(format!("varsto-{component}.log"))
}

fn rotated_path(dir: &Path, component: &str, n: usize, compressed: bool) -> PathBuf {
    let ext = if compressed { "log.zst" } else { "log" };
    dir.join(format!("varsto-{component}.{n}.{ext}"))
}

/// Create the log directory, readable by this user only.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = o.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = f.metadata() {
            if m.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
        }
    }
    Ok(f)
}

#[cfg(unix)]
fn file_id(m: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino() ^ (m.dev() << 48)
}
#[cfg(not(unix))]
fn file_id(_m: &fs::Metadata) -> u64 {
    0
}

/// One component's log file with its write buffer.
pub(crate) struct Sink {
    dir: PathBuf,
    component: String,
    rotation: Rotation,
    file: Option<File>,
    id: u64,
    buf: Vec<u8>,
}

impl Sink {
    pub fn new(dir: &Path, component: &str, rotation: Rotation) -> Sink {
        let mut s = Sink {
            dir: dir.to_path_buf(),
            component: component.to_string(),
            rotation,
            file: None,
            id: 0,
            buf: Vec::with_capacity(BUFFER_BYTES),
        };
        s.open();
        s
    }

    fn open(&mut self) {
        if ensure_dir(&self.dir).is_err() {
            return;
        }
        let path = active_path(&self.dir, &self.component);
        if let Ok(f) = open_append(&path) {
            self.id = f.metadata().map(|m| file_id(&m)).unwrap_or(0);
            self.file = Some(f);
        }
    }

    pub fn push(&mut self, line: &[u8], urgent: bool) {
        if self.file.is_none() && self.buf.len() + line.len() > MAX_PENDING {
            return;
        }
        self.buf.extend_from_slice(line);
        if urgent || self.buf.len() >= BUFFER_BYTES {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let path = active_path(&self.dir, &self.component);
        // Another process rotated the file (or it was removed): reopen.
        let moved = match fs::metadata(&path) {
            Ok(m) => file_id(&m) != self.id,
            Err(_) => true,
        };
        if moved || self.file.is_none() {
            self.file = None;
            self.open();
        }
        let size = self
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| m.len())
            .unwrap_or(0);
        if size > 0 && size + self.buf.len() as u64 > self.rotation.max_file_bytes {
            let _ = self.rotate();
        }
        if let Some(f) = self.file.as_mut() {
            if f.write_all(&self.buf).is_ok() {
                self.buf.clear();
            } else {
                // Disk full or the file went away: try a fresh file next time.
                self.file = None;
                if self.buf.len() > MAX_PENDING {
                    self.buf.clear();
                }
            }
        }
    }

    /// Move the active file aside, compress it as `.1`, shift the older ones
    /// and start a new active file.
    fn rotate(&mut self) -> io::Result<()> {
        let path = active_path(&self.dir, &self.component);
        let aside = self
            .dir
            .join(format!("varsto-{}.rotating-{}.log", self.component, std::process::id()));
        fs::rename(&path, &aside)?;
        self.file = None;
        self.open();
        let keep = self.rotation.keep;
        for compressed in [true, false] {
            let _ = fs::remove_file(rotated_path(&self.dir, &self.component, keep, compressed));
        }
        for n in (1..keep).rev() {
            for compressed in [true, false] {
                let from = rotated_path(&self.dir, &self.component, n, compressed);
                if from.exists() {
                    let _ = fs::rename(&from, rotated_path(&self.dir, &self.component, n + 1, compressed));
                }
            }
        }
        if keep == 0 {
            let _ = fs::remove_file(&aside);
        } else if self.rotation.compress {
            let target = rotated_path(&self.dir, &self.component, 1, true);
            let ok = compress_file(&aside, &target).is_ok();
            if ok {
                let _ = fs::remove_file(&aside);
            } else {
                let _ = fs::rename(&aside, rotated_path(&self.dir, &self.component, 1, false));
            }
        } else {
            let _ = fs::rename(&aside, rotated_path(&self.dir, &self.component, 1, false));
        }
        enforce_cap(&self.dir, self.rotation.total_cap_bytes);
        Ok(())
    }
}

fn compress_file(from: &Path, to: &Path) -> io::Result<()> {
    let input = File::open(from)?;
    let tmp = to.with_extension("zst.tmp");
    let out = open_append(&tmp)?;
    out.set_len(0)?;
    let mut enc = zstd::Encoder::new(out, 3)?;
    io::copy(&mut io::BufReader::new(input), &mut enc)?;
    enc.finish()?.sync_all()?;
    fs::rename(&tmp, to)
}

/// One file of the log directory.
#[derive(Clone, Debug)]
pub struct LogFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub modified: SystemTime,
    /// The component's active file (never removed by the cap).
    pub active: bool,
}

/// The log files in `dir`, oldest first.
pub fn list(dir: &Path) -> Vec<LogFile> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with("varsto-") || !(name.ends_with(".log") || name.ends_with(".log.zst")) {
            continue;
        }
        let Ok(m) = e.metadata() else { continue };
        if !m.is_file() {
            continue;
        }
        let stem = name.trim_end_matches(".zst").trim_end_matches(".log");
        // `varsto-cli` is active, `varsto-cli.2` or `varsto-cli.rotating-12` is not.
        let active = !stem.contains('.');
        out.push(LogFile {
            path: e.path(),
            bytes: m.len(),
            modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            active,
        });
    }
    out.sort_by_key(|f| f.modified);
    out
}

/// Bytes and number of files in the log directory.
pub fn usage(dir: &Path) -> (u64, usize) {
    let l = list(dir);
    (l.iter().map(|f| f.bytes).sum(), l.len())
}

/// Remove the oldest rotated files until the directory fits in `cap`.
pub fn enforce_cap(dir: &Path, cap: u64) {
    let files = list(dir);
    let mut total: u64 = files.iter().map(|f| f.bytes).sum();
    for f in files.iter().filter(|f| !f.active) {
        if total <= cap {
            break;
        }
        if fs::remove_file(&f.path).is_ok() {
            total = total.saturating_sub(f.bytes);
        }
    }
}

/// Read a log file as text, decompressing a rotated one.
pub fn read_text(path: &Path) -> io::Result<String> {
    let raw = fs::read(path)?;
    let bytes = if path.extension().map(|e| e == "zst").unwrap_or(false) {
        zstd::decode_all(&raw[..])?
    } else {
        raw
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A minimal ustar writer for the diagnostics bundle.
pub struct TarWriter<W: Write> {
    out: W,
}

impl<W: Write> TarWriter<W> {
    pub fn new(out: W) -> Self {
        TarWriter { out }
    }

    /// Add one regular file (mode 0600). `name` must be under 100 bytes.
    pub fn add(&mut self, name: &str, data: &[u8], mtime: u64) -> io::Result<()> {
        let name = name.as_bytes();
        if name.len() >= 100 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        fn octal(field: &mut [u8], v: u64) {
            let s = format!("{:0width$o}\0", v, width = field.len() - 1);
            field.copy_from_slice(s.as_bytes());
        }
        octal(&mut h[100..108], 0o600);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], data.len() as u64);
        octal(&mut h[136..148], mtime);
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        self.out.write_all(&h)?;
        self.out.write_all(data)?;
        let pad = (512 - data.len() % 512) % 512;
        self.out.write_all(&vec![0u8; pad])?;
        Ok(())
    }

    /// End the archive and hand back the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.out.write_all(&[0u8; 1024])?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_compresses_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let rot = Rotation {
            max_file_bytes: 4096,
            keep: 2,
            total_cap_bytes: 1 << 20,
            compress: true,
        };
        let mut s = Sink::new(dir.path(), "test", rot);
        let line = format!("{}\n", "x".repeat(99));
        for _ in 0..200 {
            s.push(line.as_bytes(), true);
        }
        s.flush();
        let names: Vec<String> = list(dir.path())
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"varsto-test.log".to_string()), "{names:?}");
        assert!(names.contains(&"varsto-test.1.log.zst".to_string()), "{names:?}");
        assert!(names.contains(&"varsto-test.2.log.zst".to_string()), "{names:?}");
        assert!(!names.iter().any(|n| n.contains(".3.")), "{names:?}");
        assert!(fs::metadata(active_path(dir.path(), "test")).unwrap().len() <= 4096);
        let text = read_text(&dir.path().join("varsto-test.1.log.zst")).unwrap();
        assert!(text.lines().all(|l| l == "x".repeat(99)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = fs::metadata(active_path(dir.path(), "test")).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        // The cap removes rotated files, never the active one.
        enforce_cap(dir.path(), 1);
        let left = list(dir.path());
        assert_eq!(left.len(), 1);
        assert!(left[0].active);
    }

    #[test]
    fn tar_is_readable() {
        let mut t = TarWriter::new(Vec::new());
        t.add("a/b.txt", b"hello", 0).unwrap();
        let out = t.finish().unwrap();
        assert_eq!(out.len(), 512 + 512 + 1024);
        assert_eq!(&out[512..517], b"hello");
        assert_eq!(&out[257..262], b"ustar");
    }
}
