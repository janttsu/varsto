// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Removable-disk pool (plan 6.35 and 6.41, "offline disk pool").
//!
//! A pool is one storage made of disks that come and go. Every disk is a
//! local directory with an identity: a marker file `<mount>/.varsto-disk.json`
//! names the pool and the disk and carries a keyed tag of the vault, so a disk
//! found anywhere can be recognised without revealing which vault it belongs
//! to. Objects live under `<mount>/varsto/` in the same layout as any
//! local-directory storage, so a disk is readable with the format document
//! alone. The pool never formats or mounts anything.
//!
//! The device keeps a pool index (`<home>/pool-<pool id>.json`) that maps every
//! object to the disk that holds it, remembers deletions queued for disks that
//! were away, and carries the disk registry. Each disk also carries its own
//! index (`<mount>/varsto/index.json`) so another device of the vault can adopt
//! a disk it has never seen: the pool id is derived from the vault key and the
//! pool name, so every device computes the same one.
//!
//! Attach detection reads one small file per candidate: the disk's last mount
//! path first, then the platform's mount roots (`/media/*/*`, `/run/media/*/*`
//! and `/mnt/*` on Linux, `/Volumes/*` on macOS, every drive letter on
//! Windows) and any extra roots configured on the pool.
//!
//! Every object written to a disk is read back from the disk and hashed
//! before the write counts (`write_checked`), and the pool index remembers
//! per copy when it was last hashed, so the reattach routine re-reads only
//! the copies whose check is older than the pool's `verify_after_days`.
//! Preparing whole devices (partitioning, formatting, mounting) lives in
//! `blockdev`; this module only sees mounted directories.

use crate::storage::{Storage, StorageSpec};
use crate::util;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

/// Marker file at the root of every disk.
pub const MARKER_FILE: &str = ".varsto-disk.json";
/// Directory on the disk that holds the objects (and the disk's own index).
pub const DATA_DIR: &str = "varsto";
/// The disk's own index, inside `DATA_DIR`.
pub const DISK_INDEX_FILE: &str = "index.json";
pub const MARKER_FORMAT: u32 = 1;
pub const DEFAULT_RESERVE_PERCENT: u32 = 5;
pub const DEFAULT_MIN_RESERVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Copies on a disk are re-hashed when their last check is older than this.
pub const DEFAULT_VERIFY_AFTER_DAYS: u32 = 180;
/// Leftover temporary files of interrupted writes older than this are removed.
const STALE_TEMP_SECS: u64 = 3600;

/// One disk of a pool, as kept in the storage specification and the pool index.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct PoolDisk {
    /// Random 128-bit identifier (hex).
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub last_mount: Option<PathBuf>,
    #[serde(default)]
    pub capacity_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub last_seen_utc: i64,
    #[serde(default)]
    pub last_verified_utc: i64,
    /// A retired disk receives nothing new; what it holds stays readable.
    #[serde(default)]
    pub retired: bool,
    /// Where the disk is kept ("home", "offsite", ...): empty means the
    /// pool's place. Disk groups keep copies on disks in different places.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub place: String,
    /// Free bytes of the disk's file system at the last measurement
    /// (statvfs), next to `capacity_bytes`.
    #[serde(default)]
    pub free_bytes: u64,
    /// When `capacity_bytes` and `free_bytes` were last measured: at every
    /// attach, add, insert, check, fill and eject (0: never).
    #[serde(default)]
    pub space_measured_utc: i64,
    /// When a write to the disk last read back wrong twice
    /// (`PoolError::WriteNotVerified`); cleared by a later write that reads
    /// back right. 0: never.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub write_failed_utc: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// `<mount>/.varsto-disk.json`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DiskMarker {
    pub pool_id: String,
    pub disk_id: String,
    pub label: String,
    /// Keyed hash of the vault id under a key derived from the vault key:
    /// the marker does not reveal the vault, but every device of the vault
    /// recognises its own disks.
    pub vault_tag: String,
    pub created_utc: i64,
    pub format: u32,
}

impl DiskMarker {
    pub fn path(mount: &Path) -> PathBuf {
        mount.join(MARKER_FILE)
    }
    pub fn read(mount: &Path) -> Option<DiskMarker> {
        let bytes = fs::read(Self::path(mount)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// `<mount>/varsto/index.json`: what the disk holds, written at eject, check
/// and after writes, so another device can adopt the disk.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct DiskIndex {
    pub format: u32,
    pub pool_id: String,
    pub disk_id: String,
    pub label: String,
    pub written_utc: i64,
    /// Object key -> size in bytes.
    pub objects: BTreeMap<String, u64>,
    /// The disk's place, when it has one of its own.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub place: String,
}

impl DiskIndex {
    pub fn path(mount: &Path) -> PathBuf {
        mount.join(DATA_DIR).join(DISK_INDEX_FILE)
    }
    pub fn read(mount: &Path) -> Option<DiskIndex> {
        let bytes = fs::read(Self::path(mount)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ObjectEntry {
    disk: String,
    size: u64,
    /// Further disks holding a copy (disk groups, `copies` > 1). Versions
    /// before disk groups ignore them and know the first copy only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extra: Vec<String>,
    /// Disk id -> when the copy on that disk was last read back and hashed
    /// (at its write or by a check). A copy missing here was never checked
    /// by this device.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    checked: BTreeMap<String, i64>,
}

impl ObjectEntry {
    fn new(disk: &str, size: u64) -> Self {
        ObjectEntry {
            disk: disk.to_string(),
            size,
            extra: Vec::new(),
            checked: BTreeMap::new(),
        }
    }

    /// Every disk holding a copy, the first one first.
    fn holders(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.disk).chain(self.extra.iter())
    }

    fn held_by(&self, disk: &str) -> bool {
        self.holders().any(|d| d == disk)
    }

    /// Forget the copy on `disk`; false when no copy is left.
    fn remove_holder(&mut self, disk: &str) -> bool {
        self.extra.retain(|d| d != disk);
        self.checked.remove(disk);
        if self.disk == disk {
            if self.extra.is_empty() {
                return false;
            }
            self.disk = self.extra.remove(0);
        }
        true
    }
}

/// `<home>/pool-<pool id>.json`.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct PoolIndex {
    #[serde(default)]
    format: u32,
    #[serde(default)]
    pool_id: String,
    #[serde(default)]
    objects: BTreeMap<String, ObjectEntry>,
    /// Disk id -> (object key -> size) of deletions to apply at the next attach.
    #[serde(default)]
    pending_deletes: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default)]
    disks: BTreeMap<String, PoolDisk>,
}

/// Typed errors the engine recognises (`anyhow::Error::chain` + downcast).
#[derive(Debug, thiserror::Error, Clone, Serialize)]
pub enum PoolError {
    /// The object is on a disk that is not attached right now.
    #[error("attach disk {label} ({place})")]
    NeedsDisk {
        label: String,
        disk_id: String,
        place: String,
    },
    #[error("no disk of pool {pool} is attached")]
    NoDiskAttached { pool: String },
    #[error("no attached disk of pool {pool} has room for {size} bytes within its reserve")]
    NoRoom { pool: String, size: u64 },
    /// An object written to the disk read back wrong twice: the disk (or its
    /// cable or dock) is failing and nothing more should go to it.
    #[error("disk {label} returned different bytes than were written to it, twice ({key}): the disk, its cable or dock may be failing")]
    WriteNotVerified { label: String, key: String },
}

/// The first `PoolError` in an error chain, if any.
pub fn pool_error(e: &anyhow::Error) -> Option<&PoolError> {
    e.chain().find_map(|c| c.downcast_ref::<PoolError>())
}

/// Identity of a pool as derived by the engine from the vault key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolIdentity {
    pub pool_id: String,
    pub vault_tag: String,
}

/// Free and total bytes of the filesystem holding a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskSpace {
    pub free: u64,
    pub total: u64,
}

static FAKE_SPACE: RwLock<Vec<(PathBuf, DiskSpace)>> = RwLock::new(Vec::new());

/// Test hook: report `space` for `mount` (and paths below it) instead of
/// asking the operating system. Tests use it to simulate small disks.
#[doc(hidden)]
pub fn set_fake_space(mount: &Path, space: Option<DiskSpace>) {
    // Keyed by the canonical path: mounts are stored canonicalised (macOS turns
    // /var/... into /private/var/...).
    let mount = mount.canonicalize().unwrap_or_else(|_| mount.to_path_buf());
    let mount = mount.as_path();
    let mut v = FAKE_SPACE.write().unwrap();
    v.retain(|(p, _)| p != mount);
    if let Some(s) = space {
        v.push((mount.to_path_buf(), s));
    }
}

static FAKE_CAPACITY: RwLock<Vec<(PathBuf, u64)>> = RwLock::new(Vec::new());

/// Test hook: a disk of `total` bytes at `mount` whose free space falls as
/// Varsto's objects are written below it (`varsto/chunks`), like a real
/// disk filling up. `None` removes it.
#[doc(hidden)]
pub fn set_fake_capacity(mount: &Path, total: Option<u64>) {
    let mount = mount.canonicalize().unwrap_or_else(|_| mount.to_path_buf());
    let mut v = FAKE_CAPACITY.write().unwrap();
    v.retain(|(p, _)| p != &mount);
    if let Some(t) = total {
        v.push((mount, t));
    }
}

/// Bytes of the files below `dir`.
fn tree_bytes(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => tree_bytes(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Free and total space of the filesystem at `path`.
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    {
        let v = FAKE_CAPACITY.read().unwrap();
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if let Some((mount, total)) = v.iter().find(|(p, _)| canon.starts_with(p)) {
            let used = tree_bytes(&mount.join(DATA_DIR).join("chunks"));
            return Some(DiskSpace {
                free: total.saturating_sub(used),
                total: *total,
            });
        }
    }
    {
        let v = FAKE_SPACE.read().unwrap();
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if let Some((_, s)) = v
            .iter()
            .find(|(p, _)| path.starts_with(p) || canon.starts_with(p))
        {
            return Some(*s);
        }
    }
    os_disk_space(path)
}

#[cfg(unix)]
fn os_disk_space(path: &Path) -> Option<DiskSpace> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    let frsize = if st.f_frsize > 0 {
        st.f_frsize as u64
    } else {
        st.f_bsize as u64
    };
    Some(DiskSpace {
        free: st.f_bavail as u64 * frsize,
        total: st.f_blocks as u64 * frsize,
    })
}

#[cfg(windows)]
fn os_disk_space(path: &Path) -> Option<DiskSpace> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
    if ok == 0 {
        return None;
    }
    Some(DiskSpace { free: avail, total })
}

#[cfg(not(any(unix, windows)))]
fn os_disk_space(_path: &Path) -> Option<DiskSpace> {
    None
}

static CORRUPT_WRITES: Mutex<Vec<(PathBuf, u32)>> = Mutex::new(Vec::new());

/// Test hook: damage the next `n` objects written below `mount` after they
/// reach the disk and before they are read back, as a failing disk would.
#[doc(hidden)]
pub fn corrupt_writes_under(mount: &Path, n: u32) {
    let mount = mount.canonicalize().unwrap_or_else(|_| mount.to_path_buf());
    let mut v = CORRUPT_WRITES.lock().unwrap();
    v.retain(|(p, _)| p != &mount);
    if n > 0 {
        v.push((mount, n));
    }
}

fn take_corruption(path: &Path) -> bool {
    let mut v = CORRUPT_WRITES.lock().unwrap();
    if v.is_empty() {
        return false;
    }
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    for (p, n) in v.iter_mut() {
        if *n > 0 && canon.starts_with(p.as_path()) {
            *n -= 1;
            return true;
        }
    }
    false
}

/// Record a disk's capacity and free space as measured now (statvfs).
/// Returns false when the file system could not be asked.
fn measure(d: &mut PoolDisk, mount: &Path, now: i64) -> bool {
    let Some(sp) = disk_space(mount) else {
        return false;
    };
    d.capacity_bytes = sp.total;
    d.free_bytes = sp.free;
    d.space_measured_utc = now;
    true
}

/// The object name a key ends with, when it is one (64 hex digits).
fn object_name_of(key: &str) -> Option<&str> {
    let name = key.rsplit('/').next()?;
    (name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())).then_some(name)
}

/// BLAKE3 of a file as the disk returns it, not as the page cache remembers
/// it. On Linux the file's cached pages are dropped first
/// (`posix_fadvise(POSIX_FADV_DONTNEED)`) and the file is read with
/// `O_DIRECT` (aligned buffer), falling back to a plain read where the
/// filesystem refuses direct reads. Both are best effort: neither reaches
/// past the drive's own cache, so a drive that acknowledges a write it then
/// loses is caught by the next periodic check, not here. Elsewhere the file
/// is read normally.
pub fn read_back_hash(path: &Path) -> std::io::Result<[u8; 32]> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        if let Ok(f) = fs::File::open(path) {
            // SAFETY: plain advice call on an open descriptor.
            unsafe {
                libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
            }
        }
        if let Ok(f) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(path)
        {
            if let Ok(h) = hash_direct(f) {
                return Ok(h);
            }
        }
    }
    let mut f = fs::File::open(path)?;
    let mut h = blake3::Hasher::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(*h.finalize().as_bytes())
}

/// Hash a file opened with `O_DIRECT`: reads into a 4 KiB-aligned buffer of
/// a whole number of blocks; the last read is short at the end of the file.
#[cfg(target_os = "linux")]
fn hash_direct(mut f: fs::File) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    const ALIGN: usize = 4096;
    const LEN: usize = 1 << 20;
    let mut raw = vec![0u8; LEN + ALIGN];
    let off = raw.as_ptr().align_offset(ALIGN);
    let buf = &mut raw[off..off + LEN];
    let mut h = blake3::Hasher::new();
    loop {
        let n = f.read(buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        if n % ALIGN != 0 {
            // A short, unaligned read is the end of the file.
            break;
        }
    }
    Ok(*h.finalize().as_bytes())
}

/// Write an object to a disk and prove it is there: temporary file, fsync,
/// rename, fsync of the directory (`util::write_atomic`), then read it back
/// from the disk (`read_back_hash`) and compare with the object name (or,
/// for a key that is not an object name, the hash of `data`). A mismatch
/// deletes the file and writes once more; a second mismatch fails with
/// `PoolError::WriteNotVerified`.
fn write_checked(path: &Path, key: &str, data: &[u8], label: &str) -> Result<()> {
    let want = match object_name_of(key) {
        Some(n) => n.to_ascii_lowercase(),
        None => hex::encode(crate::crypto::hash(data)),
    };
    for _ in 0..2 {
        util::write_atomic(path, data)?;
        if take_corruption(path) {
            let mut b = fs::read(path)?;
            if let Some(x) = b.first_mut() {
                *x ^= 0xff;
            }
            fs::write(path, b)?;
        }
        match read_back_hash(path) {
            Ok(h) if hex::encode(h) == want => return Ok(()),
            _ => {
                let _ = fs::remove_file(path);
            }
        }
    }
    Err(anyhow::Error::new(PoolError::WriteNotVerified {
        label: label.to_string(),
        key: key.to_string(),
    }))
}

/// Where removable media appears on this platform: (root, depth). Depth 0
/// means the root itself is the candidate, 1 its children, 2 its grandchildren.
pub fn platform_mount_roots() -> Vec<(PathBuf, usize)> {
    if cfg!(target_os = "macos") {
        vec![(PathBuf::from("/Volumes"), 1)]
    } else if cfg!(windows) {
        (b'A'..=b'Z')
            .map(|c| (PathBuf::from(format!("{}:\\", c as char)), 0))
            .collect()
    } else {
        vec![
            (PathBuf::from("/media"), 2),
            (PathBuf::from("/run/media"), 2),
            (PathBuf::from("/mnt"), 1),
        ]
    }
}

fn children(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

/// Every marker found under the given roots: (mount path, marker). Reads one
/// small file per candidate directory and nothing else.
pub fn scan_mounts(roots: &[(PathBuf, usize)]) -> Vec<(PathBuf, DiskMarker)> {
    let mut out = Vec::new();
    for (root, depth) in roots {
        let mut level = vec![root.clone()];
        for _ in 0..*depth {
            level = level.iter().flat_map(|d| children(d)).collect();
        }
        for cand in level {
            if let Some(m) = DiskMarker::read(&cand) {
                if !out.iter().any(|(p, _)| p == &cand) {
                    out.push((cand, m));
                }
            }
        }
    }
    out
}

/// Summary of one disk for listings (`varsto disk list`, `/api/disks`).
#[derive(Clone, Debug, Serialize)]
pub struct DiskStatus {
    pub pool: String,
    /// The disk's place (its own, or the pool's).
    pub place: String,
    pub label: String,
    pub disk_id: String,
    pub attached: bool,
    pub mount: Option<PathBuf>,
    pub free_bytes: Option<u64>,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub objects: u64,
    pub last_seen_utc: i64,
    pub last_verified_utc: i64,
    pub pending_deletes: u64,
    pub retired: bool,
    /// Bytes the pool keeps free on the disk (`reserve(capacity_bytes)`).
    pub reserve_bytes: u64,
    /// When `capacity_bytes` and `free_bytes` were measured (0: never).
    /// `free_bytes` is live for an attached disk and the last measurement
    /// for one that is away.
    pub space_measured_utc: i64,
    /// Bytes of the deletions queued for the disk.
    pub pending_delete_bytes: u64,
    /// Bytes waiting to be freed at the next insert: the queued deletions
    /// plus `unneeded_bytes` when known.
    pub reclaimable_bytes: u64,
    /// The pool's `verify_after_days`.
    pub verify_after_days: u32,
    /// Oldest per-copy check on the disk (`Some(0)`: a copy was never
    /// checked here; `None`: the disk holds nothing).
    pub oldest_check_utc: Option<i64>,
    /// Copies whose last check is older than `verify_after_days` (or that
    /// were never checked), their bytes, and their share of all copies.
    pub copies_overdue: u64,
    pub bytes_overdue: u64,
    pub overdue_share: f64,
    /// See `PoolDisk::write_failed_utc`.
    pub write_failed_utc: i64,
    /// The disk should not be suggested: its last file system check left
    /// errors or failed, or a write read back wrong twice.
    pub failing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_reason: Option<String>,
    /// The last forced file system check of the disk's partition
    /// (`disk-checks.json`), when this device knows its partition.
    pub fsck: Option<crate::blockdev::FsckOutcome>,
    /// Facts that need the ledger (`BookInput`); `None` in the cheap listing.
    /// Copies on the disk the ledger no longer wants on this pool.
    pub unneeded_objects: Option<u64>,
    pub unneeded_bytes: Option<u64>,
    /// Objects of which this disk holds the only copy anywhere (no other
    /// disk, no other storage), their bytes, and how many of them are overdue.
    pub only_copy_objects: Option<u64>,
    pub only_copy_bytes: Option<u64>,
    pub only_copy_overdue: Option<u64>,
    /// Bytes the pool lacks that this disk could take (first copies, and
    /// further copies its place lacks under a disk group rule), and how
    /// much of that fits: `min(free - reserve, lacking)` (0 when retired).
    pub lacking_bytes: Option<u64>,
    pub fill_potential_bytes: Option<u64>,
    /// Objects on the disk that a queued repair needs.
    pub repair_objects: Option<u64>,
    /// Objects (and bytes) a pending step of the fetch plan reads from it.
    pub fetch_objects: Option<u64>,
    pub fetch_bytes: Option<u64>,
}

/// What the ledger knows, for the per-disk facts of `statuses_with`.
#[derive(Default)]
pub struct BookInput<'a> {
    /// Object names (lower-case hex) the ledger still wants on this pool;
    /// `None`: not known, nothing counts as unneeded.
    pub wanted: Option<&'a std::collections::HashSet<String>>,
    /// Object names with a copy on a storage other than this pool.
    pub elsewhere: Option<&'a std::collections::HashSet<String>>,
    /// Object names a queued repair needs.
    pub repair: Option<&'a std::collections::HashSet<String>>,
    /// Disk id -> object keys a pending fetch plan step reads from it.
    pub fetch: Option<&'a BTreeMap<String, Vec<String>>>,
    /// Bytes of blocks of current files placed on this pool that it holds
    /// on no disk (any disk can take them).
    pub first_copy_bytes: u64,
    /// Object keys of current files: further copies under a disk group
    /// rule are counted for these only (`None`: every object of the index).
    pub current: Option<&'a std::collections::HashSet<String>>,
}

/// Where an object of the pool is.
#[derive(Clone, Debug)]
pub struct ObjectLocation {
    pub disk_id: String,
    pub label: String,
    /// The disk's place (its own, or the pool's).
    pub place: String,
    pub attached: bool,
    pub last_verified_utc: i64,
    pub size: u64,
}

/// Result of `verify_disk`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct VerifyOutcome {
    pub objects_checked: u64,
    pub bytes_checked: u64,
    /// Objects whose size or hash did not match; removed from the index.
    pub bad: Vec<String>,
    /// Objects the index listed but the disk no longer has; removed from the index.
    pub missing: Vec<String>,
    /// Objects found on the disk that the index did not know; adopted.
    pub adopted: u64,
    /// Keys whose copy hashed right (for `chunk_verified` events).
    #[serde(skip)]
    pub verified_keys: Vec<String>,
}

/// Result of `tidy_disk` (listings only, nothing read).
#[derive(Clone, Debug, Default, Serialize)]
pub struct TidyOutcome {
    /// Deletions queued while the disk was away, applied now.
    pub pending_removed: u64,
    pub pending_bytes: u64,
    /// Files on the disk that the vault no longer references.
    pub unneeded_removed: u64,
    pub unneeded_bytes: u64,
    /// Temporary files of writes that never finished.
    pub temp_removed: u64,
    /// Copies the index placed on the disk that are gone (forgotten).
    pub missing: Vec<String>,
    /// Copies at the wrong size (removed and forgotten).
    pub bad: Vec<String>,
    /// Files the vault references that the index did not place here; their
    /// first check is due at once.
    pub adopted: u64,
}

struct State {
    index: PoolIndex,
    /// Disk id -> mount, computed once per instance.
    attached: Option<BTreeMap<String, PathBuf>>,
    /// Disks whose on-disk index must be rewritten.
    dirty: BTreeSet<String>,
    /// The disk the last put went to: the next one goes there too while it
    /// has room, so the blocks of one file stay together on one disk.
    last_put: Option<String>,
}

pub struct PoolStorage {
    name: String,
    place: String,
    /// Copies of every object on disks in different places (disk group rule).
    copies: u32,
    identity: PoolIdentity,
    reserve_percent: u32,
    min_reserve_bytes: u64,
    verify_after_days: u32,
    scan_roots: Vec<PathBuf>,
    index_path: PathBuf,
    state: Mutex<State>,
    /// How verification reads a disk (`crate::parverify`); auto: by the medium.
    verify_parallelism: crate::parverify::Parallelism,
}

impl PoolStorage {
    /// Open the pool described by `spec` (a `StorageSpec::Pool`) with the
    /// device directory `home` and the identity the engine derived.
    pub fn open(spec: &StorageSpec, home: &Path, identity: PoolIdentity) -> Result<PoolStorage> {
        let StorageSpec::Pool {
            name,
            place: _,
            reserve_percent,
            min_reserve_bytes,
            disks,
            scan_roots,
            copies,
            verify_after_days,
        } = spec
        else {
            bail!("storage {} is not a disk pool", spec.name());
        };
        let index_path = home.join(format!("pool-{}.json", identity.pool_id));
        let mut index: PoolIndex = util::read_json_or_default(&index_path)?;
        index.format = 1;
        index.pool_id = identity.pool_id.clone();
        for d in disks {
            index.disks.entry(d.id.clone()).or_insert_with(|| d.clone());
        }
        Ok(PoolStorage {
            name: name.clone(),
            place: spec.place(),
            copies: (*copies).max(1),
            identity,
            reserve_percent: *reserve_percent,
            min_reserve_bytes: *min_reserve_bytes,
            verify_after_days: *verify_after_days,
            scan_roots: scan_roots.clone(),
            index_path,
            state: Mutex::new(State {
                index,
                attached: None,
                dirty: BTreeSet::new(),
                last_put: None,
            }),
            verify_parallelism: crate::parverify::Parallelism::Auto,
        })
    }

    /// How verification reads this pool's disks (the device's setting).
    pub fn with_verify_parallelism(mut self, p: crate::parverify::Parallelism) -> Self {
        self.verify_parallelism = p;
        self
    }

    /// How verification reads one mounted disk: by its medium (one reader,
    /// in order, on a spinning disk) unless the setting says otherwise.
    pub fn disk_lane(&self, mount: &Path) -> crate::parverify::LanePlan {
        crate::parverify::lane_plan(crate::media::storage_media(mount), self.verify_parallelism)
    }

    pub fn identity(&self) -> &PoolIdentity {
        &self.identity
    }

    pub fn place(&self) -> &str {
        &self.place
    }

    /// Copies of every object the disk group rule asks for (1: no rule).
    pub fn copies(&self) -> u32 {
        self.copies
    }

    /// Copies whose last check is older than this many days are re-hashed
    /// when their disk is inserted (0: every copy, every time).
    pub fn verify_after_days(&self) -> u32 {
        self.verify_after_days
    }

    /// A disk's place: its own, or the pool's.
    pub fn disk_place(&self, disk: &PoolDisk) -> String {
        if disk.place.is_empty() {
            self.place.clone()
        } else {
            disk.place.clone()
        }
    }

    fn place_of(&self, st: &State, disk_id: &str) -> String {
        st.index
            .disks
            .get(disk_id)
            .map(|d| self.disk_place(d))
            .unwrap_or_else(|| self.place.clone())
    }

    /// The distinct places that hold a copy of `entry`.
    fn places_holding(&self, st: &State, entry: &ObjectEntry) -> BTreeSet<String> {
        entry.holders().map(|d| self.place_of(st, d)).collect()
    }

    /// Bytes that must stay free on a disk of `total` bytes.
    pub fn reserve(&self, total: u64) -> u64 {
        (total / 100)
            .saturating_mul(self.reserve_percent as u64)
            .max(self.min_reserve_bytes)
    }

    fn save_index(&self, st: &State) -> Result<()> {
        util::write_json(&self.index_path, &st.index)
    }

    fn data_path(mount: &Path, key: &str) -> Result<PathBuf> {
        crate::storage::validate_key(key)?;
        Ok(mount.join(DATA_DIR).join(key))
    }

    fn marker_matches(&self, mount: &Path, disk_id: &str) -> bool {
        DiskMarker::read(mount)
            .is_some_and(|m| m.pool_id == self.identity.pool_id && m.disk_id == disk_id)
    }

    fn roots(&self) -> Vec<(PathBuf, usize)> {
        let mut roots = platform_mount_roots();
        for r in &self.scan_roots {
            roots.push((r.clone(), 1));
        }
        roots
    }

    /// Disk id -> mount for every disk attached right now. Computed once per
    /// instance; adopts unknown disks of this pool and vault on the way.
    fn attached(&self, st: &mut State) -> BTreeMap<String, PathBuf> {
        if let Some(a) = &st.attached {
            return a.clone();
        }
        let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
        for (id, d) in &st.index.disks {
            if let Some(m) = &d.last_mount {
                if self.marker_matches(m, id) {
                    found.insert(id.clone(), m.clone());
                }
            }
        }
        let mut changed = false;
        for (mount, marker) in scan_mounts(&self.roots()) {
            if marker.pool_id != self.identity.pool_id {
                continue;
            }
            if st.index.disks.contains_key(&marker.disk_id) {
                found.entry(marker.disk_id.clone()).or_insert(mount);
            } else if marker.vault_tag == self.identity.vault_tag {
                self.adopt(st, &mount, &marker);
                found.insert(marker.disk_id.clone(), mount);
                changed = true;
            }
        }
        let now = util::now_utc();
        for (id, mount) in &found {
            if let Some(d) = st.index.disks.get_mut(id) {
                if d.last_mount.as_ref() != Some(mount) {
                    d.last_mount = Some(mount.clone());
                    changed = true;
                }
                if now - d.last_seen_utc > 60 {
                    d.last_seen_utc = now;
                    changed = true;
                }
                // Free space while attached, at most once a minute.
                let stale = now - d.space_measured_utc > 60;
                if (stale || disk_space(mount).is_some_and(|sp| sp.total != d.capacity_bytes))
                    && measure(d, mount, now)
                {
                    changed = true;
                }
            }
        }
        if changed {
            let _ = self.save_index(st);
        }
        st.attached = Some(found.clone());
        found
    }

    /// Learn a disk of this pool that another device filled: its registry
    /// entry and the objects its own index lists.
    fn adopt(&self, st: &mut State, mount: &Path, marker: &DiskMarker) {
        let idx = DiskIndex::read(mount).unwrap_or_default();
        let mut used = 0u64;
        for (key, size) in &idx.objects {
            // A disk's own index is a claim: count only objects that are
            // really there, under a key that stays inside the data directory.
            let present = Self::data_path(mount, key)
                .ok()
                .and_then(|p| fs::metadata(p).ok())
                .is_some_and(|md| md.len() == *size);
            if !present {
                continue;
            }
            used += size;
            match st.index.objects.get_mut(key) {
                Some(e) => {
                    if !e.held_by(&marker.disk_id) {
                        e.extra.push(marker.disk_id.clone());
                    }
                }
                None => {
                    st.index
                        .objects
                        .insert(key.clone(), ObjectEntry::new(&marker.disk_id, *size));
                }
            }
        }
        let mut disk = PoolDisk {
            id: marker.disk_id.clone(),
            label: marker.label.clone(),
            last_mount: Some(mount.to_path_buf()),
            used_bytes: used,
            last_seen_utc: util::now_utc(),
            place: idx.place.clone(),
            ..Default::default()
        };
        measure(&mut disk, mount, util::now_utc());
        st.index.disks.insert(marker.disk_id.clone(), disk);
    }

    /// The attached, non-retired disk with the most free space that keeps its
    /// reserve after writing `size` bytes.
    fn choose_disk(&self, st: &mut State, size: u64) -> Result<(String, PathBuf)> {
        self.choose_disk_outside(st, size, &BTreeSet::new())
    }

    /// Like `choose_disk`, among disks whose place is not in `taken`.
    fn choose_disk_outside(
        &self,
        st: &mut State,
        size: u64,
        taken: &BTreeSet<String>,
    ) -> Result<(String, PathBuf)> {
        let attached = self.attached(st);
        let mut best: Option<(u64, String, PathBuf)> = None;
        let mut any = false;
        for (id, mount) in &attached {
            let Some(d) = st.index.disks.get(id) else {
                continue;
            };
            if d.retired || taken.contains(&self.disk_place(d)) {
                continue;
            }
            any = true;
            let Some(sp) = disk_space(mount) else {
                continue;
            };
            if sp.free < size.saturating_add(self.reserve(sp.total)) {
                continue;
            }
            if st.last_put.as_deref() == Some(id.as_str()) {
                // Stay on the disk that took the previous block.
                best = Some((u64::MAX, id.clone(), mount.clone()));
            } else if best.as_ref().is_none_or(|(f, _, _)| sp.free > *f) {
                best = Some((sp.free, id.clone(), mount.clone()));
            }
        }
        match best {
            Some((_, id, mount)) => Ok((id, mount)),
            None if !any => Err(anyhow::Error::new(PoolError::NoDiskAttached {
                pool: self.name.clone(),
            })),
            None => Err(anyhow::Error::new(PoolError::NoRoom {
                pool: self.name.clone(),
                size,
            })),
        }
    }

    fn write_object(
        &self,
        st: &mut State,
        disk_id: &str,
        mount: &Path,
        key: &str,
        data: &[u8],
    ) -> Result<()> {
        let path = Self::data_path(mount, key)?;
        let label = st
            .index
            .disks
            .get(disk_id)
            .map(|d| d.label.clone())
            .unwrap_or_default();
        if let Err(e) = write_checked(&path, key, data, &label) {
            if matches!(pool_error(&e), Some(PoolError::WriteNotVerified { .. })) {
                if let Some(d) = st.index.disks.get_mut(disk_id) {
                    d.write_failed_utc = util::now_utc();
                }
                let _ = self.save_index(st);
            }
            return Err(e);
        }
        let now = util::now_utc();
        match st.index.objects.get_mut(key) {
            Some(e) => {
                if !e.held_by(disk_id) {
                    e.extra.push(disk_id.to_string());
                }
                e.checked.insert(disk_id.to_string(), now);
            }
            None => {
                let mut e = ObjectEntry::new(disk_id, data.len() as u64);
                e.checked.insert(disk_id.to_string(), now);
                st.index.objects.insert(key.to_string(), e);
            }
        }
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes += data.len() as u64;
            d.write_failed_utc = 0;
        }
        st.dirty.insert(disk_id.to_string());
        self.save_index(st)
    }

    /// Measure an attached disk's space now and keep it in the index.
    fn measure_now(st: &mut State, disk_id: &str, mount: &Path) {
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            measure(d, mount, util::now_utc());
        }
    }

    /// Bytes that can still go to an attached disk within its reserve.
    pub fn room(&self, disk_id: &str) -> Option<u64> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let sp = disk_space(attached.get(disk_id)?)?;
        Some(sp.free.saturating_sub(self.reserve(sp.total)))
    }

    /// Would `size` more bytes fit on the disk within its reserve?
    pub fn has_room(&self, disk_id: &str, size: u64) -> bool {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id) else {
            return false;
        };
        disk_space(mount).is_some_and(|sp| sp.free >= size.saturating_add(self.reserve(sp.total)))
    }

    /// Write `key` to one specific attached disk (used when filling a disk).
    /// Returns false when the pool already holds the object.
    pub fn put_on_disk(&self, disk_id: &str, key: &str, data: &[u8]) -> Result<bool> {
        let mut st = self.state.lock().unwrap();
        if st.index.objects.contains_key(key) {
            return Ok(false);
        }
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id).cloned() else {
            let d = st.index.disks.get(disk_id);
            return Err(anyhow::Error::new(PoolError::NeedsDisk {
                label: d.map(|d| d.label.clone()).unwrap_or_default(),
                disk_id: disk_id.to_string(),
                place: self.place.clone(),
            }));
        };
        let Some(sp) = disk_space(&mount) else {
            bail!("cannot read the free space of {}", mount.display());
        };
        if sp.free < (data.len() as u64).saturating_add(self.reserve(sp.total)) {
            return Err(anyhow::Error::new(PoolError::NoRoom {
                pool: self.name.clone(),
                size: data.len() as u64,
            }));
        }
        self.write_object(&mut st, disk_id, &mount, key, data)?;
        Ok(true)
    }

    /// Whether the disk group rule wants a copy of `key` on `disk_id`: the
    /// pool holds fewer copies in different places than `copies`, the disk
    /// holds none, and no copy is in the disk's place yet. Objects the pool
    /// does not hold at all are wanted too.
    pub fn wants_copy(&self, disk_id: &str, key: &str) -> bool {
        let st = self.state.lock().unwrap();
        let Some(e) = st.index.objects.get(key) else {
            return true;
        };
        if e.held_by(disk_id) {
            return false;
        }
        let places = self.places_holding(&st, e);
        (places.len() as u32) < self.copies && !places.contains(&self.place_of(&st, disk_id))
    }

    /// Write a further copy of `key` to one attached disk (disk groups).
    /// Returns false when that disk already holds it.
    pub fn add_copy_on_disk(&self, disk_id: &str, key: &str, data: &[u8]) -> Result<bool> {
        {
            let st = self.state.lock().unwrap();
            match st.index.objects.get(key) {
                None => {
                    drop(st);
                    return self.put_on_disk(disk_id, key, data);
                }
                Some(e) if e.held_by(disk_id) => return Ok(false),
                Some(_) => {}
            }
        }
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id).cloned() else {
            bail!("disk is not attached");
        };
        let Some(sp) = disk_space(&mount) else {
            bail!("cannot read the free space of {}", mount.display());
        };
        if sp.free < (data.len() as u64).saturating_add(self.reserve(sp.total)) {
            return Err(anyhow::Error::new(PoolError::NoRoom {
                pool: self.name.clone(),
                size: data.len() as u64,
            }));
        }
        self.write_object(&mut st, disk_id, &mount, key, data)?;
        Ok(true)
    }

    /// Set a disk's place ("" returns it to the pool's place).
    pub fn set_disk_place(&self, disk_id: &str, place: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let d = st
            .index
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| anyhow!("unknown disk"))?;
        d.place = place.trim().to_string();
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)
    }

    /// Objects with fewer copies in different places than the disk group
    /// rule asks for: (objects, bytes). Nothing when `copies` is 1.
    pub fn group_shortfall(&self) -> (u64, u64) {
        if self.copies <= 1 {
            return (0, 0);
        }
        let st = self.state.lock().unwrap();
        let mut out = (0u64, 0u64);
        for e in st.index.objects.values() {
            if (self.places_holding(&st, e).len() as u32) < self.copies {
                out.0 += 1;
                out.1 += e.size;
            }
        }
        out
    }

    /// The distinct places holding `key` on this pool (empty when none).
    pub fn places_of(&self, key: &str) -> BTreeSet<String> {
        let st = self.state.lock().unwrap();
        st.index
            .objects
            .get(key)
            .map(|e| self.places_holding(&st, e))
            .unwrap_or_default()
    }

    /// Register a new disk at `mount`: writes the marker and the disk index.
    /// Refuses a directory that already belongs to another pool or vault.
    pub fn add_disk(&self, mount: &Path, label: &str) -> Result<PoolDisk> {
        self.add_disk_at(mount, label, "")
    }

    /// Like `add_disk`, for a disk kept at `place` ("" for the pool's place).
    pub fn add_disk_at(&self, mount: &Path, label: &str, place: &str) -> Result<PoolDisk> {
        if label.trim().is_empty() {
            bail!("the disk needs a label");
        }
        if !mount.is_dir() {
            bail!(
                "{} is not a directory (is the disk mounted?)",
                mount.display()
            );
        }
        let mount = mount.canonicalize().unwrap_or_else(|_| mount.to_path_buf());
        let mut st = self.state.lock().unwrap();
        if let Some(m) = DiskMarker::read(&mount) {
            if m.pool_id == self.identity.pool_id && st.index.disks.contains_key(&m.disk_id) {
                bail!(
                    "{} already is disk {} of this pool; run `varsto disk check {}`",
                    mount.display(),
                    m.label,
                    m.label
                );
            }
            if m.vault_tag == self.identity.vault_tag {
                bail!(
                    "{} already holds disk {} of another pool of this vault",
                    mount.display(),
                    m.label
                );
            }
            bail!(
                "{} already holds a Varsto disk of another vault; the program never reuses it",
                mount.display()
            );
        }
        if st.index.disks.values().any(|d| d.label == label) {
            bail!(
                "a disk labelled {label} already exists in pool {}",
                self.name
            );
        }
        let id = crate::ids::Id::random().to_string();
        let marker = DiskMarker {
            pool_id: self.identity.pool_id.clone(),
            disk_id: id.clone(),
            label: label.to_string(),
            vault_tag: self.identity.vault_tag.clone(),
            created_utc: util::now_utc(),
            format: MARKER_FORMAT,
        };
        fs::create_dir_all(mount.join(DATA_DIR))?;
        util::write_atomic(
            &DiskMarker::path(&mount),
            &serde_json::to_vec_pretty(&marker)?,
        )?;
        let mut disk = PoolDisk {
            id: id.clone(),
            label: label.to_string(),
            last_mount: Some(mount.clone()),
            last_seen_utc: util::now_utc(),
            last_verified_utc: util::now_utc(),
            place: place.trim().to_string(),
            ..Default::default()
        };
        measure(&mut disk, &mount, util::now_utc());
        st.index.disks.insert(id.clone(), disk.clone());
        if let Some(a) = st.attached.as_mut() {
            a.insert(id.clone(), mount.clone());
        }
        self.write_disk_index(&st, &id, &mount)?;
        self.save_index(&st)?;
        Ok(disk)
    }

    fn write_disk_index(&self, st: &State, disk_id: &str, mount: &Path) -> Result<()> {
        let Some(d) = st.index.disks.get(disk_id) else {
            return Ok(());
        };
        let idx = DiskIndex {
            format: MARKER_FORMAT,
            pool_id: self.identity.pool_id.clone(),
            disk_id: disk_id.to_string(),
            label: d.label.clone(),
            written_utc: util::now_utc(),
            objects: st
                .index
                .objects
                .iter()
                .filter(|(_, e)| e.held_by(disk_id))
                .map(|(k, e)| (k.clone(), e.size))
                .collect(),
            place: d.place.clone(),
        };
        util::write_atomic(&DiskIndex::path(mount), &serde_json::to_vec(&idx)?)
    }

    /// Write the on-disk index of every attached disk that changed.
    pub fn flush(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let dirty = std::mem::take(&mut st.dirty);
        let mut measured = false;
        for id in dirty {
            if let Some(mount) = attached.get(&id) {
                self.write_disk_index(&st, &id, mount)?;
                Self::measure_now(&mut st, &id, mount);
                measured = true;
            }
        }
        if measured {
            self.save_index(&st)?;
        }
        Ok(())
    }

    /// Eject: write the disk's index and sync the data directory. Does not
    /// unmount; the caller tells the user the disk is safe to remove.
    pub fn eject(&self, disk_id: &str) -> Result<PathBuf> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let mount = attached
            .get(disk_id)
            .cloned()
            .ok_or_else(|| anyhow!("disk is not attached"))?;
        self.write_disk_index(&st, disk_id, &mount)?;
        st.dirty.remove(disk_id);
        for dir in [mount.join(DATA_DIR), mount.clone()] {
            if let Ok(d) = fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.last_seen_utc = util::now_utc();
        }
        Self::measure_now(&mut st, disk_id, &mount);
        self.save_index(&st)?;
        Ok(mount)
    }

    /// Apply the deletions queued while the disk was away. Returns (objects, bytes).
    pub fn apply_pending_deletes(&self, disk_id: &str) -> Result<(u64, u64)> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id).cloned() else {
            bail!("disk is not attached");
        };
        self.apply_pending(&mut st, disk_id, &mount)
    }

    fn apply_pending(&self, st: &mut State, disk_id: &str, mount: &Path) -> Result<(u64, u64)> {
        let Some(pending) = st.index.pending_deletes.remove(disk_id) else {
            return Ok((0, 0));
        };
        let (mut n, mut bytes) = (0u64, 0u64);
        for (key, size) in pending {
            let path = Self::data_path(mount, &key)?;
            let _ = fs::remove_file(&path);
            n += 1;
            bytes += size;
            if let Some(d) = st.index.disks.get_mut(disk_id) {
                d.used_bytes = d.used_bytes.saturating_sub(size);
            }
        }
        st.dirty.insert(disk_id.to_string());
        Self::measure_now(st, disk_id, mount);
        self.save_index(st)?;
        Ok((n, bytes))
    }

    /// First phase of the insert routine, from listings alone (no object is
    /// read): check the marker, apply the queued deletions, remove leftover
    /// temporary files of interrupted writes, forget copies the disk lost or
    /// holds at the wrong size, adopt files the vault still references
    /// (`referenced(object name)`) and remove the ones nothing needs.
    pub fn tidy_disk(
        &self,
        disk_id: &str,
        referenced: &dyn Fn(&str) -> bool,
    ) -> Result<TidyOutcome> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id).cloned() else {
            bail!("disk is not attached");
        };
        if !self.marker_matches(&mount, disk_id) {
            bail!("the marker at {} does not match this disk", mount.display());
        }
        let mut out = TidyOutcome::default();
        (out.pending_removed, out.pending_bytes) = self.apply_pending(&mut st, disk_id, &mount)?;
        // What the disk holds: key -> size, from the directory listing.
        let data = mount.join(DATA_DIR);
        let mut present: BTreeMap<String, u64> = BTreeMap::new();
        let chunks = data.join("chunks");
        if chunks.is_dir() {
            for entry in walkdir::WalkDir::new(&chunks)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let Ok(md) = entry.metadata() else { continue };
                let name = entry.file_name().to_string_lossy();
                if name.starts_with('.') {
                    // `.<name>.tmp-<pid>-<seq>` of a write that never finished;
                    // a fresh one may belong to a write running right now.
                    let old = md
                        .modified()
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > STALE_TEMP_SECS);
                    if name.contains(".tmp-") && old && fs::remove_file(entry.path()).is_ok() {
                        out.temp_removed += 1;
                    }
                    continue;
                }
                let Ok(rel) = entry.path().strip_prefix(&data) else {
                    continue;
                };
                let Some(key) = rel.to_str() else { continue };
                present.insert(key.replace(std::path::MAIN_SEPARATOR, "/"), md.len());
            }
        }
        let held: Vec<(String, u64)> = st
            .index
            .objects
            .iter()
            .filter(|(_, e)| e.held_by(disk_id))
            .map(|(k, e)| (k.clone(), e.size))
            .collect();
        for (key, size) in held {
            match present.remove(&key) {
                Some(s) if s == size => {}
                found => {
                    if found.is_some() {
                        let _ = fs::remove_file(Self::data_path(&mount, &key)?);
                        out.bad.push(key.clone());
                    } else {
                        out.missing.push(key.clone());
                    }
                    if let Some(e) = st.index.objects.get_mut(&key) {
                        if !e.remove_holder(disk_id) {
                            st.index.objects.remove(&key);
                        }
                    }
                }
            }
        }
        // Files the index does not place on this disk.
        for (key, size) in present {
            let wanted = object_name_of(&key).is_some_and(referenced);
            if wanted {
                let e = st
                    .index
                    .objects
                    .entry(key)
                    .or_insert_with(|| ObjectEntry::new(disk_id, size));
                if !e.held_by(disk_id) {
                    e.extra.push(disk_id.to_string());
                }
                out.adopted += 1;
            } else if fs::remove_file(Self::data_path(&mount, &key)?).is_ok() {
                out.unneeded_removed += 1;
                out.unneeded_bytes += size;
            }
        }
        let used: u64 = st
            .index
            .objects
            .values()
            .filter(|e| e.held_by(disk_id))
            .map(|e| e.size)
            .sum();
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes = used;
            d.last_seen_utc = util::now_utc();
        }
        Self::measure_now(&mut st, disk_id, &mount);
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok(out)
    }

    /// Copies on the disk whose last check is older than `cutoff_utc` (or
    /// that were never checked): (key, size), oldest check first.
    pub fn stale_on(&self, disk_id: &str, cutoff_utc: i64) -> Vec<(String, u64)> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<(i64, String, u64)> = st
            .index
            .objects
            .iter()
            .filter(|(_, e)| e.held_by(disk_id))
            .map(|(k, e)| {
                (
                    e.checked.get(disk_id).copied().unwrap_or(0),
                    k.clone(),
                    e.size,
                )
            })
            .filter(|(t, _, _)| *t < cutoff_utc)
            .collect();
        v.sort();
        v.into_iter().map(|(_, k, s)| (k, s)).collect()
    }

    /// Re-hash the given copies on an attached disk (read back from the disk,
    /// `read_back_hash`). A good copy records its check; a bad or missing one
    /// is removed and forgotten. `progress(objects, bytes)` follows the work.
    /// Afterwards the disk's `last_verified_utc` is its oldest copy check.
    pub fn verify_objects(
        &self,
        disk_id: &str,
        keys: &[(String, u64)],
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<VerifyOutcome> {
        let mount = {
            let mut st = self.state.lock().unwrap();
            let attached = self.attached(&mut st);
            let Some(mount) = attached.get(disk_id).cloned() else {
                bail!("disk is not attached");
            };
            if !self.marker_matches(&mount, disk_id) {
                bail!("the marker at {} does not match this disk", mount.display());
            }
            mount
        };
        let mut out = VerifyOutcome::default();
        let mut good: Vec<String> = Vec::new();
        let mut gone: Vec<(String, bool)> = Vec::new();
        // Hash without holding the index: a big disk takes hours. The
        // caller's task (`activity`) counts the bytes. Reads run in parallel
        // only where the disk's medium allows (`crate::parverify`).
        let jobs: Vec<crate::parverify::Job<(String, u64)>> = keys
            .iter()
            .map(|(k, s)| crate::parverify::Job {
                item: (k.clone(), *s),
                lane: 0,
                size: *s,
            })
            .collect();
        let mut failed: Option<anyhow::Error> = None;
        crate::parverify::run_ordered(
            &jobs,
            &[self.disk_lane(&mount)],
            |(key, size)| -> Result<Option<bool>> {
                let path = Self::data_path(&mount, key)?;
                Ok(match fs::metadata(&path) {
                    Err(_) => None,
                    Ok(md) => Some(
                        md.len() == *size
                            && read_back_hash(&path).is_ok_and(|h| {
                                object_name_of(key)
                                    .is_none_or(|n| hex::encode(h) == n.to_ascii_lowercase())
                            }),
                    ),
                })
            },
            |_, r| r,
            |_, (key, size), r| {
                crate::activity::advance_current(*size);
                match r {
                    Err(e) => {
                        failed = Some(e);
                        return false;
                    }
                    Ok(None) => gone.push((key.clone(), false)),
                    Ok(Some(true)) => {
                        out.objects_checked += 1;
                        out.bytes_checked += size;
                        good.push(key.clone());
                    }
                    Ok(Some(false)) => {
                        if let Ok(path) = Self::data_path(&mount, key) {
                            let _ = fs::remove_file(&path);
                        }
                        gone.push((key.clone(), true));
                    }
                }
                progress(out.objects_checked, out.bytes_checked);
                true
            },
        );
        if let Some(e) = failed {
            return Err(e);
        }
        let mut st = self.state.lock().unwrap();
        let now = util::now_utc();
        for key in &good {
            if let Some(e) = st.index.objects.get_mut(key) {
                if e.held_by(disk_id) {
                    e.checked.insert(disk_id.to_string(), now);
                }
            }
        }
        for (key, bad) in gone {
            if bad {
                out.bad.push(key.clone());
            } else {
                out.missing.push(key.clone());
            }
            if let Some(e) = st.index.objects.get_mut(&key) {
                if !e.remove_holder(disk_id) {
                    st.index.objects.remove(&key);
                }
            }
        }
        let mut used = 0u64;
        let mut oldest = now;
        for e in st.index.objects.values().filter(|e| e.held_by(disk_id)) {
            used += e.size;
            oldest = oldest.min(e.checked.get(disk_id).copied().unwrap_or(0));
        }
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes = used;
            d.last_verified_utc = oldest;
            d.last_seen_utc = now;
        }
        Self::measure_now(&mut st, disk_id, &mount);
        out.verified_keys = good;
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok(out)
    }

    /// Make what was written to an attached disk durable: its index, then
    /// the data directory and the mount itself are fsynced. The disk stays
    /// attached (`eject` also records it as seen).
    pub fn sync_disk(&self, disk_id: &str) -> Result<PathBuf> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let mount = attached
            .get(disk_id)
            .cloned()
            .ok_or_else(|| anyhow!("disk is not attached"))?;
        self.write_disk_index(&st, disk_id, &mount)?;
        st.dirty.remove(disk_id);
        for dir in [mount.join(DATA_DIR), mount.clone()] {
            if let Ok(d) = fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        Self::measure_now(&mut st, disk_id, &mount);
        self.save_index(&st)?;
        Ok(mount)
    }

    /// Verify the marker and every object the index places on the disk:
    /// sizes always, content hashes with `full`. Objects found on the disk
    /// that the index does not know are adopted.
    pub fn verify_disk(&self, disk_id: &str, full: bool) -> Result<VerifyOutcome> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(disk_id).cloned() else {
            bail!("disk is not attached");
        };
        if !self.marker_matches(&mount, disk_id) {
            bail!("the marker at {} does not match this disk", mount.display());
        }
        let mut out = VerifyOutcome::default();
        let keys: Vec<(String, u64)> = st
            .index
            .objects
            .iter()
            .filter(|(_, e)| e.held_by(disk_id))
            .map(|(k, e)| (k.clone(), e.size))
            .collect();
        // Forget the copy on this disk (other disks may still hold one).
        let forget = |st: &mut State, key: &str| {
            if let Some(e) = st.index.objects.get_mut(key) {
                if !e.remove_holder(disk_id) {
                    st.index.objects.remove(key);
                }
            }
        };
        // The disk check's task (`activity`) counts the bytes looked at.
        crate::activity::set_current_total(keys.iter().map(|(_, size)| size).sum());
        let lane = self.disk_lane(&mount);
        let jobs: Vec<crate::parverify::Job<(String, u64)>> = keys
            .into_iter()
            .map(|(k, s)| crate::parverify::Job {
                item: (k, s),
                lane: 0,
                // Without `full` only sizes are looked at: nothing is held.
                size: if full { s } else { 1 },
            })
            .collect();
        let mut failed: Option<anyhow::Error> = None;
        crate::parverify::run_ordered(
            &jobs,
            &[lane],
            |(key, size)| -> Result<Option<bool>> {
                let path = Self::data_path(&mount, key)?;
                let Ok(md) = fs::metadata(&path) else {
                    return Ok(None);
                };
                Ok(Some(
                    md.len() == *size
                        && (!full || {
                            let name = key.rsplit('/').next().unwrap_or("");
                            read_back_hash(&path)
                                .map(|h| hex::encode(h) == name)
                                .unwrap_or(false)
                        }),
                ))
            },
            |_, r| r,
            |_, (key, size), r| {
                crate::activity::advance_current(*size);
                match r {
                    Err(e) => {
                        failed = Some(e);
                        return false;
                    }
                    Ok(None) => {
                        out.missing.push(key.clone());
                        forget(&mut st, key);
                    }
                    Ok(Some(true)) => {
                        out.objects_checked += 1;
                        out.bytes_checked += size;
                        if full {
                            if let Some(e) = st.index.objects.get_mut(key) {
                                e.checked.insert(disk_id.to_string(), util::now_utc());
                            }
                        }
                    }
                    Ok(Some(false)) => {
                        out.bad.push(key.clone());
                        forget(&mut st, key);
                        if let Ok(path) = Self::data_path(&mount, key) {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
                true
            },
        );
        if let Some(e) = failed {
            return Err(e);
        }
        // Objects on the disk that the index does not know (written by another device).
        let data = mount.join(DATA_DIR).join("chunks");
        let mut unknown: Vec<crate::parverify::Job<(String, PathBuf, u64)>> = Vec::new();
        if data.is_dir() {
            for entry in walkdir::WalkDir::new(&data)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                if entry.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }
                let Ok(rel) = entry.path().strip_prefix(mount.join(DATA_DIR)) else {
                    continue;
                };
                let Some(key) = rel.to_str() else { continue };
                let key = key.replace(std::path::MAIN_SEPARATOR, "/");
                if st
                    .index
                    .objects
                    .get(&key)
                    .is_some_and(|e| e.held_by(disk_id))
                {
                    continue;
                }
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                unknown.push(crate::parverify::Job {
                    item: (key, entry.path().to_path_buf(), size),
                    lane: 0,
                    size: if full { size.max(1) } else { 1 },
                });
            }
        }
        crate::parverify::run_ordered(
            &unknown,
            &[lane],
            |(key, path, _)| {
                !full || {
                    let name = key.rsplit('/').next().unwrap_or("");
                    read_back_hash(path)
                        .map(|h| hex::encode(h) == name)
                        .unwrap_or(false)
                }
            },
            |_, good| good,
            |_, (key, path, size), good| {
                if !good {
                    out.bad.push(key.clone());
                    let _ = fs::remove_file(path);
                    return true;
                }
                let entry = st
                    .index
                    .objects
                    .entry(key.clone())
                    .or_insert_with(|| ObjectEntry::new(disk_id, *size));
                // A further copy of an object another disk holds.
                if !entry.held_by(disk_id) {
                    entry.extra.push(disk_id.to_string());
                }
                if full {
                    entry.checked.insert(disk_id.to_string(), util::now_utc());
                }
                out.adopted += 1;
                out.objects_checked += 1;
                out.bytes_checked += size;
                true
            },
        );
        let used: u64 = st
            .index
            .objects
            .values()
            .filter(|e| e.held_by(disk_id))
            .map(|e| e.size)
            .sum();
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes = used;
            d.last_verified_utc = util::now_utc();
            d.last_seen_utc = util::now_utc();
        }
        Self::measure_now(&mut st, disk_id, &mount);
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok(out)
    }

    /// The copy of `key` on one attached disk (a scrub reads each disk's
    /// copy, where `get` reads the first one it finds). None when the disk
    /// does not have the file.
    pub fn read_on_disk(&self, disk_id: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let mount = {
            let mut st = self.state.lock().unwrap();
            self.attached(&mut st).get(disk_id).cloned()
        };
        let Some(mount) = mount else {
            bail!("disk is not attached");
        };
        let path = Self::data_path(&mount, key)?;
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Forget and delete a bad copy of `key` on an attached disk (as
    /// `verify_disk` does). Returns whether another disk still holds a copy.
    pub fn drop_bad_copy(&self, disk_id: &str, key: &str) -> Result<bool> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        if let Some(mount) = attached.get(disk_id) {
            let _ = fs::remove_file(Self::data_path(mount, key)?);
        }
        let mut left = false;
        if let Some(e) = st.index.objects.get_mut(key) {
            let size = e.size;
            if e.held_by(disk_id) {
                left = e.remove_holder(disk_id);
                if let Some(d) = st.index.disks.get_mut(disk_id) {
                    d.used_bytes = d.used_bytes.saturating_sub(size);
                }
            } else {
                left = true;
            }
            if !left {
                st.index.objects.remove(key);
            }
        }
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok(left)
    }

    /// Record that the attached disks were verified now (after `fsck --verify`).
    pub fn mark_verified(&self, disk_ids: &[String]) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let now = util::now_utc();
        for id in disk_ids {
            if let Some(d) = st.index.disks.get_mut(id) {
                d.last_verified_utc = now;
            }
        }
        for e in st.index.objects.values_mut() {
            for id in disk_ids {
                if e.held_by(id) {
                    e.checked.insert(id.clone(), now);
                }
            }
        }
        self.save_index(&st)
    }

    pub fn set_retired(&self, disk_id: &str, retired: bool) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let d = st
            .index
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| anyhow!("unknown disk"))?;
        d.retired = retired;
        self.save_index(&st)
    }

    /// Every disk of the pool (registry merged with what was learned).
    pub fn disks(&self) -> Vec<PoolDisk> {
        let mut st = self.state.lock().unwrap();
        let _ = self.attached(&mut st);
        st.index.disks.values().cloned().collect()
    }

    pub fn disk_by_label(&self, label: &str) -> Option<PoolDisk> {
        let st = self.state.lock().unwrap();
        st.index
            .disks
            .values()
            .find(|d| d.label == label || d.id == label)
            .cloned()
    }

    /// Mount path of an attached disk.
    pub fn mount_of(&self, disk_id: &str) -> Option<PathBuf> {
        let mut st = self.state.lock().unwrap();
        self.attached(&mut st).get(disk_id).cloned()
    }

    /// Object keys (and sizes) the index places on a disk.
    pub fn objects_on(&self, disk_id: &str) -> Vec<(String, u64)> {
        let st = self.state.lock().unwrap();
        st.index
            .objects
            .iter()
            .filter(|(_, e)| e.held_by(disk_id))
            .map(|(k, e)| (k.clone(), e.size))
            .collect()
    }

    /// Every object key the pool holds, with its disk id.
    pub fn objects(&self) -> BTreeMap<String, (String, u64)> {
        let st = self.state.lock().unwrap();
        st.index
            .objects
            .iter()
            .map(|(k, e)| (k.clone(), (e.disk.clone(), e.size)))
            .collect()
    }

    /// Where the object is: an attached copy first.
    pub fn locate(&self, key: &str) -> Option<ObjectLocation> {
        let mut all = self.locate_all(key);
        all.sort_by_key(|l| !l.attached);
        all.into_iter().next()
    }

    /// Every copy of the object, on every disk that holds one.
    pub fn locate_all(&self, key: &str) -> Vec<ObjectLocation> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let Some(e) = st.index.objects.get(key) else {
            return Vec::new();
        };
        e.holders()
            .filter_map(|id| {
                let d = st.index.disks.get(id)?;
                Some(ObjectLocation {
                    disk_id: id.clone(),
                    label: d.label.clone(),
                    place: self.disk_place(d),
                    attached: attached.contains_key(id),
                    last_verified_utc: d.last_verified_utc,
                    size: e.size,
                })
            })
            .collect()
    }

    /// Listing rows for every disk, from the index alone (no ledger facts).
    pub fn statuses(&self) -> Vec<DiskStatus> {
        self.statuses_with(None)
    }

    /// Copies whose last check is older than this are overdue (`i64::MAX`
    /// with `verify_after_days` 0: every copy, as the insert routine does).
    pub fn verify_cutoff(&self, now: i64) -> i64 {
        if self.verify_after_days == 0 {
            i64::MAX
        } else {
            now - self.verify_after_days as i64 * 86_400
        }
    }

    /// Listing rows for every disk with its bookkeeping: space as last
    /// measured, queued deletions, the age of its copy checks and, given
    /// what the ledger knows (`input`), what could be freed, what exists
    /// only there, what the pool lacks that it could take and what a
    /// repair or a fetch plan needs from it. Reads no disk beyond the
    /// attach detection.
    pub fn statuses_with(&self, input: Option<&BookInput>) -> Vec<DiskStatus> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let now = util::now_utc();
        let cutoff = self.verify_cutoff(now);
        #[derive(Default)]
        struct Acc {
            copies: u64,
            oldest: Option<i64>,
            overdue: u64,
            overdue_bytes: u64,
            unneeded: u64,
            unneeded_bytes: u64,
            only: u64,
            only_bytes: u64,
            only_overdue: u64,
            repair: u64,
            short_bytes: u64,
        }
        let mut acc: BTreeMap<String, Acc> = st
            .index
            .disks
            .keys()
            .map(|k| (k.clone(), Acc::default()))
            .collect();
        let place_of: BTreeMap<String, String> = st
            .index
            .disks
            .iter()
            .map(|(id, d)| (id.clone(), self.disk_place(d)))
            .collect();
        let takers: Vec<(String, String)> = st
            .index
            .disks
            .values()
            .filter(|d| !d.retired)
            .map(|d| (d.id.clone(), self.disk_place(d)))
            .collect();
        for (key, e) in &st.index.objects {
            let name = object_name_of(key).map(|n| n.to_ascii_lowercase());
            let unneeded = match (input.and_then(|i| i.wanted), &name) {
                (Some(w), Some(n)) => !w.contains(n),
                _ => false,
            };
            let holders: Vec<&String> = e.holders().collect();
            let elsewhere = match (input.and_then(|i| i.elsewhere), &name) {
                (Some(x), Some(n)) => x.contains(n),
                _ => true,
            };
            let in_repair = match (input.and_then(|i| i.repair), &name) {
                (Some(r), Some(n)) => r.contains(n),
                _ => false,
            };
            for d in &holders {
                let a = acc.entry((*d).clone()).or_default();
                a.copies += 1;
                let checked = e.checked.get(*d).copied().unwrap_or(0);
                a.oldest = Some(a.oldest.map_or(checked, |o| o.min(checked)));
                let overdue = checked < cutoff;
                if overdue {
                    a.overdue += 1;
                    a.overdue_bytes += e.size;
                }
                if unneeded {
                    a.unneeded += 1;
                    a.unneeded_bytes += e.size;
                } else if holders.len() == 1 && !elsewhere {
                    a.only += 1;
                    a.only_bytes += e.size;
                    if overdue {
                        a.only_overdue += 1;
                    }
                }
                if in_repair {
                    a.repair += 1;
                }
            }
            // Disk groups: further copies a disk of a place without one could take.
            let current = input
                .and_then(|i| i.current)
                .is_none_or(|c| c.contains(key));
            if self.copies > 1 && !unneeded && current {
                let places: BTreeSet<&String> =
                    holders.iter().filter_map(|d| place_of.get(*d)).collect();
                if (places.len() as u32) < self.copies {
                    for (id, place) in &takers {
                        if !places.contains(place) && !e.held_by(id) {
                            acc.entry(id.clone()).or_default().short_bytes += e.size;
                        }
                    }
                }
            }
        }
        let mut disks: Vec<&PoolDisk> = st.index.disks.values().collect();
        disks.sort_by(|a, b| a.label.cmp(&b.label));
        disks
            .into_iter()
            .map(|d| {
                let mount = attached.get(&d.id).cloned();
                let live = mount.as_ref().and_then(|m| disk_space(m));
                let a = acc.remove(&d.id).unwrap_or_default();
                let (free, total, measured) = match live {
                    Some(sp) => (Some(sp.free), sp.total, now),
                    None if d.space_measured_utc > 0 => {
                        (Some(d.free_bytes), d.capacity_bytes, d.space_measured_utc)
                    }
                    None => (None, d.capacity_bytes, 0),
                };
                let reserve = self.reserve(total);
                let pending: Option<&BTreeMap<String, u64>> = st.index.pending_deletes.get(&d.id);
                let pending_bytes: u64 = pending.map(|p| p.values().sum()).unwrap_or(0);
                let failing_reason = (d.write_failed_utc > 0).then(|| {
                    format!(
                        "it returned different bytes than were written to it, twice, on {}: the disk, its cable or dock may be failing",
                        util::format_date(d.write_failed_utc)
                    )
                });
                let with = |v: u64| input.map(|_| v);
                let (lacking, fill) = match input {
                    Some(i) => {
                        let lacking = i.first_copy_bytes + a.short_bytes;
                        let room = free
                            .unwrap_or_else(|| total.saturating_sub(d.used_bytes))
                            .saturating_sub(reserve);
                        let fill = if d.retired || failing_reason.is_some() {
                            0
                        } else {
                            room.min(lacking)
                        };
                        (Some(lacking), Some(fill))
                    }
                    None => (None, None),
                };
                let (fetch_objects, fetch_bytes) = match input.and_then(|i| i.fetch) {
                    Some(f) => {
                        let keys = f.get(&d.id).map(|v| v.as_slice()).unwrap_or(&[]);
                        let bytes = keys
                            .iter()
                            .filter_map(|k| st.index.objects.get(k).map(|e| e.size))
                            .sum();
                        (Some(keys.len() as u64), Some(bytes))
                    }
                    None => (with(0), with(0)),
                };
                DiskStatus {
                    pool: self.name.clone(),
                    place: self.disk_place(d),
                    label: d.label.clone(),
                    disk_id: d.id.clone(),
                    attached: mount.is_some(),
                    free_bytes: free,
                    mount: mount.or_else(|| d.last_mount.clone()),
                    capacity_bytes: total,
                    used_bytes: d.used_bytes,
                    objects: a.copies,
                    last_seen_utc: d.last_seen_utc,
                    last_verified_utc: d.last_verified_utc,
                    pending_deletes: pending.map(|p| p.len() as u64).unwrap_or(0),
                    retired: d.retired,
                    reserve_bytes: reserve,
                    space_measured_utc: measured,
                    pending_delete_bytes: pending_bytes,
                    reclaimable_bytes: pending_bytes + a.unneeded_bytes,
                    verify_after_days: self.verify_after_days,
                    oldest_check_utc: a.oldest,
                    copies_overdue: a.overdue,
                    bytes_overdue: a.overdue_bytes,
                    overdue_share: if a.copies == 0 {
                        0.0
                    } else {
                        a.overdue as f64 / a.copies as f64
                    },
                    write_failed_utc: d.write_failed_utc,
                    failing: failing_reason.is_some(),
                    failing_reason,
                    fsck: None,
                    unneeded_objects: with(a.unneeded),
                    unneeded_bytes: with(a.unneeded_bytes),
                    only_copy_objects: with(a.only),
                    only_copy_bytes: with(a.only_bytes),
                    only_copy_overdue: with(a.only_overdue),
                    lacking_bytes: lacking,
                    fill_potential_bytes: fill,
                    repair_objects: with(a.repair),
                    fetch_objects,
                    fetch_bytes,
                }
            })
            .collect()
    }
}

impl Drop for PoolStorage {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl Storage for PoolStorage {
    fn name(&self) -> &str {
        &self.name
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let mut st = self.state.lock().unwrap();
        if st.index.objects.contains_key(key) {
            return Ok(false);
        }
        let (disk_id, mount) = self.choose_disk(&mut st, data.len() as u64)?;
        self.write_object(&mut st, &disk_id, &mount, key, data)?;
        st.last_put = Some(disk_id.clone());
        // Disk groups: further copies on attached disks in other places.
        let mut taken = BTreeSet::from([self.place_of(&st, &disk_id)]);
        while (taken.len() as u32) < self.copies {
            let Ok((d, m)) = self.choose_disk_outside(&mut st, data.len() as u64, &taken) else {
                break;
            };
            taken.insert(self.place_of(&st, &d));
            self.write_object(&mut st, &d, &m, key, data)?;
        }
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut st = self.state.lock().unwrap();
        let Some(e) = st.index.objects.get(key).cloned() else {
            return Ok(None);
        };
        let attached = self.attached(&mut st);
        let Some(mount) = e.holders().find_map(|d| attached.get(d)) else {
            let label = st
                .index
                .disks
                .get(&e.disk)
                .map(|d| d.label.clone())
                .unwrap_or_default();
            return Err(anyhow::Error::new(PoolError::NeedsDisk {
                label,
                disk_id: e.disk,
                place: self.place.clone(),
            }));
        };
        let path = Self::data_path(mount, key)?;
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let st = self.state.lock().unwrap();
        Ok(st.index.objects.contains_key(key))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let st = self.state.lock().unwrap();
        Ok(st
            .index
            .objects
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        use std::ops::Bound;
        let st = self.state.lock().unwrap();
        Ok(st
            .index
            .objects
            .range::<str, _>((Bound::Excluded(start_after), Bound::Unbounded))
            .map(|(k, _)| k)
            .skip_while(|k| k.as_str() < prefix)
            .take_while(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let Some(e) = st.index.objects.get(key).cloned() else {
            return Ok(());
        };
        let attached = self.attached(&mut st);
        for disk in e.holders() {
            if let Some(mount) = attached.get(disk) {
                let path = Self::data_path(mount, key)?;
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
                if let Some(d) = st.index.disks.get_mut(disk) {
                    d.used_bytes = d.used_bytes.saturating_sub(e.size);
                }
                st.dirty.insert(disk.clone());
            } else {
                st.index
                    .pending_deletes
                    .entry(disk.clone())
                    .or_default()
                    .insert(key.to_string(), e.size);
            }
        }
        st.index.objects.remove(key);
        self.save_index(&st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(pool: &str, disk: &str, label: &str) -> DiskMarker {
        DiskMarker {
            pool_id: pool.into(),
            disk_id: disk.into(),
            label: label.into(),
            vault_tag: "tag".into(),
            created_utc: 0,
            format: MARKER_FORMAT,
        }
    }

    fn write_marker(mount: &Path, m: &DiskMarker) {
        fs::create_dir_all(mount).unwrap();
        fs::write(DiskMarker::path(mount), serde_json::to_vec(m).unwrap()).unwrap();
    }

    #[test]
    fn scan_finds_markers_at_the_configured_depth() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // /media/<user>/<disk> style: depth 2.
        write_marker(
            &root.join("media/me/data-01"),
            &marker("p", "d1", "data-01"),
        );
        // /mnt/<disk> style: depth 1.
        write_marker(&root.join("mnt/data-02"), &marker("p", "d2", "data-02"));
        // Too deep for the /mnt root, and a directory without a marker.
        write_marker(
            &root.join("mnt/deeper/data-03"),
            &marker("p", "d3", "data-03"),
        );
        fs::create_dir_all(root.join("mnt/plain")).unwrap();
        let found = scan_mounts(&[(root.join("media"), 2), (root.join("mnt"), 1)]);
        let mut labels: Vec<String> = found.iter().map(|(_, m)| m.label.clone()).collect();
        labels.sort();
        assert_eq!(labels, vec!["data-01".to_string(), "data-02".to_string()]);
        assert!(found
            .iter()
            .any(|(p, m)| m.disk_id == "d1" && p == &root.join("media/me/data-01")));
        // Depth 0: the root itself is the candidate (Windows drive letters).
        let found = scan_mounts(&[(root.join("mnt/data-02"), 0)]);
        assert_eq!(found.len(), 1);
        // A missing root is not an error.
        assert!(scan_mounts(&[(root.join("nowhere"), 2)]).is_empty());
    }

    #[test]
    fn reserve_takes_the_larger_of_percent_and_minimum() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = StorageSpec::Pool {
            name: "shelf".into(),
            place: String::new(),
            reserve_percent: 5,
            min_reserve_bytes: 2 << 30,
            disks: vec![],
            scan_roots: vec![],
            copies: 1,
            verify_after_days: DEFAULT_VERIFY_AFTER_DAYS,
        };
        let p = PoolStorage::open(
            &spec,
            tmp.path(),
            PoolIdentity {
                pool_id: "p".into(),
                vault_tag: "t".into(),
            },
        )
        .unwrap();
        assert_eq!(p.reserve(100 << 30), 5 << 30);
        assert_eq!(p.reserve(10 << 30), 2 << 30);
        assert_eq!(p.place(), "home");
    }

    fn object(data: &[u8]) -> String {
        let name = hex::encode(crate::crypto::hash(data));
        format!("chunks/{}/{name}", &name[..2])
    }

    #[test]
    fn bookkeeping_comes_from_the_index_and_what_the_ledger_knows() {
        const GIB: u64 = 1 << 30;
        let tmp = tempfile::tempdir().unwrap();
        let mounts = tmp.path().join("mounts");
        let (a, b) = (mounts.join("a"), mounts.join("b"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let spec = StorageSpec::Pool {
            name: "shelf".into(),
            place: "home".into(),
            reserve_percent: 5,
            min_reserve_bytes: 2 * GIB,
            disks: vec![],
            scan_roots: vec![mounts.clone()],
            copies: 2,
            verify_after_days: DEFAULT_VERIFY_AFTER_DAYS,
        };
        let id = || PoolIdentity {
            pool_id: "p".into(),
            vault_tag: "t".into(),
        };
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        set_fake_space(
            &a,
            Some(DiskSpace {
                free: 50 * GIB,
                total: 100 * GIB,
            }),
        );
        set_fake_space(
            &b,
            Some(DiskSpace {
                free: 20 * GIB,
                total: 40 * GIB,
            }),
        );
        let (da, db) = {
            let p = PoolStorage::open(&spec, &home, id()).unwrap();
            let da = p.add_disk_at(&a, "A", "").unwrap();
            let db = p.add_disk_at(&b, "B", "offsite").unwrap();
            assert_eq!(da.free_bytes, 50 * GIB);
            assert!(da.space_measured_utc > 0);
            (da.id, db.id)
        };
        // B goes away; three objects go to A alone.
        let away = tmp.path().join("away");
        fs::create_dir_all(&away).unwrap();
        fs::rename(&b, away.join("b")).unwrap();
        let (x1, x2, x3) = (
            b"one".to_vec(),
            b"two two".to_vec(),
            b"three three three".to_vec(),
        );
        {
            let p = PoolStorage::open(&spec, &home, id()).unwrap();
            // A write that reads back wrong twice marks the disk failing ...
            corrupt_writes_under(&a, 2);
            assert!(p.put_if_absent(&object(b"bad"), b"bad").is_err());
            let row = p.statuses().into_iter().find(|d| d.label == "A").unwrap();
            assert!(row.failing && row.write_failed_utc > 0, "{row:?}");
            assert!(row.failing_reason.unwrap().contains("may be failing"));
            // ... and a later write that reads back right clears it.
            for x in [&x1, &x2, &x3] {
                assert!(p.put_if_absent(&object(x), x).unwrap());
            }
            assert!(!p.statuses().iter().any(|d| d.failing));
            p.state
                .lock()
                .unwrap()
                .index
                .objects
                .get_mut(&object(&x1))
                .unwrap()
                .checked
                .insert(da.clone(), 1_000);
            // Measured again when the disk's index is flushed (after a fill).
            set_fake_space(
                &a,
                Some(DiskSpace {
                    free: 45 * GIB,
                    total: 100 * GIB,
                }),
            );
            p.flush().unwrap();
        }
        // A goes away too; deleting x3 queues it.
        fs::rename(&a, away.join("a")).unwrap();
        let p = PoolStorage::open(&spec, &home, id()).unwrap();
        p.delete(&object(&x3)).unwrap();
        let wanted: std::collections::HashSet<String> =
            [object_name_of(&object(&x1)).unwrap().to_string()].into();
        let elsewhere = std::collections::HashSet::new();
        let fetch: BTreeMap<String, Vec<String>> = [(da.clone(), vec![object(&x1)])].into();
        let input = BookInput {
            wanted: Some(&wanted),
            elsewhere: Some(&elsewhere),
            repair: Some(&wanted),
            fetch: Some(&fetch),
            first_copy_bytes: 100,
            current: None,
        };
        let rows = p.statuses_with(Some(&input));
        let ra = rows.iter().find(|d| d.label == "A").unwrap();
        let rb = rows.iter().find(|d| d.label == "B").unwrap();
        assert!(!ra.attached && !rb.attached);
        // Space as last measured, with the reserve.
        assert_eq!(ra.free_bytes, Some(45 * GIB));
        assert_eq!(ra.capacity_bytes, 100 * GIB);
        assert_eq!(ra.reserve_bytes, 5 * GIB);
        assert_eq!(rb.free_bytes, Some(20 * GIB));
        assert_eq!(rb.reserve_bytes, 2 * GIB);
        // x1 and x2 are on A; x3 waits to be deleted, x2 is unneeded.
        assert_eq!(ra.objects, 2);
        assert_eq!(ra.pending_deletes, 1);
        assert_eq!(ra.pending_delete_bytes, x3.len() as u64);
        assert_eq!(ra.unneeded_objects, Some(1));
        assert_eq!(ra.unneeded_bytes, Some(x2.len() as u64));
        assert_eq!(ra.reclaimable_bytes, (x2.len() + x3.len()) as u64);
        // x1: only copy anywhere, checked long ago; a repair and the fetch plan want it.
        assert_eq!(ra.oldest_check_utc, Some(1_000));
        assert_eq!(ra.copies_overdue, 1);
        assert_eq!(ra.overdue_share, 0.5);
        assert_eq!(ra.only_copy_objects, Some(1));
        assert_eq!(ra.only_copy_overdue, Some(1));
        assert_eq!(ra.repair_objects, Some(1));
        assert_eq!(
            (ra.fetch_objects, ra.fetch_bytes),
            (Some(1), Some(x1.len() as u64))
        );
        // The pool lacks 100 bytes of first copies; B's place also lacks x1.
        assert_eq!(ra.lacking_bytes, Some(100));
        assert_eq!(ra.fill_potential_bytes, Some(100));
        assert_eq!(rb.lacking_bytes, Some(100 + x1.len() as u64));
        assert_eq!(rb.fill_potential_bytes, rb.lacking_bytes);
        assert_eq!(rb.objects, 0);
        assert_eq!(rb.oldest_check_utc, None);
        // Without the ledger only the index facts are there.
        let cheap = p.statuses();
        let ca = cheap.iter().find(|d| d.label == "A").unwrap();
        assert_eq!(ca.unneeded_bytes, None);
        assert_eq!(ca.reclaimable_bytes, x3.len() as u64);
        assert_eq!(ca.copies_overdue, 1);
        // A retired disk can take nothing.
        p.set_retired(&db, true).unwrap();
        let rows = p.statuses_with(Some(&input));
        let rb = rows.iter().find(|d| d.label == "B").unwrap();
        assert_eq!(rb.fill_potential_bytes, Some(0));
    }

    #[test]
    fn fake_space_applies_to_paths_below_the_mount() {
        let tmp = tempfile::tempdir().unwrap();
        let m = tmp.path().join("m");
        fs::create_dir_all(m.join("varsto")).unwrap();
        set_fake_space(
            &m,
            Some(DiskSpace {
                free: 10,
                total: 20,
            }),
        );
        assert_eq!(disk_space(&m.join("varsto")).unwrap().free, 10);
        set_fake_space(&m, None);
        assert_ne!(disk_space(&m).map(|s| s.total), Some(20));
    }
}
