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
    let mut v = FAKE_SPACE.write().unwrap();
    v.retain(|(p, _)| p != mount);
    if let Some(s) = space {
        v.push((mount.to_path_buf(), s));
    }
}

/// Free and total space of the filesystem at `path`.
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    {
        let v = FAKE_SPACE.read().unwrap();
        if let Some((_, s)) = v.iter().find(|(p, _)| path.starts_with(p)) {
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
}

/// Where an object of the pool is.
#[derive(Clone, Debug)]
pub struct ObjectLocation {
    pub disk_id: String,
    pub label: String,
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
}

struct State {
    index: PoolIndex,
    /// Disk id -> mount, computed once per instance.
    attached: Option<BTreeMap<String, PathBuf>>,
    /// Disks whose on-disk index must be rewritten.
    dirty: BTreeSet<String>,
}

pub struct PoolStorage {
    name: String,
    place: String,
    identity: PoolIdentity,
    reserve_percent: u32,
    min_reserve_bytes: u64,
    scan_roots: Vec<PathBuf>,
    index_path: PathBuf,
    state: Mutex<State>,
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
            identity,
            reserve_percent: *reserve_percent,
            min_reserve_bytes: *min_reserve_bytes,
            scan_roots: scan_roots.clone(),
            index_path,
            state: Mutex::new(State {
                index,
                attached: None,
                dirty: BTreeSet::new(),
            }),
        })
    }

    pub fn identity(&self) -> &PoolIdentity {
        &self.identity
    }

    pub fn place(&self) -> &str {
        &self.place
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
        if key.is_empty()
            || key.starts_with('/')
            || key
                .split('/')
                .any(|c| c == ".." || c.is_empty() || c == ".")
        {
            bail!("invalid object key {key:?}");
        }
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
                if let Some(sp) = disk_space(mount) {
                    if d.capacity_bytes != sp.total {
                        d.capacity_bytes = sp.total;
                        changed = true;
                    }
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
            used += size;
            st.index
                .objects
                .entry(key.clone())
                .or_insert_with(|| ObjectEntry {
                    disk: marker.disk_id.clone(),
                    size: *size,
                });
        }
        st.index.disks.insert(
            marker.disk_id.clone(),
            PoolDisk {
                id: marker.disk_id.clone(),
                label: marker.label.clone(),
                last_mount: Some(mount.to_path_buf()),
                capacity_bytes: disk_space(mount).map(|s| s.total).unwrap_or(0),
                used_bytes: used,
                last_seen_utc: util::now_utc(),
                last_verified_utc: 0,
                retired: false,
            },
        );
    }

    /// The attached, non-retired disk with the most free space that keeps its
    /// reserve after writing `size` bytes.
    fn choose_disk(&self, st: &mut State, size: u64) -> Result<(String, PathBuf)> {
        let attached = self.attached(st);
        let mut best: Option<(u64, String, PathBuf)> = None;
        let mut any = false;
        for (id, mount) in &attached {
            let Some(d) = st.index.disks.get(id) else {
                continue;
            };
            if d.retired {
                continue;
            }
            any = true;
            let Some(sp) = disk_space(mount) else {
                continue;
            };
            if sp.free < size.saturating_add(self.reserve(sp.total)) {
                continue;
            }
            if best.as_ref().is_none_or(|(f, _, _)| sp.free > *f) {
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
        util::write_atomic(&path, data)?;
        st.index.objects.insert(
            key.to_string(),
            ObjectEntry {
                disk: disk_id.to_string(),
                size: data.len() as u64,
            },
        );
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes += data.len() as u64;
        }
        st.dirty.insert(disk_id.to_string());
        self.save_index(st)
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

    /// Register a new disk at `mount`: writes the marker and the disk index.
    /// Refuses a directory that already belongs to another pool or vault.
    pub fn add_disk(&self, mount: &Path, label: &str) -> Result<PoolDisk> {
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
        let sp = disk_space(&mount);
        let disk = PoolDisk {
            id: id.clone(),
            label: label.to_string(),
            last_mount: Some(mount.clone()),
            capacity_bytes: sp.map(|s| s.total).unwrap_or(0),
            used_bytes: 0,
            last_seen_utc: util::now_utc(),
            last_verified_utc: util::now_utc(),
            retired: false,
        };
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
                .filter(|(_, e)| e.disk == disk_id)
                .map(|(k, e)| (k.clone(), e.size))
                .collect(),
        };
        util::write_atomic(&DiskIndex::path(mount), &serde_json::to_vec(&idx)?)
    }

    /// Write the on-disk index of every attached disk that changed.
    pub fn flush(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let dirty = std::mem::take(&mut st.dirty);
        for id in dirty {
            if let Some(mount) = attached.get(&id) {
                self.write_disk_index(&st, &id, mount)?;
            }
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
        let Some(pending) = st.index.pending_deletes.remove(disk_id) else {
            return Ok((0, 0));
        };
        let (mut n, mut bytes) = (0u64, 0u64);
        for (key, size) in pending {
            let path = Self::data_path(&mount, &key)?;
            let _ = fs::remove_file(&path);
            n += 1;
            bytes += size;
            if let Some(d) = st.index.disks.get_mut(disk_id) {
                d.used_bytes = d.used_bytes.saturating_sub(size);
            }
        }
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok((n, bytes))
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
            .filter(|(_, e)| e.disk == disk_id)
            .map(|(k, e)| (k.clone(), e.size))
            .collect();
        for (key, size) in keys {
            let path = Self::data_path(&mount, &key)?;
            let Ok(md) = fs::metadata(&path) else {
                out.missing.push(key.clone());
                st.index.objects.remove(&key);
                continue;
            };
            let ok = md.len() == size
                && (!full || {
                    let name = key.rsplit('/').next().unwrap_or("");
                    fs::read(&path)
                        .map(|b| hex::encode(crate::crypto::hash(&b)) == name)
                        .unwrap_or(false)
                });
            if ok {
                out.objects_checked += 1;
                out.bytes_checked += size;
            } else {
                out.bad.push(key.clone());
                st.index.objects.remove(&key);
                let _ = fs::remove_file(&path);
            }
        }
        // Objects on the disk that the index does not know (written by another device).
        let data = mount.join(DATA_DIR).join("chunks");
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
                if st.index.objects.contains_key(&key) {
                    continue;
                }
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if full {
                    let name = key.rsplit('/').next().unwrap_or("");
                    let good = fs::read(entry.path())
                        .map(|b| hex::encode(crate::crypto::hash(&b)) == name)
                        .unwrap_or(false);
                    if !good {
                        out.bad.push(key);
                        let _ = fs::remove_file(entry.path());
                        continue;
                    }
                }
                st.index.objects.insert(
                    key,
                    ObjectEntry {
                        disk: disk_id.to_string(),
                        size,
                    },
                );
                out.adopted += 1;
                out.objects_checked += 1;
                out.bytes_checked += size;
            }
        }
        let used: u64 = st
            .index
            .objects
            .values()
            .filter(|e| e.disk == disk_id)
            .map(|e| e.size)
            .sum();
        if let Some(d) = st.index.disks.get_mut(disk_id) {
            d.used_bytes = used;
            d.last_verified_utc = util::now_utc();
            d.last_seen_utc = util::now_utc();
        }
        st.dirty.insert(disk_id.to_string());
        self.save_index(&st)?;
        Ok(out)
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
            .filter(|(_, e)| e.disk == disk_id)
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

    pub fn locate(&self, key: &str) -> Option<ObjectLocation> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let e = st.index.objects.get(key)?;
        let d = st.index.disks.get(&e.disk)?;
        Some(ObjectLocation {
            disk_id: e.disk.clone(),
            label: d.label.clone(),
            attached: attached.contains_key(&e.disk),
            last_verified_utc: d.last_verified_utc,
            size: e.size,
        })
    }

    /// Listing rows for every disk.
    pub fn statuses(&self) -> Vec<DiskStatus> {
        let mut st = self.state.lock().unwrap();
        let attached = self.attached(&mut st);
        let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
        for e in st.index.objects.values() {
            *counts.entry(e.disk.as_str()).or_default() += 1;
        }
        st.index
            .disks
            .values()
            .map(|d| {
                let mount = attached.get(&d.id).cloned();
                DiskStatus {
                    pool: self.name.clone(),
                    place: self.place.clone(),
                    label: d.label.clone(),
                    disk_id: d.id.clone(),
                    attached: mount.is_some(),
                    free_bytes: mount.as_ref().and_then(|m| disk_space(m)).map(|s| s.free),
                    mount: mount.or_else(|| d.last_mount.clone()),
                    capacity_bytes: d.capacity_bytes,
                    used_bytes: d.used_bytes,
                    objects: counts.get(d.id.as_str()).copied().unwrap_or(0),
                    last_seen_utc: d.last_seen_utc,
                    last_verified_utc: d.last_verified_utc,
                    pending_deletes: st
                        .index
                        .pending_deletes
                        .get(&d.id)
                        .map(|p| p.len() as u64)
                        .unwrap_or(0),
                    retired: d.retired,
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
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut st = self.state.lock().unwrap();
        let Some(e) = st.index.objects.get(key).cloned() else {
            return Ok(None);
        };
        let attached = self.attached(&mut st);
        let Some(mount) = attached.get(&e.disk) else {
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

    fn delete(&self, key: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let Some(e) = st.index.objects.get(key).cloned() else {
            return Ok(());
        };
        let attached = self.attached(&mut st);
        if let Some(mount) = attached.get(&e.disk) {
            let path = Self::data_path(mount, key)?;
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            if let Some(d) = st.index.disks.get_mut(&e.disk) {
                d.used_bytes = d.used_bytes.saturating_sub(e.size);
            }
            st.dirty.insert(e.disk.clone());
        } else {
            st.index
                .pending_deletes
                .entry(e.disk.clone())
                .or_default()
                .insert(key.to_string(), e.size);
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
