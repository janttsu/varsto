// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! File metadata beyond the content: permissions, symbolic links, extended
//! attributes and ownership (spec section "File metadata").
//!
//! A device records what its filesystem shows (`observe`), and publishes a
//! change only for a property it can represent and that changed since it
//! last looked (`combine`): a device that cannot represent a property (a
//! phone without mode bits, Windows without extended attributes, a setting
//! turned off, a filesystem that drops what is written) carries the value
//! it has from the vault unchanged, so it never publishes its removal and
//! never flaps. On pull, `apply` writes what this device can and leaves the
//! rest. Symbolic links are never followed: they are read with `readlink`,
//! created as links, and every path Varsto writes or reads is refused when
//! a directory above it is a link.

use anyhow::{bail, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// Version of the `FileMeta` record this build writes and applies. A record
/// with a higher version is carried unchanged and not applied.
pub const META_VERSION: u8 = 1;
/// Extended attributes of one file, names and values together, at most this
/// many bytes; a file with more has its attributes left out of sync (the
/// value in the vault, if any, is kept).
pub const XATTR_LIMIT: usize = 64 * 1024;
/// The permission bits synced (no setuid, setgid or sticky bit).
pub const PERM_BITS: u32 = 0o777;
/// Longest symbolic link target taken.
pub const LINK_MAX: usize = 4096;
/// Suffix of the note written instead of a symbolic link where none can be
/// made (Windows without the privilege): `<path>.varsto-link`.
pub const LINK_NOTE_SUFFIX: &str = ".varsto-link";

/// Extended attributes never synced: per-device noise (quarantine and
/// provenance flags, sandbox grants, last-used dates) and attribute
/// namespaces only the system or root may write.
const XATTR_DENY: &[&str] = &[
    "com.apple.quarantine",
    "com.apple.provenance",
    "com.apple.macl",
    "com.apple.lastuseddate#PS",
    "com.apple.rootless",
    "com.apple.decmpfs",
    "com.apple.system.Security",
    "com.apple.cs.CodeDirectory",
    "com.apple.cs.CodeRequirements",
    "com.apple.cs.CodeSignature",
];
const XATTR_DENY_PREFIX: &[&str] = &["security.", "system.", "trusted.", "com.apple.system."];

/// Metadata of one entry as published in its `FileState` (`meta`). Every
/// field is optional: absent means "not known" (never "none"), and a device
/// leaves a property it does not know alone.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMeta {
    /// Record version (`META_VERSION`).
    pub v: u8,
    /// Unix permission bits: rwx for user, group and others (`0o777`).
    /// Setuid, setgid and sticky are neither recorded nor applied (another
    /// device must not be able to plant a setuid file). On Windows only
    /// "read-only" (no write bit) is seen and set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// The entry is a symbolic link with this target, as given (relative
    /// targets stay relative; an absolute one is kept and flagged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<String>,
    /// Extended attributes: name -> value in standard base64. Some(empty):
    /// known to have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xattrs: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl FileMeta {
    /// None when nothing is known (kept out of manifests).
    pub fn normalized(self) -> Option<FileMeta> {
        if self.mode.is_none()
            && self.symlink.is_none()
            && self.xattrs.is_none()
            && self.owner.is_none()
        {
            None
        } else {
            Some(self)
        }
    }

    /// Refuse what an honest device could not have written.
    pub fn validate(&self) -> Result<()> {
        if let Some(m) = self.mode {
            if m > 0o7777 {
                bail!("mode {m:o} has more than permission bits");
            }
        }
        if let Some(t) = &self.symlink {
            if t.is_empty() || t.len() > LINK_MAX || t.contains('\0') {
                bail!("symbolic link target is empty, too long or has a NUL");
            }
        }
        if let Some(x) = &self.xattrs {
            let mut total = 0usize;
            for (k, v) in x {
                if k.is_empty() || k.len() > 255 || k.contains('\0') {
                    bail!("extended attribute name {k:?} is not valid");
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(|_| anyhow::anyhow!("extended attribute {k:?} is not base64"))?;
                total += k.len() + bytes.len();
            }
            if total > XATTR_LIMIT {
                bail!("extended attributes hold {total} bytes, more than {XATTR_LIMIT}");
            }
        }
        if let Some(o) = &self.owner {
            for n in [&o.user, &o.group].into_iter().flatten() {
                if n.is_empty() || n.len() > 256 || n.contains(['\0', '/', ':']) {
                    bail!("owner name {n:?} is not valid");
                }
            }
        }
        Ok(())
    }

    /// `rwxr-xr-x` style text of the mode, for listings.
    pub fn mode_text(&self) -> Option<String> {
        self.mode.map(mode_text)
    }
}

/// The metadata a new content version of a file keeps from the previous
/// version (all but a link target).
pub fn carry_for_file(prev: Option<&FileMeta>) -> Option<FileMeta> {
    let mut m = prev?.clone();
    m.symlink = None;
    m.normalized()
}

pub fn mode_text(m: u32) -> String {
    let mut s = String::with_capacity(9);
    for (shift, special, lower, upper) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let bits = (m >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        let x = bits & 1 != 0;
        s.push(match (m & special != 0, x) {
            (true, true) => lower,
            (true, false) => upper,
            (false, true) => 'x',
            (false, false) => '-',
        });
    }
    s
}

/// Whether a link target leaves any folder it could be in: absolute (a
/// leading `/`, a drive letter or a UNC path).
pub fn target_is_absolute(t: &str) -> bool {
    let b = t.as_bytes();
    t.starts_with('/')
        || t.starts_with('\\')
        || (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
}

/// Per-folder settings on this device (`FolderMount::meta`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaSettings {
    #[serde(default = "yes")]
    pub permissions: bool,
    #[serde(default = "yes")]
    pub symlinks: bool,
    #[serde(default = "yes")]
    pub xattrs: bool,
    /// Off by default: user and group ids rarely mean the same on two devices.
    #[serde(default)]
    pub ownership: bool,
}

fn yes() -> bool {
    true
}

impl Default for MetaSettings {
    fn default() -> Self {
        MetaSettings {
            permissions: true,
            symlinks: true,
            xattrs: true,
            ownership: false,
        }
    }
}

impl MetaSettings {
    pub fn is_default(&self) -> bool {
        *self == MetaSettings::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ModeCap {
    /// No permissions at all.
    None,
    /// Only a read-only flag (Windows).
    ReadOnly,
    /// Unix mode bits.
    Full,
}

/// What this device can represent. `Caps::here()` for the running system;
/// tests make a device that cannot represent something.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Caps {
    pub mode: ModeCap,
    pub xattrs: bool,
    pub owner: bool,
    pub symlinks: bool,
}

impl Caps {
    pub fn here() -> Caps {
        if cfg!(windows) {
            Caps {
                mode: ModeCap::ReadOnly,
                xattrs: false,
                owner: false,
                // Tried; without the privilege a note is written instead.
                symlinks: true,
            }
        } else if cfg!(any(target_os = "linux", target_os = "macos")) {
            Caps {
                mode: ModeCap::Full,
                xattrs: true,
                owner: true,
                symlinks: true,
            }
        } else if cfg!(unix) {
            // Android, iOS and other Unix systems: mode bits and links, but
            // no extended attributes or ownership worth syncing.
            Caps {
                mode: ModeCap::Full,
                xattrs: false,
                owner: false,
                symlinks: true,
            }
        } else {
            Caps::none()
        }
    }

    pub fn none() -> Caps {
        Caps {
            mode: ModeCap::None,
            xattrs: false,
            owner: false,
            symlinks: false,
        }
    }
}

/// Whether an extended attribute is synced at all.
pub fn xattr_synced(name: &str) -> bool {
    !XATTR_DENY.contains(&name) && !XATTR_DENY_PREFIX.iter().any(|p| name.starts_with(p))
}

/// Whether this system can hold an attribute of that name (an unprivileged
/// process on Linux only writes the `user.` namespace).
pub fn xattr_representable(name: &str) -> bool {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        name.starts_with("user.")
    } else {
        cfg!(target_os = "macos")
    }
}

/// User and group names by id, looked up once per scan.
#[derive(Default)]
pub struct Names {
    users: HashMap<u32, Option<String>>,
    groups: HashMap<u32, Option<String>>,
}

/// What the filesystem shows for an entry, as far as this device can see
/// and the settings allow; absent fields are not known. `md` is the
/// entry's own metadata (not following a link).
pub fn observe(
    path: &Path,
    md: &fs::Metadata,
    caps: &Caps,
    settings: &MetaSettings,
    names: &mut Names,
) -> FileMeta {
    let link = md.file_type().is_symlink();
    let mut m = FileMeta {
        v: META_VERSION,
        ..Default::default()
    };
    if settings.permissions && !link {
        m.mode = match caps.mode {
            ModeCap::None => None,
            ModeCap::ReadOnly => Some(if md.permissions().readonly() {
                0o444
            } else {
                0o666
            }),
            ModeCap::Full => unix_mode(md),
        };
    }
    if settings.xattrs && caps.xattrs && !link {
        m.xattrs = read_xattrs(path);
    }
    if settings.ownership && caps.owner {
        m.owner = owner_of(md, names);
    }
    m
}

#[cfg(unix)]
fn unix_mode(md: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(md.permissions().mode() & PERM_BITS)
}

#[cfg(not(unix))]
fn unix_mode(md: &fs::Metadata) -> Option<u32> {
    Some(if md.permissions().readonly() {
        0o444
    } else {
        0o666
    })
}

/// The metadata to publish for an entry: per property, what was observed
/// when it changed since this device last looked (`seen`), else what the
/// vault has (`prev`). Attributes this system cannot hold are kept from
/// `prev`. A record of a newer version is carried as it is.
pub fn combine(
    obs: &FileMeta,
    seen: Option<&FileMeta>,
    prev: Option<&FileMeta>,
    caps: &Caps,
) -> Option<FileMeta> {
    if let Some(p) = prev {
        if p.v > META_VERSION {
            return Some(p.clone());
        }
    }
    let empty = FileMeta::default();
    let seen = seen.unwrap_or(&empty);
    let mut out = prev.cloned().unwrap_or_default();
    out.v = META_VERSION;
    out.symlink = None;
    if obs.mode.is_some() && obs.mode != seen.mode {
        out.mode = match caps.mode {
            ModeCap::ReadOnly => {
                let ro = obs.mode.is_some_and(|m| m & 0o222 == 0);
                match out.mode {
                    Some(m) if ro => Some(m & !0o222),
                    Some(m) if m & 0o222 == 0 => Some(m | 0o200),
                    Some(m) => Some(m),
                    None if ro => Some(0o444),
                    None => None,
                }
            }
            _ => obs.mode,
        };
    }
    if obs.xattrs.is_some() && obs.xattrs != seen.xattrs {
        let mut x = obs.xattrs.clone().unwrap_or_default();
        if let Some(px) = prev.and_then(|p| p.xattrs.as_ref()) {
            for (k, v) in px {
                if !xattr_representable(k) && xattr_synced(k) {
                    x.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        out.xattrs = Some(x);
    }
    if obs.owner.is_some() && obs.owner != seen.owner {
        out.owner = obs.owner.clone();
    }
    out.normalized()
}

/// Write the metadata this device can represent and the settings allow onto
/// `path` (already written, or a link). Problems are returned, not raised:
/// metadata never stops a file from arriving.
pub fn apply(path: &Path, meta: &FileMeta, caps: &Caps, settings: &MetaSettings) -> Vec<String> {
    let mut problems = Vec::new();
    if meta.v > META_VERSION {
        return problems;
    }
    let link = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    if let (true, Some(mode), false) = (settings.permissions, meta.mode, link) {
        if let Err(e) = set_mode(path, mode, caps) {
            problems.push(format!("permissions: {e}"));
        }
    }
    if let (true, true, Some(want), false) = (settings.xattrs, caps.xattrs, &meta.xattrs, link) {
        if let Err(e) = write_xattrs(path, want) {
            problems.push(format!("extended attributes: {e}"));
        }
    }
    if let (true, true, Some(o)) = (settings.ownership, caps.owner, &meta.owner) {
        set_owner(path, o);
    }
    problems
}

fn set_mode(path: &Path, mode: u32, caps: &Caps) -> std::io::Result<()> {
    match caps.mode {
        ModeCap::None => Ok(()),
        ModeCap::ReadOnly => {
            let mut p = fs::metadata(path)?.permissions();
            let ro = mode & 0o222 == 0;
            if p.readonly() != ro {
                #[allow(clippy::permissions_set_readonly_false)]
                p.set_readonly(ro);
                fs::set_permissions(path, p)?;
            }
            Ok(())
        }
        ModeCap::Full => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(mode & PERM_BITS))
            }
            #[cfg(not(unix))]
            {
                let _ = (path, mode);
                Ok(())
            }
        }
    }
}

/// Make a file writable again before Varsto replaces it (Windows refuses to
/// replace a read-only file).
pub fn make_replaceable(path: &Path) {
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_file() && md.permissions().readonly() {
            let mut p = md.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            let _ = fs::set_permissions(path, p);
        }
    }
}

// ----- symbolic links ---------------------------------------------------------

/// The keyed content hash of a link: over its target, apart from any file
/// content by a prefix no file hash is computed with.
pub fn link_hash(key: &crate::crypto::SecretKey, target: &str) -> String {
    let mut data = b"varsto-symlink\0".to_vec();
    data.extend_from_slice(target.as_bytes());
    hex::encode(crate::crypto::keyed_hash(key, &data))
}

/// A link's target as text (None: not UTF-8 or too long; such a link is
/// left alone).
pub fn read_link(path: &Path) -> Option<String> {
    let t = fs::read_link(path).ok()?;
    let s = t.to_str()?.to_string();
    (!s.is_empty() && s.len() <= LINK_MAX).then_some(s)
}

/// How a link was written.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    Link,
    /// The system refused a link; a note at `<path>.varsto-link` says what it is.
    Note,
}

/// Put a symbolic link to `target` at `path`, replacing a file or link
/// there (never a directory), atomically where the system allows. Where no
/// link can be made, a small note is written next to the path instead.
pub fn write_link(path: &Path, target: &str) -> Result<LinkOutcome> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent", path.display()))?;
    fs::create_dir_all(dir)?;
    let tmp = path.with_file_name(format!(".varsto-link-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    match make_link(target, &tmp, dir) {
        Ok(()) => {
            if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
                let _ = fs::remove_file(&tmp);
                bail!(
                    "{} is a directory; a link does not replace it",
                    path.display()
                );
            }
            make_replaceable(path);
            if let Err(e) = fs::rename(&tmp, path) {
                let _ = fs::remove_file(&tmp);
                return Err(e.into());
            }
            let _ = fs::remove_file(note_path(path));
            Ok(LinkOutcome::Link)
        }
        Err(_) => {
            let note = serde_json::json!({
                "varsto": "symbolic link",
                "target": target,
                "hint": "this system did not allow Varsto to create the link (on Windows: Developer Mode or the privilege to create symbolic links)",
            });
            crate::util::write_atomic(&note_path(path), &serde_json::to_vec_pretty(&note)?)?;
            Ok(LinkOutcome::Note)
        }
    }
}

pub fn note_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(LINK_NOTE_SUFFIX);
    PathBuf::from(s)
}

#[cfg(unix)]
fn make_link(target: &str, at: &Path, _dir: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(windows)]
fn make_link(target: &str, at: &Path, dir: &Path) -> std::io::Result<()> {
    let native = target.replace('/', "\\");
    if dir.join(&native).is_dir() {
        std::os::windows::fs::symlink_dir(&native, at)
    } else {
        std::os::windows::fs::symlink_file(&native, at)
    }
}

#[cfg(not(any(unix, windows)))]
fn make_link(_target: &str, _at: &Path, _dir: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("no symbolic links here"))
}

/// `root/rel` for writing or removing the entry itself: `rel` must be a
/// valid folder path and no directory above the entry may be a link (the
/// entry may be one: it is replaced, never followed).
pub fn join_entry(root: &Path, rel: &str) -> Result<PathBuf> {
    crate::util::check_rel_path(rel)?;
    check_no_link_above(root, rel)?;
    Ok(root.join(rel))
}

/// Refuse a path whose directories inside the folder include a link.
pub fn check_no_link_above(root: &Path, rel: &str) -> Result<()> {
    let mut p = root.to_path_buf();
    let comps: Vec<&str> = rel.split('/').collect();
    for c in &comps[..comps.len().saturating_sub(1)] {
        p.push(c);
        if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!(
                "{} is a symbolic link; Varsto does not go through links",
                p.display()
            );
        }
    }
    Ok(())
}

/// Refuse to read `root/rel` when it or a directory above it is a link.
pub fn check_no_link(root: &Path, rel: &str) -> Result<()> {
    check_no_link_above(root, rel)?;
    let p = root.join(rel);
    if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("{rel} is a symbolic link; Varsto does not follow links");
    }
    Ok(())
}

// ----- extended attributes ------------------------------------------------------

/// The synced attributes of `path` (not following a link), or None when the
/// filesystem has none to offer or they exceed `XATTR_LIMIT`.
pub fn read_xattrs(path: &Path) -> Option<BTreeMap<String, String>> {
    let names = sys::list(path).ok()?;
    let mut out = BTreeMap::new();
    let mut total = 0usize;
    for n in names {
        if !xattr_synced(&n) || !xattr_representable(&n) {
            continue;
        }
        let Ok(v) = sys::get(path, &n) else {
            continue;
        };
        total += n.len() + v.len();
        if total > XATTR_LIMIT {
            return None;
        }
        out.insert(n, base64::engine::general_purpose::STANDARD.encode(v));
    }
    Some(out)
}

/// One extended attribute of `path` (not following a link).
pub fn get_xattr(path: &Path, name: &str) -> std::io::Result<Vec<u8>> {
    sys::get(path, name)
}

/// Set one extended attribute of `path` (not following a link).
pub fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    sys::set(path, name, value)
}

/// Make the synced attributes this system can hold equal to `want`.
fn write_xattrs(path: &Path, want: &BTreeMap<String, String>) -> std::io::Result<()> {
    let mut have: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for n in sys::list(path)? {
        if xattr_synced(&n) && xattr_representable(&n) {
            if let Ok(v) = sys::get(path, &n) {
                have.insert(n, v);
            }
        }
    }
    for n in have.keys() {
        if !want.contains_key(n) {
            sys::remove(path, n)?;
        }
    }
    for (n, v) in want {
        if !xattr_synced(n) || !xattr_representable(n) {
            continue;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(v) else {
            continue;
        };
        if have.get(n) != Some(&bytes) {
            sys::set(path, n, &bytes)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
mod sys {
    use std::ffi::CString;
    use std::io::{Error, Result};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn c(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::other("NUL in path"))
    }
    fn cn(name: &str) -> Result<CString> {
        CString::new(name).map_err(|_| Error::other("NUL in name"))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe fn list_raw(p: *const libc::c_char, buf: *mut libc::c_char, size: usize) -> isize {
        libc::llistxattr(p, buf, size)
    }
    #[cfg(target_os = "macos")]
    unsafe fn list_raw(p: *const libc::c_char, buf: *mut libc::c_char, size: usize) -> isize {
        libc::listxattr(p, buf, size, libc::XATTR_NOFOLLOW)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe fn get_raw(
        p: *const libc::c_char,
        n: *const libc::c_char,
        buf: *mut libc::c_void,
        size: usize,
    ) -> isize {
        libc::lgetxattr(p, n, buf, size)
    }
    #[cfg(target_os = "macos")]
    unsafe fn get_raw(
        p: *const libc::c_char,
        n: *const libc::c_char,
        buf: *mut libc::c_void,
        size: usize,
    ) -> isize {
        libc::getxattr(p, n, buf, size, 0, libc::XATTR_NOFOLLOW)
    }

    pub fn list(path: &Path) -> Result<Vec<String>> {
        let p = c(path)?;
        // SAFETY: a NUL-terminated path; a null buffer asks for the size.
        let size = unsafe { list_raw(p.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: the buffer holds `buf.len()` bytes.
        let got = unsafe { list_raw(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if got < 0 {
            return Err(Error::last_os_error());
        }
        buf.truncate(got as usize);
        Ok(buf
            .split(|b| *b == 0)
            .filter(|n| !n.is_empty())
            .filter_map(|n| std::str::from_utf8(n).ok().map(str::to_string))
            .collect())
    }

    pub fn get(path: &Path, name: &str) -> Result<Vec<u8>> {
        let (p, n) = (c(path)?, cn(name)?);
        // SAFETY: NUL-terminated strings; a null buffer asks for the size.
        let size = unsafe { get_raw(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(Error::last_os_error());
        }
        let mut buf = vec![0u8; size as usize];
        if size == 0 {
            return Ok(buf);
        }
        // SAFETY: the buffer holds `buf.len()` bytes.
        let got = unsafe { get_raw(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if got < 0 {
            return Err(Error::last_os_error());
        }
        buf.truncate(got as usize);
        Ok(buf)
    }

    pub fn set(path: &Path, name: &str, value: &[u8]) -> Result<()> {
        let (p, n) = (c(path)?, cn(name)?);
        // SAFETY: NUL-terminated strings and a buffer of `value.len()` bytes.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let r = unsafe {
            libc::lsetxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let r = unsafe {
            libc::setxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn remove(path: &Path, name: &str) -> Result<()> {
        let (p, n) = (c(path)?, cn(name)?);
        // SAFETY: NUL-terminated strings.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let r = unsafe { libc::lremovexattr(p.as_ptr(), n.as_ptr()) };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let r = unsafe { libc::removexattr(p.as_ptr(), n.as_ptr(), libc::XATTR_NOFOLLOW) };
        if r < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
mod sys {
    use std::io::{Error, Result};
    use std::path::Path;
    pub fn list(_: &Path) -> Result<Vec<String>> {
        Err(Error::other("no extended attributes here"))
    }
    pub fn get(_: &Path, _: &str) -> Result<Vec<u8>> {
        Err(Error::other("no extended attributes here"))
    }
    pub fn set(_: &Path, _: &str, _: &[u8]) -> Result<()> {
        Err(Error::other("no extended attributes here"))
    }
    pub fn remove(_: &Path, _: &str) -> Result<()> {
        Err(Error::other("no extended attributes here"))
    }
}

// ----- ownership --------------------------------------------------------------

#[cfg(unix)]
fn owner_of(md: &fs::Metadata, names: &mut Names) -> Option<Owner> {
    use std::os::unix::fs::MetadataExt;
    let (uid, gid) = (md.uid(), md.gid());
    let user = names
        .users
        .entry(uid)
        .or_insert_with(|| user_name(uid))
        .clone();
    let group = names
        .groups
        .entry(gid)
        .or_insert_with(|| group_name(gid))
        .clone();
    Some(Owner {
        uid,
        gid,
        user,
        group,
    })
}

#[cfg(not(unix))]
fn owner_of(_: &fs::Metadata, _: &mut Names) -> Option<Owner> {
    None
}

/// Set ownership when it can mean the same here: as root (names first,
/// numbers when a name is unknown), otherwise only when both names exist
/// here with the same ids (then the change is one this user may make, or
/// the system refuses it quietly).
#[cfg(unix)]
fn set_owner(path: &Path, o: &Owner) {
    let local_uid = o.user.as_deref().and_then(user_id);
    let local_gid = o.group.as_deref().and_then(group_id);
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let (uid, gid) = if root {
        (local_uid.unwrap_or(o.uid), local_gid.unwrap_or(o.gid))
    } else if local_uid == Some(o.uid) && local_gid == Some(o.gid) {
        (o.uid, o.gid)
    } else {
        return;
    };
    let _ = std::os::unix::fs::lchown(path, Some(uid), Some(gid));
}

#[cfg(not(unix))]
fn set_owner(_: &Path, _: &Owner) {}

#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: zeroed passwd is a valid out-parameter; the buffer is ours.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if r != 0 || res.is_null() || pw.pw_name.is_null() {
        return None;
    }
    // SAFETY: pw_name points into `buf`, NUL-terminated.
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
    name.to_str().ok().map(str::to_string)
}

#[cfg(unix)]
fn group_name(gid: u32) -> Option<String> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: as in `user_name`.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if r != 0 || res.is_null() || gr.gr_name.is_null() {
        return None;
    }
    // SAFETY: gr_name points into `buf`, NUL-terminated.
    let name = unsafe { std::ffi::CStr::from_ptr(gr.gr_name) };
    name.to_str().ok().map(str::to_string)
}

#[cfg(unix)]
fn user_id(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: as in `user_name`.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut res,
        )
    };
    (r == 0 && !res.is_null()).then_some(pw.pw_uid)
}

#[cfg(unix)]
fn group_id(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 16384];
    // SAFETY: as in `user_name`.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut gr,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut res,
        )
    };
    (r == 0 && !res.is_null()).then_some(gr.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: Option<u32>) -> FileMeta {
        FileMeta {
            v: META_VERSION,
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn a_property_is_taken_only_when_it_changed_here() {
        let full = Caps::here();
        // New: what is seen is published.
        let c = combine(&meta(Some(0o755)), None, None, &full).unwrap();
        assert_eq!(c.mode, Some(0o755));
        // The filesystem shows 0o644 although the vault says 0o600 (it could
        // not store that): unchanged since last seen, the vault's value stays.
        let seen = meta(Some(0o644));
        let c = combine(
            &meta(Some(0o644)),
            Some(&seen),
            Some(&meta(Some(0o600))),
            &full,
        )
        .unwrap();
        assert_eq!(c.mode, Some(0o600));
        // A real change here wins.
        let c = combine(
            &meta(Some(0o640)),
            Some(&seen),
            Some(&meta(Some(0o600))),
            &full,
        )
        .unwrap();
        assert_eq!(c.mode, Some(0o640));
        // Not seen at all (setting off, no support): the vault's value stays.
        let c = combine(&meta(None), Some(&seen), Some(&meta(Some(0o600))), &full).unwrap();
        assert_eq!(c.mode, Some(0o600));
        assert_eq!(combine(&meta(None), None, None, &full), None);
    }

    #[test]
    fn windows_sees_only_read_only() {
        let caps = Caps {
            mode: ModeCap::ReadOnly,
            ..Caps::none()
        };
        let seen = meta(Some(0o666));
        // Marked read-only: the write bits go, the rest stays.
        let c = combine(
            &meta(Some(0o444)),
            Some(&seen),
            Some(&meta(Some(0o755))),
            &caps,
        )
        .unwrap();
        assert_eq!(c.mode, Some(0o555));
        // Writable again: the owner may write.
        let seen = meta(Some(0o444));
        let c = combine(
            &meta(Some(0o666)),
            Some(&seen),
            Some(&meta(Some(0o555))),
            &caps,
        )
        .unwrap();
        assert_eq!(c.mode, Some(0o755));
    }

    #[test]
    fn attributes_this_system_cannot_hold_are_kept() {
        let mut prev = meta(None);
        prev.xattrs = Some(BTreeMap::from([
            ("com.apple.FinderInfo".to_string(), "AAAA".to_string()),
            ("user.tag".to_string(), "b2xk".to_string()),
        ]));
        let mut obs = meta(None);
        obs.xattrs = Some(BTreeMap::from([(
            "user.tag".to_string(),
            "bmV3".to_string(),
        )]));
        let c = combine(&obs, None, Some(&prev), &Caps::here()).unwrap();
        let x = c.xattrs.unwrap();
        assert_eq!(x["user.tag"], "bmV3");
        if cfg!(target_os = "linux") {
            assert_eq!(x["com.apple.FinderInfo"], "AAAA");
        }
    }

    #[test]
    fn newer_records_are_carried() {
        let mut prev = meta(Some(0o600));
        prev.v = META_VERSION + 1;
        let c = combine(&meta(Some(0o644)), None, Some(&prev), &Caps::here()).unwrap();
        assert_eq!(c, prev);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_that_does_not_map_is_left_alone_without_root() {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root may set any owner
        }
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        fs::write(&f, b"x").unwrap();
        let before = fs::metadata(&f).unwrap();
        let settings = MetaSettings {
            ownership: true,
            ..Default::default()
        };
        let caps = Caps {
            owner: true,
            ..Caps::none()
        };
        for owner in [
            Owner {
                uid: 0,
                gid: 0,
                user: Some("root".into()),
                group: Some("root".into()),
            },
            Owner {
                uid: 4_000_000,
                gid: 4_000_000,
                user: Some("no-such-user-here".into()),
                group: None,
            },
        ] {
            let m = FileMeta {
                v: META_VERSION,
                owner: Some(owner),
                ..Default::default()
            };
            assert!(apply(&f, &m, &caps, &settings).is_empty());
            let after = fs::metadata(&f).unwrap();
            assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        }
        // What this device sees is its own ids, with names where known.
        let seen = observe(
            &f,
            &fs::symlink_metadata(&f).unwrap(),
            &caps,
            &settings,
            &mut Names::default(),
        );
        assert_eq!(seen.owner.as_ref().map(|o| o.uid), Some(before.uid()));
        // Ownership is off by default.
        let seen = observe(
            &f,
            &fs::symlink_metadata(&f).unwrap(),
            &caps,
            &MetaSettings::default(),
            &mut Names::default(),
        );
        assert!(seen.owner.is_none());
    }

    #[test]
    fn validation_and_text() {
        assert!(meta(Some(0o10000)).validate().is_err());
        let mut m = meta(None);
        m.symlink = Some(String::new());
        assert!(m.validate().is_err());
        assert_eq!(mode_text(0o755), "rwxr-xr-x");
        assert_eq!(mode_text(0o4755), "rwsr-xr-x");
        assert_eq!(mode_text(0o1777), "rwxrwxrwt");
        assert!(target_is_absolute("/etc"));
        assert!(target_is_absolute("C:\\x"));
        assert!(!target_is_absolute("../x"));
        assert!(xattr_synced("user.x"));
        assert!(!xattr_synced("com.apple.quarantine"));
        assert!(!xattr_synced("security.selinux"));
    }
}
