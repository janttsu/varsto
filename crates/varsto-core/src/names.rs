// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Names of files: what a vault path may be, and how a device writes a
//! vault path to a local filesystem that forbids some of its characters.
//!
//! Vault paths keep the original names (spec: "Paths"): every UTF-8 name
//! component is allowed except an empty one, `.`, `..` and one holding NUL
//! (`/` is the separator). Nothing is normalised: the bytes a device read
//! from its filesystem are the bytes other devices see.
//!
//! A device writes a vault path as it is wherever its filesystem accepts
//! it. Where it does not (Windows, or an exFAT/FAT/NTFS disk mounted on
//! Linux), the forbidden characters are written as private-use characters
//! U+F000 + code, the scheme Cygwin, Samba and the Windows SFM driver use
//! (`:` is U+F03A), and a file whose name collides with another one on a
//! case-insensitive filesystem gets a ` (2)` suffix. Every name written
//! differently from its vault path is recorded in the folder's local name
//! map ([`LocalNames`]), so a scan maps the local name back to the vault
//! path and the file does not look renamed.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Longest vault path accepted, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// Whether `path` is a valid vault path: relative, `/` as the separator,
/// every component a non-empty name other than `.` and `..`, no NUL. Any
/// other character (`:`, `\`, `?`, control characters, a trailing dot or
/// space, a Windows device name such as `CON.txt`) is part of the name.
/// Paths from other devices (manifests, notes) go through this before they
/// touch a filesystem.
pub fn check_vault_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        bail!(
            "path must be a non-empty path relative to the folder: {}",
            display(path)
        );
    }
    if path.contains('\0') {
        bail!("path contains a NUL character: {}", display(path));
    }
    if path.starts_with('/') {
        bail!("path must be relative to the folder: {}", display(path));
    }
    for c in path.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            bail!(
                "path must be relative to the folder and must not contain '..', '.' or empty names: {}",
                display(path)
            );
        }
    }
    Ok(())
}

/// A name for people to read: control characters and the invisible
/// direction overrides (which could make a name look like another one)
/// are shown as `\u{..}` escapes. Everything else, `:` and `\` included,
/// is shown as it is.
pub fn display(name: &str) -> Cow<'_, str> {
    if !name.chars().any(needs_escape) {
        return Cow::Borrowed(name);
    }
    let mut out = String::with_capacity(name.len() + 8);
    for ch in name.chars() {
        if needs_escape(ch) {
            out.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

fn needs_escape(ch: char) -> bool {
    ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

// ----- the Windows mapping ------------------------------------------------

/// First code point of the private-use range the Windows mapping uses.
pub const PRIVATE_BASE: u32 = 0xF000;

/// Characters Windows does not allow anywhere in a name.
fn windows_forbidden(ch: char) -> bool {
    matches!(ch, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
        || ('\u{1}'..='\u{1f}').contains(&ch)
}

/// Device names Windows reserves, with or without an extension.
const RESERVED: [&str; 30] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³", "CONIN$", "CONOUT$",
];

fn is_reserved_stem(stem: &str) -> bool {
    let s = stem.trim_end_matches(' ').to_uppercase();
    RESERVED.contains(&s.as_str())
}

/// Characters the encoder can turn into a private-use one, and so the
/// only ones the decoder turns back: everything else in U+F000..U+F0FF is
/// left as it is.
fn decodable(ch: char) -> bool {
    windows_forbidden(ch)
        || ch == '.'
        || ch == ' '
        || ch == '$'
        || ch.is_ascii_alphanumeric()
        || matches!(ch, '¹' | '²' | '³')
}

fn private(ch: char) -> char {
    char::from_u32(PRIVATE_BASE + ch as u32).expect("private-use code point")
}

/// One name component written for Windows: forbidden characters and
/// control characters 1-31 become U+F000 + code, a trailing dot or space
/// becomes U+F02E / U+F020, and the last character of a reserved device
/// name (`CON`, `NUL`, `COM1`, `LPT9`, ... with any extension) becomes its
/// private-use form (`CON.txt` is written `CO\u{F04E}.txt`). Names without
/// any of these come back unchanged.
pub fn windows_encode_component(name: &str) -> Cow<'_, str> {
    let ends_badly = name.ends_with('.') || name.ends_with(' ');
    let stem = name.split('.').next().unwrap_or("");
    let reserved = is_reserved_stem(stem);
    if !ends_badly && !reserved && !name.chars().any(windows_forbidden) {
        return Cow::Borrowed(name);
    }
    let mut chars: Vec<char> = name
        .chars()
        .map(|c| if windows_forbidden(c) { private(c) } else { c })
        .collect();
    if let Some(last) = chars.last_mut() {
        if *last == '.' || *last == ' ' {
            *last = private(*last);
        }
    }
    if reserved {
        // The last character of the device name (before its trailing
        // spaces, which Windows ignores when it matches device names).
        let stem_len = stem.chars().count();
        let trimmed_len = stem.trim_end_matches(' ').chars().count();
        if trimmed_len > 0 && trimmed_len <= stem_len {
            let i = trimmed_len - 1;
            if !(PRIVATE_BASE..=PRIVATE_BASE + 0xff).contains(&(chars[i] as u32)) {
                chars[i] = private(chars[i]);
            }
        }
    }
    Cow::Owned(chars.into_iter().collect())
}

/// The inverse of [`windows_encode_component`]: private-use characters
/// U+F000 + code whose code the encoder produces are turned back.
pub fn windows_decode_component(name: &str) -> Cow<'_, str> {
    let decode = |c: char| -> Option<char> {
        let v = c as u32;
        if (PRIVATE_BASE + 1..=PRIVATE_BASE + 0xff).contains(&v) {
            char::from_u32(v - PRIVATE_BASE).filter(|d| decodable(*d))
        } else {
            None
        }
    };
    if !name.chars().any(|c| decode(c).is_some()) {
        return Cow::Borrowed(name);
    }
    Cow::Owned(name.chars().map(|c| decode(c).unwrap_or(c)).collect())
}

fn map_components(path: &str, f: impl Fn(&str) -> Cow<'_, str>) -> String {
    path.split('/')
        .map(|c| f(c).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// A vault path written for Windows, component by component.
pub fn windows_encode_path(path: &str) -> String {
    map_components(path, windows_encode_component)
}

/// A local path read on Windows, turned back into the vault path.
pub fn windows_decode_path(path: &str) -> String {
    map_components(path, windows_decode_component)
}

/// Whether a vault path is written differently on Windows (for the
/// import reports: "N names will be mapped on Windows devices").
pub fn mapped_on_windows(path: &str) -> bool {
    path.split('/')
        .any(|c| matches!(windows_encode_component(c), Cow::Owned(_)))
}

// ----- local filesystem rules ------------------------------------------------

/// What a folder's filesystem does with names on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalRules {
    /// Names are written with the Windows mapping, and private-use
    /// characters in local names are read back as escapes.
    pub windows_names: bool,
    /// Two names that differ only in case (or Unicode normalisation) are
    /// the same file.
    pub case_insensitive: bool,
}

impl LocalRules {
    /// Linux and other case-sensitive POSIX filesystems: names as they are.
    pub const POSIX: LocalRules = LocalRules {
        windows_names: false,
        case_insensitive: false,
    };

    /// The rules of the filesystem `root` is on: the Windows mapping on
    /// Windows; case sensitivity found by writing a probe file (macOS and
    /// Windows default to case-insensitive, and so do exFAT and FAT disks
    /// on Linux). Remembered per root for the life of the process.
    pub fn detect(root: &Path) -> LocalRules {
        static CACHE: Mutex<Option<HashMap<PathBuf, LocalRules>>> = Mutex::new(None);
        let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.get_or_insert_with(HashMap::new);
        if let Some(r) = cache.get(root) {
            return *r;
        }
        let platform = cfg!(any(windows, target_os = "macos"));
        if !root.is_dir() {
            // Not there yet: the platform's default, not remembered.
            return LocalRules {
                windows_names: cfg!(windows),
                case_insensitive: platform,
            };
        }
        // A directory that cannot be written (a backup's source): the
        // platform's default, remembered like a probe's answer.
        let r = LocalRules {
            windows_names: cfg!(windows),
            case_insensitive: probe_case_insensitive(root).unwrap_or(platform),
        };
        cache.insert(root.to_path_buf(), r);
        r
    }

    /// The local path a vault path is written to when nothing else (a
    /// collision, a filesystem that refused the name) is recorded for it.
    pub fn default_local<'a>(&self, vault: &'a str) -> Cow<'a, str> {
        if self.windows_names {
            Cow::Owned(windows_encode_path(vault))
        } else {
            Cow::Borrowed(vault)
        }
    }

    /// The vault path of a local path the name map does not know.
    pub fn default_vault<'a>(&self, local: &'a str) -> Cow<'a, str> {
        if self.windows_names {
            Cow::Owned(windows_decode_path(local))
        } else {
            Cow::Borrowed(local)
        }
    }

    fn fold(&self, name: &str) -> String {
        fold(name)
    }
}

/// The key two names share when a case-insensitive filesystem takes them
/// for the same file: lower case, Unicode NFC (macOS also ignores the
/// normalisation of names).
pub fn fold(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    name.nfc().collect::<String>().to_lowercase()
}

/// Whether the filesystem of `root` ignores case. An entry already in the
/// directory is looked up with its case swapped (nothing is written, so a
/// backup's source is left alone); an empty directory gets a probe file
/// `.varsto-case-probe-<random>` that is removed at once.
fn probe_case_insensitive(root: &Path) -> Option<bool> {
    if !root.is_dir() {
        return None;
    }
    let swap = |n: &str| -> String {
        n.chars()
            .map(|c| {
                if c.is_lowercase() {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c.to_lowercase().next().unwrap_or(c)
                }
            })
            .collect()
    };
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten().take(64) {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let flipped = swap(&name);
            if flipped == name || !name.is_ascii() {
                continue;
            }
            let (Ok(a), other) = (
                std::fs::symlink_metadata(e.path()),
                std::fs::symlink_metadata(root.join(&flipped)),
            ) else {
                continue;
            };
            return match other {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(_) => continue,
                Ok(b) => Some(same_file(&a, &b)),
            };
        }
    }
    let tag: u64 = rand::random();
    let lower = root.join(format!(".varsto-case-probe-{tag:x}"));
    let upper = root.join(format!(".VARSTO-CASE-PROBE-{tag:X}"));
    std::fs::write(&lower, b"").ok()?;
    let insensitive = std::fs::symlink_metadata(&upper).is_ok();
    let _ = std::fs::remove_file(&lower);
    Some(insensitive)
}

/// Two names found for one file (on a case-insensitive filesystem) rather
/// than two files that differ in case.
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok() && a.is_dir() == b.is_dir()
    }
}

// ----- the local name map ------------------------------------------------

/// Per folder and device: the vault paths written under another local
/// path (Windows mapping, a case collision, a filesystem that refused a
/// name). Empty on Linux in the usual case.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalNames {
    /// Vault path -> local path (both with `/` separators).
    map: BTreeMap<String, String>,
    /// Local path -> vault path, built when first needed.
    #[serde(skip)]
    rev: Option<HashMap<String, String>>,
    /// Directory listings read for case-insensitive placement: local
    /// directory -> (folded name -> name on disk).
    #[serde(skip)]
    listings: HashMap<String, HashMap<String, String>>,
    /// Local directories chosen by placement (they may not exist yet).
    #[serde(skip)]
    dirs: std::collections::HashSet<String>,
}

/// What [`LocalNames::place`] did with a name, for the warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placed {
    /// Written under the vault path itself.
    AsIs,
    /// Written with the Windows mapping (the platform's rule, or a
    /// filesystem that refused the name).
    Mapped(String),
    /// Renamed locally because another file has the same name on this
    /// case-insensitive filesystem.
    Disambiguated(String),
}

impl LocalNames {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// The recorded local path of a vault path, if any.
    pub fn get(&self, vault: &str) -> Option<&str> {
        self.map.get(vault).map(|s| s.as_str())
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &String)> {
        self.map.iter()
    }

    /// The local path (relative, `/` separators) a vault path is at.
    pub fn local_rel<'a>(&'a self, rules: LocalRules, vault: &'a str) -> Cow<'a, str> {
        match self.map.get(vault) {
            Some(l) => Cow::Borrowed(l.as_str()),
            None => rules.default_local(vault),
        }
    }

    /// `root` joined with the local path of a vault path, for reading
    /// and checks. Writes go through [`LocalNames::place`].
    pub fn disk(&self, root: &Path, rules: LocalRules, vault: &str) -> PathBuf {
        join(root, &self.local_rel(rules, vault))
    }

    fn rev(&mut self) -> &mut HashMap<String, String> {
        let map = &self.map;
        self.rev
            .get_or_insert_with(|| map.iter().map(|(v, l)| (l.clone(), v.clone())).collect())
    }

    /// The vault path of a file found at local path `local` by a scan.
    /// A name with private-use escapes typed by a person on Windows (or
    /// one whose decoded name another local file already has) is recorded
    /// so that the file keeps its local name when it is written back.
    pub fn vault_of(&mut self, rules: LocalRules, local: &str) -> String {
        if let Some(v) = self.rev().get(local) {
            return v.clone();
        }
        let mut vault = rules.default_vault(local).into_owned();
        if vault != local {
            if let Some(other) = self.map.get(&vault) {
                if other != local {
                    // `a\u{F03A}b` and a mapped `a:b` both on disk: the
                    // former keeps its name verbatim.
                    vault = local.to_string();
                }
            }
        }
        if check_vault_path(&vault).is_err() {
            vault = local.to_string();
        }
        if rules.default_local(&vault) != local {
            self.record(&vault, local);
        }
        vault
    }

    /// [`LocalNames::vault_of`] without recording anything (a path named
    /// by the file manager, the interface).
    pub fn vault_of_local(&self, rules: LocalRules, local: &str) -> String {
        if let Some(v) = self.rev.as_ref().and_then(|r| r.get(local)) {
            return v.clone();
        }
        if let Some((v, _)) = self.map.iter().find(|(_, l)| l.as_str() == local) {
            return v.clone();
        }
        rules.default_vault(local).into_owned()
    }

    /// Record that `vault` is written at `local`.
    pub fn record(&mut self, vault: &str, local: &str) {
        if let Some(old) = self.map.insert(vault.to_string(), local.to_string()) {
            if let Some(rev) = self.rev.as_mut() {
                rev.remove(&old);
            }
        }
        if let Some(rev) = self.rev.as_mut() {
            rev.insert(local.to_string(), vault.to_string());
        }
    }

    /// The vault path is gone from the disk (deleted, moved away): drop
    /// its record and its name from the listings read for placement.
    pub fn forget(&mut self, rules: LocalRules, vault: &str) {
        let local = self.local_rel(rules, vault).into_owned();
        if let Some(old) = self.map.remove(vault) {
            if let Some(rev) = self.rev.as_mut() {
                rev.remove(&old);
            }
        }
        if !self.listings.is_empty() {
            let (d, n) = match local.rfind('/') {
                Some(i) => (&local[..i], &local[i + 1..]),
                None => ("", local.as_str()),
            };
            if let Some(l) = self.listings.get_mut(d) {
                if l.get(&fold(n)).is_some_and(|x| x == n) {
                    l.remove(&fold(n));
                }
            }
        }
    }

    /// Records whose vault path `keep` no longer wants (files deleted
    /// while this device was not looking).
    pub fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        let before = self.map.len();
        self.map.retain(|v, _| keep(v));
        if self.map.len() != before {
            self.rev = None;
        }
    }

    /// Where to write vault path `vault` under `root`: its recorded local
    /// path, else the platform's form of it, renamed with a ` (2)` suffix
    /// when a case-insensitive filesystem already has another file of that
    /// name, else (a Linux disk whose filesystem refuses `:` and the like)
    /// the Windows mapping. Whatever differs from the vault path is
    /// recorded. The path is checked like [`crate::util::safe_join`]: no
    /// symbolic links on the way.
    pub fn place(
        &mut self,
        root: &Path,
        rules: LocalRules,
        vault: &str,
    ) -> Result<(PathBuf, Placed)> {
        self.place_with(root, rules, vault, &default_probe)
    }

    /// [`LocalNames::place`] with the test for "this filesystem refuses
    /// the name" given (tests simulate exFAT with it).
    pub fn place_with(
        &mut self,
        root: &Path,
        rules: LocalRules,
        vault: &str,
        refuses: &dyn Fn(&Path, &Path) -> bool,
    ) -> Result<(PathBuf, Placed)> {
        check_vault_path(vault)?;
        if let Some(local) = self.map.get(vault).cloned() {
            let p = checked_join(root, &local)?;
            let placed = if local == vault {
                Placed::AsIs
            } else {
                Placed::Mapped(local)
            };
            return Ok((p, placed));
        }
        let mut local = rules.default_local(vault).into_owned();
        let mut mapped = local != vault;
        if !rules.windows_names && may_be_refused(&local) {
            // A name Linux allows; the filesystem under the folder (exFAT,
            // FAT, NTFS) may not.
            let p = join(root, &local);
            if refuses(root, &p) {
                local = windows_encode_path(vault);
                mapped = true;
            }
        }
        let mut disambiguated = false;
        if rules.case_insensitive {
            let (l, d) = self.case_place(root, rules, vault, &local);
            local = l;
            disambiguated = d;
        }
        if local != vault || rules.default_vault(&local) != vault {
            self.record(vault, &local);
        }
        let p = checked_join(root, &local)?;
        let placed = if disambiguated {
            Placed::Disambiguated(local)
        } else if mapped {
            Placed::Mapped(local)
        } else {
            Placed::AsIs
        };
        Ok((p, placed))
    }

    /// On a case-insensitive filesystem: each directory of `local` takes
    /// the spelling already on disk; the file's own name gets ` (2)`,
    /// ` (3)`... when the directory has a file of that name (by fold) that
    /// belongs to another vault path.
    fn case_place(
        &mut self,
        root: &Path,
        rules: LocalRules,
        vault: &str,
        local: &str,
    ) -> (String, bool) {
        let parts: Vec<&str> = local.split('/').collect();
        let mut dir = String::new();
        let mut out: Vec<String> = Vec::with_capacity(parts.len());
        let mut disambiguated = false;
        for (i, name) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let listing = self.listing(root, &dir);
            let existing = listing.get(&rules.fold(name)).cloned();
            let chosen = if !last {
                match existing {
                    Some(e) if self.is_dir(root, &child(&dir, &e)) => e,
                    Some(_) => {
                        // A file has the directory's name.
                        disambiguated = true;
                        self.free_name(root, rules, &dir, name, None)
                    }
                    None => name.to_string(),
                }
            } else {
                match existing {
                    None => name.to_string(),
                    Some(e) => {
                        let owner = self.owner_of(rules, &child(&dir, &e));
                        if owner == vault {
                            e
                        } else {
                            disambiguated = true;
                            self.free_name(root, rules, &dir, name, Some(vault))
                        }
                    }
                }
            };
            self.listings
                .entry(dir.clone())
                .or_default()
                .insert(rules.fold(&chosen), chosen.clone());
            dir = child(&dir, &chosen);
            if !last {
                self.dirs.insert(dir.clone());
            }
            out.push(chosen);
        }
        (out.join("/"), disambiguated)
    }

    fn is_dir(&self, root: &Path, local: &str) -> bool {
        self.dirs.contains(local) || join(root, local).is_dir()
    }

    fn owner_of(&mut self, rules: LocalRules, local: &str) -> String {
        if let Some(v) = self.rev().get(local) {
            return v.clone();
        }
        rules.default_vault(local).into_owned()
    }

    /// `name (2).ext`, `name (3).ext`, ...: the first one the directory
    /// does not have (by fold), or that already belongs to `vault`.
    fn free_name(
        &mut self,
        root: &Path,
        rules: LocalRules,
        dir: &str,
        name: &str,
        vault: Option<&str>,
    ) -> String {
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 => (&name[..i], &name[i..]),
            _ => (name, ""),
        };
        for n in 2u32.. {
            let candidate = format!("{stem} ({n}){ext}");
            let existing = self
                .listing(root, dir)
                .get(&rules.fold(&candidate))
                .cloned();
            match existing {
                None => return candidate,
                Some(e) => match vault {
                    Some(v) if self.owner_of(rules, &child(dir, &e)) == v => return e,
                    None if self.is_dir(root, &child(dir, &e)) => return e,
                    _ => {}
                },
            }
        }
        unreachable!()
    }

    /// Folded names in a local directory: what is on disk, plus what this
    /// map recorded there (a file may be placed before it is written).
    fn listing(&mut self, root: &Path, dir: &str) -> &HashMap<String, String> {
        if !self.listings.contains_key(dir) {
            let mut names = HashMap::new();
            if let Ok(rd) = std::fs::read_dir(join(root, dir)) {
                for e in rd.flatten() {
                    if let Some(n) = e.file_name().to_str() {
                        let n = n
                            .strip_suffix(crate::engine::PLACEHOLDER_SUFFIX)
                            .unwrap_or(n);
                        names.insert(fold(n), n.to_string());
                    }
                }
            }
            for l in self.map.values() {
                let (d, n) = match l.rfind('/') {
                    Some(i) => (&l[..i], &l[i + 1..]),
                    None => ("", l.as_str()),
                };
                if d == dir {
                    names.entry(fold(n)).or_insert_with(|| n.to_string());
                }
            }
            self.listings.insert(dir.to_string(), names);
        }
        &self.listings[dir]
    }
}

/// Whether a filesystem made for Windows (exFAT, FAT, NTFS) mounted on
/// Linux may refuse a name: one with a character Windows forbids, or a
/// trailing dot or space.
fn may_be_refused(local: &str) -> bool {
    local
        .split('/')
        .any(|c| c.ends_with('.') || c.ends_with(' ') || c.chars().any(windows_forbidden))
}

fn child(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// `root` joined with a relative path with `/` separators.
pub fn join(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    if !rel.is_empty() {
        for c in rel.split('/') {
            p.push(c);
        }
    }
    p
}

/// [`join`] for writing: a local path from the map or the rules (checked
/// for traversal; on Windows also for the characters Windows would read
/// as a drive, a stream or a separator), and no symbolic link on the way.
/// The entry itself may be a link: it is replaced, never followed
/// (`crate::fsmeta`).
pub fn checked_join(root: &Path, local: &str) -> Result<PathBuf> {
    check_vault_path(local)?;
    if cfg!(windows) && local.split('/').any(|c| c.chars().any(windows_forbidden)) {
        bail!("local path is not a valid Windows name: {}", display(local));
    }
    let mut p = root.to_path_buf();
    let parts: Vec<&str> = local.split('/').collect();
    for (n, c) in parts.iter().enumerate() {
        p.push(c);
        if n + 1 == parts.len() {
            break;
        }
        if let Ok(md) = std::fs::symlink_metadata(&p) {
            if md.file_type().is_symlink() {
                bail!(
                    "{} is a symbolic link; files are not written through links",
                    p.display()
                );
            }
        }
    }
    Ok(p)
}

/// Whether the filesystem refuses to create `path` (exFAT, FAT or NTFS on
/// Linux answer EINVAL, some drivers ENOENT): its directories are created
/// and an empty file is tried and removed again.
fn default_probe(_root: &Path, path: &Path) -> bool {
    fn refused(e: &std::io::Error) -> bool {
        e.kind() == std::io::ErrorKind::InvalidInput
            || e.kind() == std::io::ErrorKind::NotFound
            || e.raw_os_error() == Some(22)
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return refused(&e);
        }
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(path);
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => refused(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AFFECTED: &[&str] = &[
        "12:30.jpg",
        "a\\b",
        "what?",
        "star*",
        "say \"hi\"",
        "<tag>",
        "pipe|pipe",
        "dot.",
        "space ",
        "dots..",
        "...",
        "CON",
        "con.txt",
        "Nul.tar.gz",
        "COM1",
        "lpt9.log",
        "CON .txt",
        "conin$",
        "COM¹.x",
        "bell\u{7}",
        "tab\tname",
        "\u{1f}",
        "CON.",
        "a:b:c.",
    ];

    #[test]
    fn vault_paths_keep_any_name_but_no_traversal() {
        for ok in [
            "a.txt",
            "12:30.jpg",
            "dir/a\\b",
            "C:/x",
            "c:x",
            "con.txt",
            "dir/LPT1",
            "a\nb",
            "trailing. /x",
            "😀/e\u{301}.txt",
            "...",
            "-rf",
        ] {
            check_vault_path(ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a/./b",
            "a//b",
            "a/",
            ".",
            "..",
            "a\0b",
            "x/..",
        ] {
            assert!(check_vault_path(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(check_vault_path(&"a".repeat(MAX_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn windows_mapping_round_trips() {
        for name in AFFECTED {
            let enc = windows_encode_component(name);
            assert_ne!(enc.as_ref(), *name, "{name:?} must be mapped");
            assert!(!enc.chars().any(windows_forbidden), "{enc:?}");
            assert!(!enc.ends_with('.') && !enc.ends_with(' '), "{enc:?}");
            let stem = enc.split('.').next().unwrap();
            assert!(!is_reserved_stem(stem), "{enc:?} is still a device name");
            assert_eq!(windows_decode_component(&enc), *name, "{name:?}");
            assert!(mapped_on_windows(name));
        }
        // Names Windows takes are left alone.
        for name in [
            "plain.txt",
            "ünï 😀",
            "CONSOLE.txt",
            "COM10",
            "LPT",
            ".hidden",
            "a.b.c",
        ] {
            assert_eq!(windows_encode_component(name), *name);
            assert_eq!(windows_decode_component(name), *name);
            assert!(!mapped_on_windows(name));
        }
        assert_eq!(windows_encode_component("12:30.jpg"), "12\u{f03a}30.jpg");
        assert_eq!(windows_encode_component("CON.txt"), "CO\u{f04e}.txt");
        assert_eq!(windows_encode_component("a."), "a\u{f02e}");
        assert_eq!(windows_encode_component("a "), "a\u{f020}");
        assert_eq!(
            windows_encode_path("x:y/CON/z?"),
            "x\u{f03a}y/CO\u{f04e}/z\u{f03f}"
        );
        assert_eq!(
            windows_decode_path("x\u{f03a}y/CO\u{f04e}/z\u{f03f}"),
            "x:y/CON/z?"
        );
    }

    #[test]
    fn windows_mapping_is_injective_on_the_affected_set() {
        let mut seen = std::collections::HashSet::new();
        for name in AFFECTED {
            assert!(
                seen.insert(windows_encode_component(name).into_owned()),
                "{name:?}"
            );
        }
        // Every single character the encoder maps, alone and in a name.
        for code in 1u32..0x80 {
            let ch = char::from_u32(code).unwrap();
            if ch == '/' {
                continue;
            }
            let name = format!("x{ch}y");
            assert_eq!(
                windows_decode_component(&windows_encode_component(&name)),
                name
            );
        }
        // Private-use characters the encoder never makes stay as they are.
        assert_eq!(
            windows_decode_component("\u{f000}\u{f02f}\u{f100}"),
            "\u{f000}\u{f02f}\u{f100}"
        );
    }

    #[test]
    fn display_escapes_control_characters_only() {
        assert_eq!(display("12:30.jpg"), "12:30.jpg");
        assert_eq!(display("a\\b"), "a\\b");
        assert_eq!(display("a\nb\u{1b}[31m"), "a\\u{a}b\\u{1b}[31m");
        assert_eq!(display("evil\u{202e}gpj.exe"), "evil\\u{202e}gpj.exe");
    }

    const CI: LocalRules = LocalRules {
        windows_names: false,
        case_insensitive: true,
    };
    const WIN: LocalRules = LocalRules {
        windows_names: true,
        case_insensitive: true,
    };

    fn write(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn posix_places_names_as_they_are() {
        let tmp = tempfile::tempdir().unwrap();
        let mut names = LocalNames::default();
        for v in ["12:30.jpg", "d/a\\b?", "CON.txt", "dot."] {
            let (p, placed) = names.place(tmp.path(), LocalRules::POSIX, v).unwrap();
            assert_eq!(placed, Placed::AsIs);
            assert_eq!(p, join(tmp.path(), v));
        }
        assert!(names.is_empty());
    }

    #[test]
    fn windows_rules_map_and_scan_back() {
        let tmp = tempfile::tempdir().unwrap();
        let mut names = LocalNames::default();
        let (p, placed) = names.place(tmp.path(), WIN, "x:y/12:30.jpg").unwrap();
        assert_eq!(placed, Placed::Mapped("x\u{f03a}y/12\u{f03a}30.jpg".into()));
        write(&p);
        assert_eq!(
            names.vault_of(WIN, "x\u{f03a}y/12\u{f03a}30.jpg"),
            "x:y/12:30.jpg"
        );
        // A name typed by a person with a private-use character is read as
        // an escape, and keeps its local name.
        assert_eq!(names.vault_of(WIN, "a\u{f04e}b"), "aNb");
        assert_eq!(names.local_rel(WIN, "aNb"), "a\u{f04e}b");
        // Plain names need no record.
        let before = names.len();
        assert_eq!(names.vault_of(WIN, "plain.txt"), "plain.txt");
        assert_eq!(names.len(), before);
    }

    #[test]
    fn case_collisions_get_a_suffix_and_map_back() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut names = LocalNames::default();
        let (a, pa) = names.place(root, CI, "Photos/File.txt").unwrap();
        assert_eq!(pa, Placed::AsIs);
        write(&a);
        let (b, pb) = names.place(root, CI, "Photos/file.txt").unwrap();
        assert_eq!(pb, Placed::Disambiguated("Photos/file (2).txt".into()));
        write(&b);
        // A third spelling, and a file under the directory's other case.
        let (c, _) = names.place(root, CI, "Photos/FILE.TXT").unwrap();
        assert_eq!(c, join(root, "Photos/FILE (3).TXT"));
        write(&c);
        let (d, pd) = names.place(root, CI, "photos/other.txt").unwrap();
        assert_eq!(d, join(root, "Photos/other.txt"));
        assert_eq!(pd, Placed::AsIs);
        write(&d);
        // Writing the same vault path again reuses its place.
        assert_eq!(names.place(root, CI, "Photos/file.txt").unwrap().0, b);
        assert_eq!(names.place(root, CI, "Photos/File.txt").unwrap().0, a);
        // A scan maps every local name back.
        let mut found: Vec<String> = walkdir::WalkDir::new(root)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .map(|e| crate::util::manifest_path(e.path().strip_prefix(root).unwrap()).unwrap())
            .map(|l| names.vault_of(CI, &l))
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                "Photos/FILE.TXT",
                "Photos/File.txt",
                "Photos/file.txt",
                "photos/other.txt"
            ]
        );
        // A forgotten path frees its record.
        names.forget(CI, "Photos/file.txt");
        assert!(names.get("Photos/file.txt").is_none());
    }

    #[test]
    fn normalisation_twins_collide_on_case_insensitive_filesystems() {
        let tmp = tempfile::tempdir().unwrap();
        let mut names = LocalNames::default();
        let (a, _) = names.place(tmp.path(), CI, "caf\u{e9}").unwrap();
        write(&a);
        let (_, placed) = names.place(tmp.path(), CI, "cafe\u{301}").unwrap();
        assert_eq!(placed, Placed::Disambiguated("cafe\u{301} (2)".into()));
    }

    #[test]
    fn refused_names_fall_back_to_the_windows_mapping() {
        let tmp = tempfile::tempdir().unwrap();
        let mut names = LocalNames::default();
        let refuses = |_: &Path, p: &Path| p.to_string_lossy().contains(':');
        let (p, placed) = names
            .place_with(tmp.path(), LocalRules::POSIX, "12:30.jpg", &refuses)
            .unwrap();
        assert_eq!(placed, Placed::Mapped("12\u{f03a}30.jpg".into()));
        write(&p);
        // Linux rules do not decode escapes; the record maps it back.
        assert_eq!(
            names.vault_of(LocalRules::POSIX, "12\u{f03a}30.jpg"),
            "12:30.jpg"
        );
        // Names the filesystem takes are not probed.
        let (_, placed) = names
            .place_with(tmp.path(), LocalRules::POSIX, "plain", &|_, _| {
                panic!("probed")
            })
            .unwrap();
        assert_eq!(placed, Placed::AsIs);
    }

    #[test]
    fn placing_refuses_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let mut names = LocalNames::default();
        for bad in ["../x", "/abs", "a\0b", "a/../b", ""] {
            assert!(names.place(tmp.path(), WIN, bad).is_err(), "{bad:?}");
            assert!(
                names.place(tmp.path(), LocalRules::POSIX, bad).is_err(),
                "{bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn placing_does_not_follow_links() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(tmp.path(), root.join("link")).unwrap();
        let mut names = LocalNames::default();
        assert!(names.place(&root, LocalRules::POSIX, "link/x").is_err());
    }

    #[test]
    fn probe_finds_case_sensitivity() {
        let tmp = tempfile::tempdir().unwrap();
        // Whatever the test machine's filesystem is, the probe leaves
        // nothing behind, and an existing entry gives the same answer
        // without writing anything.
        let empty = probe_case_insensitive(tmp.path()).unwrap();
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
        std::fs::write(tmp.path().join("Probe.txt"), b"x").unwrap();
        assert_eq!(probe_case_insensitive(tmp.path()), Some(empty));
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
        if !empty {
            // Two files that differ in case on a case-sensitive disk.
            std::fs::write(tmp.path().join("pROBE.TXT"), b"y").unwrap();
            assert_eq!(probe_case_insensitive(tmp.path()), Some(false));
        }
    }
}
