// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Importing data that lives elsewhere into Varsto folders
//! (`docs/spec/alpha-0-format.md`, section "Importing git-annex
//! repositories, cloud drives and local directories").
//!
//! Three kinds of source share one framework:
//!
//! - a git-annex repository ([`annex`]), read with read-only git plumbing:
//!   the file list of a commit, and the annexed objects present on the disk
//!   at hand. Every clone of the repository (each of the user's disks)
//!   continues the same Varsto folder;
//! - any rclone remote ([`rclone`]): Dropbox, OneDrive, Google Drive, ...;
//! - a local directory ([`dir`]), optionally emptied once its files are
//!   safely stored and the folder's durability policy is met.
//!
//! One Varsto folder per source. The source's identity is recorded with the
//! folder in an *import book* ([`ImportBook`]): which content ids (git-annex
//! keys, provider hashes, file versions) are imported under which content
//! hash, the file list of the source as last seen, what was damaged, and
//! which disks were read when. The book travels with the folder, sealed
//! under its metadata key (`vault/imports/...`), so that another device can
//! continue importing from other disks.
//!
//! Files whose content is not on the disk at hand are *awaiting import*:
//! listed by the book with their size, never put in a manifest (no other
//! device sees an empty file or a deletion), and completed by a later
//! import from another disk.

pub mod annex;
pub mod dir;
pub mod hashes;
pub mod rclone;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

/// What kind of source a folder was imported from.
pub const KIND_ANNEX: &str = "git-annex";
pub const KIND_RCLONE: &str = "rclone";
pub const KIND_DIR: &str = "dir";

/// How a source describes itself before anything is read.
#[derive(Clone, Debug, Serialize)]
pub struct SourceInfo {
    /// `git-annex`, `rclone` or `dir`.
    pub kind: &'static str,
    /// Any one in common with a folder's book means "the same source":
    /// git-annex: the root commits of the git-annex branch (every clone
    /// shares them); rclone: `rclone:<type>:<remote>:<path>`; a directory:
    /// `dir:<absolute path>`.
    pub identity: Vec<String>,
    /// For people: the repository path, `remote:path`, the directory.
    pub display: String,
    /// The folder name used when none is given.
    pub default_folder: String,
    /// This copy of the source: the git-annex repository UUID (one per
    /// disk); otherwise the identity.
    pub instance: String,
    /// The copy's name: the git-annex description, the remote, the path.
    pub instance_name: String,
    /// git-annex: every repository the location logs may name, by UUID.
    pub repositories: BTreeMap<String, String>,
    /// git-annex: repositories marked dead (never suggested).
    pub dead: BTreeSet<String>,
    /// Where the source is on this device (a path), for checks.
    pub local_path: Option<std::path::PathBuf>,
}

/// An expected hash of some content, by algorithm name (`hashes::Hasher`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Check {
    pub algo: String,
    pub hex: String,
}

/// One file of the source.
#[derive(Clone, Debug)]
pub struct ListedItem {
    /// Path inside the folder (slashes).
    pub path: String,
    /// Content id: a git-annex key, `git:<blob id>`, `rclone:...`, `dir:...`.
    /// Paths with the same id have the same content.
    pub id: String,
    pub size: Option<u64>,
    pub mtime_ns: Option<i64>,
    /// How to verify the content; `None`: it cannot be (WORM, URL keys,
    /// a remote without hashes).
    pub check: Option<Check>,
    /// The content can be read from this copy of the source now.
    pub present: bool,
}

/// A path of the source that is not imported, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub path: String,
    pub reason: String,
}

/// The source's file list.
#[derive(Default)]
pub struct Listing {
    pub items: Vec<ListedItem>,
    pub skipped: Vec<Note>,
    /// Imported, with something to know (names that differ only by case).
    pub warnings: Vec<Note>,
    /// The version listed: a commit id, or the time of a cloud listing.
    pub tree_ref: String,
}

/// Content the engine asks a source for.
#[derive(Clone, Debug)]
pub struct Wanted {
    pub id: String,
    /// The first path that uses it (for messages and reading).
    pub path: String,
    pub size: Option<u64>,
}

/// What a source hands the engine for one wanted id.
pub enum Delivery<'a> {
    Content {
        reader: &'a mut dyn Read,
        /// The content's modification time, when the source knows it.
        mtime_ns: Option<i64>,
        /// A mismatch can be retried (a download); a disk's copy cannot.
        retry: bool,
    },
    /// Not here after all (removed since the listing).
    Missing,
    /// Could not be read; the reason.
    Failed(String),
}

/// The engine's answer for one delivery.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Imported,
    /// The content does not match its hash: the source may try once more.
    Mismatch,
    /// Stop delivering (an error that ends the run).
    Stop,
}

/// Another copy of the source said to hold some of the missing content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Holder {
    pub instance: String,
    pub name: String,
    pub items: u64,
    pub bytes: u64,
}

pub type Sink<'s> = dyn FnMut(usize, Delivery) -> anyhow::Result<Verdict> + 's;

/// A source of files to import.
pub trait ImportSource {
    fn info(&self) -> &SourceInfo;
    /// Everything in the source, with what is readable from here.
    fn list(&mut self) -> anyhow::Result<Listing>;
    /// Hand over the content of each wanted id once (by index into
    /// `wanted`), in the order that reads the source fastest.
    fn deliver(&mut self, wanted: &[Wanted], sink: &mut Sink) -> anyhow::Result<()>;
    /// Which other copies claim to hold these ids (id, size): git-annex
    /// location logs. Others know of none.
    fn holders(&mut self, _ids: &[(String, u64)]) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
        Ok(BTreeMap::new())
    }
    /// Optional: the hash of a whole file as recorded by the source for
    /// cleaning up after an import (local directories only).
    fn wants_source_hash(&self) -> bool {
        false
    }
}

// ----- the import book ---------------------------------------------------------

/// One content id that is in the vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Imported {
    /// The folder's keyed content hash of the file (`FileState::content_hash`).
    pub hash: String,
    pub size: u64,
    pub utc: i64,
    /// The copy it was read from (git-annex UUID, or the source identity).
    pub from: String,
    /// Whether it was verified against the source's own hash.
    #[serde(default)]
    pub verified: bool,
    /// SHA-256 of the content (local directories: checked again before the
    /// source file is removed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A copy whose content did not match its hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Damage {
    pub from: String,
    pub path: String,
    pub utc: i64,
    pub detail: String,
}

/// A path of the source as last listed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeEntry {
    pub id: String,
    pub size: u64,
    #[serde(default)]
    pub mtime_ns: i64,
}

/// One read of one copy of the source.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct RunRecord {
    pub name: String,
    pub location: String,
    pub device: String,
    pub last_utc: i64,
    /// Content ids present on that copy at the time.
    pub present: u64,
    pub imported: u64,
    pub imported_bytes: u64,
    pub damaged: u64,
    pub failed: u64,
    /// Every id present on that copy was in the vault after the run.
    pub complete: bool,
}

/// A file removed from a local source after it was safely stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Removal {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub removed_utc: i64,
}

/// What a folder knows about the source it was imported from.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct ImportBook {
    pub kind: String,
    pub identity: BTreeSet<String>,
    pub display: String,
    /// git-annex repositories by UUID (from `uuid.log`).
    #[serde(default)]
    pub repositories: BTreeMap<String, String>,
    #[serde(default)]
    pub dead: BTreeSet<String>,
    pub imported: BTreeMap<String, Imported>,
    #[serde(default)]
    pub damaged: BTreeMap<String, Vec<Damage>>,
    /// The source's files as last listed (by any device).
    pub tree: BTreeMap<String, TreeEntry>,
    pub tree_ref: String,
    pub tree_utc: i64,
    /// Ids not imported at the last run and the copies said to hold them.
    #[serde(default)]
    pub missing_holders: BTreeMap<String, Vec<String>>,
    /// Paths that were in an earlier listing and are gone from the source.
    #[serde(default)]
    pub gone_at_source: BTreeSet<String>,
    #[serde(default)]
    pub runs: BTreeMap<String, RunRecord>,
    #[serde(default)]
    pub removals: Vec<Removal>,
    /// Where a local source is (for `import cleanup`).
    #[serde(default)]
    pub source_path: Option<String>,
}

impl ImportBook {
    pub fn matches(&self, info: &SourceInfo) -> bool {
        self.kind == info.kind && info.identity.iter().any(|i| self.identity.contains(i))
    }

    /// Fold another device's book in: content imported anywhere counts,
    /// the newest file list wins, runs keep the newest per copy.
    pub fn merge(&mut self, other: &ImportBook) {
        if self.kind.is_empty() {
            self.kind = other.kind.clone();
            self.display = other.display.clone();
        }
        self.identity.extend(other.identity.iter().cloned());
        for (k, v) in &other.repositories {
            self.repositories
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        self.dead.extend(other.dead.iter().cloned());
        for (k, v) in &other.imported {
            self.imported.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, list) in &other.damaged {
            let mine = self.damaged.entry(k.clone()).or_default();
            for d in list {
                if !mine.contains(d) {
                    mine.push(d.clone());
                }
            }
        }
        if other.tree_utc > self.tree_utc {
            self.tree = other.tree.clone();
            self.tree_ref = other.tree_ref.clone();
            self.tree_utc = other.tree_utc;
            self.missing_holders = other.missing_holders.clone();
            self.gone_at_source = other.gone_at_source.clone();
        }
        self.missing_holders
            .retain(|id, _| !other.imported.contains_key(id));
        for (k, r) in &other.runs {
            if self.runs.get(k).is_none_or(|m| r.last_utc > m.last_utc) {
                self.runs.insert(k.clone(), r.clone());
            }
        }
        for r in &other.removals {
            if !self.removals.contains(r) {
                self.removals.push(r.clone());
            }
        }
        if self.source_path.is_none() {
            self.source_path = other.source_path.clone();
        }
    }

    /// Ids of the current file list with no content in the vault yet.
    pub fn missing_ids(&self) -> BTreeMap<&str, u64> {
        let mut out = BTreeMap::new();
        for e in self.tree.values() {
            if !self.imported.contains_key(&e.id) {
                out.insert(e.id.as_str(), e.size);
            }
        }
        out
    }
}

/// Folder names cannot hold some characters; make a source's name one.
pub fn folder_name_from(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '-',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let t = cleaned.trim().trim_matches('-').trim();
    if t.is_empty() {
        "import".to_string()
    } else {
        t.chars().take(80).collect()
    }
}

/// Parse an RFC 3339 time (`2024-05-01T12:00:00.123456789Z`, offsets
/// allowed) into nanoseconds since the Unix epoch.
pub fn parse_rfc3339_ns(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    let mut nanos: i64 = 0;
    if let Some(r) = rest.strip_prefix('.') {
        let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        rest = &r[digits.len()..];
        let mut frac = digits.clone();
        frac.truncate(9);
        while frac.len() < 9 {
            frac.push('0');
        }
        nanos = frac.parse().ok()?;
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let oh: i64 = o[1..3].parse().ok()?;
            let om: i64 = o[4..6].parse().ok()?;
            let v = oh * 3600 + om * 60;
            if o.starts_with('-') {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times() {
        assert_eq!(parse_rfc3339_ns("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ns("2024-05-01T12:00:00.5Z"),
            Some(1_714_564_800_500_000_000)
        );
        assert_eq!(
            parse_rfc3339_ns("2024-05-01T14:00:00.000000001+02:00"),
            Some(1_714_564_800_000_000_001)
        );
        assert_eq!(parse_rfc3339_ns("nonsense"), None);
    }

    #[test]
    fn folder_names() {
        assert_eq!(folder_name_from("disk one"), "disk one");
        assert_eq!(folder_name_from("a/b:c"), "a-b-c");
        assert_eq!(folder_name_from("  "), "import");
    }

    #[test]
    fn books_merge() {
        let mut a = ImportBook {
            kind: KIND_ANNEX.into(),
            identity: ["root1".to_string()].into(),
            tree_utc: 5,
            ..Default::default()
        };
        a.tree.insert(
            "x".into(),
            TreeEntry {
                id: "K1".into(),
                size: 1,
                mtime_ns: 0,
            },
        );
        let mut b = a.clone();
        b.tree_utc = 9;
        b.tree.insert(
            "y".into(),
            TreeEntry {
                id: "K2".into(),
                size: 2,
                mtime_ns: 0,
            },
        );
        b.imported.insert(
            "K2".into(),
            Imported {
                hash: "h".into(),
                size: 2,
                utc: 1,
                from: "u2".into(),
                verified: true,
                sha256: None,
            },
        );
        a.merge(&b);
        assert_eq!(a.tree.len(), 2);
        assert_eq!(a.missing_ids().into_keys().collect::<Vec<_>>(), vec!["K1"]);
    }
}
