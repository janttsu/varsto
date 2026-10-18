// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The mailbox for offline pool disks (`docs/spec/alpha-0-format.md`
//! section 78): the device with the dock keeps, in a durable outbox, the
//! ciphertext objects that a disk which is docked now holds and that a disk
//! (or storage) which is away needs, and writes them there when that one is
//! docked.
//!
//! This module holds what needs no engine: the outbox directory, the task
//! file, the settings and the free-space rule. Running the tasks is
//! `engine::mailbox`.
//!
//! Objects are named by their hash (blocks by `ObjectName`, packs by their
//! id), so the outbox is keyless: it never opens a block, it checks every
//! object against its name when it is written and again before it is used.
//! A staged object is never a copy for any policy: its tasks are *in
//! transit* until the target copy is written, read back and recorded.

use crate::freespace::MinFree;
use crate::ids::{ChunkId, FolderId, ObjectName};
use crate::{crypto, util};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// `<home>/outbox`: staged objects at their storage keys
/// (`chunks/<xx>/<object>`, `packs/<xx>/<pack id>`).
pub const OUTBOX_DIR: &str = "outbox";
/// `<home>/state/mailbox.json`: the tasks and the last run.
pub const STATE_FILE: &str = "state/mailbox.json";
/// `<home>/state/mailbox.lock`: one run at a time (service and command line).
const LOCK_FILE: &str = "state/mailbox.lock";
/// A lock this old without being refreshed belongs to a run that died.
const LOCK_STALE_SECS: u64 = 600;
/// Temporary files of interrupted writes older than this are removed.
const STALE_TEMP_SECS: u64 = 3600;

/// The default free-space rule: staging leaves at least the larger of 15 %
/// of the volume and 50 GB free.
pub fn default_keep_free() -> Vec<MinFree> {
    vec![MinFree::Basis(1500), MinFree::Bytes(50_000_000_000)]
}

fn yes() -> bool {
    true
}

/// `config.json` `mailbox`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxSettings {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free space staging must leave on the device directory's disk, after
    /// the write: the largest of these limits counts. Empty: the default,
    /// `["15%", "50GB"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep_free: Vec<MinFree>,
}

impl Default for MailboxSettings {
    fn default() -> Self {
        MailboxSettings {
            enabled: true,
            keep_free: Vec::new(),
        }
    }
}

impl MailboxSettings {
    pub fn is_default(&self) -> bool {
        *self == MailboxSettings::default()
    }

    /// The limits in force (the default when none is set).
    pub fn limits(&self) -> Vec<MinFree> {
        if self.keep_free.is_empty() {
            default_keep_free()
        } else {
            self.keep_free.clone()
        }
    }

    /// Bytes that must stay free on a volume of `total` bytes.
    pub fn keep_free_bytes(&self, total: u64) -> u64 {
        self.limits()
            .iter()
            .map(|m| m.bytes(total))
            .max()
            .unwrap_or(0)
    }

    /// "15 % or 50.0 GB, whichever is more".
    pub fn describe_keep_free(&self) -> String {
        let l = self.limits();
        let parts: Vec<String> = l.iter().map(|m| m.describe()).collect();
        if parts.len() == 1 {
            parts[0].clone()
        } else {
            format!("{}, whichever is more", parts.join(" or "))
        }
    }
}

/// What a task carries an object for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// A further copy of a pack on a disk of another place of the same pool
    /// (the pool's disk group rule, section 23).
    Group,
    /// A block the folder's copy rules need on another storage of this
    /// device (a pool whose disks are away, or a storage that cannot be
    /// written now).
    Storage,
    /// A block of an open move job (section 59) whose target cannot take it
    /// now: the job reads it from the outbox and drops the source copy by
    /// its own rules.
    Move,
}

impl TaskKind {
    pub fn label(&self) -> &'static str {
        match self {
            TaskKind::Group => "group",
            TaskKind::Storage => "storage",
            TaskKind::Move => "move",
        }
    }
}

/// Where a task stands. Only the target's recorded copy is a copy:
/// `Held` objects count for no policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// The source disk is not docked (or the outbox had no room when it was).
    #[default]
    WaitingForSource,
    /// Read and checked, kept in the outbox until a target can take it.
    Held,
}

/// One object on its way from a pool disk to a target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub kind: TaskKind,
    /// The object's storage key, which is also its outbox path.
    pub key: String,
    pub size: u64,
    /// The pool the object is read from, and the disk that holds it.
    pub pool: String,
    pub source_disk: String,
    pub source_label: String,
    /// Group: the pool; storage: the target storage; move: the job's target.
    pub target: String,
    /// Group: the places the pool rule still needs a copy in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<String>,
    /// The disks (labels) of the target that would take the object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_disks: Vec<String>,
    /// Storage and move tasks: the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<FolderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk: Option<ChunkId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectName>,
    /// Move tasks: the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    pub state: TaskState,
    pub created_utc: i64,
    #[serde(default)]
    pub staged_utc: i64,
    #[serde(default)]
    pub updated_utc: i64,
}

impl Task {
    /// The task's id in the task file: one per kind, target and object.
    pub fn id(&self) -> String {
        task_id(self.kind, &self.target, &self.key)
    }

    /// "disk «B»", "disk «B» or «C»", "a disk of place offsite", "storage «s3»".
    pub fn target_text(&self) -> String {
        if !self.target_disks.is_empty() {
            let quoted: Vec<String> = self.target_disks.iter().map(|d| format!("«{d}»")).collect();
            return format!(
                "disk{} {}",
                if quoted.len() == 1 { "" } else { "s" },
                quoted.join(" or ")
            );
        }
        match self.kind {
            TaskKind::Group if !self.places.is_empty() => format!(
                "a disk of pool «{}» kept in {}",
                self.target,
                self.places.join(" or ")
            ),
            _ => format!("«{}»", self.target),
        }
    }
}

pub fn task_id(kind: TaskKind, target: &str, key: &str) -> String {
    format!("{}:{target}:{key}", kind.label())
}

/// `state/mailbox.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MailboxState {
    #[serde(default)]
    pub tasks: BTreeMap<String, Task>,
    #[serde(default)]
    pub last: Option<MailboxReport>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// The attached disks when the last run started: a run is due when they change.
    #[serde(default)]
    pub disks_sig: String,
    #[serde(default)]
    pub total_delivered: u64,
    #[serde(default)]
    pub total_delivered_bytes: u64,
    /// What other devices hold staged, from their published lists at the
    /// last run: (device name, entry).
    #[serde(default)]
    pub elsewhere: Vec<(String, BoardEntry)>,
    /// The hash and time of this device's list as last published.
    #[serde(default)]
    pub board_sig: String,
    #[serde(default)]
    pub board_utc: i64,
}

impl MailboxState {
    pub fn load(home: &Path) -> MailboxState {
        util::read_json_or_default(&home.join(STATE_FILE)).unwrap_or_default()
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join(STATE_FILE), self)
    }
    /// Lines for `varsto status`, from the task file alone: "2.1 GiB from
    /// disk «A» waiting for disk «B» (staged on this device)".
    pub fn summary_lines(&self) -> Vec<String> {
        // (source, target, held on, held) -> (keys counted, bytes)
        type Line = (String, String, String, bool);
        let mut by: BTreeMap<Line, (std::collections::BTreeSet<String>, u64)> = BTreeMap::new();
        for t in self.tasks.values() {
            let e = by
                .entry((
                    t.source_label.clone(),
                    t.target_text(),
                    "this device".to_string(),
                    t.state == TaskState::Held,
                ))
                .or_default();
            if e.0.insert(t.key.clone()) {
                e.1 += t.size;
            }
        }
        for (dev, e) in &self.elsewhere {
            let t = Task {
                kind: e.kind,
                key: e.key.clone(),
                size: e.size,
                pool: e.pool.clone(),
                source_disk: String::new(),
                source_label: e.source_label.clone(),
                target: e.target.clone(),
                places: e.places.clone(),
                target_disks: e.target_disks.clone(),
                folder: None,
                chunk: None,
                object: None,
                job: None,
                state: TaskState::Held,
                created_utc: 0,
                staged_utc: 0,
                updated_utc: 0,
            };
            let g = by
                .entry((e.source_label.clone(), t.target_text(), dev.clone(), true))
                .or_default();
            if g.0.insert(e.key.clone()) {
                g.1 += e.size;
            }
        }
        by.into_iter()
            .map(|((source, target, on, held), (_, bytes))| {
                let size = util::human_bytes(bytes);
                if held {
                    format!("mailbox: {size} from disk «{source}» waiting for {target} (staged on {on})")
                } else {
                    format!("mailbox: {size} to be read from disk «{source}» for {target}")
                }
            })
            .collect()
    }

    /// Objects held in the outbox and their bytes (each object once).
    pub fn held(&self) -> (u64, u64) {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = (0, 0);
        for t in self.tasks.values().filter(|t| t.state == TaskState::Held) {
            if seen.insert(&t.key) {
                out.0 += 1;
                out.1 += t.size;
            }
        }
        out
    }
}

/// What one run did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MailboxReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub enabled: bool,
    /// Objects read from a docked disk into the outbox.
    pub staged: u64,
    pub staged_bytes: u64,
    /// Objects written to their target (read back, and recorded for storages).
    pub delivered: u64,
    pub delivered_bytes: u64,
    /// Deliveries by target (pool or storage).
    pub delivered_to: BTreeMap<String, u64>,
    /// Of those, copied straight from a docked disk to a docked target.
    pub direct: u64,
    /// Blocks another device staged, fetched from it over peer-to-peer.
    pub pulled_from_peers: u64,
    /// Objects that did not match their name (on the disk or in the outbox).
    pub rejected: u64,
    /// Staged objects removed to give the device space back.
    pub evicted: u64,
    pub evicted_bytes: u64,
    /// Objects another device holds staged: not staged here again.
    pub held_elsewhere: u64,
    /// Tasks finished (delivered here or elsewhere, or no longer needed).
    pub finished: u64,
    /// Tasks whose object is not staged: the source disk is away or the
    /// outbox had no room.
    pub waiting_for_source: u64,
    pub waiting_for_source_bytes: u64,
    /// Held objects whose target is not docked.
    pub waiting_for_target: u64,
    pub waiting_for_target_bytes: u64,
    /// Bytes that found no room in the outbox in this run.
    pub room_needed_bytes: u64,
    /// Another device holds the mailbox lease (it is staging now).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busy: Option<String>,
    pub notes: Vec<String>,
}

impl MailboxReport {
    /// "staged 12 objects (48.0 MiB); delivered 3 to shelf".
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "off".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        if self.staged > 0 {
            parts.push(format!(
                "staged {} ({})",
                plural(self.staged, "object", "objects"),
                util::human_bytes(self.staged_bytes)
            ));
        }
        if self.delivered > 0 {
            let to: Vec<String> = self.delivered_to.keys().cloned().collect();
            parts.push(format!(
                "delivered {} ({}) to {}",
                plural(self.delivered, "object", "objects"),
                util::human_bytes(self.delivered_bytes),
                to.join(", ")
            ));
        }
        if self.pulled_from_peers > 0 {
            parts.push(format!(
                "{} from another device's mailbox",
                plural(self.pulled_from_peers, "block", "blocks")
            ));
        }
        if self.rejected > 0 {
            parts.push(format!(
                "{} refused (did not match {})",
                plural(self.rejected, "object", "objects"),
                if self.rejected == 1 {
                    "its name"
                } else {
                    "their names"
                }
            ));
        }
        if self.evicted > 0 {
            parts.push(format!(
                "{} removed from the outbox to free space",
                util::human_bytes(self.evicted_bytes)
            ));
        }
        if self.held_elsewhere > 0 {
            parts.push(format!(
                "{} held by another device",
                plural(self.held_elsewhere, "object", "objects")
            ));
        }
        if let Some(b) = &self.busy {
            parts.push(format!("{b} is staging now"));
        }
        if self.room_needed_bytes > 0 {
            parts.push(format!(
                "{} more free space needed on this device",
                util::human_bytes(self.room_needed_bytes)
            ));
        }
        if parts.is_empty() {
            "nothing to carry".to_string()
        } else {
            parts.join("; ")
        }
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A group of tasks with the same source, target and state, for the status
/// lines: "2.1 GiB from disk «A» waiting for disk «B» (staged on this device)".
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MailboxGroup {
    pub kind: String,
    /// The pool the objects come from and its disk.
    pub pool: String,
    pub source: String,
    /// The target in words ("disk «B»"), its pool or storage, and its disks.
    pub target: String,
    pub target_name: String,
    #[serde(default)]
    pub target_disks: Vec<String>,
    /// "held" or "waiting_for_source".
    pub state: String,
    /// The device that holds the objects (this one, or another).
    pub held_on: String,
    pub here: bool,
    pub objects: u64,
    pub bytes: u64,
    /// Whether the source disk is docked now (staging goes on).
    pub source_attached: bool,
    /// While the source is docked: minutes of reading left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_attached_minutes: Option<u64>,
    pub text: String,
}

/// What `varsto mailbox` and `/api/mailbox` show.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MailboxStatus {
    pub enabled: bool,
    /// The free-space rule as set ("15%", "50000000000") and in words.
    pub keep_free: Vec<String>,
    pub keep_free_text: String,
    /// On the device directory's disk now: free bytes and the bytes the rule keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_free_bytes: Option<u64>,
    /// Objects and bytes in this device's outbox.
    pub held_objects: u64,
    pub held_bytes: u64,
    /// Bytes waiting for their source disk.
    pub waiting_bytes: u64,
    pub groups: Vec<MailboxGroup>,
    pub last: Option<MailboxReport>,
    pub last_error: Option<String>,
    pub total_delivered: u64,
    pub total_delivered_bytes: u64,
}

impl MailboxStatus {
    /// One line: "mailbox: 2.1 GiB waiting for disk «B» (staged on this device)".
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "mailbox: off".to_string();
        }
        if self.groups.is_empty() {
            return match &self.last_error {
                Some(e) => format!("mailbox: the last run failed: {e}"),
                None => "mailbox: nothing in transit".to_string(),
            };
        }
        let lines: Vec<&str> = self.groups.iter().map(|g| g.text.as_str()).collect();
        format!("mailbox: {}", lines.join("; "))
    }
}

/// An entry of a device's published list of staged objects
/// (`vault/mailbox/<device>/<utc>.enc`), which the other devices read.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BoardEntry {
    pub kind: TaskKind,
    pub key: String,
    pub size: u64,
    pub pool: String,
    pub source_label: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_disks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<FolderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk: Option<ChunkId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectName>,
    pub staged_utc: i64,
}

impl BoardEntry {
    pub fn of(t: &Task) -> BoardEntry {
        BoardEntry {
            kind: t.kind,
            key: t.key.clone(),
            size: t.size,
            pool: t.pool.clone(),
            source_label: t.source_label.clone(),
            target: t.target.clone(),
            target_disks: t.target_disks.clone(),
            places: t.places.clone(),
            folder: t.folder.clone(),
            chunk: t.chunk.clone(),
            object: t.object.clone(),
            staged_utc: t.staged_utc,
        }
    }
}

/// A device's list of staged objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Board {
    pub device: crate::ids::DeviceId,
    pub updated_utc: i64,
    pub held: Vec<BoardEntry>,
}

/// What the disk suggestion (section 40) learns from the mailbox.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MailboxWait {
    pub pool: String,
    /// The disks (ids) this wait is about.
    pub disk_ids: Vec<String>,
    /// "target": docking one of the disks writes `bytes` of staged objects;
    /// "source": `bytes` are waiting to be read from the disk.
    pub role: String,
    pub bytes: u64,
    /// Minutes of reading at the dock's speed (sources).
    pub minutes: u64,
    /// The sentence for the reason.
    pub text: String,
}

/// Does `bytes` hash to the name at the end of `key`?
pub fn name_matches(key: &str, bytes: &[u8]) -> bool {
    let Some(name) = key.rsplit('/').next() else {
        return false;
    };
    name.eq_ignore_ascii_case(&hex::encode(crypto::hash(bytes)))
}

/// What reading a staged object found.
#[derive(Debug, PartialEq, Eq)]
pub enum Staged {
    Missing,
    /// The file did not match its name: it was deleted.
    Bad,
    Good(Vec<u8>),
}

/// The outbox directory.
pub struct Outbox {
    root: PathBuf,
}

impl Outbox {
    pub fn new(home: &Path) -> Outbox {
        Outbox {
            root: home.join(OUTBOX_DIR),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        crate::storage::validate_key(key)?;
        if !(key.starts_with("chunks/") || key.starts_with("packs/")) || key.split('/').count() != 3
        {
            bail!("not an object key: {key}");
        }
        Ok(self.root.join(key))
    }

    /// Stage `bytes` at `key`: refused unless they match the name; written
    /// through a temporary file, fsynced and renamed, then read back.
    pub fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        if !name_matches(key, bytes) {
            bail!("refused to stage {key}: the bytes do not match the name");
        }
        let path = self.path(key)?;
        util::write_atomic(&path, bytes)?;
        match fs::read(&path) {
            Ok(back) if name_matches(key, &back) => Ok(()),
            _ => {
                let _ = fs::remove_file(&path);
                Err(anyhow!(
                    "the staged copy of {key} did not read back intact; this device's disk may be failing"
                ))
            }
        }
    }

    /// The staged object at `key`, checked against its name (a bad one is deleted).
    pub fn get(&self, key: &str) -> Staged {
        let Ok(path) = self.path(key) else {
            return Staged::Missing;
        };
        match fs::read(&path) {
            Ok(b) if name_matches(key, &b) => Staged::Good(b),
            Ok(_) => {
                let _ = fs::remove_file(&path);
                Staged::Bad
            }
            Err(_) => Staged::Missing,
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.path(key).is_ok_and(|p| p.is_file())
    }

    pub fn remove(&self, key: &str) {
        if let Ok(p) = self.path(key) {
            let _ = fs::remove_file(&p);
            if let Some(dir) = p.parent() {
                let _ = fs::remove_dir(dir); // only when empty
            }
        }
    }

    /// Every staged object (key, size); temporary files of interrupted
    /// writes older than an hour are removed on the way.
    pub fn list(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for top in ["chunks", "packs"] {
            let Ok(dirs) = fs::read_dir(self.root.join(top)) else {
                continue;
            };
            for d in dirs.flatten() {
                let Ok(files) = fs::read_dir(d.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().into_owned();
                    let Ok(meta) = f.metadata() else { continue };
                    let is_object = name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
                    if !is_object {
                        let old = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .is_some_and(|a| a.as_secs() > STALE_TEMP_SECS);
                        if old {
                            let _ = fs::remove_file(f.path());
                        }
                        continue;
                    }
                    out.push((
                        format!("{top}/{}/{name}", d.file_name().to_string_lossy()),
                        meta.len(),
                    ));
                }
            }
        }
        out.sort();
        out
    }
}

/// One mailbox run at a time on a device.
pub struct RunLock {
    path: PathBuf,
}

impl RunLock {
    pub fn acquire(home: &Path) -> Option<RunLock> {
        let path = home.join(LOCK_FILE);
        fs::create_dir_all(path.parent()?).ok()?;
        for _ in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => {
                    let _ = fs::write(&path, std::process::id().to_string());
                    return Some(RunLock { path });
                }
                Err(_) => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > LOCK_STALE_SECS);
                    if stale {
                        let _ = fs::remove_file(&path);
                    } else {
                        return None;
                    }
                }
            }
        }
        None
    }

    /// Show that the run is alive.
    pub fn touch(&self) {
        let _ = fs::write(&self.path, std::process::id().to_string());
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_keeps_15_percent_or_50_gb_whichever_is_more() {
        let s = MailboxSettings::default();
        assert!(s.is_default());
        // 15 % of 1 TB is 150 GB; of 100 GB it is 15 GB, so 50 GB counts.
        assert_eq!(s.keep_free_bytes(1_000_000_000_000), 150_000_000_000);
        assert_eq!(s.keep_free_bytes(100_000_000_000), 50_000_000_000);
        assert_eq!(s.describe_keep_free(), "15 % or 50.0 GB, whichever is more");
        let one: MailboxSettings = serde_json::from_str(r#"{"keep_free": ["10GB"]}"#).unwrap();
        assert!(one.enabled);
        assert_eq!(one.keep_free_bytes(1_000_000_000_000), 10_000_000_000);
        let json = serde_json::to_string(&one).unwrap();
        assert!(json.contains("10000000000"), "{json}");
    }

    #[test]
    fn the_outbox_refuses_and_drops_objects_that_do_not_match_their_name() {
        let tmp = tempfile::tempdir().unwrap();
        let ob = Outbox::new(tmp.path());
        let bytes = b"some ciphertext".to_vec();
        let name = hex::encode(crypto::hash(&bytes));
        let key = format!("chunks/{}/{name}", &name[..2]);
        assert!(ob.put(&key, b"other bytes").is_err());
        assert!(!ob.has(&key));
        ob.put(&key, &bytes).unwrap();
        assert_eq!(ob.get(&key), Staged::Good(bytes.clone()));
        assert_eq!(ob.list(), vec![(key.clone(), bytes.len() as u64)]);
        // Damaged on disk: refused and deleted.
        fs::write(tmp.path().join(OUTBOX_DIR).join(&key), b"rot").unwrap();
        assert_eq!(ob.get(&key), Staged::Bad);
        assert!(!ob.has(&key));
        assert_eq!(ob.get(&key), Staged::Missing);
        assert!(ob.put("../etc/passwd", &bytes).is_err());
        assert!(ob.put("vault/x/y", &bytes).is_err());
    }

    #[test]
    fn one_run_holds_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let l = RunLock::acquire(tmp.path()).unwrap();
        assert!(RunLock::acquire(tmp.path()).is_none());
        drop(l);
        assert!(RunLock::acquire(tmp.path()).is_some());
    }
}
