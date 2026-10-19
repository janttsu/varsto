// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic repair (`docs/spec/alpha-0-format.md` section 25).
//!
//! `fsck` (objects missing from a storage that the ledger says holds them,
//! blocks of current files on no storage, and with `--verify` corrupt
//! objects) and automatic verification (missing or corrupt copies another
//! device wrote) put what they find in a queue, `state/repair.json`. A
//! repair run takes the queue, oldest damage on the fewest copies first and
//! within a budget, and for each damaged copy on a storage of this device:
//!
//! Copies dropped on purpose (`chunk_dropped`, data moves) and storages a
//! folder's placement does not take are never written back.
//!
//! 1. reads the copy again: a copy that is intact by now (another device
//!    repaired it, a pool disk came back) is recorded as verified;
//! 2. finds the same ciphertext elsewhere, in this order: the encrypted
//!    block cache, the other hot storages, this device's plain files (chunk
//!    encryption is deterministic, so re-encrypting the plaintext gives the
//!    very object), and peers; a cold storage only when the user asked for it
//!    (`varsto repair --from-cold`), because reading one costs a retrieval;
//!    every candidate is checked against the object name before use;
//! 3. deletes a corrupt copy, writes the object, reads it back, checks the
//!    hash and records `chunk_stored` for the storage in the ledger.
//!
//! Transferrers are never written (they only ever take what another device
//! lacks), cold storages are never read without that confirmation, and a
//! storage that is no longer configured here is gone for good: nothing is
//! done for it (removing a storage is its own action). Copies that cannot be
//! repaired stay in the queue with the reason, are tried again a day later
//! (a peer may come online, a disk may be attached), and raise a desktop
//! notification once in the service.

use super::*;

const REPAIR_FILE: &str = "state/repair.json";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DamageKind {
    /// The storage does not have the object.
    Missing,
    /// The storage returned bytes whose hash is not the object name.
    Corrupt,
}

/// One damaged copy: `object` should be on this device's storage `storage`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Damage {
    pub folder: FolderId,
    pub chunk: ChunkId,
    pub object: ObjectName,
    /// Local name of the storage.
    pub storage: String,
    pub kind: DamageKind,
    /// "fsck" or "verify".
    pub found_by: String,
    pub found_utc: i64,
    /// Not tried again before this time (UTC seconds; 0: at once).
    #[serde(default)]
    pub retry_utc: i64,
    /// Why the last attempt did not repair it.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Damage {
    fn key(&self) -> (ObjectName, String) {
        (self.object.clone(), self.storage.clone())
    }
}

/// A damaged copy of a whole pack (storage format 3 repairs packs): its
/// object and chunk are the pack id, its folder the one the view gives the
/// pack (zeros when none).
pub(super) fn pack_damage(
    view: &crate::ledger3::LedgerView,
    pack: &[u8; 32],
    storage: &str,
    kind: DamageKind,
    found_by: &str,
    now: i64,
) -> Damage {
    Damage {
        folder: view
            .pack_folder(pack)
            .map(|f| FolderId::from_bytes(&f))
            .unwrap_or_else(|| FolderId::from_bytes(&[0; 16])),
        chunk: ChunkId::from_bytes(pack),
        object: ObjectName::from_bytes(pack),
        storage: storage.to_string(),
        kind,
        found_by: found_by.to_string(),
        found_utc: now,
        retry_utc: 0,
        reason: None,
    }
}

/// How one repair run behaves.
#[derive(Clone, Debug)]
pub struct RepairOptions {
    /// Report what would be done; write and record nothing.
    pub dry_run: bool,
    /// Read cold storages as a source (the user confirmed the retrieval).
    pub from_cold: bool,
    /// Compare the ledger with the hot storages first (an `fsck` without
    /// downloading), instead of working on the queue alone.
    pub scan: bool,
    /// Also take copies whose retry time has not come yet.
    pub retry_all: bool,
    pub max_blocks: u64,
    pub max_bytes: u64,
}

impl RepairOptions {
    /// What the background service runs after verification and fsck.
    pub fn service() -> Self {
        RepairOptions {
            dry_run: false,
            from_cold: false,
            scan: false,
            retry_all: false,
            max_blocks: 500,
            max_bytes: 256 * 1024 * 1024,
        }
    }

    /// `varsto repair`: scan, then everything, without a budget.
    pub fn manual() -> Self {
        RepairOptions {
            dry_run: false,
            from_cold: false,
            scan: true,
            retry_all: true,
            max_blocks: u64::MAX,
            max_bytes: u64::MAX,
        }
    }
}

/// A copy written again (or, in a dry run, that would be).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RepairedCopy {
    pub folder: String,
    pub storage: String,
    pub object: String,
    pub kind: DamageKind,
    /// "block cache", "storage <name>", "local file", "peer <device>" or "cold storage <name>".
    pub source: String,
    pub bytes: u64,
}

/// A copy that could not be repaired, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Unrepairable {
    pub folder: String,
    pub storage: String,
    pub object: String,
    pub kind: DamageKind,
    pub reason: String,
}

/// What one run did.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct RepairReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub dry_run: bool,
    /// Damaged copies considered.
    pub found: u64,
    pub repaired: Vec<RepairedCopy>,
    pub unrepairable: Vec<Unrepairable>,
    /// Copies that were intact when read again.
    pub already_intact: u64,
    /// Copies no current file uses any more, or on a storage that is gone.
    pub not_needed: u64,
    /// Storages that could not be reached (tried again later).
    pub unreachable: Vec<String>,
    /// Copies left for the next run because the budget ran out or their
    /// retry time has not come.
    pub left_for_next_run: u64,
    pub bytes_written: u64,
    /// Unrepairable copies not reported before (the service notifies them).
    pub new_losses: u64,
}

/// Kept in `state/repair.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RepairState {
    #[serde(default)]
    queue: Vec<Damage>,
    #[serde(default)]
    last_run_utc: Option<i64>,
    #[serde(default)]
    last: Option<RepairReport>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    total_repaired: u64,
    /// Unrepairable copies already notified ("object@storage").
    #[serde(default)]
    notified: BTreeSet<String>,
}

/// Queue, last run and open losses, for the API, the CLI and the interface.
#[derive(Clone, Debug, Serialize)]
pub struct RepairStatus {
    pub last_run_utc: Option<i64>,
    pub last: Option<RepairReport>,
    pub last_error: Option<String>,
    /// Damaged copies waiting for a run.
    pub queued: u64,
    pub total_repaired: u64,
    /// Copies that could not be repaired so far, with the reason.
    pub open_losses: Vec<Unrepairable>,
}

impl RepairStatus {
    /// "3 copies repaired, 1 could not be repaired: <why>".
    pub fn describe(&self) -> String {
        let mut s = match (&self.last, self.last_run_utc) {
            (Some(r), Some(t)) => format!(
                "automatic repair: last run {}: {} cop{} repaired",
                crate::util::format_date(t),
                r.repaired.len(),
                if r.repaired.len() == 1 { "y" } else { "ies" }
            ),
            _ => "automatic repair: nothing repaired yet".to_string(),
        };
        if self.total_repaired > 0 {
            s += &format!(" ({} in all)", self.total_repaired);
        }
        if !self.open_losses.is_empty() {
            let mut why: Vec<&str> = self.open_losses.iter().map(|l| l.reason.as_str()).collect();
            why.sort();
            why.dedup();
            s += &format!(
                ", {} could not be repaired: {}",
                self.open_losses.len(),
                why.join("; ")
            );
        }
        let waiting = self.queued - self.open_losses.len() as u64;
        if waiting > 0 {
            s += &format!(", {waiting} waiting");
        }
        if let Some(e) = &self.last_error {
            s += &format!("; last error: {e}");
        }
        s
    }
}

impl Engine {
    fn repair_path(&self) -> PathBuf {
        self.home.join(REPAIR_FILE)
    }

    /// Object names (hex) of every damaged copy waiting in the repair queue.
    pub(super) fn repair_queue_objects(&self) -> HashSet<String> {
        self.load_repair_state()
            .queue
            .iter()
            .map(|d| d.object.as_str().to_ascii_lowercase())
            .collect()
    }

    /// The damaged copies waiting in the repair queue.
    pub(super) fn load_repair_queue(&self) -> Vec<Damage> {
        self.load_repair_state().queue
    }

    fn load_repair_state(&self) -> RepairState {
        util::read_json_or_default(&self.repair_path()).unwrap_or_default()
    }

    fn save_repair_state(&self, st: &RepairState) -> Result<()> {
        if !self.home.join("state").is_dir() {
            return Ok(());
        }
        util::write_json(&self.repair_path(), st)
    }

    /// Add damage found by fsck or verification to the queue. A copy found
    /// again is due at once. Returns how many copies the queue holds.
    pub(super) fn queue_damage(&self, found: Vec<Damage>) -> Result<u64> {
        let mut st = self.load_repair_state();
        if found.is_empty() {
            return Ok(st.queue.len() as u64);
        }
        merge_damage(&mut st.queue, found);
        self.save_repair_state(&st)?;
        Ok(st.queue.len() as u64)
    }

    pub fn repair_status(&self) -> RepairStatus {
        let st = self.load_repair_state();
        RepairStatus {
            last_run_utc: st.last_run_utc,
            last: st.last,
            last_error: st.last_error,
            queued: st.queue.len() as u64,
            total_repaired: st.total_repaired,
            open_losses: st
                .queue
                .iter()
                .filter(|d| d.reason.is_some())
                .map(|d| self.unrepairable(d, d.reason.clone().unwrap_or_default()))
                .collect(),
        }
    }

    /// Whether a damaged copy is waiting and due.
    pub fn repair_due(&self, now_utc: i64) -> bool {
        self.load_repair_state()
            .queue
            .iter()
            .any(|d| d.retry_utc <= now_utc)
    }

    /// One repair run (see the module documentation).
    pub fn repair(&mut self, opts: &RepairOptions) -> Result<RepairReport> {
        crate::logged_op!("repair", "", { self.exclusive(|e| e.repair_inner(opts)) })
    }

    fn repair_inner(&mut self, opts: &RepairOptions) -> Result<RepairReport> {
        self.ensure_active()?;
        self.ensure_ledger_writable()?;
        let result = self.one_batch(|e| e.run_repair(opts));
        if opts.dry_run {
            return result.map(|(r, _)| r);
        }
        let mut st = self.load_repair_state();
        st.last_run_utc = Some(util::now_utc());
        match result {
            Ok((mut report, queue)) => {
                // Notify each loss once; forget those no longer open.
                let open: BTreeSet<String> = queue
                    .iter()
                    .filter(|d| d.reason.is_some())
                    .map(|d| format!("{}@{}", d.object, d.storage))
                    .collect();
                report.new_losses = open.difference(&st.notified).count() as u64;
                st.notified = open;
                st.queue = queue;
                st.total_repaired += report.repaired.len() as u64;
                st.last = Some(report.clone());
                st.last_error = None;
                self.save_repair_state(&st)?;
                Ok(report)
            }
            Err(e) => {
                st.last_error = Some(format!("{e:#}"));
                self.save_repair_state(&st)?;
                Err(e)
            }
        }
    }

    fn unrepairable(&self, d: &Damage, reason: String) -> Unrepairable {
        Unrepairable {
            folder: self.folder_label(&d.folder),
            storage: d.storage.clone(),
            object: d.object.short().to_string(),
            kind: d.kind,
            reason,
        }
    }

    pub(super) fn folder_label3(&self, folder: &FolderId) -> String {
        self.folder_label(folder)
    }

    fn folder_label(&self, folder: &FolderId) -> String {
        self.keyring
            .folders
            .get(folder)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| folder.short().to_string())
    }
}

/// Add `found` to `queue`, one entry per (object, storage); a copy found
/// again keeps its first finding time and is due at once.
pub(super) fn merge_damage(queue: &mut Vec<Damage>, found: Vec<Damage>) {
    for f in found {
        match queue.iter_mut().find(|q| q.key() == f.key()) {
            Some(q) => {
                q.kind = q.kind.max(f.kind);
                q.retry_utc = 0;
            }
            None => queue.push(f),
        }
    }
}
