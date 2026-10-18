// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Finding and repairing lost ledger copies (`docs/spec/alpha-0-format.md`
//! section 38).
//!
//! Every metadata storage and every device holds the ledger, so most losses
//! repair themselves: a storage that lost its ledger objects is filled again
//! by the next push (S1), and a damaged cached view is rebuilt from the
//! batches (S5). Two losses need more:
//!
//! - **The device's own history** (S2): the local `ledger/` directory was
//!   deleted, or its files no longer read. Signing now would reuse a
//!   sequence number the storages already hold (a fork), so nothing is
//!   signed until the device has taken its own batches and checkpoints back
//!   from the storages and continues after the newest one. A device
//!   restored from an old backup (S3) is the same case one step later: the
//!   storages hold this identity's later batches. They are adopted when
//!   they verify with this device's key and chain onto what it holds;
//!   otherwise two devices use one identity and it must be paired again.
//! - **The ledger everywhere** (S4): every storage and every device lost it,
//!   while the folders' manifests and the blocks remain. The claims are
//!   rebuilt from what the storages actually hold, mapped to folders and
//!   blocks through the newest manifests and snapshots, and signed by this
//!   device.
//!
//! Detection is cheap: the local files are checked when the engine opens,
//! a signing action lists this identity's batches after the local head on
//! one storage (normally an empty listing), and the "ledger lost
//! everywhere" check runs only when the view has no block claims at all.

use super::*;
use crate::ledger::Rescan;
use crate::record::Id16;

/// What the command line suggests.
pub const REBUILD_COMMAND: &str = "varsto ledger rebuild";
pub const REBUILD_FROM_STORAGE_COMMAND: &str = "varsto ledger rebuild --from-storage";
pub const CLEAN_JUNK_COMMAND: &str = "varsto ledger clean-junk --yes";
pub const RESOLVE_EPOCH_COMMAND: &str = "varsto device resolve-epoch";
const REPAIR_ADVICE: &str =
    "pair this computer again as a new device (`varsto reset --yes`, then `varsto join`)";

/// A fork found by a rebuild is remembered here, so the device stays
/// fenced across restarts until it is paired again.
const FORK_FILE: &str = "ledger/fork.json";

/// The verification of a rebuild from the storages is on by default up to
/// this much data; above it, objects are verified up to the budget.
pub const AUTO_VERIFY_BYTES: u64 = 1 << 30;

/// The "ledger lost everywhere" check runs at most this often.
const LOST_CHECK_EVERY: i64 = 3600;

/// One thing found wrong with the ledger.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerProblem {
    /// `local_ledger_missing`, `local_files_damaged`, `local_batches_missing`,
    /// `behind_pushed`, `behind_storage`, `fenced`, `forked`, `epoch_fork`,
    /// `no_ledger_anywhere`.
    pub code: String,
    pub detail: String,
}

/// Another device's ledger batches this device lacks: another full device
/// said (in a signed batch, `seen`) that it holds them up to `seen`, or
/// batches up to `seen` wait here for a predecessor no storage offered.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerBehind {
    pub device: String,
    pub name: String,
    /// The newest batch of the device held here (the end of its chain).
    pub held: u64,
    pub seen: u64,
    /// Pulls in a row that found it so; from `WITHHOLD_PULLS` on, a
    /// storage may be withholding batches and `warnings` says so.
    pub pulls: u32,
    /// Where the gap was learned from: `acks` (another device's signed
    /// acknowledgement), `peer` (a batch a peer proved, by an envelope or
    /// the writer's own peer record) or `pending` (batches wait for a
    /// predecessor that no storage offered).
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "acks".into()
}

/// Pulls in a row a gap must survive before it is reported as a storage
/// that may be withholding batches.
pub const WITHHOLD_PULLS: u32 = 3;

/// What the ledger pulls noticed that needs no repair but should be seen
/// (`ledger/watch.json`, kept across runs).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Watch {
    #[serde(default)]
    pub(super) behind: BTreeMap<DeviceId, LedgerBehind>,
    /// Batches that did not parse or verify on some storage (last pull).
    #[serde(default)]
    pub(super) malformed: u64,
    /// Batches refused: a Lamport time no device can have reached, or too
    /// far ahead of the chain (every pull so far).
    #[serde(default)]
    pub(super) refused: u64,
    /// Events left out of the view because their signer may not make them.
    #[serde(default)]
    pub(super) events_refused: u64,
    /// Objects under this device's own ledger prefix that do not verify
    /// with its key, by storage name: junk someone else wrote. They never
    /// fence this device; `varsto ledger clean-junk --yes` deletes them.
    #[serde(default)]
    pub(super) junk: BTreeMap<String, BTreeSet<String>>,
    /// Rollback warnings of the last pull (design section 8: a storage
    /// shows less of a device's ledger than a peer proved).
    #[serde(default)]
    pub(super) rollback: Vec<String>,
    /// The writing devices those warnings name (for the Help page).
    #[serde(default)]
    pub(super) rollback_devices: Vec<String>,
}

/// Kept apart from what peers proved (`p2p::v3::heads::WATCH_FILE`).
const WATCH_FILE: &str = "ledger/health.json";

impl Watch {
    pub(super) fn load(home: &Path) -> Watch {
        util::read_json(&home.join(WATCH_FILE)).unwrap_or_default()
    }

    pub(super) fn save(&self, home: &Path) {
        // Never recreate a ledger directory that was removed.
        if home.join("ledger").is_dir() {
            let _ = util::write_json(&home.join(WATCH_FILE), self);
        }
    }
}

/// The state of this device's ledger, for `status`, the service and the
/// interface. `state` is `ok`, `rebuild_needed` (the local ledger was lost
/// or damaged), `fenced` (the storages hold newer batches of this device
/// than it has), `forked` (another copy of this identity signed a
/// different history), `epoch_fork` (two devices wrote one key epoch
/// number; the user keeps one), `no_ledger` (no ledger anywhere while
/// folders hold files) or `repairing`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerHealth {
    pub state: String,
    #[serde(default)]
    pub problems: Vec<LedgerProblem>,
    /// Things that went and do not need an action (events lost with a
    /// damaged `pending.json`, a rebuilt `pushed.json`).
    #[serde(default)]
    pub notes: Vec<String>,
    /// The background service repairs it by itself.
    pub automatic: bool,
    /// What to run on the command line, or what to do.
    pub suggestion: Option<String>,
    /// This device's newest own batch held here.
    pub own_head: u64,
    /// The newest own batch or checkpoint seen on a storage after it.
    pub storage_ahead: Option<u64>,
    /// Other devices' batches this device lacks (`LedgerBehind`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub behind: Vec<LedgerBehind>,
    /// Ledger batches that did not parse or verify on a storage at the
    /// last pull (skipped; the other storages' copies count).
    #[serde(default)]
    pub batches_malformed: u64,
    /// Ledger batches refused (a Lamport time no device can have reached).
    #[serde(default)]
    pub batches_refused: u64,
    /// Ledger events left out because their signer may not make them (a
    /// replica's or a member's outside its scope).
    #[serde(default)]
    pub events_refused: u64,
    /// Objects under this device's own ledger name on the storages that
    /// it did not sign (junk; `varsto ledger clean-junk --yes`).
    #[serde(default)]
    pub junk_objects: u64,
    /// Things worth knowing that do not stop syncing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl LedgerHealth {
    pub fn is_ok(&self) -> bool {
        self.state == "ok"
    }

    /// One line: "ok", or what is wrong and what to do (with warnings).
    pub fn describe(&self) -> String {
        if self.is_ok() {
            if self.warnings.is_empty() {
                return "ok".into();
            }
            return format!("ok; warning: {}", self.warnings.join("; "));
        }
        let what: Vec<&str> = self.problems.iter().map(|p| p.detail.as_str()).collect();
        let mut line = if what.is_empty() {
            self.state.replace('_', " ")
        } else {
            what.join("; ")
        };
        if let Some(s) = &self.suggestion {
            let how = if s.starts_with("varsto ") {
                format!("run `{s}`")
            } else {
                s.clone()
            };
            line = format!("{line}; rebuild recommended: {how}");
            if self.automatic {
                line.push_str(" (the background service does this by itself)");
            }
        }
        line
    }
}

/// What this engine knows to be wrong with its ledger.
#[derive(Default)]
pub(super) struct Alarm {
    /// What the pulls noticed (`ledger/watch.json`).
    pub(super) watch: Watch,
    /// The local copy of this device's own history was lost or damaged.
    local: Vec<LedgerProblem>,
    notes: Vec<String>,
    storage_ahead: Option<u64>,
    /// Text of a fork found by a rebuild (`ledger/fork.json`).
    fork: Option<String>,
    no_ledger: bool,
    repairing: bool,
    lost_checked_utc: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct ForkFile {
    detail: String,
    found_utc: i64,
}

impl Alarm {
    /// What the local files say when the engine opens (no storage is read).
    pub(super) fn at_open(e: &Engine, pending_lost: bool) -> Alarm {
        // Format 3: the ledger is `ledger3` (`Engine::f3`).
        let me = &e.me3();
        let head = e.f3.ledger.head(me);
        let mut a = Alarm { ..Alarm::default() };
        if e.removal.is_some() {
            // A removed device signs nothing anyway.
            return a;
        }
        let damaged = e.f3.ledger.damaged();
        if damaged.iter().any(|n| n == "heads.json") {
            a.local.push(LedgerProblem {
                code: "local_files_damaged".into(),
                detail: "the local ledger's heads file could not be read".into(),
            });
        } else if e.f3.ledger.heads_absent() && !e.vault.member {
            // Every full device signs its enrolment when it is created, so
            // its heads file exists from then on.
            a.local.push(LedgerProblem {
                code: "local_ledger_missing".into(),
                detail: "this device's local ledger is missing".into(),
            });
        }
        if damaged.iter().any(|n| n == "pushed.json") {
            a.notes.push(
                "the record of what was pushed where could not be read; the next push lists the storages again"
                    .into(),
            );
        }
        if pending_lost {
            a.notes.push(
                "events waiting for the next batch could not be read; the next sync records the blocks again"
                    .into(),
            );
        }
        let pushed = e.f3.ledger.pushed_max();
        if a.local.is_empty() && pushed > head.seq {
            a.local.push(LedgerProblem {
                code: "behind_pushed".into(),
                detail: format!(
                    "the storages hold this device's ledger up to #{pushed}, this device only up to #{}",
                    head.seq
                ),
            });
        }
        if a.local.is_empty()
            && head.seq > head.dropped
            && head.base.as_ref().is_none_or(|b| b.seq < head.seq)
            && e.f3
                .ledger
                .get(me, head.seq)
                .map(|b| b.is_none())
                .unwrap_or(true)
        {
            a.local.push(LedgerProblem {
                code: "local_batches_missing".into(),
                detail: format!(
                    "this device's newest ledger batch #{} is missing or unreadable here",
                    head.seq
                ),
            });
        }
        a.fork = util::read_json::<ForkFile>(&e.home.join(FORK_FILE))
            .ok()
            .map(|f| f.detail);
        a.watch = Watch::load(&e.home);
        a
    }

    /// Nothing may be signed until a rebuild ran.
    pub(super) fn needs_rebuild(&self) -> bool {
        !self.local.is_empty() || self.fork.is_some()
    }

    pub(super) fn fork_marked(&self) -> bool {
        self.fork.is_some()
    }
}

/// How to rebuild.
#[derive(Clone, Debug)]
pub struct LedgerRebuildOptions {
    /// Also rebuild the block claims from what the storages hold (S4).
    pub from_storage: bool,
    /// Verify each object before claiming it: `None` decides by size (all
    /// up to `AUTO_VERIFY_BYTES`, otherwise up to `verify_budget_bytes`).
    pub verify: Option<bool>,
    pub verify_budget_bytes: u64,
    /// Read cold storages too (list, fetch ledger objects, verify).
    pub confirm_cold_read: bool,
    /// Run by the service: rebuilds the claims from the storages by itself
    /// when no ledger is left anywhere.
    pub automatic: bool,
}

impl Default for LedgerRebuildOptions {
    fn default() -> Self {
        LedgerRebuildOptions {
            from_storage: false,
            verify: None,
            verify_budget_bytes: AUTO_VERIFY_BYTES,
            confirm_cold_read: false,
            automatic: false,
        }
    }
}

impl LedgerRebuildOptions {
    /// What the background service runs.
    pub fn service() -> Self {
        LedgerRebuildOptions {
            automatic: true,
            ..Default::default()
        }
    }
}

/// What rebuilding the claims from the storages did.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageRebuildReport {
    pub folders: u64,
    /// Folders whose keys this device does not hold now (locked Strongroom).
    pub folders_skipped: Vec<String>,
    pub manifests_read: u64,
    pub snapshots_read: u64,
    /// Distinct block objects the newest manifests and snapshots name.
    pub objects_mapped: u64,
    pub storages_listed: Vec<String>,
    pub storages_skipped_cold: Vec<String>,
    /// Claims written (one per object and storage).
    pub claims_written: u64,
    /// Claims that were already in the ledger.
    pub claims_known: u64,
    pub objects_verified: u64,
    pub bytes_verified: u64,
    /// Claimed without being read (over the budget, or `--no-verify`).
    pub objects_unverified: u64,
    /// Objects whose bytes do not match their name: not claimed, queued for repair.
    pub objects_corrupt: u64,
    /// Objects the manifests name that no storage listed.
    pub objects_missing: u64,
    pub blocks_on_device: u64,
    pub manifests_announced: u64,
    pub snapshots_announced: u64,
    pub batches: u64,
}

/// What `ledger_clean_junk` found and deleted.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JunkReport {
    pub dry_run: bool,
    /// This device's own objects that verify (left alone).
    pub genuine: u64,
    /// "<storage>: <object>" for each object that does not.
    pub junk: Vec<String>,
    pub deleted: u64,
}

/// What `ledger_rebuild` did.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerRebuildReport {
    pub local: Rescan,
    pub own_head_before: u64,
    pub own_head_after: u64,
    /// Any batch or checkpoint of this device was found on a storage.
    pub own_found_on_storages: bool,
    pub adopted_batches: u64,
    pub adopted_checkpoint: Option<u64>,
    /// Own batches that were never published and whose numbers the storages
    /// hold with other batches: set aside, their events signed again.
    pub discarded_unpublished: Vec<u64>,
    pub events_requeued: u64,
    /// Other devices' batches downloaded again.
    pub batches_pulled: u64,
    pub checkpoints_pulled: u64,
    /// Folders whose next manifest number moved past one this device
    /// published in its later history (a device restored from a backup).
    pub manifests_caught_up: u64,
    /// The device signed its enrolment again (nothing of it was found).
    pub reenrolled: bool,
    /// No claims anywhere while the folders hold files.
    pub no_ledger_anywhere: bool,
    pub from_storage: Option<StorageRebuildReport>,
    pub notes: Vec<String>,
    pub health: LedgerHealth,
}

/// Where a device's batches are held.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerHolding {
    /// A storage name, or "this device".
    pub place: String,
    pub cold: bool,
    pub batches: u64,
    pub first: Option<u64>,
    pub last: Option<u64>,
    pub checkpoints: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One device's ledger as seen from here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerDeviceStatus {
    pub device: String,
    pub name: String,
    pub this_device: bool,
    pub revoked: bool,
    pub head: u64,
    /// The newest checkpoint held here: it stands for batches 1..=seq.
    pub checkpoint: Option<u64>,
    /// Batches up to this number were dropped here (a checkpoint covers them).
    pub dropped: u64,
    pub forked: bool,
    pub held: Vec<LedgerHolding>,
}

/// `varsto ledger status`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerStatus {
    pub health: LedgerHealth,
    pub devices: Vec<LedgerDeviceStatus>,
}

const TWO_HISTORIES: &str = "the storages hold two different ledger histories of this device";

impl Engine {
    /// One sentence on key epoch `e`, written by two devices.
    fn epoch_fork_detail(&self, e: u32) -> String {
        let who: Vec<String> = self
            .epochs
            .forks
            .found
            .get(&e)
            .into_iter()
            .flatten()
            .map(|d| format!("{} ({})", self.device_name(d), d.short()))
            .collect();
        format!(
            "two devices wrote key epoch {e} at once: {}",
            who.join(" and ")
        )
    }

    /// The ledger's state as far as this device knows without reading a
    /// storage (see `ledger_check_storages` for the one cheap read).
    pub fn ledger_health(&self) -> LedgerHealth {
        let a = &self.ledger_alarm;
        let own_head = self.own_head3();
        let mut problems = a.local.clone();
        if let Some(n) = a.storage_ahead {
            problems.push(LedgerProblem {
                code: "behind_storage".into(),
                detail: format!(
                    "a storage holds this device's ledger up to #{n}, this device only up to #{own_head}"
                ),
            });
        }
        if let Some(f) = &a.fork {
            problems.push(LedgerProblem {
                code: "forked".into(),
                detail: f.clone(),
            });
        } else if self.forked_self {
            problems.push(LedgerProblem {
                code: "fenced".into(),
                detail: "the storages hold newer ledger batches of this device than it has (restored from an older copy?); it signs nothing until it continues from them".into(),
            });
        }
        let epoch_forks = self.epochs.forks.unresolved();
        for e in &epoch_forks {
            problems.push(LedgerProblem {
                code: "epoch_fork".into(),
                detail: self.epoch_fork_detail(*e),
            });
        }
        if a.no_ledger {
            problems.push(LedgerProblem {
                code: "no_ledger_anywhere".into(),
                detail: "no storage holds any record of where the blocks are, while the folders hold files".into(),
            });
        }
        let state = if a.repairing {
            "repairing"
        } else if a.fork.is_some() {
            "forked"
        } else if !epoch_forks.is_empty() {
            "epoch_fork"
        } else if !a.local.is_empty() {
            "rebuild_needed"
        } else if a.no_ledger {
            "no_ledger"
        } else if self.forked_self || a.storage_ahead.is_some() {
            "fenced"
        } else {
            "ok"
        };
        let suggestion = match state {
            "rebuild_needed" | "fenced" => Some(REBUILD_COMMAND.to_string()),
            "no_ledger" => Some(REBUILD_FROM_STORAGE_COMMAND.to_string()),
            "forked" => Some(REPAIR_ADVICE.to_string()),
            "epoch_fork" => Some(format!(
                "{RESOLVE_EPOCH_COMMAND} {} --keep <device>",
                epoch_forks[0]
            )),
            _ => None,
        };
        // A fenced device that holds nothing of its own lost its ledger:
        // continuing from the storages cannot contradict anything here.
        let automatic = matches!(state, "rebuild_needed" | "no_ledger" | "repairing")
            || (state == "fenced" && own_head == 0);
        let behind: Vec<LedgerBehind> = a.watch.behind.values().cloned().collect();
        let mut warnings: Vec<String> = behind
            .iter()
            .filter(|b| b.pulls >= WITHHOLD_PULLS)
            .map(|b| {
                if b.source == "peer" {
                    format!(
                        "a storage may be withholding or rolling back ledger batches of {} (a peer holds #{}, the storages give #{})",
                        b.name, b.seen, b.held
                    )
                } else {
                    format!(
                        "a storage may be withholding ledger batches of {} (held up to #{}, another device holds #{})",
                        b.name, b.held, b.seen
                    )
                }
            })
            .collect();
        warnings.extend(a.watch.rollback.iter().cloned());
        let junk: u64 = a.watch.junk.values().map(|k| k.len() as u64).sum();
        if junk > 0 {
            warnings.push(format!(
                "{junk} objects under this device's ledger name on the storages were not signed by it (junk, ignored); `{CLEAN_JUNK_COMMAND}` deletes them"
            ));
        }
        if a.watch.malformed > 0 {
            warnings.push(format!(
                "{} ledger batches on a storage did not parse or verify and were skipped",
                a.watch.malformed
            ));
        }
        LedgerHealth {
            state: state.into(),
            problems,
            notes: a.notes.clone(),
            automatic,
            suggestion,
            own_head,
            storage_ahead: a.storage_ahead,
            behind,
            batches_malformed: a.watch.malformed,
            batches_refused: a.watch.refused,
            events_refused: a.watch.events_refused,
            junk_objects: junk,
            warnings,
        }
    }

    /// Refuse to sign while the ledger needs a rebuild or the device is
    /// fenced, saying what to do.
    pub(super) fn ensure_ledger_writable(&self) -> Result<()> {
        if let Some(f) = &self.ledger_alarm.fork {
            bail!("{f}; this device signs nothing more: {REPAIR_ADVICE}");
        }
        if let Some(e) = self.epochs.forks.unresolved().first() {
            bail!(
                "{}; nothing is signed until you keep one: run `{RESOLVE_EPOCH_COMMAND} {e} --keep <device>`",
                self.epoch_fork_detail(*e)
            );
        }
        if !self.ledger_alarm.local.is_empty() {
            let what: Vec<&str> = self
                .ledger_alarm
                .local
                .iter()
                .map(|p| p.detail.as_str())
                .collect();
            bail!(
                "{}; nothing is signed until it is restored from the storages: run `{REBUILD_COMMAND}` (the background service does this by itself)",
                what.join("; ")
            );
        }
        if self.forked_self {
            bail!(
                "the storages hold newer ledger batches of this device than it has (restored from an older copy?); run `{REBUILD_COMMAND}` to continue from them, or {REPAIR_ADVICE} if another copy of this device is in use"
            );
        }
        Ok(())
    }

    /// The devices whose ledger a storage may be withholding or rolling
    /// back (the rollback warning of the last pull).
    pub(super) fn ledger_rollback_devices(&self) -> Vec<String> {
        self.ledger_alarm.watch.rollback_devices.clone()
    }

    /// This device's own ledger prefix on the storages.
    fn own_prefix3(&self) -> String {
        format!("ledger/{}/", hex::encode(self.me3()))
    }

    /// Own batches or checkpoints after the local head on the first hot
    /// metadata storage that answers: `Some(newest)` when there are any
    /// that this device's key signed. Anything else under its name is junk
    /// (noted, never a reason to stop signing).
    fn own_objects_ahead(&mut self) -> Result<Option<u64>> {
        let me = self.me3();
        let head = self.own_head3();
        let prefix = self.own_prefix3();
        let start = if head == 0 {
            String::new()
        } else {
            crate::ledger3::checkpoint::batch_key(&me, head)
        };
        for (spec, backend) in self.metadata_storages(false)? {
            if spec.is_carrier() {
                continue;
            }
            let Ok(keys) = backend.list_after(&prefix, &start) else {
                continue;
            };
            let mut newest = None;
            for k in keys {
                let Some(o) = k
                    .strip_prefix(&prefix)
                    .and_then(crate::ledger3::LedgerObject::parse)
                else {
                    continue;
                };
                let seq = match o {
                    crate::ledger3::LedgerObject::Batch(s)
                    | crate::ledger3::LedgerObject::Checkpoint(s, _) => s,
                };
                if seq <= head || newest.is_some_and(|n| n >= seq) {
                    continue;
                }
                if self.own_object_genuine(spec.name(), backend.as_ref(), &k)? {
                    newest = Some(seq);
                }
            }
            self.ledger_alarm.watch.save(&self.home);
            return Ok(newest);
        }
        Ok(None)
    }

    /// Whether the own ledger object `key` on a storage was signed by this
    /// device: a record of this device under that number that verifies
    /// with its key. One that does not is junk: noted (`Watch::junk`) and
    /// not read again. Objects that do not answer are neither.
    pub(super) fn own_object_genuine(
        &mut self,
        storage: &str,
        backend: &dyn Storage,
        key: &str,
    ) -> Result<bool> {
        let me = self.me3();
        let prefix = self.own_prefix3();
        let Some(o) = key
            .strip_prefix(&prefix)
            .and_then(crate::ledger3::LedgerObject::parse)
        else {
            return Ok(false);
        };
        if self
            .ledger_alarm
            .watch
            .junk
            .get(storage)
            .is_some_and(|j| j.contains(key))
        {
            return Ok(false);
        }
        let Some(blob) = backend.get_bounded(key, crate::record::MAX_PART_READ)? else {
            return Ok(false);
        };
        let seq = match o {
            crate::ledger3::LedgerObject::Batch(s)
            | crate::ledger3::LedgerObject::Checkpoint(s, _) => s,
        };
        let pk = self.keys.signer.public();
        let genuine = crate::record::SignedRecord::decode(&blob)
            .is_ok_and(|r| r.device == me && r.seq == seq && r.verify(&pk).is_ok());
        if !genuine {
            log::warn!(storage = storage, key = key; "junk under this device's ledger name");
            self.ledger_alarm
                .watch
                .junk
                .entry(storage.to_string())
                .or_default()
                .insert(key.to_string());
        }
        Ok(genuine)
    }

    /// Delete the junk under this device's own ledger name on every hot
    /// metadata storage: objects that do not verify with its key, and
    /// names it never writes. With `dry_run` they are only listed. Its
    /// genuine objects are never touched, whatever their number.
    pub fn ledger_clean_junk(&mut self, dry_run: bool) -> Result<JunkReport> {
        self.ensure_active()?;
        let prefix = self.own_prefix3();
        let mut report = JunkReport {
            dry_run,
            ..Default::default()
        };
        self.ledger_alarm.watch.junk.clear();
        for (spec, backend) in self.metadata_storages(false)? {
            for key in backend.list(&prefix)? {
                if self.own_object_genuine(spec.name(), backend.as_ref(), &key)? {
                    report.genuine += 1;
                    continue;
                }
                report.junk.push(format!("{}: {key}", spec.name()));
                if !dry_run {
                    backend.delete(&key)?;
                    report.deleted += 1;
                }
            }
        }
        if !dry_run {
            self.ledger_alarm.watch.junk.clear();
        }
        self.ledger_alarm.watch.save(&self.home);
        Ok(report)
    }

    /// Before signing: a storage that holds this identity's batches after
    /// the local head fences the device (nothing is signed).
    pub(super) fn check_storage_before_signing(&mut self) -> Result<()> {
        if let Some(n) = self.own_objects_ahead()? {
            self.ledger_alarm.storage_ahead = Some(n);
            self.forked_self = true;
            self.ensure_ledger_writable()?;
        }
        Ok(())
    }

    /// The cheap check of the storages (at service start and now and then):
    /// one listing of this identity's batches after the local head.
    pub fn ledger_check_storages(&mut self) -> Result<LedgerHealth> {
        let ahead = self.own_objects_ahead()?;
        self.ledger_alarm.storage_ahead = ahead;
        if ahead.is_some() && self.ledger_alarm.local.is_empty() {
            self.forked_self = true;
        }
        Ok(self.ledger_health())
    }

    /// Whether some folder held here names blocks in its files.
    fn files_name_blocks(&self) -> bool {
        self.keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_backup())
            .any(|r| {
                self.load_state(&r.folder_id).is_ok_and(|st| {
                    st.files
                        .values()
                        .any(|f| !f.deleted && !f.chunks.is_empty())
                })
            })
    }

    /// Whether the ledger is gone everywhere (no pack claims at all while
    /// the folders' files name blocks), checked at most once an hour.
    /// Sets `no_ledger`.
    pub fn ledger_lost_everywhere(&mut self, force: bool) -> Result<bool> {
        if self.vault.member {
            return Ok(false);
        }
        let now = util::now_utc();
        if !force
            && self
                .ledger_alarm
                .lost_checked_utc
                .is_some_and(|t| now >= t && now - t < LOST_CHECK_EVERY)
        {
            return Ok(self.ledger_alarm.no_ledger);
        }
        self.ledger_alarm.lost_checked_utc = Some(now);
        let lost = self.view3()?.packs.is_empty() && self.files_name_blocks();
        self.ledger_alarm.no_ledger = lost;
        Ok(lost)
    }

    /// Restore this device's ledger (`rebuild3`, spec section 77.10):
    /// rebuild the heads from the local files, take every device's newest
    /// checkpoint and the batches after it back from the metadata storages
    /// (this device's own included, continuing after the newest), refuse
    /// when two histories of this identity exist or when other devices
    /// hold batches of it that no storage gives, and sign again the events
    /// that were in lost batches: claims of the packs this device's maps
    /// name, announcements of its map and manifest records, folders it
    /// holds, its enrolment. With `from_storage` (and in the service when
    /// no ledger is left anywhere) the packs the maps name are read and
    /// hashed first, and packs nobody claims are claimed once their hash is
    /// their id.
    pub fn ledger_rebuild(&mut self, opts: &LedgerRebuildOptions) -> Result<LedgerRebuildReport> {
        self.ensure_active()?;
        let task = activity::start(activity::LEDGER_REBUILD, "", 0, activity::Unit::Items);
        self.ledger_alarm.repairing = true;
        let out = self.ledger_rebuild_steps(opts, &task);
        self.ledger_alarm.repairing = false;
        let mut report = out?;
        report.health = self.ledger_health();
        Ok(report)
    }

    fn ledger_rebuild_steps(
        &mut self,
        opts: &LedgerRebuildOptions,
        task: &activity::Guard,
    ) -> Result<LedgerRebuildReport> {
        let me = self.me3();
        let mut report = LedgerRebuildReport::default();
        task.set_phase("local");
        report.local = self.f3.ledger.rescan()?;
        report.own_head_before = self.f3.ledger.head(&me).seq;
        let base_before = self.f3.ledger.head(&me).base.map(|b| b.seq);
        self.refresh_members3()?;

        task.set_phase("own");
        // Own batches signed here that no storage holds while the storages
        // hold other batches of this device under those numbers (a copy
        // restored from a backup that signed before it noticed): set aside,
        // their events signed again after the storages' history.
        let requeued = self.set_aside_unpublished3(&mut report)?;
        let no_ledger_before = self.ledger_lost_everywhere(true)?;
        let verify = opts.from_storage || (opts.automatic && no_ledger_before);
        let storages: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .metadata_storages(true)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let descs: Vec<crate::fsck3::StorageDesc> = storages
            .iter()
            .map(|(spec, b)| crate::fsck3::StorageDesc {
                name: spec.name().to_string(),
                storage: b.as_ref(),
                cold: spec.is_cold(),
                meta: true,
                media: crate::media::Media::Unknown,
            })
            .collect();
        let folders: Vec<Id16> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && (!r.key_hex.is_empty() || !r.epoch_keys.is_empty()))
            .filter_map(|r| members3::bin(&r.folder_id).ok())
            .collect();
        let (key_id, ledger_key) = self.ledger_key3()?;
        let vault = members3::bin(&self.vault.vault_id)?;
        let device_name = self.vault.device_name.clone();
        let vault_keys = self.vault_keys3();
        let marker = self.home.join("ledger");
        let verify_pack = |c: &crate::fsck3::PackCheck| -> crate::fsck3::PackVerdict {
            match crate::blockmap::class_of_len(c.class_len)
                .map(|class| crate::gc3::verify_pack(c.backend, &c.pack, class))
            {
                Some(Ok(v)) if v.check == crate::gc3::PackCheck::Good => {
                    crate::fsck3::PackVerdict::Ok
                }
                Some(Ok(_)) => crate::fsck3::PackVerdict::Corrupt("damaged".into()),
                Some(Err(e)) => crate::fsck3::PackVerdict::Unreadable(format!("{e:#}")),
                None => crate::fsck3::PackVerdict::Corrupt("no size class".into()),
            }
        };
        let result = {
            let Engine {
                f3, epochs, keys, ..
            } = &mut *self;
            let members = &f3.members;
            let key_for = |id: &str| super::ledger3_ops::key_for3_in(epochs, members, id);
            let scope_of = |d: &Id16, id: &str| super::ledger3_ops::scope3_in(members, d, id);
            let pubkey_of = |d: &Id16| -> Option<crypto::VerifyingKey> {
                members
                    .devices
                    .devices
                    .get(d)
                    .and_then(|(r, _)| r.signing_key())
                    .or_else(|| (*d == me).then(|| keys.signer.public()))
            };
            let ring = crate::membership3::KeyRing {
                me,
                vault: &vault_keys,
                kem: epochs.kem.as_ref(),
                devices: Some(&members.devices),
                folders: Some(&members.granted),
                recovery: None,
                extra: Vec::new(),
                members: Some(&members.members),
            };
            let trust = members.trust();
            let input = crate::rebuild3::RebuildInput {
                vault,
                me,
                device_name,
                signer: &keys.signer,
                ledger_key: &ledger_key,
                key_id,
                key_for: &key_for,
                scope_of: &scope_of,
                pubkey_of: &pubkey_of,
                storages: &descs,
                folders,
                record_keys: &ring,
                record_trust: &trust,
                verify_pack: verify.then_some(&verify_pack as &crate::fsck3::VerifyPack),
                fill_own: None,
                marker_dir: Some(&marker),
            };
            crate::rebuild3::rebuild(
                &mut f3.ledger,
                &input,
                &crate::rebuild3::RebuildOptions {
                    confirm_cold_read: opts.confirm_cold_read,
                    verify_named: verify,
                    push: true,
                },
            )
        };
        drop(descs);
        drop(storages);
        let rep = match result {
            Ok(r) => r,
            Err(crate::rebuild3::RebuildError::Forked(what)) => {
                return self
                    .refuse_fork(format!("{TWO_HISTORIES} ({what})"))
                    .map(|_| report)
            }
            Err(e) => bail!("{e}"),
        };
        report.own_head_after = self.f3.ledger.head(&me).seq;
        report.own_found_on_storages = rep.own_on_storage.values().any(|s| *s > 0);
        report.adopted_batches = report
            .own_head_after
            .saturating_sub(report.own_head_before.max(rep.own_head_before))
            .saturating_sub(rep.new_batches.len() as u64);
        let base_after = self.f3.ledger.head(&me).base.map(|b| b.seq);
        if base_after != base_before {
            report.adopted_checkpoint = base_after;
        }
        report.batches_pulled = rep.batches;
        report.checkpoints_pulled = rep.checkpoints;
        report.reenrolled = rep.enrolled;
        report.notes.extend(rep.skipped.iter().cloned());
        if !rep.new_batches.is_empty() {
            report
                .notes
                .push(format!("signed again: {}", rep.describe()));
        }
        self.ledger_alarm.local.clear();
        self.ledger_alarm.storage_ahead = None;
        self.ledger_alarm.fork = None;
        let _ = fs::remove_file(self.home.join(FORK_FILE));
        self.forked_self = false;
        self.f3.ledger.clear_fork(&me)?;
        self.f3.ledger.save()?;
        self.reset_view3();

        task.set_phase("others");
        let forks = self.pull_ledger()?;
        if forks.contains(&DeviceId::from_bytes(&me)) {
            // Something signed by this identity appeared meanwhile.
            self.forked_self = true;
            bail!("a storage received a batch of this device while it was being restored; run `{REBUILD_COMMAND}` again");
        }
        if requeued > 0 {
            report.events_requeued = requeued;
        }
        report.no_ledger_anywhere = self.ledger_lost_everywhere(true)?;
        let claims = rep.claims_from_maps + rep.claims_from_listing;
        if verify || claims > 0 {
            report.from_storage = Some(StorageRebuildReport {
                folders: self.keyring.folders.len() as u64,
                storages_listed: rep.own_on_storage.keys().cloned().collect(),
                claims_written: claims,
                objects_verified: rep.verified,
                objects_corrupt: (rep.unnamed_corrupt.len() + rep.named_corrupt.len()) as u64,
                objects_unverified: if verify { 0 } else { rep.claims_from_maps },
                manifests_announced: rep.announced,
                batches: rep.new_batches.len() as u64,
                ..Default::default()
            });
            self.ledger_alarm.no_ledger = report.no_ledger_anywhere;
        }
        // Packs whose bytes do not match their id are not claimed: the
        // repair queue takes them.
        let view = self.view3()?;
        let damage: Vec<Damage> = rep
            .unnamed_corrupt
            .iter()
            .chain(&rep.named_corrupt)
            .filter_map(|s| {
                let (storage, id) = s.rsplit_once(':')?;
                let mut pack = [0u8; 32];
                hex::decode_to_slice(id, &mut pack).ok()?;
                Some(super::repair::pack_damage(
                    &view,
                    &pack,
                    storage,
                    DamageKind::Corrupt,
                    "ledger rebuild",
                    util::now_utc(),
                ))
            })
            .collect();
        self.queue_damage(damage)?;
        if report.no_ledger_anywhere {
            report.notes.push(format!(
                "no storage holds any record of where the blocks are; run `{REBUILD_FROM_STORAGE_COMMAND}` to read and claim what the storages hold"
            ));
        }
        report.notes.append(&mut self.ledger_alarm.notes);
        Ok(report)
    }

    /// Own batches held here past the newest own batch that the storages'
    /// history agrees with, while a storage holds another batch of this
    /// device under one of their numbers: they were published nowhere (the
    /// storage's copy would be the same), so they are set aside under
    /// `ledger/discarded/` and their events go into the next batch.
    /// Returns how many events were requeued.
    fn set_aside_unpublished3(&mut self, report: &mut LedgerRebuildReport) -> Result<u64> {
        let me = self.me3();
        let head = self.f3.ledger.head(&me);
        if head.seq == 0 {
            return Ok(0);
        }
        let pk = self.keys.signer.public();
        let mut first_bad: Option<u64> = None;
        for (spec, backend) in self.metadata_storages(true)? {
            if spec.is_carrier() || (spec.is_cold()) {
                continue;
            }
            for seq in (head.dropped + 1).max(1)..=head.seq {
                let Some(mine) = self.f3.ledger.get(&me, seq)? else {
                    continue;
                };
                let key = crate::ledger3::checkpoint::batch_key(&me, seq);
                let Some(blob) = backend.get_bounded(&key, crate::record::MAX_PART_READ)? else {
                    continue;
                };
                let Ok(theirs) = crate::record::SignedRecord::decode(&blob) else {
                    continue;
                };
                if theirs.body_hash != mine.body_hash && theirs.verify(&pk).is_ok() {
                    first_bad = Some(first_bad.map_or(seq, |f: u64| f.min(seq)));
                    break;
                }
            }
        }
        let Some(from) = first_bad else {
            return Ok(0);
        };
        let vault = members3::bin(&self.vault.vault_id)?;
        let mut events: Vec<crate::ledger3::events::Event> = Vec::new();
        for seq in (from..=head.seq).rev() {
            let Some(rec) = self.f3.ledger.get(&me, seq)? else {
                continue;
            };
            let key = self.key_for3(&rec.key_id);
            if let Ok(Some(b)) = crate::ledger3::store::check_batch(&rec, &vault, &pk, key.as_ref())
            {
                let mut evs: Vec<_> = b.decoded().0.into_iter().map(|(_, e)| e).collect();
                evs.append(&mut events);
                events = evs;
            }
            self.f3.ledger.discard_own(&me, seq)?;
            report.discarded_unpublished.insert(0, seq);
        }
        let n = events.len() as u64;
        events.append(&mut self.f3.pending);
        self.f3.pending = events;
        report.events_requeued = n;
        Ok(n)
    }

    /// Remember a fork found while restoring and refuse.
    fn refuse_fork(&mut self, detail: String) -> Result<()> {
        let _ = util::write_json(
            &self.home.join(FORK_FILE),
            &ForkFile {
                detail: detail.clone(),
                found_utc: util::now_utc(),
            },
        );
        self.ledger_alarm.fork = Some(detail.clone());
        self.forked_self = true;
        bail!("{detail}; this device signs nothing more: {REPAIR_ADVICE}")
    }

    /// `varsto ledger status`: heads per device, where each device's
    /// batches are held (this device and, with `list_storages`, every
    /// metadata storage) and the health.
    pub fn ledger_status(&mut self, list_storages: bool) -> Result<LedgerStatus> {
        let mut health = self.ledger_health();
        let mut listings: Vec<(String, bool, std::result::Result<Vec<String>, String>)> =
            Vec::new();
        if list_storages {
            health = self.ledger_check_storages().unwrap_or(health);
            if health.is_ok() || health.state == "no_ledger" {
                let _ = self.ledger_lost_everywhere(true);
                health = self.ledger_health();
            }
            for (spec, backend) in self.metadata_storages(true)? {
                if spec.is_carrier() {
                    continue;
                }
                let listed = backend.list("ledger/").map_err(|e| format!("{e:#}"));
                listings.push((spec.name().to_string(), spec.is_cold(), listed));
            }
        }
        let view = self.view3().unwrap_or_default();
        let me = self.me3();
        let mut ids: BTreeSet<Id16> = self.f3.ledger.devices().into_iter().collect();
        ids.extend(self.f3.members.devices.devices.keys().copied());
        ids.insert(me);
        let mut devices = Vec::new();
        for d in ids {
            let h = self.f3.ledger.head(&d);
            let local: Vec<u64> = (h.dropped + 1..=h.seq)
                .filter(|s| self.f3.ledger.get(&d, *s).ok().flatten().is_some())
                .collect();
            let mut held = vec![LedgerHolding {
                place: "this device".into(),
                cold: false,
                batches: local.len() as u64,
                first: local.first().copied(),
                last: local.last().copied(),
                checkpoints: h.base.as_ref().map(|b| vec![b.seq]).unwrap_or_default(),
                error: None,
            }];
            let prefix = format!("ledger/{}/", hex::encode(d));
            for (name, cold, listed) in &listings {
                let mut hold = LedgerHolding {
                    place: name.clone(),
                    cold: *cold,
                    ..Default::default()
                };
                match listed {
                    Ok(keys) => {
                        for o in keys.iter().filter_map(|k| {
                            k.strip_prefix(&prefix)
                                .and_then(crate::ledger3::LedgerObject::parse)
                        }) {
                            match o {
                                crate::ledger3::LedgerObject::Batch(s) => {
                                    hold.batches += 1;
                                    hold.first = Some(hold.first.map_or(s, |f| f.min(s)));
                                    hold.last = Some(hold.last.map_or(s, |l| l.max(s)));
                                }
                                crate::ledger3::LedgerObject::Checkpoint(s, 0) => {
                                    hold.checkpoints.push(s)
                                }
                                crate::ledger3::LedgerObject::Checkpoint(..) => {}
                            }
                        }
                    }
                    Err(e) => hold.error = Some(e.clone()),
                }
                held.push(hold);
            }
            let did = DeviceId::from_bytes(&d);
            let name = view
                .devices
                .get(&d)
                .cloned()
                .unwrap_or_else(|| self.device_name(&did));
            devices.push(LedgerDeviceStatus {
                device: did.to_string(),
                name,
                this_device: d == me,
                revoked: self.f3.members.revoked.contains(&d),
                head: h.seq,
                checkpoint: h.base.as_ref().map(|b| b.seq),
                dropped: h.dropped,
                forked: h.forked || (d == me && self.forked_self),
                held,
            });
        }
        Ok(LedgerStatus { health, devices })
    }
}

#[cfg(test)]
mod tests {
    use super::super::ledger_upkeep::tests::{append_synthetic, copy_tree, devices, lab};
    use super::*;

    const PASS: &str = "correct horse battery staple";

    /// A copy restored from a backup that signed batches before it noticed
    /// (the check before signing could not see the storage): those batches
    /// were published nowhere and their numbers are taken on the storage,
    /// so they are set aside, their events signed again after the
    /// storage's history, and the other device sees no fork.
    #[test]
    fn unpublished_batches_are_set_aside_and_signed_again() {
        let (_tmp, lab) = lab("discard");
        let mut devs = devices(&lab, 2);
        let folder = FolderId::random();
        let home = devs[0].home.clone();
        let backup = lab.root.join("backup");
        copy_tree(&home, &backup);
        let me = devs[0].me3();
        let old = devs[0].f3.ledger.head(&me).seq;
        append_synthetic(&mut devs[0], 0, 3, &folder);
        devs[0].push_own_batches().unwrap();
        drop(devs);
        fs::remove_dir_all(&home).unwrap();
        copy_tree(&backup, &home);

        let mut a = Engine::open(&home, PASS).unwrap();
        append_synthetic(&mut a, 9, 2, &folder);
        assert_eq!(a.f3.ledger.head(&me).seq, old + 2);
        let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
        assert_eq!(r.discarded_unpublished, vec![old + 1, old + 2]);
        assert_eq!(r.events_requeued, 2, "one synthetic claim in each");
        assert_eq!(a.f3.pending.len() as u64, r.events_requeued);
        assert_eq!(a.f3.ledger.head(&me).seq, old + 3, "{r:?}");
        assert!(home.join("ledger/discarded").read_dir().unwrap().count() == 2);
        assert!(r.health.is_ok());
        a.commit_batch().unwrap();
        assert_eq!(a.f3.ledger.head(&me).seq, old + 4);
        let mut b = Engine::open(&lab.root.join("dev1"), PASS).unwrap();
        assert!(b.pull_ledger().unwrap().is_empty());
        assert_eq!(b.f3.ledger.head(&me).seq, old + 4);
        assert_eq!(
            a.view3().unwrap().canonical(),
            a.view3_replayed().unwrap().canonical()
        );
    }

    #[test]
    fn health_describes_what_to_do() {
        let h = LedgerHealth {
            state: "rebuild_needed".into(),
            problems: vec![LedgerProblem {
                code: "local_ledger_missing".into(),
                detail: "this device's local ledger is missing".into(),
            }],
            automatic: true,
            suggestion: Some(REBUILD_COMMAND.into()),
            ..Default::default()
        };
        assert_eq!(
            h.describe(),
            "this device's local ledger is missing; rebuild recommended: run `varsto ledger rebuild` (the background service does this by itself)"
        );
        assert_eq!(
            LedgerHealth {
                state: "ok".into(),
                ..Default::default()
            }
            .describe(),
            "ok"
        );
    }
}
