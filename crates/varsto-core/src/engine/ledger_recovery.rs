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
use crate::ledger::{LedgerObject, Rescan, SignedCheckpoint};
use crate::snapshot::Snapshot;

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

/// Events per batch when claims are rebuilt from the storages.
const EVENTS_PER_BATCH: usize = 2000;

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
    /// acknowledgement), `peer` (a head statement a peer sent over
    /// peer-to-peer, section 74) or `pending` (batches wait for a
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
}

const WATCH_FILE: &str = "ledger/watch.json";

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
    /// The newest head statement of every peer (`ledger/heads-seen.json`).
    pub(super) heads: crate::ledger_heads::HeadsSeen,
    /// When the peers were last asked for their statements.
    pub(super) heads_asked: Option<std::time::Instant>,
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
        let mut a = Alarm {
            heads: crate::ledger_heads::HeadsSeen::load(&e.home),
            ..Alarm::default()
        };
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

/// The copies of one own batch on the storages.
enum Fetched {
    None,
    One(SignedBatch),
    /// Two storages hold different batches under this number.
    Disagree,
}

const TWO_HISTORIES: &str = "the storages hold two different ledger histories of this device";

/// Own batches and checkpoints on each storage.
struct OwnListing {
    batches: BTreeMap<u64, Vec<usize>>,
    checkpoints: BTreeMap<u64, Vec<usize>>,
    /// Per storage: (lowest batch, holds a checkpoint).
    per_storage: Vec<(usize, Option<u64>, bool)>,
}

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
        let me = &self.vault.device_id;
        let a = &self.ledger_alarm;
        let own_head = self.ledger.head(me).seq;
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

    /// Own batches or checkpoints after the local head on the first hot
    /// metadata storage that answers: `Some(newest)` when there are any
    /// that this device's key signed. Anything else under its name is junk
    /// (noted, never a reason to stop signing).
    fn own_objects_ahead(&mut self) -> Result<Option<u64>> {
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me).seq;
        let prefix = format!("ledger/{me}/");
        let start = if head == 0 {
            String::new()
        } else {
            SignedBatch::storage_key(&me, head)
        };
        for (spec, backend) in self.metadata_storages(false)? {
            let Ok(keys) = backend.list_after(&prefix, &start) else {
                continue;
            };
            let mut newest = None;
            for k in keys {
                let Some(o) = k.strip_prefix(&prefix).and_then(LedgerObject::parse) else {
                    continue;
                };
                let seq = match o {
                    LedgerObject::Batch(s) | LedgerObject::Checkpoint(s) => s,
                };
                if seq <= head || newest.is_some_and(|n| n >= seq) {
                    continue;
                }
                if self.own_object_genuine(spec.name(), backend.as_ref(), &o)? {
                    newest = Some(seq);
                }
            }
            self.ledger_alarm.watch.save(&self.home);
            return Ok(newest);
        }
        Ok(None)
    }

    /// Whether the own ledger object `o` on a storage was signed by this
    /// device: it parses as a batch or checkpoint of this device under that
    /// number and verifies with this device's key. One that does not is
    /// junk: noted (`Watch::junk`) and not read again. Objects that do not
    /// answer are neither.
    pub(super) fn own_object_genuine(
        &mut self,
        storage: &str,
        backend: &dyn Storage,
        o: &LedgerObject,
    ) -> Result<bool> {
        let me = self.vault.device_id.clone();
        let key = match o {
            LedgerObject::Batch(s) => SignedBatch::storage_key(&me, *s),
            LedgerObject::Checkpoint(s) => SignedCheckpoint::storage_key(&me, *s),
        };
        if self
            .ledger_alarm
            .watch
            .junk
            .get(storage)
            .is_some_and(|j| j.contains(&key))
        {
            return Ok(false);
        }
        let Some(blob) = backend.get(&key)? else {
            return Ok(false);
        };
        let pk = self.keys.signer.public();
        let genuine = match o {
            LedgerObject::Batch(s) => serde_json::from_slice::<SignedBatch>(&blob)
                .is_ok_and(|b| b.device == me && b.seq == *s && b.verify(&pk).is_ok()),
            LedgerObject::Checkpoint(s) => serde_json::from_slice::<SignedCheckpoint>(&blob)
                .is_ok_and(|c| c.device == me && c.seq == *s && c.verify(&pk).is_ok()),
        };
        if !genuine {
            log::warn!(storage = storage, key = key.as_str(); "junk under this device's ledger name");
            self.ledger_alarm
                .watch
                .junk
                .entry(storage.to_string())
                .or_default()
                .insert(key);
        }
        Ok(genuine)
    }

    /// Delete the junk under this device's own ledger name on every hot
    /// metadata storage: objects that do not verify with its key, and
    /// names it never writes. With `dry_run` they are only listed. Its
    /// genuine objects are never touched, whatever their number.
    pub fn ledger_clean_junk(&mut self, dry_run: bool) -> Result<JunkReport> {
        self.ensure_active()?;
        let me = self.vault.device_id.clone();
        let prefix = format!("ledger/{me}/");
        let mut report = JunkReport {
            dry_run,
            ..Default::default()
        };
        self.ledger_alarm.watch.junk.clear();
        for (spec, backend) in self.metadata_storages(false)? {
            for key in backend.list(&prefix)? {
                let genuine = match key.strip_prefix(&prefix).and_then(LedgerObject::parse) {
                    Some(o) => self.own_object_genuine(spec.name(), backend.as_ref(), &o)?,
                    None => false,
                };
                if genuine {
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

    /// Whether the ledger is gone everywhere (no block claims at all while
    /// the folders' manifests name blocks), checked at most once an hour
    /// and only when the view holds no claims. Sets `no_ledger`.
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
        // Format 3: no pack claims at all while files name blocks.
        let lost = self.view3()?.packs.is_empty() && self.chunk_map(true)?.objects_named() > 0;
        self.ledger_alarm.no_ledger = lost;
        Ok(lost)
    }

    /// Restore this device's ledger: rebuild the heads from the local
    /// files, take this device's own batches and checkpoints back from the
    /// storages and continue after the newest (or set aside batches that
    /// were never published and sign their events again), download the
    /// other devices' batches, rebuild the view, and, with `from_storage`
    /// (or by itself in the service when no ledger is left anywhere),
    /// rebuild the block claims from what the storages hold.
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
        let me = self.vault.device_id.clone();
        let mut report = LedgerRebuildReport::default();
        task.set_phase("local");
        report.local = self.ledger.rescan()?;
        report.own_head_before = self.ledger.head(&me).seq;

        task.set_phase("own");
        self.restore_own_history(opts.confirm_cold_read, &mut report)?;
        report.own_head_after = self.ledger.head(&me).seq;
        self.ledger_alarm.local.clear();
        self.ledger_alarm.storage_ahead = None;
        self.ledger_alarm.fork = None;
        let _ = fs::remove_file(self.home.join(FORK_FILE));
        self.forked_self = false;
        self.ledger.clear_fork(&me)?;
        self.ledger.save()?;

        task.set_phase("others");
        let held = |e: &Engine| -> (u64, u64) {
            e.ledger
                .devices()
                .iter()
                .filter(|d| **d != me)
                .fold((0, 0), |(b, c), d| {
                    let h = e.ledger.head(d);
                    (
                        b + h.seq.saturating_sub(h.dropped),
                        c + h.base.is_some() as u64,
                    )
                })
        };
        let (b0, c0) = held(self);
        let forks = self.pull_ledger()?;
        if forks.contains(&me) {
            // Something signed by this identity appeared meanwhile.
            self.forked_self = true;
            bail!("a storage received a batch of this device while it was being restored; run `{REBUILD_COMMAND}` again");
        }
        let (b1, c1) = held(self);
        report.batches_pulled = b1.saturating_sub(b0);
        report.checkpoints_pulled = c1.saturating_sub(c0);
        self.reset_view_cache();
        self.view()?;
        report.manifests_caught_up = self.catch_up_own_manifests()?;

        if !self.vault.member && self.ledger.head(&me).seq == 0 {
            // Nothing of this device was found anywhere: it enrols again
            // under its own name (as a new device does), starting at 1.
            self.pending.push(Event::DeviceEnrolled {
                name: self.vault.device_name.clone(),
            });
            self.commit_batch()?;
            report.reenrolled = true;
        }

        report.no_ledger_anywhere = self.ledger_lost_everywhere(true)?;
        if opts.from_storage || (opts.automatic && report.no_ledger_anywhere) {
            report.from_storage = Some(self.rebuild_claims_from_storage(opts, task)?);
            self.ledger_alarm.no_ledger = false;
            self.ledger_alarm.lost_checked_utc = Some(util::now_utc());
        } else if report.no_ledger_anywhere {
            report.notes.push(format!(
                "no storage holds any record of where the blocks are; run `{REBUILD_FROM_STORAGE_COMMAND}` to rebuild it from the storages"
            ));
        }
        report.notes.append(&mut self.ledger_alarm.notes);
        Ok(report)
    }

    /// List this device's own ledger objects on every metadata storage
    /// (cold ones too: listing is not a read of their contents).
    fn list_own(
        &self,
        storages: &OpenStorages,
        report: &mut LedgerRebuildReport,
    ) -> Result<OwnListing> {
        let me = &self.vault.device_id;
        let prefix = format!("ledger/{me}/");
        let mut out = OwnListing {
            batches: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            per_storage: Vec::new(),
        };
        for (i, (spec, backend)) in storages.iter().enumerate() {
            let keys = match backend.list(&prefix) {
                Ok(k) => k,
                Err(e) if spec.is_cold() => {
                    report
                        .notes
                        .push(format!("cold storage {} could not be listed: {e:#}", spec.name()));
                    continue;
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "storage {} could not be listed; the ledger is restored when every storage answers",
                            spec.name()
                        )
                    })
                }
            };
            let mut lowest = None;
            let mut has_cp = false;
            for o in keys
                .iter()
                .filter_map(|k| k.strip_prefix(&prefix).and_then(LedgerObject::parse))
            {
                match o {
                    LedgerObject::Batch(s) => {
                        out.batches.entry(s).or_default().push(i);
                        lowest = Some(lowest.map_or(s, |l: u64| l.min(s)));
                    }
                    LedgerObject::Checkpoint(s) => {
                        out.checkpoints.entry(s).or_default().push(i);
                        has_cp = true;
                    }
                }
            }
            out.per_storage.push((i, lowest, has_cp));
        }
        Ok(out)
    }

    /// The batch `seq` of this device from the first storage that holds a
    /// copy signed with this device's key.
    fn fetch_own_batch(
        &self,
        storages: &OpenStorages,
        holders: &[usize],
        seq: u64,
        cold_ok: bool,
    ) -> Result<Fetched> {
        let me = &self.vault.device_id;
        let pk = self.keys.signer.public();
        let mut cold_only = false;
        let mut found: Option<SignedBatch> = None;
        // Every copy is read: storages that hold different batches of this
        // device under one number mean two histories were published.
        for &i in holders {
            let (spec, backend) = &storages[i];
            if spec.is_cold() && !cold_ok {
                cold_only = true;
                continue;
            }
            let Ok(Some(blob)) = backend.get(&SignedBatch::storage_key(me, seq)) else {
                continue;
            };
            let Ok(b) = serde_json::from_slice::<SignedBatch>(&blob) else {
                continue;
            };
            if &b.device != me || b.seq != seq || b.verify(&pk).is_err() {
                continue;
            }
            match &found {
                Some(f) if f.hash != b.hash => return Ok(Fetched::Disagree),
                Some(_) => {}
                None => found = Some(b),
            }
        }
        match found {
            Some(b) => Ok(Fetched::One(b)),
            None if cold_only => bail!(
                "batch {seq} of this device is held only on cold storage: run `{REBUILD_COMMAND} --confirm-cold-read` to read it there"
            ),
            None => Ok(Fetched::None),
        }
    }

    fn fetch_own_checkpoint(
        &self,
        storages: &OpenStorages,
        holders: &[usize],
        seq: u64,
        cold_ok: bool,
    ) -> Option<SignedCheckpoint> {
        let me = &self.vault.device_id;
        let pk = self.keys.signer.public();
        for &i in holders {
            let (spec, backend) = &storages[i];
            if spec.is_cold() && !cold_ok {
                continue;
            }
            let Ok(Some(blob)) = backend.get(&SignedCheckpoint::storage_key(me, seq)) else {
                continue;
            };
            let Ok(cp) = serde_json::from_slice::<SignedCheckpoint>(&blob) else {
                continue;
            };
            if &cp.device == me && cp.seq == seq && cp.verify(&pk).is_ok() {
                return Some(cp);
            }
        }
        None
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

    /// Take this device's own history back from the storages (S2, S3).
    fn restore_own_history(
        &mut self,
        cold_ok: bool,
        report: &mut LedgerRebuildReport,
    ) -> Result<()> {
        let me = self.vault.device_id.clone();
        let pk = self.keys.signer.public();
        let storages = self.metadata_storages(true)?;
        let listing = self.list_own(&storages, report)?;
        report.own_found_on_storages =
            !listing.batches.is_empty() || !listing.checkpoints.is_empty();
        let holders = |seq: u64| listing.batches.get(&seq).cloned().unwrap_or_default();

        // 1. Where the local history and the storages' agree. Equal hashes
        // at a number mean equal histories up to it (each batch names the
        // hash of the one before), so the walk stops at the first match.
        let head = self.ledger.head(&me);
        let mut diverged: Vec<u64> = Vec::new();
        let low = head
            .dropped
            .max(head.base.as_ref().map(|b| b.seq).unwrap_or(0));
        for seq in (low + 1..=head.seq).rev() {
            let Some(local) = self.ledger.get(&me, seq)? else {
                continue;
            };
            if !listing.batches.contains_key(&seq) {
                // Not on any storage. If the storages' next batch names it
                // as its predecessor, it is part of the published history
                // (a storage lost it): that is the agreement point.
                let continues = match listing.batches.get(&(seq + 1)) {
                    Some(h) => match self.fetch_own_batch(&storages, h, seq + 1, cold_ok)? {
                        Fetched::One(next) => self
                            .key_for_id(&next.key_id)
                            .and_then(|key| next.open(&key).ok())
                            .is_some_and(|n| n.prev.as_deref() == Some(local.hash.as_str())),
                        Fetched::Disagree => {
                            return self.refuse_fork(format!(
                                "{TWO_HISTORIES} (batch #{} differs between them)",
                                seq + 1
                            ))
                        }
                        Fetched::None => false,
                    },
                    None => false,
                };
                if continues {
                    break;
                }
                diverged.push(seq);
                continue;
            }
            match self.fetch_own_batch(&storages, &holders(seq), seq, cold_ok)? {
                Fetched::One(remote) if remote.hash == local.hash => {
                    break;
                }
                Fetched::One(_) => diverged.push(seq),
                Fetched::Disagree => {
                    return self.refuse_fork(format!(
                        "{TWO_HISTORIES} (batch #{seq} differs between them)"
                    ))
                }
                // Listed but not readable as this device's batch (a damaged
                // copy): it decides nothing, compare the next one down.
                Fetched::None => {}
            }
        }
        // Batches here that no storage holds, above the agreement point, or
        // that the storages hold under the same number with other content.
        let newest_remote = listing
            .batches
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .max(listing.checkpoints.keys().next_back().copied().unwrap_or(0));
        let conflicting: Vec<u64> = diverged
            .iter()
            .copied()
            .filter(|s| listing.batches.contains_key(s) || *s <= newest_remote)
            .collect();
        if !conflicting.is_empty() {
            // Set them aside only if none of them was ever published: a
            // storage holding this device's version of one of them means
            // two histories were published (two copies of one identity).
            for seq in &conflicting {
                let local = self.ledger.get(&me, *seq)?.expect("held");
                for &i in &holders(*seq) {
                    let (spec, backend) = &storages[i];
                    if spec.is_cold() && !cold_ok {
                        continue;
                    }
                    if let Ok(Some(blob)) = backend.get(&SignedBatch::storage_key(&me, *seq)) {
                        if let Ok(b) = serde_json::from_slice::<SignedBatch>(&blob) {
                            if b.hash == local.hash {
                                return self.refuse_fork(format!(
                                    "{TWO_HISTORIES} (batch #{seq} differs between them)"
                                ));
                            }
                        }
                    }
                }
            }
            // Never published: set aside (kept in `ledger/discarded/`) from
            // the newest down, their events signed again later.
            let lowest = *conflicting.iter().min().expect("not empty");
            let mut requeued = Vec::new();
            for seq in (lowest..=head.seq).rev() {
                if self.ledger.head(&me).seq != seq {
                    continue;
                }
                if let Some(b) = self.ledger.get(&me, seq)? {
                    if let Some(key) = self.key_for_id(&b.key_id) {
                        if let Ok(batch) = b.open(&key) {
                            let mut evs = batch.events;
                            evs.append(&mut requeued);
                            requeued = evs;
                        }
                    }
                }
                self.ledger.discard_own(&me, seq)?;
                report.discarded_unpublished.push(seq);
            }
            report.discarded_unpublished.sort();
            report.events_requeued = requeued.len() as u64;
            if !requeued.is_empty() {
                requeued.append(&mut self.pending);
                self.pending = requeued;
                self.defer_events()?;
            }
        }

        // 2. Continue with the storages' newer history. A checkpoint after
        // the local head first (the batches it covers may be pruned), then
        // every batch after what is held; `ingest_with` checks that each
        // chains onto the one before, here or in the checkpoint.
        let held_to = self.ledger.head(&me).seq;
        // The newest checkpoint this device's key signed: junk under its
        // name (a higher number that does not verify) is passed over.
        let newest_cp = listing
            .checkpoints
            .iter()
            .rev()
            .find(|(seq, holders)| {
                self.fetch_own_checkpoint(&storages, holders, **seq, cold_ok)
                    .is_some()
                    || holders.iter().all(|i| storages[*i].0.is_cold())
            })
            .or_else(|| listing.checkpoints.iter().next_back());
        if let Some((&cseq, cholders)) = newest_cp {
            let base = self.ledger.head(&me).base.map(|b| b.seq).unwrap_or(0);
            if cseq > held_to.max(base) {
                if let Some(cp) = self.fetch_own_checkpoint(&storages, cholders, cseq, cold_ok) {
                    // The batch it ends at stays beside it on the storages.
                    let anchor =
                        match self.fetch_own_batch(&storages, &holders(cseq), cseq, cold_ok) {
                            Ok(Fetched::One(b)) => Some(b),
                            _ => None,
                        };
                    match self.key_for_id(&cp.key_id) {
                        Some(key) if cp.open(&key).is_ok() => {
                            match self.ledger.ingest_checkpoint_anchored(cp, anchor.as_ref())? {
                                Ingest::Fork => {
                                    return self.refuse_fork(format!(
                                        "this device's checkpoint #{cseq} on the storages contradicts its own ledger"
                                    ));
                                }
                                Ingest::Refused => bail!(
                                    "this device's checkpoint #{cseq} on the storages is too far ahead of its ledger and the batch it ends at is missing"
                                ),
                                _ => {}
                            }
                            report.adopted_checkpoint = Some(cseq);
                        }
                        _ => report.notes.push(format!(
                            "checkpoint #{cseq} of this device does not open with the keys held here; its batches are used instead"
                        )),
                    }
                } else if listing
                    .checkpoints
                    .values()
                    .next_back()
                    .is_some_and(|h| h.iter().all(|i| storages[*i].0.is_cold()))
                    && !cold_ok
                {
                    bail!("this device's newest checkpoint is held only on cold storage: run `{REBUILD_COMMAND} --confirm-cold-read` to read it there");
                }
            }
        }
        let mut gap = false;
        for (&seq, h) in listing.batches.iter() {
            let now = self.ledger.head(&me);
            if seq <= now.seq || now.base.as_ref().is_some_and(|b| seq <= b.seq) {
                continue;
            }
            let signed = match self.fetch_own_batch(&storages, h, seq, cold_ok)? {
                Fetched::One(b) => b,
                // Junk under this device's name: not its history.
                Fetched::None => continue,
                Fetched::Disagree => {
                    return self.refuse_fork(format!(
                        "{TWO_HISTORIES} (batch #{seq} differs between them)"
                    ))
                }
            };
            if seq > now.seq + 1 && !now.base.as_ref().is_some_and(|b| b.seq + 1 >= seq) {
                gap = true;
            }
            let key = self.key_for_id(&signed.key_id);
            // Its own history continues past a gap no storage can fill:
            // signing a number it already used would be a fork.
            match self.ledger.ingest_own_restored(signed, &pk, key.as_ref())? {
                Ingest::Fork => {
                    return self.refuse_fork(format!(
                        "batch #{seq} of this device on the storages does not continue the history this device holds"
                    ));
                }
                Ingest::New => report.adopted_batches += 1,
                Ingest::Known | Ingest::Refused | Ingest::Pending => {}
            }
        }
        if gap {
            report.notes.push(
                "some batches of this device are on no storage; what they recorded is missing from the view until the blocks are claimed again"
                    .into(),
            );
        }

        // 3. Pruning resumes where the storages stand.
        for (i, lowest, has_cp) in &listing.per_storage {
            let name = storages[*i].0.name().to_string();
            if let (Some(l), true) = (lowest, has_cp) {
                if *l > 1 && self.ledger.pruned(&name) < l - 1 {
                    self.ledger.set_pruned(&name, l - 1)?;
                }
            }
        }
        Ok(())
    }

    /// A device restored from a backup holds folder states that name an
    /// older manifest than it published later: its next manifest goes on
    /// after the newest one it published (in the ledger or on a storage),
    /// so no number is used twice. The files of that later manifest come
    /// back through the other devices' manifests, which include them.
    fn catch_up_own_manifests(&mut self) -> Result<u64> {
        let view = self.view()?;
        let me = self.vault.device_id.clone();
        let storages = self.metadata_storages(false)?;
        let mut n = 0;
        for (rec, mount) in self.folders() {
            if mount.is_none() {
                continue;
            }
            let mut state = self.load_state(&rec.folder_id)?;
            let mut newest = view
                .manifests
                .get(&(rec.folder_id.clone(), me.clone()))
                .copied()
                .unwrap_or(0);
            let folder_prefix = format!("manifests/{}/", rec.folder_id);
            let prefix = Manifest::storage_prefix(&rec.folder_id, &me);
            let start = Manifest::storage_key(&rec.folder_id, &me, state.published_seq.max(newest));
            for (_, backend) in &storages {
                let Ok(keys) = backend.list_after(&prefix, &start) else {
                    continue;
                };
                for k in keys {
                    if let Some((d, seq)) = super::manifest_upkeep::parse_key(&folder_prefix, &k) {
                        if d == me {
                            newest = newest.max(seq);
                        }
                    }
                }
            }
            if newest > state.published_seq {
                state.published_seq = newest;
                // Publish again at the next sync, under a new number.
                state.published_hash = String::new();
                self.save_state(&rec.folder_id, &state)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Every block object the newest manifests (and backup snapshots) of
    /// every folder name, with where it belongs. With `first_only`, stops
    /// at the first object (the "ledger lost everywhere" check).
    fn chunk_map(&self, first_only: bool) -> Result<ChunkMap> {
        let mut map = ChunkMap::default();
        let storages: OpenStorages = self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        let me = self.vault.device_id.clone();
        for rec in self.keyring.folders.values().filter(|r| !r.is_removed()) {
            let Ok(fk) = self.folder_keys(rec) else {
                map.skipped.push(rec.name.clone());
                continue;
            };
            let metas = fk.meta_keys();
            map.folders += 1;
            if rec.is_backup() {
                let prefix = Snapshot::backup_prefix(&rec.folder_id);
                let mut seen = BTreeSet::new();
                for (_, backend) in &storages {
                    for key in backend.list(&prefix)? {
                        let Some((dev, seq)) = Snapshot::parse_key(&rec.folder_id, &key) else {
                            continue;
                        };
                        if !seen.insert((dev.clone(), seq)) {
                            continue;
                        }
                        let Some(blob) = backend.get(&key)? else {
                            continue;
                        };
                        let Ok(snap) = Snapshot::open(
                            &blob,
                            &self.vault.vault_id,
                            &rec.folder_id,
                            &dev,
                            seq,
                            &metas,
                        ) else {
                            continue;
                        };
                        map.snapshots_read += 1;
                        map.add_files(&rec.folder_id, snap.files.values());
                        if dev == me {
                            map.own_snapshots.push(Event::SnapshotTaken {
                                backup: rec.folder_id.clone(),
                                seq,
                                taken_utc: snap.taken_utc,
                                expires_utc: snap.expires_utc,
                                files: snap.files.len() as u64,
                                bytes: snap.bytes(),
                                snapshot_hash: hex::encode(crypto::hash(&blob)),
                            });
                        }
                        if first_only && map.objects_named() > 0 {
                            return Ok(map);
                        }
                    }
                }
                continue;
            }
            // The newest manifest of every device, across storages.
            let prefix = format!("manifests/{}/", rec.folder_id);
            let mut newest: BTreeMap<DeviceId, (u64, usize)> = BTreeMap::new();
            for (idx, (_, backend)) in storages.iter().enumerate() {
                for key in backend.list(&prefix)? {
                    let Some((dev, seq)) = super::manifest_upkeep::parse_key(&prefix, &key) else {
                        continue;
                    };
                    let e = newest.entry(dev).or_insert((0, idx));
                    if seq > e.0 {
                        *e = (seq, idx);
                    }
                }
            }
            for (dev, (seq, idx)) in newest {
                let key = Manifest::storage_key(&rec.folder_id, &dev, seq);
                let Some(blob) = storages[idx].1.get(&key)? else {
                    continue;
                };
                let Some(m) = metas.iter().find_map(|k| {
                    Manifest::open(&blob, &self.vault.vault_id, &rec.folder_id, &dev, seq, k).ok()
                }) else {
                    continue;
                };
                map.manifests_read += 1;
                map.add_files(&rec.folder_id, m.files.values().filter(|f| !f.deleted));
                if dev == me {
                    map.own_manifests.push(Event::ManifestPublished {
                        folder: rec.folder_id.clone(),
                        seq,
                        manifest_hash: hex::encode(crypto::hash(&blob)),
                        files: m.files.values().filter(|f| !f.deleted).count() as u64,
                    });
                }
                if first_only && map.objects_named() > 0 {
                    return Ok(map);
                }
            }
        }
        Ok(map)
    }

    /// Rebuild the block claims from what the storages hold (S4): map the
    /// objects to folders and blocks through the newest manifests and
    /// snapshots, list every storage (cold ones only when confirmed),
    /// verify the objects within the budget, and sign the claims as this
    /// device's own. Claims already in the ledger are not repeated, so it
    /// is safe to run again.
    fn rebuild_claims_from_storage(
        &mut self,
        opts: &LedgerRebuildOptions,
        task: &activity::Guard,
    ) -> Result<StorageRebuildReport> {
        if self.vault.member {
            bail!("a member of shared folders does not hold the vault's ledger; rebuild it on one of the owner's devices");
        }
        self.ensure_ledger_writable()?;
        let me = self.vault.device_id.clone();
        let mut r = StorageRebuildReport::default();
        task.set_phase("manifests");
        let map = self.chunk_map(false)?;
        r.folders = map.folders;
        r.folders_skipped = map.skipped.clone();
        r.manifests_read = map.manifests_read;
        r.snapshots_read = map.snapshots_read;
        r.objects_mapped = map.objects.len() as u64;
        let view = self.view()?;

        task.set_phase("list");
        let storages: OpenStorages = self
            .open_storages(opts.confirm_cold_read)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect();
        for spec in &self.config.storages {
            if spec.is_cold() && !opts.confirm_cold_read {
                r.storages_skipped_cold.push(spec.name().to_string());
            }
        }
        // (storage index, object) pairs to claim.
        let mut found: Vec<(usize, ObjectName)> = Vec::new();
        let mut anywhere: HashSet<ObjectName> = HashSet::new();
        for (i, (spec, backend)) in storages.iter().enumerate() {
            // Blocks are in packs: where they are comes from the pack
            // indexes when the ledger lost the claims.
            if let Err(e) = self.load_pack_indexes(backend.as_ref()) {
                log::warn!(storage = spec.name(); "pack indexes not read: {e:#}");
            }
            let listed: HashSet<String> = backend.list("chunks/")?.into_iter().collect();
            r.storages_listed.push(spec.name().to_string());
            for object in map.objects.keys() {
                if listed.contains(&chunk_storage_key(object)) {
                    found.push((i, object.clone()));
                    anywhere.insert(object.clone());
                }
            }
        }
        r.objects_missing = map
            .objects
            .keys()
            .filter(|o| !anywhere.contains(*o))
            .count() as u64;
        // Skip what the ledger already says.
        let claimed = |i: usize, o: &ObjectName| -> bool {
            let storage = storages[i].0.name();
            map.objects[o].iter().all(|(folder, chunk, _)| {
                view.locate(folder, chunk)
                    .is_some_and(|c| c.storages.contains_key(storage) && !c.dropped_from(storage))
            })
        };
        let (known, todo): (Vec<_>, Vec<_>) = found.into_iter().partition(|(i, o)| claimed(*i, o));
        r.claims_known = known.len() as u64;

        // Verification: everything when asked, nothing when told not to,
        // and by default everything up to `AUTO_VERIFY_BYTES`, otherwise
        // as much as the budget allows.
        let total: u64 = todo.iter().map(|(_, o)| map.size_of(o)).sum();
        let budget = match opts.verify {
            Some(true) => u64::MAX,
            Some(false) => 0,
            None if total <= AUTO_VERIFY_BYTES => u64::MAX,
            None => opts.verify_budget_bytes,
        };
        task.set_phase("verify");
        task.set_total(todo.len() as u64);
        let mut spent = 0u64;
        let mut events = Vec::new();
        let mut damage = Vec::new();
        for (i, object) in &todo {
            if budget > 0 && (spent < budget) {
                let (spec, backend) = &storages[*i];
                match backend.get(&chunk_storage_key(object)) {
                    Ok(Some(bytes)) => {
                        spent = spent.saturating_add(bytes.len() as u64);
                        r.objects_verified += 1;
                        r.bytes_verified += bytes.len() as u64;
                        if ObjectName::from_bytes(&crypto::hash(&bytes)) != *object {
                            r.objects_corrupt += 1;
                            for (folder, chunk, _) in &map.objects[object] {
                                damage.push(Damage {
                                    folder: folder.clone(),
                                    chunk: chunk.clone(),
                                    object: object.clone(),
                                    storage: spec.name().to_string(),
                                    kind: DamageKind::Corrupt,
                                    found_by: "ledger_rebuild".into(),
                                    found_utc: util::now_utc(),
                                    retry_utc: 0,
                                    reason: None,
                                });
                            }
                            task.advance(1);
                            continue;
                        }
                    }
                    Ok(None) => {
                        task.advance(1);
                        continue;
                    }
                    Err(e) => {
                        return Err(e).with_context(|| {
                            format!("reading {} on storage {}", object.short(), spec.name())
                        })
                    }
                }
            } else {
                r.objects_unverified += 1;
            }
            for (folder, chunk, sz) in &map.objects[object] {
                events.push(Event::ChunkStored {
                    folder: folder.clone(),
                    chunk: chunk.clone(),
                    object: object.clone(),
                    storage: storages[*i].0.name().to_string(),
                    size: *sz,
                    pack: storages[*i].1.pack_location(object.as_str()),
                });
            }
            r.claims_written += 1;
            task.advance(1);
        }
        if !damage.is_empty() {
            self.queue_damage(damage)?;
        }

        // What this device holds itself, and what only it can say again.
        for (rec, mount) in self.folders() {
            if mount.is_none() || self.mount_is_encrypted(&rec.folder_id) {
                continue;
            }
            let state = self.load_state(&rec.folder_id)?;
            let mut seen = HashSet::new();
            for f in state
                .files
                .values()
                .filter(|f| !f.deleted && state.local_index.contains_key(&f.path))
            {
                for c in &f.chunks {
                    if !seen.insert(c.chunk.clone()) {
                        continue;
                    }
                    if view
                        .locate(&rec.folder_id, &c.chunk)
                        .is_some_and(|x| x.devices.contains(&me))
                    {
                        continue;
                    }
                    events.push(Event::ChunkOnDevice {
                        folder: rec.folder_id.clone(),
                        chunk: c.chunk.clone(),
                        object: c.object.clone(),
                        size: c.size,
                    });
                    r.blocks_on_device += 1;
                }
            }
        }
        for ev in &map.own_manifests {
            if let Event::ManifestPublished { folder, seq, .. } = ev {
                if view
                    .manifests
                    .get(&(folder.clone(), me.clone()))
                    .is_none_or(|s| s < seq)
                {
                    events.push(ev.clone());
                    r.manifests_announced += 1;
                }
            }
        }
        for ev in &map.own_snapshots {
            if let Event::SnapshotTaken { backup, seq, .. } = ev {
                if !view
                    .snapshots
                    .get(&(backup.clone(), me.clone(), *seq))
                    .is_some_and(|s| s.taken)
                {
                    events.push(ev.clone());
                    r.snapshots_announced += 1;
                }
            }
        }
        if !view.devices.contains_key(&me) {
            events.push(Event::DeviceEnrolled {
                name: self.vault.device_name.clone(),
            });
        }
        for rec in self.keyring.folders.values() {
            if rec.created_by == me && !rec.is_removed() && !view.folders.contains(&rec.folder_id) {
                events.push(Event::FolderAdded {
                    folder: rec.folder_id.clone(),
                });
            }
        }

        task.set_phase("seal");
        for part in events.chunks(EVENTS_PER_BATCH) {
            let lamport = self.tick()?;
            let (key_id, key) = self.ledger_key_now();
            self.ledger.append_own_seen(
                &me,
                part.to_vec(),
                self.seen_heads(),
                lamport,
                &key,
                &key_id,
                &self.keys.signer,
            )?;
            r.batches += 1;
        }
        if r.batches > 0 {
            self.push_own_batches()?;
        }
        // The device and folder records this device wrote, if a storage
        // lost them as well.
        self.publish_registry()?;
        Ok(r)
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
                let listed = backend.list("ledger/").map_err(|e| format!("{e:#}"));
                listings.push((spec.name().to_string(), spec.is_cold(), listed));
            }
        }
        let view = self.view().unwrap_or_default();
        let me = self.vault.device_id.clone();
        let mut ids: BTreeSet<DeviceId> = self.ledger.devices().into_iter().collect();
        ids.extend(self.devices.devices.keys().cloned());
        ids.insert(me.clone());
        let mut devices = Vec::new();
        for d in ids {
            let h = self.ledger.head(&d);
            let local: Vec<u64> = (h.dropped + 1..=h.seq)
                .filter(|s| self.ledger.get(&d, *s).ok().flatten().is_some())
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
            for (name, cold, listed) in &listings {
                let prefix = format!("ledger/{d}/");
                let mut hold = LedgerHolding {
                    place: name.clone(),
                    cold: *cold,
                    ..Default::default()
                };
                match listed {
                    Ok(keys) => {
                        for o in keys
                            .iter()
                            .filter_map(|k| k.strip_prefix(&prefix).and_then(LedgerObject::parse))
                        {
                            match o {
                                LedgerObject::Batch(s) => {
                                    hold.batches += 1;
                                    hold.first = Some(hold.first.map_or(s, |f| f.min(s)));
                                    hold.last = Some(hold.last.map_or(s, |l| l.max(s)));
                                }
                                LedgerObject::Checkpoint(s) => hold.checkpoints.push(s),
                            }
                        }
                    }
                    Err(e) => hold.error = Some(e.clone()),
                }
                held.push(hold);
            }
            let name = view
                .devices
                .get(&d)
                .cloned()
                .or_else(|| self.devices.devices.get(&d).map(|r| r.name.clone()))
                .unwrap_or_default();
            devices.push(LedgerDeviceStatus {
                device: d.to_string(),
                name,
                this_device: d == me,
                revoked: self.is_revoked(&d),
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

/// Block objects named by the newest manifests and snapshots.
#[derive(Default)]
struct ChunkMap {
    /// Object -> (folder, chunk, size) it stands for.
    objects: BTreeMap<ObjectName, BTreeSet<(FolderId, ChunkId, u64)>>,
    folders: u64,
    skipped: Vec<String>,
    manifests_read: u64,
    snapshots_read: u64,
    own_manifests: Vec<Event>,
    own_snapshots: Vec<Event>,
}

impl ChunkMap {
    fn add_files<'a>(&mut self, folder: &FolderId, files: impl Iterator<Item = &'a FileState>) {
        for f in files {
            for c in &f.chunks {
                self.objects.entry(c.object.clone()).or_default().insert((
                    folder.clone(),
                    c.chunk.clone(),
                    c.size,
                ));
            }
        }
    }

    fn objects_named(&self) -> usize {
        self.objects.len()
    }

    fn size_of(&self, o: &ObjectName) -> u64 {
        self.objects
            .get(o)
            .and_then(|s| s.iter().next())
            .map(|(_, _, sz)| *sz)
            .unwrap_or(0)
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
    #[ignore = "f3-switch: port in part B (ledger rebuild)"]
    fn unpublished_batches_are_set_aside_and_signed_again() {
        let (_tmp, lab) = lab("discard");
        let mut devs = devices(&lab, 2);
        let folder = FolderId::random();
        let home = devs[0].home.clone();
        let backup = lab.root.join("backup");
        copy_tree(&home, &backup);
        let me = devs[0].vault.device_id.clone();
        let old = devs[0].ledger.head(&me).seq;
        append_synthetic(&mut devs[0], 0, 3, &folder);
        devs[0].push_own_batches().unwrap();
        drop(devs);
        fs::remove_dir_all(&home).unwrap();
        copy_tree(&backup, &home);

        let mut a = Engine::open(&home, PASS).unwrap();
        append_synthetic(&mut a, 9, 2, &folder);
        assert_eq!(a.ledger.head(&me).seq, old + 2);
        let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
        assert_eq!(r.discarded_unpublished, vec![old + 1, old + 2]);
        assert!(r.events_requeued >= 4);
        assert_eq!(a.pending.len() as u64, r.events_requeued);
        assert_eq!(a.ledger.head(&me).seq, old + 3);
        assert!(home.join("ledger/discarded").read_dir().unwrap().count() == 2);
        assert!(r.health.is_ok());
        a.commit_batch().unwrap();
        assert_eq!(a.ledger.head(&me).seq, old + 4);
        let mut b = Engine::open(&lab.root.join("dev1"), PASS).unwrap();
        assert!(b.pull_ledger().unwrap().is_empty());
        assert_eq!(b.ledger.head(&me).seq, old + 4);
        assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
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
