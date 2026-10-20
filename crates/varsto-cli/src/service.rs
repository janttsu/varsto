// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Background service: watches attached folders, syncs on change and on a
//! timer, serves the local API and desktop page, and writes `service.json`
//! so that the menu-bar app and the CLI can find it.
//!
//! Unlocking: the service starts locked unless the passphrase comes from the
//! `VARSTO_PASSPHRASE` environment variable, the macOS login keychain
//! (`security find-generic-password -s varsto -a <home>`, where the menu-bar
//! app can store it), or whatever `varsto service remember` used on Linux:
//! the desktop keyring, `systemd-creds` or the kernel keyring (spec section
//! 72). The desktop page and any command line that
//! asks for the passphrase unlock it as well.

use crate::desktop::{self, Shared, State};
use anyhow::{anyhow, Context, Result};
use notify::Watcher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use varsto_core::engine::{PullReport, PushReport};
use varsto_core::Engine;

static QUIT: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceFile {
    pub pid: u32,
    pub port: u16,
    pub token: String,
    pub started_utc: i64,
    pub version: String,
}

varsto_core::redacted_debug!(ServiceFile { pid, port, started_utc, version ; token });

/// Runtime state of the service, shared with the API.
#[derive(Default)]
pub struct ServiceState {
    /// Storage format 3: folder requests already announced to the page
    /// (`folder.request`), as `<folder>/<device>/<words>`.
    pub seen_requests: std::collections::BTreeSet<String>,
    pub running: bool,
    pub paused: bool,
    pub interval_secs: u64,
    pub watching: Vec<PathBuf>,
    pub last_sync_utc: Option<i64>,
    pub last_result: String,
    pub last_error: Option<String>,
    pub next_sync_utc: Option<i64>,
    pub sync_requested: bool,
    pub folders_changed: bool,
    pub syncs: u64,
    /// Set after a successful self-update: the loop exits so the supervisor restarts us.
    pub restart_requested: bool,
    /// Latest durability policy reports (F-032) and the worst state among them.
    pub policies: Vec<varsto_core::policy::PolicyReport>,
    pub policy_worst: Option<varsto_core::policy::PolicyState>,
    /// Peer-to-peer: listening address and the peers known right now.
    pub p2p_listen: Option<std::net::SocketAddr>,
    pub p2p_peers: Vec<varsto_core::p2p::PeerAddr>,
    pub p2p_lan_peers: usize,
    pub p2p_chunks: u64,
    /// Bytes of the blocks received from peers since start.
    pub p2p_bytes: u64,
    /// Removable disks of every pool as of the last check (every 30 seconds).
    pub disks: Vec<varsto_core::pool::DiskStatus>,
    /// The next pool disk to dock, recomputed after syncs and disk changes
    /// (from the pool index and the ledger; no disk is read).
    pub disk_suggest: Option<varsto_core::disksuggest::DiskSuggestions>,
    /// NAT traversal: what STUN saw, the NAT guess, whether we are reachable,
    /// the relays we are registered with, and the path to every peer.
    pub p2p_nat: varsto_core::p2p::stun::Nat,
    pub p2p_public: Vec<std::net::SocketAddr>,
    pub p2p_reachable: bool,
    pub p2p_relays: Vec<String>,
    pub p2p_paths: Vec<varsto_core::p2p::PeerStatus>,
    pub p2p_cert_sha256: String,
    /// The port the home router forwards to us (PCP, NAT-PMP, UPnP), if any.
    pub p2p_portmap: varsto_core::p2p::portmap::PortMapStatus,
    /// Automatic verification: schedule, last run and next run.
    pub auto_verify: Option<varsto_core::autoverify::VerifyStatus>,
    /// Automatic repair: queue, last run and copies that could not be repaired.
    pub repair: Option<varsto_core::engine::RepairStatus>,
    /// Forwarding other devices' blocks to the storages: on or off, last run.
    pub forward: Option<varsto_core::engine::ForwardStatus>,
    /// The mailbox for offline pool disks: what is staged and what it waits for.
    pub mailbox: Option<varsto_core::mailbox::MailboxStatus>,
    /// Bit-rot check: schedule, last run, passes and damaged files waiting.
    pub scrub: Option<varsto_core::scrub::ScrubStatus>,
    /// Backups: when expiry last ran, the last snapshot taken here, and the
    /// backups whose last scheduled snapshot failed (with the reason).
    pub backup_upkeep_utc: Option<i64>,
    pub backup_last: Option<String>,
    pub backup_errors: std::collections::BTreeMap<String, String>,
    /// The ledger's state as of the last check (`ledger_recovery`).
    pub ledger_health: Option<varsto_core::engine::LedgerHealth>,
    /// When the storages were last asked whether they hold newer batches
    /// of this device than it has.
    pub ledger_checked: Option<Instant>,
    /// The last failed rebuild's message (notified once, retried each sync).
    pub ledger_failed: Option<String>,
    /// Backups with restic: the scheduled run under way (a child process
    /// `varsto restic run --scheduled`), when the user was last warned that
    /// the last good snapshot is too old, and a one-line summary.
    pub restic_child: Option<std::process::Child>,
    pub restic_warned_utc: Option<i64>,
    /// Not before this time: a run that failed before it could record why.
    pub restic_not_before_utc: i64,
    pub restic_text: Option<String>,
    /// Storages being drained or drained, as of the last run.
    pub drains: Vec<varsto_core::engine::DrainStatus>,
    /// Drains already announced as finished or waiting (not repeated).
    pub drain_notified: std::collections::BTreeSet<String>,
    /// Torrent jobs already announced as waiting for space (not repeated
    /// while they wait).
    pub torrent_notified: std::collections::BTreeSet<String>,
    /// YouTube jobs already announced as waiting for space (not repeated
    /// while they wait).
    pub youtube_notified: std::collections::BTreeSet<String>,
    /// Storages at their quota during the last sync, one sentence each.
    pub quota_full: Vec<String>,
    /// Folders paused on this device (marker missing, deletions held), by
    /// name, with the reason; notified once when a folder pauses.
    pub paused_folders: std::collections::BTreeMap<String, String>,
    /// Places short of disk space (`freespace`): downloads or uploads there
    /// wait until space is back. Notified once per place.
    pub low_space: Vec<varsto_core::freespace::LowSpace>,
    pub low_space_notified: std::collections::BTreeSet<String>,
    /// Storages a push had to leave out last time (`storage.problem` events).
    pub storage_problems: std::collections::BTreeSet<String>,
    /// Open and paused move jobs (staged moves to disk pools), as of the
    /// last time the service looked at them.
    pub move_jobs: Vec<varsto_core::staged_move::MoveJob>,
}

/// The storages are asked this often whether they hold newer ledger
/// batches of this device than it has.
const LEDGER_CHECK_EVERY: Duration = Duration::from_secs(3600);

/// How soon the service looks for a device that just joined: first after
/// `WATCH_MIN`, then with growing gaps up to `WATCH_MAX`. The clock starts
/// over when the service starts, the vault is unlocked, a pairing offer is
/// taken up, a peer says it published something or a device turns up.
const WATCH_MIN: Duration = Duration::from_secs(4);
const WATCH_MAX: Duration = Duration::from_secs(60);

/// Expired backup snapshots are looked for at most this often.
const BACKUP_UPKEEP_EVERY: i64 = 6 * 3600;

impl ServiceState {
    pub fn summary(&self) -> Value {
        let mut v = self.summary_base();
        // Added apart: one more key in the literal passes the macro's
        // recursion limit.
        v["forward"] = json!(self.forward);
        v["forward_text"] = json!(self.forward.as_ref().map(|f| f.describe()));
        v["mailbox"] = json!(self.mailbox);
        v["mailbox_text"] = json!(self
            .mailbox
            .as_ref()
            .filter(|m| !m.groups.is_empty())
            .map(|m| m.describe()));
        v
    }
    fn summary_base(&self) -> Value {
        json!({
            "running": self.running,
            "paused": self.paused,
            "interval_secs": self.interval_secs,
            "watching": self.watching.len(),
            "last_sync_utc": self.last_sync_utc,
            "last_result": self.last_result,
            "last_error": self.last_error,
            "next_sync_utc": self.next_sync_utc,
            "syncs": self.syncs,
            "policy_worst": self.policy_worst,
            "policies": self.policies,
            "p2p_listen": self.p2p_listen,
            "p2p_peers": self.p2p_peers,
            "p2p_lan_peers": self.p2p_lan_peers,
            "p2p_chunks": self.p2p_chunks,
            "disks": self.disks,
            "disk_suggest": self.disk_suggest,
            "p2p_nat": self.p2p_nat,
            "p2p_public": self.p2p_public,
            "p2p_reachable": self.p2p_reachable,
            "p2p_relays": self.p2p_relays,
            "p2p_paths": self.p2p_paths,
            "p2p_portmap": self.p2p_portmap,
            "p2p_portmap_text": self.p2p_portmap.describe(),
            "auto_verify": self.auto_verify,
            "auto_verify_text": self.auto_verify.as_ref().map(|v| v.describe()),
            "repair": self.repair,
            "repair_text": self.repair.as_ref().map(|r| r.describe()),
            "scrub": self.scrub,
            "scrub_text": self.scrub.as_ref().map(|r| r.describe()),
            "backup_upkeep_utc": self.backup_upkeep_utc,
            "backup_last": self.backup_last,
            "backup_errors": self.backup_errors,
            "ledger_health": self.ledger_health,
            "ledger_text": self.ledger_health.as_ref().filter(|h| !h.is_ok()).map(|h| h.describe()),
            "restic_text": self.restic_text,
            "drains": self.drains,
            "quota_full": self.quota_full,
            "paused_folders": self.paused_folders,
            "low_space": self.low_space,
            "move_jobs": self.move_jobs,
        })
    }
    /// Storage format 3: tell the page about folder requests that wait for
    /// an owner of this device (`folder.request`, and a notification). This
    /// only reads. Answering a request is up to a person, at the page or at
    /// a command line: nothing in this file approves, denies or grants.
    pub fn watch_folder_requests(&mut self, engine: &mut Engine) {
        match engine.f3_requests(None) {
            Ok(list) => {
                let mut now = std::collections::BTreeSet::new();
                for r in list {
                    let key = format!("{}/{}/{}", r.folder_id, r.device_id, r.fingerprint);
                    if !self.seen_requests.contains(&key) {
                        varsto_core::events::publish(
                            "folder.request",
                            json!({
                                "folder": r.folder,
                                "folder_id": r.folder_id,
                                "device": r.device,
                                "device_id": r.device_id,
                                "role": r.role_wanted,
                                "fingerprint": r.fingerprint,
                            }),
                        );
                        notify(
                            "Varsto folder request",
                            &format!("{} asks for folder {}", r.device, r.folder),
                        );
                    }
                    now.insert(key);
                }
                self.seen_requests = now;
            }
            Err(e) => log::debug!("folder requests not checked: {e:#}"),
        }
    }

    /// Rank the pool disks for docking next (`disk suggest`) and, at most
    /// once a week and unless turned off, remind of a disk that is away and
    /// overdue for a check.
    pub fn suggest_disks(&mut self, engine: &mut Engine) {
        match engine.disk_suggestions() {
            Ok(s) if s.ranked.is_empty() && s.attached.is_empty() && s.excluded.is_empty() => {
                self.disk_suggest = None;
            }
            Ok(s) => {
                if let Some(msg) = engine.disk_overdue_reminder(&s, varsto_core::util::now_utc()) {
                    log::info!("{msg}");
                    notify("Varsto disk check due", &msg);
                }
                self.disk_suggest = Some(s);
            }
            Err(e) => log::warn!("disk suggestion failed: {e:#}"),
        }
    }
    /// Continue the open move jobs that can go on: after a sync (jobs to
    /// ordinary storages) and whenever a disk of a target pool came or its
    /// space changed. A disk with room is used at once. Returns whether
    /// anything ran, so the disk suggestion is computed again.
    pub fn moves_if_due(&mut self, engine: &mut Engine, after_sync: bool) -> bool {
        if self.paused {
            return false;
        }
        let runs =
            engine.move_jobs_run_ready(after_sync, &varsto_core::engine::JobRunLimits::service());
        for r in &runs {
            let before = self.move_jobs.iter().find(|j| j.id == r.job.id);
            if r.report.bytes_done > 0 {
                log::info!(
                    "move job {}: {} moved of {}, {} left",
                    r.job.id,
                    varsto_core::util::human_bytes(r.job.bytes_done),
                    varsto_core::util::human_bytes(r.job.bytes_total),
                    varsto_core::util::human_bytes(r.job.bytes_remaining)
                );
            }
            match (&r.job.state, &r.job.waiting) {
                (varsto_core::staged_move::JobState::Done, _) => notify(
                    "Varsto",
                    &format!(
                        "The move of {} to {} is finished ({}).",
                        r.job.folder,
                        r.job.to,
                        varsto_core::util::human_bytes(r.job.bytes_done)
                    ),
                ),
                (varsto_core::staged_move::JobState::Open, Some(w))
                    if before.and_then(|b| b.waiting.as_ref()) != Some(w) =>
                {
                    notify("Varsto move", &format!("{}: {}", r.job.folder, w.text));
                }
                _ => {}
            }
        }
        self.move_jobs = varsto_core::staged_move::list_active(engine.home());
        !runs.is_empty()
    }
    /// Store the disk listing; log and notify when a disk appeared or went
    /// away, and ask for a sync when one appeared (pending files may be on it).
    /// Returns whether a disk appeared or went away.
    pub fn record_disks(&mut self, disks: Vec<varsto_core::pool::DiskStatus>) -> bool {
        let mut changed = false;
        // The first listing after start is the baseline: no notifications.
        let baseline = self.disks.is_empty();
        for d in &disks {
            let before = self
                .disks
                .iter()
                .find(|p| p.disk_id == d.disk_id)
                .map(|p| p.attached);
            let event = match (before, d.attached) {
                (Some(false), true) => Some("attached"),
                (None, true) if !baseline => Some("attached"),
                (Some(true), false) => Some("detached"),
                _ => None,
            };
            if let Some(ev) = event {
                changed = true;
                let msg = format!("{} {ev}", d.label);
                log::info!("disk {msg}");
                notify("Varsto disk", &msg);
                if ev == "attached" {
                    self.sync_requested = true;
                }
            }
        }
        changed |= disks.len() != self.disks.len();
        self.disks = disks;
        changed
    }
    /// Store policy reports; raise a desktop notification when a folder's
    /// state got worse (ok -> at risk -> violated) or a violation persists
    /// after an hour of silence.
    pub fn record_policies(&mut self, reports: Vec<varsto_core::policy::PolicyReport>) {
        use varsto_core::policy::PolicyState;
        let mut alerts = Vec::new();
        for r in &reports {
            let before = self
                .policies
                .iter()
                .find(|p| p.folder == r.folder)
                .map(|p| p.state);
            if before != Some(r.state) {
                varsto_core::events::publish(
                    "policy.changed",
                    json!({"folder": r.folder, "state": r.state}),
                );
            }
            let worse = match (before, r.state) {
                (None, PolicyState::Ok) | (None, PolicyState::Unknown) => false,
                (None, _) => true,
                (Some(b), n) => n > b && n != PolicyState::Unknown,
            };
            if worse {
                let detail = if r.reasons.is_empty() {
                    r.warnings.join("; ")
                } else {
                    r.reasons.join("; ")
                };
                alerts.push(format!(
                    "Folder {}: policy {} ({}). {}",
                    r.folder,
                    match r.state {
                        PolicyState::Violated => "violated",
                        PolicyState::AtRisk => "at risk",
                        _ => "unknown",
                    },
                    r.policy.describe(),
                    detail
                ));
            }
        }
        self.policy_worst = reports.iter().map(|r| r.state).max();
        self.policies = reports;
        for a in alerts {
            log::info!("{a}");
            notify("Varsto durability policy", &a);
        }
    }
    /// Run automatic verification when the schedule says it is due (called
    /// after a sync, so never while paused or locked) and keep its status.
    pub fn auto_verify_if_due(&mut self, engine: &mut Engine) {
        if engine.auto_verify_due(varsto_core::util::now_utc()) {
            match engine.auto_verify() {
                Ok(r) => {
                    log::info!(
                        "automatic verification: {} blocks verified, {} left for the next run",
                        r.blocks_verified,
                        r.left_for_next_run
                    );
                    if !r.corrupt.is_empty() || !r.missing.is_empty() {
                        let msg = format!(
                            "{} blocks do not match their hash and {} are missing on a storage; repairing them from other copies",
                            r.corrupt.len(),
                            r.missing.len()
                        );
                        log::info!("{msg}");
                        notify("Varsto verification", &msg);
                    }
                }
                Err(e) => log::warn!("automatic verification failed: {e:#}"),
            }
        }
        self.auto_verify = Some(engine.verify_status());
    }
    /// Run the bit-rot check when the schedule says it is due (after a sync
    /// and verification, before repair, which then takes what it queued);
    /// notify about damaged copies and files.
    pub fn scrub_if_due(&mut self, engine: &mut Engine) {
        if engine.scrub_due(varsto_core::util::now_utc()) {
            match engine.scrub(&varsto_core::engine::ScrubOptions::service()) {
                Ok(r) => {
                    log::info!(
                        "bit-rot check: {} objects, {} files and {} cached blocks checked, {} problems",
                        r.objects_checked,
                        r.files_checked,
                        r.cache_checked,
                        r.problems()
                    );
                    let copies = r.corrupt.len() + r.missing.len();
                    if copies > 0 {
                        let msg = format!(
                            "{copies} stored block cop{} damaged or missing; repairing them from other copies",
                            if copies == 1 { "y is" } else { "ies are" }
                        );
                        log::info!("{msg}");
                        notify("Varsto bit-rot check", &msg);
                    }
                    for d in &r.damaged_files {
                        let msg = match (&d.moved_to, d.restored) {
                            (Some(to), true) => format!(
                                "{} in {} had changed on disk without being edited; it was moved to {to} and the synced version restored",
                                d.path, d.folder
                            ),
                            _ => format!(
                                "{} in {} has changed on disk without being edited; no good copy could be fetched yet, it is left as it is",
                                d.path, d.folder
                            ),
                        };
                        log::info!("{msg}");
                        notify("Varsto bit-rot check", &msg);
                    }
                    for d in &r.disks_away {
                        log::warn!("disk not seen for long: {d}");
                    }
                }
                Err(e) => log::warn!("bit-rot check failed: {e:#}"),
            }
        }
        self.scrub = Some(engine.scrub_status());
    }
    /// Repair damaged copies that verification or fsck found (called after
    /// a sync and after verification), within the service's budget; notify
    /// once about every copy that could not be repaired.
    pub fn repair_if_due(&mut self, engine: &mut Engine) {
        if engine.repair_due(varsto_core::util::now_utc()) {
            match engine.repair(&varsto_core::engine::RepairOptions::service()) {
                Ok(r) => {
                    log::info!(
                        "automatic repair: {} copies repaired, {} could not be repaired, {} left for later",
                        r.repaired.len(),
                        r.unrepairable.len(),
                        r.left_for_next_run
                    );
                    if r.new_losses > 0 {
                        let mut why: Vec<&str> =
                            r.unrepairable.iter().map(|u| u.reason.as_str()).collect();
                        why.sort();
                        why.dedup();
                        let msg = format!(
                            "{} block cop{} could not be repaired: {}",
                            r.new_losses,
                            if r.new_losses == 1 { "y" } else { "ies" },
                            why.join("; ")
                        );
                        log::info!("{msg}");
                        notify("Varsto repair", &msg);
                    }
                }
                Err(e) => log::warn!("automatic repair failed: {e:#}"),
            }
        }
        self.repair = Some(engine.repair_status());
    }
    /// Forward other devices' blocks to this device's storages (section 70;
    /// called after a sync and repair), within the service's budget: 1 GiB
    /// a run, 256 MiB on a phone, or what `config.json` says.
    pub fn forward_if_due(&mut self, engine: &mut Engine) {
        if engine.forward_settings().enabled {
            let phone = std::env::var_os("VARSTO_MOBILE").is_some();
            match engine.forward(&engine.forward_service_options(phone)) {
                Ok(r) if r.blocks > 0 => log::info!("forwarding: {}", r.describe()),
                Ok(_) => {}
                Err(e) => log::warn!("forwarding failed: {e:#}"),
            }
        }
        self.forward = Some(engine.forward_status());
    }
    /// The mailbox for offline pool disks (section 78): after a sync, and
    /// whenever a pool disk came or went. Staged objects go first when the
    /// device needs its space back (checked every 30 seconds). Returns
    /// whether anything was staged or written.
    pub fn mailbox_if_due(&mut self, engine: &mut Engine, after_sync: bool) -> bool {
        let mut worked = false;
        if !self.paused && engine.mailbox_due(after_sync) {
            match engine.mailbox_run(&varsto_core::engine::MailboxOptions::service()) {
                Ok(r) => {
                    worked = r.staged + r.delivered > 0;
                    if r.delivered > 0 {
                        notify(
                            "Varsto mailbox",
                            &format!(
                                "Wrote {} staged object(s) ({}) to {}.",
                                r.delivered,
                                varsto_core::util::human_bytes(r.delivered_bytes),
                                r.delivered_to
                                    .keys()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        );
                    }
                }
                Err(e) => log::warn!("mailbox failed: {e:#}"),
            }
        } else {
            engine.mailbox_make_room();
        }
        self.mailbox = Some(engine.mailbox_status());
        worked
    }
    /// Before a sync: look after the ledger. A lost or damaged local ledger
    /// (or no ledger anywhere) is rebuilt from the storages at once, before
    /// anything is signed; the storages are asked at start and hourly
    /// whether they hold newer batches of this device (a copy restored from
    /// a backup), which the interface then offers to adopt.
    pub fn ledger_guard(&mut self, engine: &mut Engine) {
        let due = self
            .ledger_checked
            .is_none_or(|t| t.elapsed() >= LEDGER_CHECK_EVERY);
        if due {
            self.ledger_checked = Some(Instant::now());
            if let Err(e) = engine.ledger_check_storages() {
                log::warn!("ledger check failed: {e:#}");
            }
        }
        let health = engine.ledger_health();
        if health.automatic && health.state != "repairing" {
            self.ledger_rebuild(engine, &health);
        }
        self.set_ledger_health(engine.ledger_health());
    }

    /// Keep the ledger's state; a new state is an event.
    fn set_ledger_health(&mut self, h: varsto_core::engine::LedgerHealth) {
        // A new state, or new warnings (a storage that may be withholding or
        // rolling back batches, section 74), is an event.
        let changed = self
            .ledger_health
            .as_ref()
            .map(|o| (o.state.as_str(), &o.warnings))
            != Some((h.state.as_str(), &h.warnings));
        if changed {
            varsto_core::events::publish(
                "ledger.health",
                json!({"state": h.state, "text": h.describe(), "warnings": h.warnings}),
            );
            // A storage that may be withholding or rolling back batches:
            // notified once when the warning appears.
            let before: &[String] = self
                .ledger_health
                .as_ref()
                .map(|o| o.warnings.as_slice())
                .unwrap_or(&[]);
            for w in h.warnings.iter().filter(|w| !before.contains(w)) {
                if w.contains("withholding") {
                    notify("Varsto ledger", w);
                }
            }
        }
        self.ledger_health = Some(h);
    }

    /// After a sync: no ledger anywhere while folders hold files (checked
    /// at most hourly, and only without any claims) is rebuilt as well.
    pub fn ledger_after_sync(&mut self, engine: &mut Engine) {
        if engine.ledger_lost_everywhere(false).unwrap_or(false) {
            let health = engine.ledger_health();
            self.ledger_rebuild(engine, &health);
        }
        self.set_ledger_health(engine.ledger_health());
    }

    fn ledger_rebuild(&mut self, engine: &mut Engine, health: &varsto_core::engine::LedgerHealth) {
        log::info!("ledger: {}; rebuilding", health.describe());
        match engine.ledger_rebuild(&varsto_core::engine::LedgerRebuildOptions::service()) {
            Ok(r) => {
                let mut msg = if r.own_found_on_storages {
                    format!(
                        "This device's ledger was restored from the storages (up to #{})",
                        r.own_head_after
                    )
                } else {
                    "This device's ledger was started again".to_string()
                };
                if let Some(s) = &r.from_storage {
                    msg += &format!(
                        "; where the blocks are was rebuilt from the storages ({} copies recorded, {} damaged)",
                        s.claims_written, s.objects_corrupt
                    );
                }
                log::info!("{msg}");
                notify("Varsto ledger", &msg);
                self.ledger_failed = None;
            }
            Err(e) => {
                let msg = format!("The ledger could not be restored: {e:#}");
                log::warn!("{msg}");
                self.last_error = Some(msg.clone());
                if self.ledger_failed.as_deref() != Some(msg.as_str()) {
                    notify("Varsto ledger", &msg);
                }
                self.ledger_failed = Some(msg);
            }
        }
    }

    /// Run the drains this device drives (called after a sync, like
    /// repair), within the service's share per run and their daily
    /// budgets; notify once when one finishes or cannot go on.
    pub fn drains_if_due(&mut self, engine: &mut Engine) {
        for name in engine.drains_to_run() {
            match engine.drain_run(&name, &varsto_core::engine::DrainRunLimits::service()) {
                Ok(r) => {
                    if r.blocks_dropped > 0 || r.drained {
                        log::info!("drain: {}", r.summary);
                    }
                    if r.drained && self.drain_notified.insert(format!("done:{name}")) {
                        notify(
                            "Varsto",
                            &if r.removed {
                                format!("Storage {name} is empty and was removed.")
                            } else {
                                format!("Storage {name} is drained: it holds nothing Varsto needs.")
                            },
                        );
                    }
                    if r.blocks_dropped == 0
                        && r.blocks_copied == 0
                        && !r.drained
                        && !r.kept.is_empty()
                        && self.drain_notified.insert(format!("stuck:{name}"))
                    {
                        let msg = format!("Draining {name} cannot go on: {}", r.kept.join("; "));
                        log::warn!("{msg}");
                        notify("Varsto", &msg);
                    }
                    if r.blocks_dropped > 0 {
                        self.drain_notified.remove(&format!("stuck:{name}"));
                    }
                }
                Err(e) => log::warn!("draining {name} failed: {e:#}"),
            }
        }
        self.drains = engine.drain_statuses().unwrap_or_default();
    }
    /// Step the torrent jobs of this device (called after a sync); notify
    /// once when one waits for disk space and when one is complete.
    pub fn torrents_if_due(&mut self, engine: &mut Engine) {
        // Linux only (a local transmission-daemon); not on phones.
        if !cfg!(target_os = "linux") {
            return;
        }
        let mut changed = Vec::new();
        for j in engine.torrents_to_run() {
            let rpc = varsto_core::transmission::Rpc::new(
                engine.torrent_rpc(&j, &varsto_core::transmission::RpcSettings::default()),
            );
            match engine.torrent_tick(&j.hash, &rpc, &mut varsto_core::engine::SystemEnv, false) {
                Ok(Some(now)) if now.state != j.state => changed.push(now),
                Ok(_) => {}
                Err(e) => log::warn!("torrent job {}: {e:#}", j.short()),
            }
        }
        for j in changed {
            match j.state {
                varsto_core::engine::JobState::Complete => {
                    log::info!("torrent job {} is complete", j.short());
                    self.torrent_notified.remove(&j.hash);
                    notify(
                        "Varsto torrent",
                        &format!(
                            "{} is complete: every file is in folder {}.",
                            j.name, j.folder
                        ),
                    );
                }
                varsto_core::engine::JobState::WaitingSpace => {
                    if self.torrent_notified.insert(j.hash.clone()) {
                        notify(
                            "Varsto torrent",
                            &format!("{} waits for disk space: {}", j.name, j.text),
                        );
                    }
                }
                _ => {
                    self.torrent_notified.remove(&j.hash);
                }
            }
        }
    }
    /// Step the YouTube jobs of this device (called after a sync): yt-dlp
    /// runs between steps; notify once when one waits for disk space.
    /// Desktops only (yt-dlp is a desktop program).
    pub fn youtube_if_due(&mut self, engine: &mut Engine) {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return;
        }
        for j in engine.youtube_to_run() {
            let mut env = varsto_core::engine::ServiceYoutubeEnv;
            match engine.youtube_tick(&j.id, &mut env, false) {
                Ok(Some(now)) if now.state != j.state => {
                    if now.state == varsto_core::engine::YtState::WaitingSpace {
                        if self.youtube_notified.insert(now.id.clone()) {
                            notify(
                                "Varsto YouTube",
                                &format!("{} waits for disk space: {}", now.label, now.text),
                            );
                        }
                    } else {
                        self.youtube_notified.remove(&now.id);
                    }
                    log::info!("youtube job {}: {}", now.short(), now.line());
                }
                Ok(_) => {}
                Err(e) => log::warn!("youtube job {}: {e:#}", j.short()),
            }
        }
    }
    /// Take the scheduled backup snapshots that are due and, at most every
    /// six hours, expire old ones (called after a sync, like repair).
    pub fn backups_if_due(&mut self, engine: &mut Engine) {
        self.backup_snapshots_if_due(engine);
        let now = varsto_core::util::now_utc();
        if self
            .backup_upkeep_utc
            .is_none_or(|t| now - t >= BACKUP_UPKEEP_EVERY)
        {
            self.backup_upkeep_utc = Some(now);
            match engine.backup_upkeep() {
                Ok(r) => self.record_backup_upkeep(&r),
                Err(e) => log::warn!("backup expiry failed: {e:#}"),
            }
        }
    }
    /// Take the scheduled backup snapshots that are due (no expiry: also
    /// after a sync that could not reach every storage, spec section 79.3).
    pub fn backup_snapshots_if_due(&mut self, engine: &mut Engine) {
        let now = varsto_core::util::now_utc();
        for name in engine.backups_due(now) {
            match engine.take_snapshot(&name) {
                Ok(r) => {
                    let msg = format!(
                        "backup {name}: snapshot {} taken, {} files, {} blocks uploaded",
                        r.seq, r.files, r.chunks_uploaded
                    );
                    log::info!("{msg}");
                    varsto_core::events::publish(
                        "backup",
                        json!({"name": name, "ok": true, "text": msg}),
                    );
                    self.backup_last = Some(msg);
                    self.backup_errors.remove(&name);
                }
                Err(e) => {
                    let why = format!("{e:#}");
                    log::warn!("backup {name} failed: {why}");
                    varsto_core::events::publish(
                        "backup",
                        json!({"name": name, "ok": false, "text": why}),
                    );
                    // Once per new reason, not on every retry.
                    if self.backup_errors.get(&name) != Some(&why) {
                        notify("Varsto backup", &format!("{name}: {why}"));
                    }
                    self.backup_errors.insert(name, why);
                }
            }
        }
    }
    /// Backups with restic (called after a sync): notice a scheduled run
    /// that ended (notify when it failed), warn once a day while the last
    /// good snapshot is older than the schedule allows, and start a run when
    /// one is due. The run is a child process that talks to this service's
    /// API like `varsto restic run` would; the run lock in the device
    /// directory keeps it from running beside a run started by hand.
    pub fn restic_if_due(&mut self, engine: &Engine) {
        use varsto_core::restic::{Hold, ResticState};
        let home = engine.home().to_path_buf();
        if let Some(child) = self.restic_child.as_mut() {
            match child.try_wait() {
                Ok(None) => return,
                Ok(Some(status)) => {
                    self.restic_child = None;
                    varsto_core::events::publish(
                        "backup",
                        json!({"name": "restic", "ok": status.success()}),
                    );
                    if status.success() {
                        log::info!("scheduled restic backup done");
                    } else {
                        let why = ResticState::load(&home)
                            .last_run
                            .and_then(|r| r.message)
                            .and_then(|m| m.lines().next().map(str::to_string))
                            .unwrap_or_else(|| format!("exit status {status}; see restic-run.log"));
                        log::warn!("scheduled restic backup failed: {why}");
                        self.restic_not_before_utc =
                            varsto_core::util::now_utc() + varsto_core::restic::RETRY_SECS;
                        notify(
                            "Varsto restic backup",
                            &format!("The scheduled backup failed: {why}"),
                        );
                    }
                }
                Err(_) => self.restic_child = None,
            }
        }
        let Some(cfg) = engine.restic_config() else {
            self.restic_text = None;
            return;
        };
        let st = ResticState::load(&home);
        let now = varsto_core::util::now_utc();
        if st.stale(cfg, now) && self.restic_warned_utc.is_none_or(|t| now - t >= 86_400) {
            self.restic_warned_utc = Some(now);
            let msg = "The last good restic snapshot is older than its schedule allows; see `varsto restic status`";
            log::info!("{msg}");
            notify("Varsto restic backup", msg);
        }
        self.restic_text = Some(match (&st.last_success, st.next_run_utc(cfg)) {
            (Some(r), Some(n)) => format!(
                "restic: last snapshot {}, next run {}",
                varsto_core::util::format_date(r.started_utc),
                varsto_core::util::format_date(n)
            ),
            (Some(r), None) => format!(
                "restic: last snapshot {} (manual runs)",
                varsto_core::util::format_date(r.started_utc)
            ),
            (None, _) => "restic: no snapshot yet".to_string(),
        });
        if st.due(cfg, now)
            && now >= self.restic_not_before_utc
            && Hold::current(&home, now).is_none()
        {
            match varsto_core::restic::spawn_scheduled(&home) {
                Ok(c) => {
                    log::info!("scheduled restic backup started");
                    self.restic_child = Some(c);
                }
                Err(e) => log::warn!("could not start the restic backup: {e:#}"),
            }
        }
    }
    /// The trash upkeep, once a day (called after a sync): expire entries,
    /// move trashed blocks to the trash storage, drop what nothing uses.
    pub fn trash_if_due(&mut self, engine: &mut Engine) {
        if !engine.trash_upkeep_due(varsto_core::util::now_utc()) {
            return;
        }
        match engine.trash_upkeep() {
            Ok(r) => self.record_trash_upkeep(&r),
            Err(e) => log::warn!("trash upkeep failed: {e:#}"),
        }
    }
    pub fn record_trash_upkeep(&mut self, r: &varsto_core::engine::TrashUpkeepReport) {
        if r.expired
            + r.versions_dropped
            + r.blocks_dropped
            + r.blocks_moved
            + r.local_copies_removed
            > 0
        {
            log::info!(
                "trash: {} files expired, {} earlier versions let go, {} blocks deleted, {} blocks moved to the trash storage, {} local copies removed",
                r.expired, r.versions_dropped, r.blocks_dropped, r.blocks_moved, r.local_copies_removed
            );
        }
        for n in &r.notes {
            log::info!("trash: {n}");
        }
    }
    pub fn record_backup_upkeep(&mut self, r: &varsto_core::engine::ExpireReport) {
        self.backup_upkeep_utc = Some(varsto_core::util::now_utc());
        if r.snapshots_expired + r.objects_deleted > 0 || !r.backups_removed.is_empty() {
            log::info!(
                "backups: {} snapshots expired, {} blocks deleted, {} backups removed",
                r.snapshots_expired,
                r.objects_deleted,
                r.backups_removed.len()
            );
        }
    }
    pub fn request_sync(&mut self) {
        self.sync_requested = true;
    }
    /// Measure the places short of disk space again: tell the user once
    /// about each new one ("disk of folder X has 3 % free, below the 5 %
    /// limit; downloads paused"), and when one has room again, say so and
    /// sync at once, so what waited is fetched.
    pub fn check_space(&mut self) {
        for back in varsto_core::freespace::recheck() {
            let msg = format!(
                "disk of {} has room again; {} resume",
                back.place.label, back.place.stops
            );
            log::info!("{msg}");
            varsto_core::events::publish("space.ok", json!({"place": back.place.key, "text": msg}));
            self.low_space_notified.remove(&back.place.key);
            self.sync_requested = true;
        }
        let short = varsto_core::freespace::short_places();
        for l in &short {
            if self.low_space_notified.insert(l.place.key.clone()) {
                varsto_core::events::publish(
                    "space.low",
                    json!({"place": l.place.key, "text": l.text}),
                );
                log::warn!("{}", l.text);
                notify("Varsto disk space", &l.text);
            }
        }
        // A place no longer short without a recheck (a check found room).
        self.low_space_notified
            .retain(|k| short.iter().any(|l| &l.place.key == k));
        self.low_space = short;
    }
    pub fn record_sync(&mut self, reports: &[(PullReport, PushReport)]) {
        self.last_sync_utc = Some(varsto_core::util::now_utc());
        self.syncs += 1;
        let mut updated = 0;
        let mut deleted = 0;
        let mut conflicts = 0;
        let mut uploaded = 0;
        let mut unavailable = 0;
        let mut waiting = 0;
        let mut forked = false;
        let mut disks: Vec<String> = Vec::new();
        let mut full: Vec<String> = Vec::new();
        let mut paused = std::collections::BTreeMap::new();
        let mut left_out: std::collections::BTreeSet<String> = Default::default();
        // A read-only shared folder: local changes are not published.
        let mut kept_aside = 0;
        let mut not_synced: Vec<String> = Vec::new();
        for (pl, ps) in reports {
            kept_aside += pl.kept_aside.len() + ps.kept_aside.len();
            for f in &ps.storages_full {
                if !full.contains(f) {
                    full.push(f.clone());
                }
            }
            if let Some(p) = &pl.paused {
                if self.paused_folders.get(&p.folder) != Some(&p.message) {
                    log::warn!("{}", p.message);
                    varsto_core::events::publish(
                        "folder.paused",
                        json!({"folder": p.folder, "text": p.message}),
                    );
                    notify("Varsto folder paused", &p.message);
                }
                paused.insert(p.folder.clone(), p.message.clone());
            }
            // Counts only: names of files never go into events.
            if pl.files_updated > 0 {
                varsto_core::events::publish(
                    "files.new",
                    json!({"folder": pl.folder, "count": pl.files_updated}),
                );
            }
            if pl.files_deleted > 0 {
                varsto_core::events::publish(
                    "trash",
                    json!({"folder": pl.folder, "count": pl.files_deleted}),
                );
            }
            left_out.extend(ps.storages_unavailable.iter().cloned());
            // A folder that could not be synced (the round goes on with the
            // others and returns Ok) and the storages it could not reach.
            if let Some(err) = &pl.error {
                not_synced.push(format!("{}: {err}", pl.folder));
            }
            left_out.extend(pl.storages_down.iter().cloned());
            self.p2p_chunks += pl.chunks_from_peers;
            self.p2p_bytes += pl.bytes_from_peers;
            updated += pl.files_updated;
            deleted += pl.files_deleted;
            conflicts += pl.conflicts;
            uploaded += ps.chunks_uploaded;
            unavailable += pl.files_unavailable.len();
            waiting += pl.files_waiting_for_space;
            forked |= !pl.forked_devices.is_empty();
            for d in &pl.disks_needed {
                if !disks.contains(d) {
                    disks.push(d.clone());
                }
            }
        }
        // A sync of one folder says nothing about the others.
        if reports.len() == 1 {
            let name = &reports[0].0.folder;
            self.paused_folders.remove(name);
            self.paused_folders.extend(paused);
        } else {
            self.paused_folders = paused;
        }
        self.last_result = format!("{} folders: {updated} updated, {deleted} deleted, {conflicts} conflicts, {uploaded} chunks uploaded{}{}{}{}{}", reports.len(), if unavailable > 0 { format!(", {unavailable} unavailable") } else { String::new() }, if waiting > 0 { format!(", {waiting} waiting for disk space") } else { String::new() }, if disks.is_empty() { String::new() } else { format!(" (attach disk {})", disks.join(", ")) }, if forked { ", FORKED device" } else { "" }, if self.paused_folders.is_empty() { String::new() } else { format!(", {} paused", self.paused_folders.len()) });
        // A storage at its quota: blocks go elsewhere or wait here; say so once.
        for f in full.iter().filter(|f| !self.quota_full.contains(f)) {
            log::info!("{f}");
            notify("Varsto", &format!("{f}. New blocks go to the other storages or wait on this device; raise the quota or add a storage."));
        }
        if !full.is_empty() {
            self.last_result += &format!("; {}", full.join("; "));
        }
        self.quota_full = full;
        if kept_aside > 0 {
            self.last_result.push_str(&format!(
                "; read-only: your changes were not published ({kept_aside} {} kept aside)",
                if kept_aside == 1 { "file" } else { "files" }
            ));
        }
        // Partly done: say which folders were left out and why.
        self.last_error = if not_synced.is_empty() {
            None
        } else {
            self.last_result
                .push_str(&format!("; {} not synced", not_synced.len()));
            Some(format!("not synced: {}", not_synced.join("; ")))
        };
        for s in left_out.difference(&self.storage_problems) {
            varsto_core::events::publish(
                "storage.problem",
                json!({"storage": s, "text": format!("{s} was left out of the last sync (no disk attached, full, or no room)")}),
            );
        }
        for s in self.storage_problems.difference(&left_out) {
            varsto_core::events::publish("storage.ok", json!({ "storage": s }));
        }
        self.storage_problems = left_out;
        varsto_core::events::publish(
            "sync.finished",
            json!({
                "ok": true,
                "folders": reports.len(),
                "updated": updated,
                "deleted": deleted,
                "conflicts": conflicts,
                "uploaded": uploaded,
                "unavailable": unavailable,
                "waiting_for_space": waiting,
                "syncs": self.syncs,
            }),
        );
    }
}

/// What STUN and the self-probe learned about our place on the internet.
#[derive(Clone, Default)]
struct NatInfo {
    probe: varsto_core::p2p::stun::Probe,
    /// A public address led back to us, or the user configured one.
    reachable: bool,
    done: bool,
}

/// Peer-to-peer runtime of the service (storage format 3, `p2p::v3`): TLS
/// listener thread over TCP, QUIC node on the same port number, signed
/// beacon thread, NAT probe thread, relay thread, a shared snapshot of what
/// we serve, the directory of accepted peer records (the pins both
/// transports admit) and the peer table.
struct P2p {
    snapshot: Arc<Mutex<Option<Arc<varsto_core::p2p::Snapshot>>>>,
    lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>>,
    listen: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    quic: Option<Arc<varsto_core::p2p::quic::Node>>,
    /// The answering side of both transports: its directory decides which
    /// certificates the TLS handshakes admit.
    responder: Arc<varsto_core::p2p::v3::Responder>,
    /// The asking side, kept across table rebuilds (its TLS sessions).
    client: Arc<varsto_core::p2p::v3::Client>,
    /// K6 keys of the trusted full devices, for the beacon thread.
    beacon_keys: Arc<Mutex<BeaconKeys>>,
    /// Latest accepted records of the other devices, for the relay thread.
    records: Arc<Mutex<Vec<varsto_core::p2p::v3::PeerBody>>>,
    nat: Arc<Mutex<NatInfo>>,
    peers: Mutex<Option<Arc<varsto_core::p2p::Peers>>>,
    last_record: Mutex<Option<varsto_core::p2p::v3::PeerBody>>,
    last_publish: Mutex<Option<Instant>>,
    /// Set by the relay thread when a registration succeeded: the record
    /// should go out now, so peers learn `relay_via` without waiting for a sync.
    republish: Arc<std::sync::atomic::AtomicBool>,
    /// The service's traffic counters (`State::traffic`).
    traffic: Arc<varsto_core::p2p::Traffic>,
    /// Router port mapping: wanted (the setting), its status, and the
    /// thread that keeps it (joined on drop, after it removed the mappings).
    portmap_on: Arc<AtomicBool>,
    portmap: Arc<Mutex<varsto_core::p2p::portmap::PortMapStatus>>,
    portmap_thread: Option<std::thread::JoinHandle<()>>,
    /// Set by the beacon thread when a LAN address nobody had heard before
    /// appeared: the peer table is rebuilt at once.
    lan_new: Arc<AtomicBool>,
    /// This device has announced itself (record published, snapshot made,
    /// peers told) since the service started, before its first sync.
    announced: AtomicBool,
    /// When an unknown certificate last made us read the records again.
    knock_read: Mutex<Option<Instant>>,
    /// How long a knock waits after that read: `KNOCK_REREAD` while the
    /// storages answer, doubling up to `KNOCK_REREAD_MAX` while none does.
    knock_wait: Mutex<Duration>,
    /// When our record may be published again after a failed attempt, and
    /// the wait after the next failure.
    publish_retry: Mutex<(Option<Instant>, Duration)>,
}

/// An unknown certificate makes the records be read again at most this often.
const KNOCK_REREAD: Duration = Duration::from_secs(5);
/// ... and while no storage answers, at most this often.
const KNOCK_REREAD_MAX: Duration = Duration::from_secs(300);
/// A failed publish of our record is tried again after this long, doubling
/// up to `PUBLISH_RETRY_MAX`.
const PUBLISH_RETRY_MIN: Duration = Duration::from_secs(30);
const PUBLISH_RETRY_MAX: Duration = Duration::from_secs(600);

type BeaconKeys = std::collections::BTreeMap<[u8; 16], varsto_core::crypto::VerifyingKey>;

/// Router port mapping is on in the settings, and not switched off for this
/// process with `VARSTO_NO_PORT_MAPPING` (tests and throwaway services must
/// never touch the router of the network they run in).
/// The router mappings that go into our peer record: none until the
/// probe through the mapped UDP address came back to us.
fn published_mappings(
    pm: &varsto_core::p2p::portmap::PortMapStatus,
) -> (Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>) {
    if !pm.verified {
        return (Vec::new(), Vec::new());
    }
    (pm.tcp.into_iter().collect(), pm.udp.into_iter().collect())
}

fn port_mapping_wanted(cfg: &varsto_core::vault::P2pConfig) -> bool {
    cfg.port_mapping && std::env::var_os("VARSTO_NO_PORT_MAPPING").is_none()
}

/// STUN again this often, and at the earliest this soon after the last
/// probe when the node suspects that the mapping changed.
const NAT_REFRESH: Duration = Duration::from_secs(600);
const NAT_RECHECK_MIN: Duration = Duration::from_secs(30);
/// A failed relay registration is retried after this long, doubling each
/// time it fails again, up to `RELAY_RETRY_MAX`; a lost one is retried at once.
const RELAY_RETRY_MIN: Duration = Duration::from_secs(30);
const RELAY_RETRY_MAX: Duration = Duration::from_secs(300);
/// An unchanged record is still rewritten this often, so peers can tell a
/// device that is alive from one that stopped a month ago.
const RECORD_MAX_AGE: Duration = Duration::from_secs(3600);

impl P2p {
    fn start(state: &Shared) -> Option<P2p> {
        let (cfg, identity, responder, client, keys, traffic) = {
            let st = state.lock().unwrap();
            let e = st.engine.as_ref()?;
            let cfg = e.p2p_config();
            if !cfg.enabled {
                return None;
            }
            st.traffic.set_me(e.device_id(), e.own_device_name());
            let names = e.known_device_names();
            st.traffic
                .learn_names(names.iter().map(|(d, n)| (d, n.as_str())));
            varsto_core::activity::set_identity(e.device_id(), e.own_device_name());
            // Both transports run TLS with this certificate; without it
            // there is no peer-to-peer at all (no plain transport).
            let identity = match e.p2p_identity() {
                Ok(id) => id,
                Err(err) => {
                    log::warn!("p2p certificate unavailable, peer-to-peer off: {err:#}");
                    return None;
                }
            };
            let responder = e.p2p_responder(&identity);
            let client = e.p2p_client(identity.clone());
            (
                cfg,
                identity,
                responder,
                client,
                e.full_device_keys(),
                st.traffic.clone(),
            )
        };
        let tls = match varsto_core::p2p::v3::tls::TcpTls::new(&identity, responder.clone()) {
            Ok(t) => t,
            Err(e) => {
                log::warn!("p2p TLS setup failed: {e:#}");
                return None;
            }
        };
        // The configured port, or any free one when it is taken (another
        // vault directory on this computer, another program): peer-to-peer
        // with a changing port beats none.
        let bound = varsto_core::p2p::Server::bind(([0, 0, 0, 0], cfg.port).into(), tls.clone())
            .or_else(|e| {
                if cfg.port == 0 {
                    return Err(e);
                }
                log::warn!("p2p port {} is taken ({e:#}); using a free one", cfg.port);
                varsto_core::p2p::Server::bind(([0, 0, 0, 0], 0).into(), tls.clone())
            });
        let server = match bound {
            Ok(s) => s.with_traffic(traffic.clone()),
            Err(e) => {
                log::warn!("p2p listener failed: {e:#}");
                return None;
            }
        };
        let listen = server.addr;
        let snapshot: Arc<Mutex<Option<Arc<varsto_core::p2p::Snapshot>>>> =
            Arc::new(Mutex::new(None));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (snap2, stop2) = (snapshot.clone(), stop.clone());
        let _ = std::thread::Builder::new()
            .name("p2p-serve".into())
            .spawn(move || server.run(snap2, stop2));

        // QUIC on the same port number over UDP; without it only TCP works.
        let quic = match varsto_core::p2p::quic::Node::start_v3(
            ([0, 0, 0, 0], listen.port()).into(),
            identity.clone(),
            responder.clone(),
            snapshot.clone(),
            traffic.clone(),
        ) {
            Ok(n) => {
                n.start_keeper();
                Some(n)
            }
            Err(e) => {
                log::warn!("p2p QUIC listener failed, TCP only: {e:#}");
                None
            }
        };
        let cert_sha256 = identity.sha256.clone();

        let lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>> =
            Arc::new(Mutex::new(Vec::new()));
        let lan_new = Arc::new(AtomicBool::new(false));
        let beacon_keys: Arc<Mutex<BeaconKeys>> = Arc::new(Mutex::new(keys));
        let (lan2, stop3, lan_new2, keys2) = (
            lan_peers.clone(),
            stop.clone(),
            lan_new.clone(),
            beacon_keys.clone(),
        );
        let made = {
            let st = state.lock().unwrap();
            st.engine.as_ref().map(|e| e.p2p_beacon(listen.port()))
        };
        match made {
            Some(Ok(beacon)) => {
                let _ = std::thread::Builder::new()
                    .name("p2p-beacon".into())
                    .spawn(move || {
                        let mut heard: std::collections::BTreeMap<
                            std::net::SocketAddr,
                            (varsto_core::p2p::PeerAddr, Instant),
                        > = Default::default();
                        while !stop3.load(std::sync::atomic::Ordering::Relaxed) {
                            beacon.announce();
                            // Only beacons signed by a trusted full device
                            // count; an address only suggests where the
                            // pinned handshake then checks the device.
                            let key_of = |d: &[u8; 16]| keys2.lock().unwrap().get(d).cloned();
                            for p in beacon.listen(Duration::from_secs(5), &key_of) {
                                if heard.insert(p.addr, (p, Instant::now())).is_none() {
                                    lan_new2.store(true, Ordering::Relaxed);
                                }
                            }
                            heard.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(60));
                            *lan2.lock().unwrap() =
                                heard.values().map(|(p, _)| p.clone()).collect();
                        }
                    });
            }
            Some(Err(e)) => log::warn!("LAN beacon unavailable: {e:#}"),
            None => {}
        }

        let nat: Arc<Mutex<NatInfo>> = Arc::new(Mutex::new(NatInfo::default()));
        // The saved directory's records, so relays are known before any
        // storage answers.
        let records: Arc<Mutex<Vec<varsto_core::p2p::v3::PeerBody>>> = Arc::new(Mutex::new(
            responder.directory().bodies().cloned().collect(),
        ));
        let republish = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if let Some(node) = &quic {
            Self::spawn_nat_thread(node.clone(), cfg.clone(), nat.clone(), stop.clone());
            Self::spawn_relay_thread(
                node.clone(),
                records.clone(),
                nat.clone(),
                republish.clone(),
                stop.clone(),
            );
        }
        let portmap_on = Arc::new(AtomicBool::new(port_mapping_wanted(&cfg)));
        let portmap = Arc::new(Mutex::new(if port_mapping_wanted(&cfg) {
            varsto_core::p2p::portmap::PortMapStatus::default()
        } else {
            varsto_core::p2p::portmap::PortMapStatus::off()
        }));
        let portmap_thread = Self::spawn_portmap_thread(
            listen.port(),
            portmap_on.clone(),
            portmap.clone(),
            quic.clone(),
            republish.clone(),
            stop.clone(),
        );
        {
            let mut st = state.lock().unwrap();
            st.service.p2p_listen = Some(listen);
            st.service.p2p_cert_sha256 = cert_sha256;
        }
        println!(
            "Varsto p2p: listening on {listen} (TLS over TCP{}; encrypted blocks only; peers need a signed peer record)",
            if quic.is_some() { " and QUIC" } else { "" }
        );
        Some(P2p {
            snapshot,
            lan_peers,
            listen,
            stop,
            quic,
            responder,
            client,
            beacon_keys,
            records,
            nat,
            peers: Mutex::new(None),
            last_record: Mutex::new(None),
            last_publish: Mutex::new(None),
            republish,
            traffic,
            portmap_on,
            portmap,
            portmap_thread,
            lan_new,
            announced: AtomicBool::new(false),
            knock_read: Mutex::new(None),
            knock_wait: Mutex::new(KNOCK_REREAD),
            publish_retry: Mutex::new((None, PUBLISH_RETRY_MIN)),
        })
    }

    /// Ask every peer of the current table once, on a thread of its own, and
    /// show the paths that worked.
    fn probe_soon(&self, state: &Shared) {
        let Some(peers) = self.peers.lock().unwrap().clone() else {
            return;
        };
        let state = state.clone();
        let _ = std::thread::Builder::new()
            .name("p2p-probe".into())
            .spawn(move || {
                peers.probe();
                {
                    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                    st.service.p2p_paths = peers.status();
                }
                crate::readcache::invalidate_all();
                varsto_core::events::publish("peers.changed", json!({}));
            });
    }

    /// Did a certificate the directory does not name knock since the last
    /// read of the records, and is a read due (at most every
    /// `KNOCK_REREAD`)? A stranger knocking costs a listing of the peer
    /// records now and then, nothing more.
    fn take_unknown_knock(&self) -> bool {
        let wait = *self.knock_wait.lock().unwrap();
        let mut last = self.knock_read.lock().unwrap();
        if last.is_some_and(|t| t.elapsed() < wait) {
            return false;
        }
        if !self.responder.take_unknown() {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    /// Did a LAN device nobody had heard appear? Clears the flag.
    fn take_lan_new(&self) -> bool {
        self.lan_new.swap(false, Ordering::Relaxed)
    }

    /// Whether the accepted peer records on the storages differ from the
    /// ones the peer table was built from (a device published or changed
    /// its record): the table is then rebuilt.
    fn records_changed(&self, st: &State) -> bool {
        let Some(e) = st.engine.as_ref() else {
            return false;
        };
        let Ok(dir) = e.peer_directory() else {
            return false;
        };
        let known = self.records.lock().unwrap();
        let now: Vec<_> = dir.bodies().collect();
        now.len() != known.len()
            || now.iter().any(|r| {
                known
                    .iter()
                    .find(|k| k.device == r.device)
                    .is_none_or(|k| !k.same_as(r))
            })
    }

    /// Say who this device is before the first sync, which on a device that
    /// just joined can take a long time: publish the peer record, make
    /// the snapshot the others fetch from, and tell the peers to look.
    /// Once per service run.
    fn announce(&self, st: &mut State) {
        if self.announced.swap(true, Ordering::Relaxed) {
            return;
        }
        self.refresh_after_sync(st);
        if let Some(e) = st.engine.as_ref() {
            e.notify_peers_changed();
        }
    }

    /// Keep the peer-to-peer port forwarded on the home router (TCP and
    /// UDP) while the setting is on: map at start, renew at half the lease,
    /// map again after a network change, try again every half hour when no
    /// router offered any of the protocols, and remove the mappings when
    /// the setting goes off or the service stops. Silent unless
    /// `VARSTO_P2P_DEBUG` is set: no router support is the common case.
    fn spawn_portmap_thread(
        port: u16,
        on: Arc<AtomicBool>,
        status: Arc<Mutex<varsto_core::p2p::portmap::PortMapStatus>>,
        node: Option<Arc<varsto_core::p2p::quic::Node>>,
        republish: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    ) -> Option<std::thread::JoinHandle<()>> {
        use varsto_core::p2p::portmap::{Options, PortMapStatus, PortMapper, Proto};
        std::thread::Builder::new()
            .name("p2p-portmap".into())
            .spawn(move || {
                let mut mapper: Option<PortMapper> = None;
                // The local address the mappings point at; another one means
                // another network, and everything is mapped again.
                let mut local = varsto_core::p2p::local_ipv4_addrs();
                let mut next_local_check = Instant::now();
                while !stop.load(Ordering::Relaxed) && !QUIT.load(Ordering::Relaxed) {
                    if !on.load(Ordering::Relaxed) {
                        if let Some(mut m) = mapper.take() {
                            m.remove_all();
                            republish.store(true, Ordering::Relaxed);
                        }
                        *status.lock().unwrap() = PortMapStatus::off();
                        Self::pause(&stop, Duration::from_secs(1));
                        continue;
                    }
                    let now = Instant::now();
                    if now >= next_local_check {
                        next_local_check = now + Duration::from_secs(60);
                        let current = varsto_core::p2p::local_ipv4_addrs();
                        if current != local {
                            local = current;
                            if let Some(mut m) = mapper.take() {
                                m.remove_all();
                                republish.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    let m = mapper.get_or_insert_with(|| PortMapper::new(port, Options::system()));
                    if m.mappings().is_empty() && m.next_due().is_none_or(|t| now >= t) {
                        // Ask the routing table again: the gateway may be another.
                        m.set_options(Options::system());
                    }
                    if m.tick(now) {
                        // Does the mapped UDP address lead back to us? (A
                        // router may not loop it back; then this stays false.)
                        let verified = match (&node, m.external(Proto::Udp)) {
                            (Some(n), Some(a)) => n.probe_self(a),
                            _ => false,
                        };
                        m.set_verified(verified);
                        republish.store(true, Ordering::Relaxed);
                    }
                    *status.lock().unwrap() = m.status();
                    Self::pause(&stop, Duration::from_secs(1));
                }
                if let Some(mut m) = mapper {
                    m.remove_all();
                }
                *status.lock().unwrap() = PortMapStatus::off();
            })
            .ok()
    }

    /// The router port mapping setting changed while running.
    fn set_port_mapping(&self, on: bool) {
        self.portmap_on.store(
            on && std::env::var_os("VARSTO_NO_PORT_MAPPING").is_none(),
            Ordering::Relaxed,
        );
    }

    fn portmap_status(&self) -> varsto_core::p2p::portmap::PortMapStatus {
        self.portmap.lock().unwrap().clone()
    }

    /// Sleep in half-second steps so a stop request is honoured promptly.
    fn pause(stop: &std::sync::atomic::AtomicBool, dur: Duration) {
        let until = Instant::now() + dur;
        while Instant::now() < until && !stop.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// STUN at start and every ten minutes, then ask our own public address
    /// whether it leads back to us.
    fn spawn_nat_thread(
        node: Arc<varsto_core::p2p::quic::Node>,
        cfg: varsto_core::vault::P2pConfig,
        nat: Arc<Mutex<NatInfo>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let _ = std::thread::Builder::new()
            .name("p2p-nat".into())
            .spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let probe = node.stun(&cfg.stun, Duration::from_millis(1500));
                    let last_probe = Instant::now();
                    let reachable = !cfg.public_addrs.is_empty()
                        || probe.public_addrs().iter().any(|a| node.probe_self(*a));
                    log::debug!(
                        "stun {:?} nat {} reachable {reachable}",
                        probe.mapped,
                        probe.nat.as_str()
                    );
                    *nat.lock().unwrap() = NatInfo {
                        probe,
                        reachable,
                        done: true,
                    };
                    // Every ten minutes, or sooner when the node suspects the
                    // NAT mapping changed (a failed punched connect, a pause).
                    let until = Instant::now() + NAT_REFRESH;
                    while Instant::now() < until && !stop.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if node.take_restun() && last_probe.elapsed() >= NAT_RECHECK_MIN {
                            log::info!("asking STUN again (the NAT mapping may have changed)");
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            });
    }

    /// Keep a registration with every reachable device of the vault while we
    /// are not reachable ourselves. A failed attempt is retried after 30 s,
    /// then with doubling waits up to five minutes; a lost registration is
    /// retried at once. A success asks the main loop to republish our record.
    fn spawn_relay_thread(
        node: Arc<varsto_core::p2p::quic::Node>,
        records: Arc<Mutex<Vec<varsto_core::p2p::v3::PeerBody>>>,
        nat: Arc<Mutex<NatInfo>>,
        republish: Arc<std::sync::atomic::AtomicBool>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let _ = std::thread::Builder::new()
            .name("p2p-relay".into())
            .spawn(move || {
                // Per relay: when to try again and the wait to use after the
                // next failure. Absent means "try at once".
                let mut backoff: std::collections::BTreeMap<
                    varsto_core::ids::DeviceId,
                    (Instant, Duration),
                > = Default::default();
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let info = nat.lock().unwrap().clone();
                    let relays: Vec<varsto_core::p2p::PeerInfo> = records
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| r.reachable && r.cert_sha256 != [0u8; 32])
                        .map(|r| r.info())
                        .collect();
                    if info.done && !info.reachable {
                        let live = node.registered_relays();
                        for r in relays {
                            if live.contains(&r.device)
                                || backoff
                                    .get(&r.device)
                                    .is_some_and(|(next, _)| Instant::now() < *next)
                            {
                                continue;
                            }
                            match node.register_with(&r.device, &r.udp, &r.cert_sha256) {
                                Ok(()) => {
                                    println!("Varsto p2p: registered with relay {}", r.name);
                                    backoff.remove(&r.device);
                                    republish.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                                Err(e) => {
                                    let wait = backoff
                                        .get(&r.device)
                                        .map(|(_, w)| *w)
                                        .unwrap_or(RELAY_RETRY_MIN);
                                    log::warn!(
                                        "relay registration with {} failed: {e:#}; next try in {} s",
                                        r.name,
                                        wait.as_secs()
                                    );
                                    backoff.insert(
                                        r.device.clone(),
                                        (
                                            Instant::now() + wait,
                                            (wait * 2).min(RELAY_RETRY_MAX),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Self::pause(&stop, Duration::from_secs(5));
                }
            });
    }

    /// Did a relay registration just succeed? Clears the flag.
    fn take_republish(&self) -> bool {
        self.republish
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// Read the directory (accepted peer records of trusted full devices)
    /// again, hand it to the answering side of both transports, merge the
    /// LAN peers heard in signed beacons, and hand the table to the engine.
    fn refresh_before_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_mut() else { return };
        let mut lan = self.lan_peers.lock().unwrap().clone();
        // A removed device may still send beacons: it is no peer.
        lan.retain(|p| !e.is_revoked(&p.device));
        *self.beacon_keys.lock().unwrap() = e.full_device_keys();
        // A storage hiccup must not empty the directory: that would stop
        // the keeper's punches (so NAT mappings lapse and peers' punches
        // steal our port) and make both servers refuse every peer's
        // certificate. The read starts from the directory saved here; when
        // no storage answered, the entries in use are kept as well.
        let (mut dir, read) = e.peer_directory_read();
        let mut wait = self.knock_wait.lock().unwrap();
        if read.ok() {
            *wait = KNOCK_REREAD;
        } else {
            log::warn!(
                "peer records: none of {} storages answered; keeping the known ones",
                read.storages
            );
            dir.merge(self.responder.directory().as_ref().clone());
            // Knocks do not make us list a dead storage every few seconds.
            *wait = (*wait * 2).min(KNOCK_REREAD_MAX);
        }
        drop(wait);
        self.responder.set_directory(dir.clone());
        let mut flat = lan.clone();
        for i in dir.infos() {
            for addr in &i.tcp {
                if !flat.iter().any(|p| p.addr == *addr) {
                    flat.push(varsto_core::p2p::PeerAddr {
                        device: i.device.clone(),
                        addr: *addr,
                        name: i.name.clone(),
                    });
                }
            }
        }
        st.service.p2p_lan_peers = lan.len();
        st.service.p2p_peers = flat;
        *self.records.lock().unwrap() = dir.bodies().cloned().collect();
        let p = Arc::new(
            varsto_core::p2p::Peers::build_v3(self.client.clone(), &dir, &lan, self.quic.clone())
                .with_traffic(self.traffic.clone()),
        );
        let mut slot = self.peers.lock().unwrap();
        if let Some(prev) = slot.as_ref() {
            p.inherit(prev);
        }
        // The same table answers who is doing what (`/api/activity`).
        varsto_core::activity::global().set_peers(Some(p.clone()), e.activity_audience());
        *slot = Some(p.clone());
        drop(slot);
        e.set_peers(Some(p));
        e.set_snapshot_sink(Some(self.snapshot.clone()));
    }

    /// Refresh what we serve, read the peer records again (the pull read
    /// the membership: devices added or removed change whom the servers
    /// admit), show the paths in use, and re-publish our peer record when
    /// it changed (or once an hour regardless).
    fn refresh_after_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_ref() else { return };
        match e.peer_snapshot() {
            Ok(s) => *self.snapshot.lock().unwrap() = Some(Arc::new(s)),
            Err(err) => log::warn!("p2p snapshot failed: {err:#}"),
        }
        if self.records_changed(st) {
            self.refresh_before_sync(st);
        }
        self.publish_record(st);
    }

    /// Show the NAT state and the paths in use, and re-publish our peer
    /// record when it changed (or once an hour regardless). Also called as
    /// soon as a relay registration succeeds, so `relay_via` spreads quickly.
    fn publish_record(&self, st: &mut State) {
        let Some(e) = st.engine.as_ref() else { return };
        let info = self.nat.lock().unwrap().clone();
        let mut rec = e.peer_body(self.listen.port());
        rec.udp_public = info.probe.public_addrs();
        rec.udp_public
            .truncate(varsto_core::p2p::v3::peer::MAX_ADDRS);
        rec.nat = info.probe.nat;
        rec.reachable |= info.reachable;
        // The router forwards our port: the most direct way in from outside.
        // A mapping is announced only after our own probe through its UDP
        // address reached us: an address that does not lead back is noise at
        // best and a way to point peers elsewhere at worst.
        let pm = self.portmap_status();
        let (mapped_tcp, mapped_udp) = published_mappings(&pm);
        rec.mapped_tcp = mapped_tcp;
        rec.mapped_udp = mapped_udp;
        rec.reachable |= pm.verified;
        st.service.p2p_portmap = pm;
        let relays: Vec<varsto_core::ids::DeviceId> = self
            .quic
            .as_ref()
            .map(|n| n.registered_relays())
            .unwrap_or_default();
        rec.relay_via = relays
            .iter()
            .filter_map(varsto_core::record::id16)
            .take(varsto_core::p2p::v3::peer::MAX_RELAYS)
            .collect();
        let records = self.records.lock().unwrap();
        st.service.p2p_relays = relays
            .iter()
            .map(|d| {
                let id = varsto_core::record::id16(d);
                records
                    .iter()
                    .find(|r| Some(r.device) == id)
                    .map(|r| r.name.clone())
                    .unwrap_or_else(|| d.short().to_string())
            })
            .collect();
        drop(records);
        st.service.p2p_nat = rec.nat;
        st.service.p2p_public = rec.udp_public.clone();
        st.service.p2p_reachable = rec.reachable;
        if let Some(p) = self.peers.lock().unwrap().as_ref() {
            st.service.p2p_paths = p.status();
        }
        let mut last = self.last_publish.lock().unwrap();
        let mut last_rec = self.last_record.lock().unwrap();
        let changed = last_rec.as_ref().is_none_or(|r| !r.same_as(&rec));
        let mut retry = self.publish_retry.lock().unwrap();
        let resting = retry.0.is_some_and(|t| Instant::now() < t);
        if (changed || last.is_none_or(|t| t.elapsed() > RECORD_MAX_AGE)) && !resting {
            // Only a publish that every storage took counts as done: a
            // failed one is tried again (with a growing wait), not an hour
            // later.
            match e.publish_peer_body(&mut rec) {
                Ok(_) => {
                    *last = Some(Instant::now());
                    *last_rec = Some(rec);
                    *retry = (None, PUBLISH_RETRY_MIN);
                }
                Err(err) => {
                    let wait = retry.1;
                    log::warn!(
                        "p2p record publish failed: {err:#}; trying again in {} s",
                        wait.as_secs()
                    );
                    *retry = (
                        Some(Instant::now() + wait),
                        (wait * 2).min(PUBLISH_RETRY_MAX),
                    );
                }
            }
        }
    }
}

impl Drop for P2p {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Wait for the router mappings to be removed (a few seconds at most:
        // every request has a short timeout).
        if let Some(t) = self.portmap_thread.take() {
            let _ = t.join();
        }
    }
}

/// Best-effort desktop notification; silent where no notifier exists.
pub fn notify(title: &str, body: &str) {
    varsto_core::events::publish("notification", json!({"title": title, "body": body}));
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args(["--app-name=Varsto", title, body])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "'"),
            title.replace('"', "'")
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        windows_toast(title, body);
    }
}

/// A toast notification through PowerShell, which every Windows 10/11 has.
/// The text goes in through the environment, never into the script. The
/// setup program registers the sender name "Varsto" (with the icon); without
/// it the toast comes from Windows PowerShell.
#[cfg(target_os = "windows")]
fn windows_toast(title: &str, body: &str) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SCRIPT: &str = r#"
$id = 'Varsto.Notifier'
if (-not (Test-Path "HKCU:\Software\Classes\AppUserModelId\$id")) { $id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe' }
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$t = $x.GetElementsByTagName('text')
$t.Item(0).AppendChild($x.CreateTextNode($env:VARSTO_NOTE_TITLE)) | Out-Null
$t.Item(1).AppendChild($x.CreateTextNode($env:VARSTO_NOTE_BODY)) | Out-Null
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"#;
    let _ = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            SCRIPT,
        ])
        .env("VARSTO_NOTE_TITLE", title)
        .env("VARSTO_NOTE_BODY", body)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

pub fn service_file(home: &Path) -> PathBuf {
    home.join("service.json")
}

pub fn read_service_file(home: &Path) -> Option<ServiceFile> {
    let s = fs::read(service_file(home)).ok()?;
    let f: ServiceFile = serde_json::from_slice(&s).ok()?;
    varsto_core::logging::register_secret(&f.token);
    Some(f)
}

fn write_service_file(home: &Path, f: &ServiceFile) -> Result<()> {
    varsto_core::util::private_dir(home)?;
    varsto_core::util::write_atomic(&service_file(home), &serde_json::to_vec_pretty(f)?)?;
    Ok(())
}

pub fn request_quit(_state: &Shared) {
    QUIT.store(true, Ordering::SeqCst);
}

/// Stop the service loop (a termination signal): it ends within a second
/// unless a sync holds it, removing the router port mappings on the way.
pub fn quit() {
    QUIT.store(true, Ordering::SeqCst);
}

/// Passphrase from the environment or the macOS login keychain.
pub fn passphrase_from_system(home: &Path) -> Option<String> {
    if let Ok(p) = std::env::var("VARSTO_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    // systemd-creds, the kernel keyring, the desktop keyring or the macOS
    // login keychain, whichever `remember` used (see `remember.rs`).
    crate::remember::load(home)
}

/// Whether the desktop keyring's default collection is locked (Linux,
/// Secret Service over D-Bus): `Some(true)` locked, `Some(false)` open,
/// `None` when it cannot be told (no session bus, no keyring, no busctl).
/// Storing into a locked keyring opens an unlock window, which cannot
/// appear without a graphical session.
#[cfg(target_os = "linux")]
pub fn keyring_locked() -> Option<bool> {
    let out = std::process::Command::new("busctl")
        .args([
            "--user",
            "--timeout=3",
            "get-property",
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets/aliases/default",
            "org.freedesktop.Secret.Collection",
            "Locked",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "b true" => Some(true),
        "b false" => Some(false),
        _ => None,
    }
}

/// A graphical session where an unlock window can appear.
#[cfg(target_os = "linux")]
pub fn has_display() -> bool {
    std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

/// Keep the passphrase where the background service finds it after a
/// restart, in the first store that works (see `remember.rs`); the text
/// names the store used.
pub fn remember_passphrase(home: &Path, pass: &str) -> Result<String> {
    crate::remember::remember(home, pass)
}

/// Remove the remembered passphrase from every store.
pub fn forget_passphrase(home: &Path) -> Result<String> {
    crate::remember::forget(home)
}

/// Unlock a running service that is locked, with a passphrase the command
/// line already verified. Returns whether it did.
pub fn unlock_running(home: &Path, pass: &str) -> bool {
    let Some((f, _)) = status(home) else {
        return false;
    };
    let base = format!("http://127.0.0.1:{}", f.port);
    let locked = http_get(&format!("{base}/api/state"), &f.token)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .is_some_and(|v| {
            v.get("has_vault") == Some(&json!(true)) && v.get("unlocked") == Some(&json!(false))
        });
    locked
        && http_post(
            &format!("{base}/api/unlock"),
            &f.token,
            &json!({ "passphrase": pass }).to_string(),
        )
        .is_ok()
}

pub struct Options {
    pub home: PathBuf,
    pub port: u16,
    pub interval_secs: u64,
    pub open_browser: bool,
}

/// Run the service until quit. Blocks the calling thread.
pub fn run(opts: Options) -> Result<()> {
    // One service per home: a second one (the app and the launch agent both
    // starting one) would fight over the service file and the folders.
    if let Some((f, _)) = status(&opts.home) {
        if f.pid != std::process::id() {
            println!(
                "a Varsto service (pid {}) already runs for {}; not starting another",
                f.pid,
                opts.home.display()
            );
            return Ok(());
        }
    }
    let (server, bound) = desktop::bind(opts.port)?;
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    varsto_core::logging::register_secret(&token);
    let port: u16 = bound.rsplit(':').next().unwrap().parse()?;
    let url = format!("http://{bound}/");
    fs::create_dir_all(&opts.home)?;
    write_service_file(
        &opts.home,
        &ServiceFile {
            pid: std::process::id(),
            port,
            token: token.clone(),
            started_utc: varsto_core::util::now_utc(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )?;

    let mut engine = None;
    if opts.home.join("vault.json").exists() {
        if let Some(p) = passphrase_from_system(&opts.home) {
            match Engine::open(&opts.home, &p) {
                Ok(e) => engine = Some(e),
                Err(e) => log::warn!("unlock with the stored passphrase failed: {e:#}"),
            }
        }
        if engine.is_none() {
            // Locked at start (a phone killed without locking): drop plain copies
            // left in folders kept "encrypted on this device" by older versions.
            match Engine::wipe_encrypted_folders_locked(&opts.home) {
                Ok(n) if n > 0 => {
                    log::info!("removed {n} plaintext copies of encrypted-here folders")
                }
                Ok(_) => {}
                Err(e) => log::warn!("could not clean encrypted-here folders: {e:#}"),
            }
        }
    }
    // Decrypted copies handed to other apps last time (the app may have been
    // killed before it locked) go at every start.
    let exports = Engine::clear_exports(&opts.home);
    if exports > 0 {
        log::info!("removed {exports} decrypted copies made for other apps");
    }
    let state: Shared = Arc::new(Mutex::new(State {
        home: opts.home.clone(),
        engine,
        token,
        bound: bound.clone(),
        traffic: Arc::default(),
        service: ServiceState {
            running: true,
            interval_secs: opts.interval_secs.max(15),
            sync_requested: true,
            folders_changed: true,
            ..Default::default()
        },
        pair: None,
        link: None,
        busy: None,
    }));
    // The token is not printed: stdout ends up in service.log under the
    // tray and launchd. `varsto desktop` reads it from the service file.
    println!("Varsto service: {url} (open it with `varsto desktop`)");
    println!(
        "Only this computer can reach it. Service file: {}",
        service_file(&opts.home).display()
    );
    if opts.open_browser {
        desktop::open_in_browser(&format!("{url}?boot={}", desktop::mint_boot_code()));
    }
    let http_state = state.clone();
    let server = Arc::new(server);
    let http_server = server.clone();
    std::thread::Builder::new()
        .name("http".into())
        .spawn(move || desktop::serve_arc(http_server, http_state))?;
    // Looks for a new version once a day (the `auto-update` setting) and
    // installs it where this copy can; the signature chain of `varsto update`
    // is the only way in.
    {
        let restart_state = state.clone();
        crate::update::spawn_auto_update(opts.home.clone(), notify, move |_| {
            restart_state.lock().unwrap().service.restart_requested = true
        });
    }

    // Peer-to-peer: serve our chunks, announce on the LAN, learn peers.
    // Peer-to-peer starts as soon as the vault is open and the setting is on: a
    // phone or a tray app starts locked, so the node often comes up only after
    // the user unlocks; a failed start is retried every 30 seconds.
    let mut p2p = P2p::start(&state);
    let mut p2p_retry_at = Instant::now();
    // Whether the vault was open at the last look, while p2p is not running.
    let mut p2p_unlocked = state.lock().unwrap().engine.is_some();
    // Asks the peers what they are doing, only while someone watches.
    let activity_stop = Arc::new(AtomicBool::new(false));
    varsto_core::activity::global().spawn_poller(activity_stop.clone());
    // Tasks, transfers and peers as events while a page listens.
    crate::sse::spawn_sampler(state.lock().unwrap().traffic.clone(), activity_stop.clone());
    // Torrent and YouTube jobs move on between syncs too, and pages hear
    // of every change of the import list.
    crate::import_jobs::spawn_driver(state.clone(), activity_stop.clone());

    // File watcher: sends a signal on any change under an attached folder.
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = make_watcher(tx)?;
    let mut watched: Vec<PathBuf> = Vec::new();
    let mut last_change: Option<Instant> = None;
    let mut next_sync = Instant::now();
    // Folders known at the last sync; a new one is announced to the peers.
    let mut known_folders = usize::MAX;
    let debounce = Duration::from_secs(2);
    let disk_check_every = Duration::from_secs(30);
    let mut next_disk_check = Instant::now();
    // Syncs run through the local API (`POST /api/sync`, the CLI) change what
    // we can serve; the snapshot follows them as it follows our own syncs.
    let mut snapshot_syncs = 0u64;
    // The local files another process may change under us (the command line
    // attaching a folder or adding a storage): reloaded when they change.
    let local_files = [opts.home.join("config.json"), opts.home.join("keyring.enc")];
    let stamp = |paths: &[PathBuf]| -> Vec<Option<std::time::SystemTime>> {
        paths
            .iter()
            .map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
            .collect()
    };
    let mut local_stamp = stamp(&local_files);
    // Looking for new devices between the syncs (see `WATCH_MIN`).
    let mut watch_every = WATCH_MIN;
    let mut next_watch = Instant::now() + WATCH_MIN;
    let mut was_unlocked = false;
    let mut paired_seen: Option<String> = None;

    while !QUIT.load(Ordering::SeqCst) {
        // Removable disks: notice what was attached or taken away.
        if Instant::now() >= next_disk_check {
            next_disk_check = Instant::now() + disk_check_every;
            // With the engine out of the state (the mailbox and the moves
            // may wait on disks and storages): the interface answers meanwhile.
            let mut st = desktop::checkout(&state, "disk check");
            // Space back where downloads waited: sync now.
            st.service.check_space();
            if let Some(e) = st.engine.as_ref() {
                // Who this device is in `/api/activity` (also while p2p is off).
                varsto_core::activity::set_identity(e.device_id(), e.own_device_name());
            }
            let listed = st.engine.as_mut().map(|e| e.disks());
            match listed {
                Some(Ok(disks)) => {
                    let first = st.service.disk_suggest.is_none() && !disks.is_empty();
                    if st.service.record_disks(disks) || first {
                        let st = &mut *st;
                        if let Some(e) = st.engine.as_mut() {
                            st.service.suggest_disks(e);
                        }
                    }
                }
                Some(Err(e)) => log::warn!("disk check failed: {e:#}"),
                None => {}
            }
            // A disk came, or one has room it had not: the mailbox stages
            // from it or writes to it, then the moves go on (a move reads
            // what the mailbox staged).
            let st = &mut *st;
            if let Some(e) = st.engine.as_mut() {
                let staged = st.service.mailbox_if_due(e, false);
                let ran = st.service.moves_if_due(e, false) || staged;
                st.service.move_jobs = varsto_core::staged_move::list_active(e.home());
                if ran {
                    st.service.suggest_disks(e);
                }
            }
        }
        // Changed by another process: read them again, watch what is now
        // attached and sync. (Our own writes land here too, harmlessly.)
        let now_stamp = stamp(&local_files);
        if now_stamp != local_stamp {
            local_stamp = now_stamp;
            log::debug!("local configuration changed on disk; reloading");
            let mut st = desktop::lock_idle(&state);
            let reloaded = st.engine.as_mut().map(|e| e.reload_local());
            if reloaded.as_ref().is_some_and(|r| r.is_ok()) {
                varsto_core::events::publish("config.changed", json!({"source": "file"}));
            }
            match reloaded {
                Some(Ok(true)) => {
                    st.service.folders_changed = true;
                    st.service.request_sync();
                }
                Some(Ok(false)) => {}
                Some(Err(e)) => {
                    log::warn!("reloading the local configuration failed: {e:#}")
                }
                None => {}
            }
        }
        // Drain change notifications.
        while rx.try_recv().is_ok() {
            last_change = Some(Instant::now());
        }
        // Re-evaluate watched folders when the engine or its folders changed.
        {
            let mut st = desktop::lock_idle(&state);
            if st.service.folders_changed {
                let paths: Vec<PathBuf> = st
                    .engine
                    .as_ref()
                    .map(|e| e.folders().into_iter().filter_map(|(_, m)| m).collect())
                    .unwrap_or_default();
                if paths != watched {
                    for p in &watched {
                        let _ = watcher.unwatch(p);
                    }
                    for p in &paths {
                        if let Err(e) = watcher.watch(p, notify::RecursiveMode::Recursive) {
                            log::warn!("cannot watch {}: {e}", p.display());
                        }
                    }
                    watched = paths;
                }
                st.service.watching = watched.clone();
                st.service.folders_changed = false;
            }
        }
        // Turned off while running: stop serving and fetching from peers.
        if p2p.is_some() {
            let (wanted, mapping) = {
                let st = desktop::lock_idle(&state);
                st.engine
                    .as_ref()
                    .map(|e| {
                        let c = e.p2p_config();
                        (c.enabled, c.port_mapping)
                    })
                    .unwrap_or((true, true))
            };
            if let Some(p) = &p2p {
                p.set_port_mapping(mapping);
                desktop::lock_idle(&state).service.p2p_portmap = p.portmap_status();
            }
            if !wanted {
                if let Some(p) = p2p.take() {
                    p.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let mut st = desktop::lock_idle(&state);
                if let Some(e) = st.engine.as_mut() {
                    e.set_peers(None);
                    e.set_snapshot_sink(None);
                }
                st.service.p2p_listen = None;
                st.service.p2p_portmap = varsto_core::p2p::portmap::PortMapStatus::off();
                varsto_core::activity::global().set_peers(None, None);
                log::info!("p2p stopped (turned off)");
            }
        }
        if p2p.is_none() {
            let unlocked = state.lock().unwrap().engine.is_some();
            // Unlocked just now (a phone that started locked): start at
            // once rather than after the retry wait of the locked attempt.
            if unlocked && !p2p_unlocked {
                p2p_retry_at = Instant::now();
            }
            p2p_unlocked = unlocked;
        }
        if p2p.is_none() && Instant::now() >= p2p_retry_at {
            let wanted = {
                let st = desktop::lock_idle(&state);
                st.engine
                    .as_ref()
                    .map(|e| e.p2p_config().enabled)
                    .unwrap_or(false)
            };
            if wanted {
                p2p = P2p::start(&state);
                if p2p.is_some() {
                    log::info!("p2p started after unlock");
                } else {
                    p2p_retry_at = Instant::now() + Duration::from_secs(30);
                }
            }
        }
        if let Some(p) = &p2p {
            // A relay registration just succeeded: tell the other devices
            // now. Publishing writes to the storages: with the engine out of
            // the state, so the interface answers meanwhile.
            let republish = p.take_republish();
            let synced = desktop::lock_idle(&state).service.syncs != snapshot_syncs;
            if republish || synced {
                let mut st = desktop::checkout(&state, "peer record");
                if republish {
                    p.publish_record(&mut st);
                }
                if st.service.syncs != snapshot_syncs {
                    snapshot_syncs = st.service.syncs;
                    p.refresh_after_sync(&mut st);
                }
            }
        }
        if desktop::lock_idle(&state).service.restart_requested {
            log::info!("restarting after update");
            std::thread::sleep(Duration::from_millis(300));
            break;
        }
        // Another device published something (a folder, files, itself): sync
        // now, and look for new devices soon.
        if varsto_core::p2p::take_change_heard() {
            state.lock().unwrap().service.sync_requested = true;
            watch_every = WATCH_MIN;
            next_watch = Instant::now();
        }
        // A new device between the syncs: the host of a pairing sees it
        // join, a device on the LAN beacons, a device that joined with the
        // vault key only shows in the storage's device records.
        {
            let (unlocked_now, paired) = {
                let st = desktop::lock_idle(&state);
                let paired = st
                    .pair
                    .as_ref()
                    .and_then(|o| o.status().paired_with)
                    .filter(|w| paired_seen.as_ref() != Some(w));
                (st.engine.is_some(), paired)
            };
            if unlocked_now && !was_unlocked {
                watch_every = WATCH_MIN;
                next_watch = Instant::now() + WATCH_MIN;
            }
            was_unlocked = unlocked_now;
            if let Some(w) = paired {
                // The new device is still joining: look soon and often.
                paired_seen = Some(w);
                watch_every = WATCH_MIN;
                next_watch = Instant::now() + WATCH_MIN;
            }
            let lan_new = p2p.as_ref().is_some_and(|p| p.take_lan_new());
            // A device whose certificate our directory does not name yet
            // knocked (it published its record after our last read): read
            // the records again, at most every few seconds.
            let knocked = p2p.as_ref().is_some_and(|p| p.take_unknown_knock());
            if unlocked_now && (lan_new || knocked || Instant::now() >= next_watch) {
                next_watch = Instant::now() + watch_every;
                watch_every = (watch_every * 2).min(WATCH_MAX);
                // The device records and the peer records are read from the
                // storages: with the engine out of the state, so that the
                // interface, pause and lock answer while a storage is slow.
                let mut st = desktop::checkout(&state, "device check");
                let found = st.engine.as_mut().map(|e| e.refresh_devices());
                let mut grew = false;
                match found {
                    Some(Ok(true)) => {
                        grew = true;
                        log::info!("a new device turned up in the vault; syncing now");
                    }
                    Some(Ok(false)) | None => {}
                    Some(Err(e)) => {
                        // Offline or a storage down: not again every few
                        // seconds; a LAN device or a knock still looks at once.
                        log::debug!("device check failed: {e:#}");
                        watch_every = WATCH_MAX;
                        next_watch = Instant::now() + WATCH_MAX;
                    }
                }
                if let Some(p) = &p2p {
                    if grew || lan_new || knocked || p.records_changed(&st) {
                        p.refresh_before_sync(&mut st);
                        crate::readcache::invalidate_all();
                        varsto_core::events::publish("peers.changed", json!({}));
                        // Ask the new table once, so that the first path to
                        // a new device is known (and shown) at once.
                        p.probe_soon(&state);
                    }
                }
                if grew {
                    crate::readcache::invalidate_all();
                    st.service.request_sync();
                    st.service.folders_changed = true;
                    watch_every = WATCH_MIN;
                    next_watch = Instant::now() + WATCH_MIN;
                    varsto_core::events::publish("devices.changed", json!({}));
                }
            }
        }
        let due_change = last_change
            .map(|t| t.elapsed() >= debounce)
            .unwrap_or(false);
        let due_timer = Instant::now() >= next_sync;
        let (requested, paused, unlocked) = {
            let st = desktop::lock_idle(&state);
            (
                st.service.sync_requested,
                st.service.paused,
                st.engine.is_some(),
            )
        };
        if unlocked && !paused && (due_change || due_timer || requested) {
            last_change = None;
            // The whole round (peer records, ledger, the sync itself, the
            // upkeep) runs with the engine and the service's state taken out
            // of the shared state: the interface, the tray, the command line
            // and MCP get the summary from before the round (marked busy) and
            // the cached reads, and pause, lock and quit answer at once.
            let mut st = desktop::checkout(&state, "sync");
            st.service.sync_requested = false;
            let interval = st.service.interval_secs;
            if let Some(p) = &p2p {
                p.refresh_before_sync(&mut st);
                // A device that has just joined may sync for a long time
                // before it is done: say who it is first.
                p.announce(&mut st);
            }
            if let Some(e) = st.engine.as_mut() {
                e.expire_strongrooms();
            }
            {
                let st = &mut *st;
                if let Some(e) = st.engine.as_mut() {
                    st.service.ledger_guard(e);
                }
            }
            let why = if due_change {
                "files changed"
            } else if requested {
                "requested"
            } else {
                "interval"
            };
            let started = Instant::now();
            varsto_core::events::publish("sync.started", json!({ "reason": why }));
            let result = st.engine.as_mut().map(|e| e.sync(None));
            if let Some(Ok(reports)) = &result {
                {
                    let (pulled, pushed) = reports.iter().fold((0, 0), |(a, b), (pl, ps)| {
                        (
                            a + pl.files_updated + pl.files_deleted,
                            b + ps.files_changed,
                        )
                    });
                    log::debug!(why = why, ms = started.elapsed().as_millis() as u64, pulled = pulled, pushed = pushed, folders = reports.len(); "service sync round");
                    if pulled + pushed > 0 || started.elapsed() > Duration::from_secs(10) {
                        log::info!(
                            "sync ({why}) took {:.1} s: {pulled} files from other devices, {pushed} changed here",
                            started.elapsed().as_secs_f64()
                        );
                    }
                }
            }
            if let Some(p) = &p2p {
                p.refresh_after_sync(&mut st);
            }
            st.service.check_space();
            match result {
                Some(Ok(reports)) => {
                    st.service.record_sync(&reports);
                    // Something new went out (files, or a folder the other
                    // devices have not seen): tell them to fetch it now.
                    let folders = st.engine.as_ref().map(|e| e.folders().len()).unwrap_or(0);
                    let pushed = reports.iter().any(|(_, p)| p.files_changed > 0);
                    if pushed || folders != known_folders {
                        known_folders = folders;
                        if let Some(e) = st.engine.as_ref() {
                            e.notify_peers_changed();
                        }
                    }
                    snapshot_syncs = st.service.syncs; // the snapshot above is current
                    let upkeep = varsto_core::logging::Timer::start();
                    // One step at a time, with the engine handed back in
                    // between: requests waiting for it get their turn (each
                    // step can take a while on a big vault).
                    st = run_upkeep(st, false);
                    log::debug!(ms = upkeep.ms(); "service upkeep after sync (ledger, verify, scrub, repair, forwarding, mailbox, drains, backups, trash, restic, YouTube, moves, torrents, disk suggestions, device details)");
                    let checked = st.engine.as_ref().map(|e| e.policy_check());
                    match checked {
                        Some(Ok(reps)) => st.service.record_policies(reps),
                        Some(Err(e)) => log::warn!("policy check failed: {e:#}"),
                        None => {}
                    }
                }
                Some(Err(e)) => {
                    st.service.last_error = Some(format!("{e:#}"));
                    varsto_core::events::publish(
                        "sync.finished",
                        json!({"ok": false, "error": format!("{e:#}")}),
                    );
                    log::warn!("sync failed: {e:#}");
                    // A wipe order was carried out: nothing of the vault is left.
                    let removed = e.downcast_ref::<varsto_core::engine::DeviceRemoved>();
                    if removed.is_some_and(|r| r.wiped) {
                        st.engine = None;
                    }
                    // A storage out of reach (offline, a dead bucket) failed
                    // the round: the upkeep that does not need it still runs
                    // (the mailbox for docked disks, scheduled snapshots,
                    // restic, moves to pool disks, disk suggestions).
                    if removed.is_none() {
                        st = run_upkeep(st, true);
                    }
                }
                None => {}
            }
            st.service.folders_changed = true; // folders may have arrived from other devices
            next_sync = Instant::now() + Duration::from_secs(interval);
            st.service.next_sync_utc = Some(varsto_core::util::now_utc() + interval as i64);
        } else if !unlocked {
            next_sync = Instant::now() + Duration::from_secs(5);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    activity_stop.store(true, Ordering::Relaxed);
    crate::sse::SHUTDOWN.store(true, Ordering::Relaxed);
    // Stop peer-to-peer first: the router mappings are removed on the way.
    drop(p2p);
    let restart = state.lock().unwrap().service.restart_requested;
    let _ = fs::remove_file(service_file(&opts.home));
    server.unblock();
    if restart {
        // Exit code 75 tells a supervisor (launchd, systemd, the tray app) to start us again.
        std::process::exit(75);
    }
    Ok(())
}

/// Does a watcher event mean that something may have changed? Opening or
/// reading a file is not a change: the watcher reports every open (inotify
/// `IN_OPEN`), and serving blocks to peers, a backup tool or a viewer would
/// otherwise start a full sync every few seconds. Closing a file that was
/// open for writing is. Our own temporary files never are.
fn is_change(ev: &notify::Event) -> bool {
    use notify::event::{AccessKind, AccessMode, EventKind};
    if let EventKind::Access(kind) = ev.kind {
        if kind != AccessKind::Close(AccessMode::Write) {
            return false;
        }
    }
    !ev.paths.iter().all(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().starts_with(".varsto"))
            .unwrap_or(false)
    })
}

fn make_watcher(tx: mpsc::Sender<()>) -> Result<notify::RecommendedWatcher> {
    let watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                if is_change(&ev) {
                    let _ = tx.send(());
                }
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(30)),
    )
    .context("start file watcher")?;
    Ok(watcher)
}

/// How long `status` waits for the summary; it is answered from the state
/// without the engine, so only a stuck service takes longer.
const STATUS_WAIT: Duration = Duration::from_secs(5);
/// How long the liveness probe (`/api/alive`, answered before any state is
/// looked at) may take.
const ALIVE_WAIT: Duration = Duration::from_secs(3);

/// Is the service recorded in `service.json` still alive? Answers within a
/// few seconds. A service that is there but slow to answer (busy) counts as
/// running, with `{"busy": true}` as its summary: the command line must not
/// open the vault beside it, nor the tray start a second one.
pub fn status(home: &Path) -> Option<(ServiceFile, Value)> {
    let f = read_service_file(home)?;
    let base = format!("http://127.0.0.1:{}", f.port);
    match http_call_within(
        "GET",
        &format!("{base}/api/service"),
        &f.token,
        None,
        STATUS_WAIT,
    ) {
        Ok(body) => Some((f, serde_json::from_str(&body).unwrap_or(json!({})))),
        Err(e) if refused(&e) => None,
        Err(_) => {
            // No summary in time (or an error answer): alive if the probe
            // that never touches the state answers.
            let alive = http_call_within(
                "GET",
                &format!("{base}/api/alive"),
                &f.token,
                None,
                ALIVE_WAIT,
            )
            .ok()
            .and_then(|b| serde_json::from_str::<Value>(&b).ok())
            .filter(|v| v["pid"].as_u64() == Some(u64::from(f.pid)))?;
            Some((
                f,
                json!({"running": true, "busy": alive["busy"].as_str().unwrap_or("busy")}),
            ))
        }
    }
}

/// The connection was refused: nothing listens on the port (the service
/// is not running, whatever `service.json` says).
fn refused(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
}

/// The address that opens the interface in a browser: a one-time code
/// (valid for a minute) that the page trades for the session token, so that
/// the token itself is in no process argument or browser history.
pub fn boot_url(f: &ServiceFile) -> Result<String> {
    let base = format!("http://127.0.0.1:{}", f.port);
    let answer = http_post(&format!("{base}/api/session/boot"), &f.token, "{}")?;
    let code = serde_json::from_str::<serde_json::Value>(&answer)?["boot"]
        .as_str()
        .ok_or_else(|| anyhow!("the service gave no start code"))?
        .to_string();
    Ok(format!("{base}/?boot={code}"))
}

/// The service's upkeep after a sync, in order (ledger, verify, scrub,
/// repair, drains, backups, trash, restic, YouTube jobs, moves, torrents,
/// disk suggestions, device details); each runs with the engine taken anew.
type UpkeepStep = fn(&mut ServiceState, &mut varsto_core::engine::Engine);

/// One upkeep step: whether it runs after a full sync round, and whether
/// also after one that failed (offline, or a storage out of reach). Those
/// are the steps that work on this device's own disks or only add
/// (snapshots); the steps that check, repair, rebuild or delete wait for a
/// round that reached every storage: with one of them missing, its blocks
/// would look lost.
struct Upkeep {
    name: &'static str,
    run: UpkeepStep,
    after_sync: bool,
    after_failed_sync: bool,
}

const fn full(name: &'static str, run: UpkeepStep) -> Upkeep {
    Upkeep {
        name,
        run,
        after_sync: true,
        after_failed_sync: false,
    }
}

const fn always(name: &'static str, run: UpkeepStep) -> Upkeep {
    Upkeep {
        name,
        run,
        after_sync: true,
        after_failed_sync: true,
    }
}

const UPKEEP_STEPS: &[Upkeep] = &[
    full("ledger", |s, e| s.ledger_after_sync(e)),
    full("verify", |s, e| s.auto_verify_if_due(e)),
    full("scrub", |s, e| s.scrub_if_due(e)),
    full("repair", |s, e| s.repair_if_due(e)),
    // In one sync round each (storage health layer, spec section 79): the
    // steps that pull the ledger reuse one pull instead of listing every
    // storage again.
    full("forward", |s, e| {
        let _ = e.sync_round(|e| {
            s.forward_if_due(e);
            Ok(())
        });
    }),
    always("mailbox", |s, e| {
        s.mailbox_if_due(e, true);
    }),
    full("drains", |s, e| {
        let _ = e.sync_round(|e| {
            s.drains_if_due(e);
            Ok(())
        });
    }),
    full("backups", |s, e| s.backups_if_due(e)),
    // After a failed round only the snapshots that are due (they only add);
    // expiry, which deletes, waits for a full round.
    Upkeep {
        name: "backup snapshots",
        run: |s, e| s.backup_snapshots_if_due(e),
        after_sync: false,
        after_failed_sync: true,
    },
    full("trash", |s, e| s.trash_if_due(e)),
    always("restic", |s, e| s.restic_if_due(e)),
    // Imports only add, on this device: they run after a failed round too.
    always("youtube", |s, e| s.youtube_if_due(e)),
    always("moves", |s, e| {
        let _ = e.sync_round(|e| {
            s.moves_if_due(e, true);
            Ok(())
        });
    }),
    always("torrents", |s, e| s.torrents_if_due(e)),
    always("disk suggestions", |s, e| s.suggest_disks(e)),
    full("folder requests", |s, e| s.watch_folder_requests(e)),
    full("device details", |s, e| {
        if let Err(err) = e.publish_device_details(s.last_sync_utc) {
            log::info!("device details not published: {err:#}");
        }
    }),
];

/// The upkeep steps of a sync round (`failed`: one that failed, see
/// [`Upkeep`]).
fn upkeep_steps(failed: bool) -> impl Iterator<Item = &'static Upkeep> {
    UPKEEP_STEPS.iter().filter(move |u| {
        if failed {
            u.after_failed_sync
        } else {
            u.after_sync
        }
    })
}

/// Run the upkeep steps on the engine out of the state; between them the
/// engine goes back for a moment, so a request waiting for it gets it first.
fn run_upkeep(mut st: desktop::Work<'_>, failed: bool) -> desktop::Work<'_> {
    for step in upkeep_steps(failed) {
        st = desktop::requeue(st, step.name);
        let st = &mut *st;
        if let Some(e) = st.engine.as_mut() {
            (step.run)(&mut st.service, e);
        }
    }
    desktop::requeue(st, "upkeep")
}

/// Minimal HTTP client for talking to the local service (no extra dependency).
pub fn http_get(url: &str, token: &str) -> Result<String> {
    http_call("GET", url, token, None)
}

pub fn http_post(url: &str, token: &str, body: &str) -> Result<String> {
    http_call("POST", url, token, Some(body))
}

pub fn http_call(method: &str, url: &str, token: &str, body: Option<&str>) -> Result<String> {
    http_call_within(method, url, token, body, Duration::from_secs(600))
}

/// POST that gives up after `secs`.
pub fn http_post_within(url: &str, token: &str, body: &str, secs: u64) -> Result<String> {
    http_call_within("POST", url, token, Some(body), Duration::from_secs(secs))
}

/// GET that gives up after `secs` (for answers that wait while a sync holds the engine).
pub fn http_get_within(url: &str, token: &str, secs: u64) -> Result<String> {
    http_call_within("GET", url, token, None, Duration::from_secs(secs))
}

fn http_call_within(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&str>,
    wait: Duration,
) -> Result<String> {
    use std::io::{Read, Write};
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("http only"))?;
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = std::net::TcpStream::connect(hostport)?;
    stream.set_read_timeout(Some(wait))?;
    let body = body.unwrap_or("");
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nX-Varsto-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("bad response"))?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(anyhow!("service answered {status}: {resp_body}"));
    }
    Ok(resp_body.to_string())
}

// ----- install as a login item ------------------------------------------------

/// The marker `varsto service uninstall` leaves so that commands stop
/// setting the service up again on their own.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub fn opted_out(home: &Path) -> bool {
    home.join("service-off").exists()
}

pub fn set_opted_out(home: &Path, off: bool) {
    let m = home.join("service-off");
    if off {
        let _ = fs::create_dir_all(home);
        let _ = fs::write(
            &m,
            "background sync was turned off with `varsto uninstall`\n",
        );
    } else {
        let _ = fs::remove_file(&m);
    }
}

/// Whether background sync starts at login on this computer.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub fn login_service_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        return std::env::var_os("HOME").is_some_and(|h| {
            PathBuf::from(h)
                .join("Library/LaunchAgents/in.soderlund.varsto.plist")
                .exists()
        });
    }
    #[cfg(target_os = "linux")]
    {
        return linux::installed();
    }
    #[allow(unreachable_code)]
    true
}

/// Ask the running service to restart (exit code 75), so its supervisor
/// starts the binary that is on disk now (after `varsto update`).
pub fn restart_running(home: &Path) -> bool {
    match status(home) {
        Some((f, _)) => http_post(
            &format!("http://127.0.0.1:{}/api/service/restart", f.port),
            &f.token,
            "{}",
        )
        .is_ok(),
        None => false,
    }
}

/// Restart the running service and wait until a new one answers. A
/// supervisor (launchd, systemd, the tray app) starts it again after exit
/// code 75; without one, the service is started here. Returns whether a
/// service runs afterwards (false when none ran before).
pub fn restart_and_wait(home: &Path) -> bool {
    let Some((old, _)) = status(home) else {
        return false;
    };
    if !restart_running(home) {
        return false;
    }
    let new_service_up = |secs: u64| {
        for _ in 0..(secs * 5) {
            std::thread::sleep(Duration::from_millis(200));
            if status(home).is_some_and(|(f, _)| f.pid != old.pid) {
                return true;
            }
        }
        false
    };
    if new_service_up(15) {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe)
            .arg("--home")
            .arg(home)
            .args(["service", "run"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    new_service_up(10)
}

pub fn install(home: &Path, interval_secs: u64) -> Result<String> {
    let exe = std::env::current_exe()?;
    // Through a link on PATH, run the file it points to (inside Varsto.app,
    // so an updated app is an updated service). Not on Windows: there the
    // result is a `\\?\` path, which Explorer cannot start from a verb.
    #[cfg(unix)]
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    #[cfg(target_os = "macos")]
    {
        let dir = PathBuf::from(std::env::var("HOME")?).join("Library/LaunchAgents");
        fs::create_dir_all(&dir)?;
        let plist = dir.join("in.soderlund.varsto.plist");
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>in.soderlund.varsto</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--home</string><string>{}</string><string>service</string><string>run</string><string>--interval</string><string>{}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
            exe.display(),
            home.display(),
            interval_secs,
            home.join("service.log").display(),
            home.join("service.log").display()
        );
        fs::write(&plist, content)?;
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist.display().to_string()])
            .output();
        let out = std::process::Command::new("launchctl")
            .args(["load", "-w", &plist.display().to_string()])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "launchctl load failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(format!("installed and started: {}", plist.display()));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = exe;
        return linux::install(home, interval_secs).map(|lines| lines.join("\n"));
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA")?;
        let dir = PathBuf::from(appdata).join("Microsoft/Windows/Start Menu/Programs/Startup");
        fs::create_dir_all(&dir)?;
        let cmd = dir.join("Varsto.cmd");
        fs::write(
            &cmd,
            format!(
                "@echo off\r\nstart \"\" /B \"{}\" --home \"{}\" tray --interval {}\r\n",
                exe.display(),
                home.display(),
                interval_secs
            ),
        )?;
        let mut done = vec![format!(
            "installed: {} (starts the tray app at login)",
            cmd.display()
        )];
        done.extend(crate::filemanager::windows::install(&exe, home)?);
        return Ok(done.join("\n"));
    }
    #[allow(unreachable_code)]
    {
        let _ = (home, interval_secs, exe);
        Err(anyhow!("automatic installation is not available on this platform; run `varsto service run` from your login items"))
    }
}

pub fn uninstall() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let plist = PathBuf::from(std::env::var("HOME")?)
            .join("Library/LaunchAgents/in.soderlund.varsto.plist");
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w", &plist.display().to_string()])
            .output();
        let _ = fs::remove_file(&plist);
        return Ok("removed the launch agent".into());
    }
    #[cfg(target_os = "linux")]
    {
        return linux::uninstall().map(|lines| lines.join("\n"));
    }
    #[cfg(target_os = "windows")]
    {
        let dir = PathBuf::from(std::env::var("APPDATA")?)
            .join("Microsoft/Windows/Start Menu/Programs/Startup");
        let _ = fs::remove_file(dir.join("Varsto.cmd"));
        let mut done = vec!["removed the startup entry".to_string()];
        done.extend(crate::filemanager::windows::uninstall()?);
        return Ok(done.join("\n"));
    }
    #[allow(unreachable_code)]
    Err(anyhow!("not available on this platform"))
}

/// Linux: install like an ordinary program, without root. The binary goes to
/// `~/.local/bin` (added to PATH in the shell profiles when missing), a
/// systemd user unit runs the background service (restarting it after a
/// self-update, exit code 75), the tray starts at login and attaches to that
/// service, and the application menu gets an entry with the icon.
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use anyhow::bail;
    use std::io::Write;
    use std::process::Command;

    const ICON_PNG: &[u8] = include_bytes!("../../../brand/png/logo-256.png");
    const UNIT: &str = "varsto.service";
    const MARK: &str = "# Added by varsto install";

    fn user_home() -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?,
        ))
    }

    fn xdg(var: &str, fallback: &str) -> Result<PathBuf> {
        Ok(std::env::var_os(var)
            .map(PathBuf::from)
            .unwrap_or(user_home()?.join(fallback)))
    }

    /// Where `varsto install` puts the binary.
    pub fn installed_binary() -> Result<PathBuf> {
        Ok(user_home()?.join(".local/bin/varsto"))
    }

    /// Whether the background service unit (or at least the binary) is installed.
    pub fn installed() -> bool {
        let unit = xdg("XDG_CONFIG_HOME", ".config").map(|c| c.join("systemd/user").join(UNIT));
        unit.map(|u| u.exists()).unwrap_or(false)
            || installed_binary().map(|b| b.exists()).unwrap_or(false)
    }

    /// Whether this process runs the installed copy.
    pub fn running_installed() -> bool {
        match (
            std::env::current_exe().and_then(fs::canonicalize),
            installed_binary(),
        ) {
            (Ok(me), Ok(target)) => fs::canonicalize(target).map(|t| t == me).unwrap_or(false),
            _ => false,
        }
    }

    fn systemd_user() -> bool {
        Command::new("systemctl")
            .args(["--user", "show-environment"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let out = Command::new("systemctl")
            .arg("--user")
            .args(args)
            .output()?;
        if !out.status.success() {
            bail!(
                "systemctl --user {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn quote(p: &Path) -> String {
        let s = p.display().to_string();
        if s.contains(' ') {
            format!("\"{s}\"")
        } else {
            s
        }
    }

    /// Ask a service already running for this home (started by hand or by an
    /// older copy) to stop, so the installed one takes over.
    fn stop_running(home: &Path) {
        if let Some((file, _)) = status(home) {
            let url = format!("http://127.0.0.1:{}/api/quit", file.port);
            let _ = http_post(&url, &file.token, "{}");
            for _ in 0..50 {
                if status(home).is_none() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    pub fn install(home: &Path, interval_secs: u64) -> Result<Vec<String>> {
        let mut done = Vec::new();
        let target = installed_binary()?;
        let bin_dir = target.parent().unwrap().to_path_buf();
        fs::create_dir_all(&bin_dir)?;
        if !running_installed() {
            // Copy then rename: replacing a running binary in place would
            // break the process that runs it.
            let tmp = bin_dir.join(".varsto.new");
            fs::copy(std::env::current_exe()?, &tmp)?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
            fs::rename(&tmp, &target)?;
            done.push(format!("binary: {}", target.display()));
        }
        let on_path = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d == bin_dir))
            .unwrap_or(false);
        if !on_path {
            let line = format!("\n{MARK}\nexport PATH=\"$HOME/.local/bin:$PATH\"\n");
            for rc in [".profile", ".bashrc", ".zshrc"] {
                let f = user_home()?.join(rc);
                if rc != ".profile" && !f.exists() {
                    continue;
                }
                let text = fs::read_to_string(&f).unwrap_or_default();
                if !text.contains(MARK) {
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&f)?
                        .write_all(line.as_bytes())?;
                    done.push(format!(
                        "PATH: added ~/.local/bin in ~/{rc} (open a new terminal)"
                    ));
                }
            }
        }
        fs::create_dir_all(home)?;
        let exec = format!("{} --home {}", quote(&target), quote(home));
        if systemd_user() {
            let dir = xdg("XDG_CONFIG_HOME", ".config")?.join("systemd/user");
            fs::create_dir_all(&dir)?;
            fs::write(
                dir.join(UNIT),
                format!(
                    "[Unit]\nDescription=Varsto background sync\nAfter=network-online.target\n\n[Service]\nExecStart={exec} service run --port 0 --interval {interval_secs}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
                ),
            )?;
            stop_running(home);
            systemctl(&["daemon-reload"])?;
            systemctl(&["enable", UNIT])?;
            // Restart, not just start: a service that lost its service file
            // (a reset removes it) is not found by stop_running, and would
            // keep running the old binary.
            systemctl(&["restart", UNIT])?;
            done.push(format!(
                "background service: systemd user unit {UNIT}, started and enabled at login"
            ));
            // Keep syncing while nobody is logged in (allowed for oneself on
            // most systems; harmless when it is not).
            let lingering = Command::new("loginctl")
                .arg("enable-linger")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            done.push(if lingering {
                "background service: keeps running when you are logged out (systemd linger)".into()
            } else {
                "background service: runs while you are logged in (`loginctl enable-linger` was not allowed)".into()
            });
        } else {
            done.push("background service: no systemd user session; the tray app runs it while you are logged in".into());
        }
        let config = xdg("XDG_CONFIG_HOME", ".config")?;
        fs::create_dir_all(config.join("autostart"))?;
        fs::write(
            config.join("autostart/varsto.desktop"),
            format!("[Desktop Entry]\nType=Application\nName=Varsto\nComment=Encrypted sync with your own storage\nExec={exec} tray --interval {interval_secs}\nIcon=varsto\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"),
        )?;
        done.push("tray icon: starts at login".into());
        let data = xdg("XDG_DATA_HOME", ".local/share")?;
        let icon_dir = data.join("icons/hicolor/256x256/apps");
        fs::create_dir_all(&icon_dir)?;
        fs::write(icon_dir.join("varsto.png"), ICON_PNG)?;
        fs::create_dir_all(data.join("applications"))?;
        fs::write(
            data.join("applications/varsto.desktop"),
            format!("[Desktop Entry]\nType=Application\nName=Varsto\nComment=Encrypted sync with your own storage\nExec={exec} tray --open\nIcon=varsto\nTerminal=false\nCategories=Utility;FileTools;Network;\n"),
        )?;
        done.push("application menu: Varsto".into());
        done.extend(crate::filemanager::linux::install(
            &data, &config, &target, home,
        )?);
        Ok(done)
    }

    pub fn uninstall() -> Result<Vec<String>> {
        let mut done = Vec::new();
        if systemd_user() {
            let _ = systemctl(&["disable", "--now", UNIT]);
            let unit = xdg("XDG_CONFIG_HOME", ".config")?
                .join("systemd/user")
                .join(UNIT);
            if fs::remove_file(unit).is_ok() {
                let _ = systemctl(&["daemon-reload"]);
                done.push("background service: stopped and removed".into());
            }
        }
        let config = xdg("XDG_CONFIG_HOME", ".config")?;
        let data = xdg("XDG_DATA_HOME", ".local/share")?;
        for f in [
            config.join("autostart/varsto.desktop"),
            data.join("applications/varsto.desktop"),
            data.join("icons/hicolor/256x256/apps/varsto.png"),
        ] {
            let _ = fs::remove_file(f);
        }
        done.push("autostart and menu entries removed".into());
        done.extend(crate::filemanager::linux::uninstall(&data, &config)?);
        let target = installed_binary()?;
        if !running_installed() && fs::remove_file(&target).is_ok() {
            done.push(format!("binary removed: {}", target.display()));
        } else if target.exists() {
            done.push(format!(
                "binary kept: {} (remove it by hand after this)",
                target.display()
            ));
        }
        done.push("your vault and folders were not touched".into());
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The background service never answers a folder request (design
    /// section 6, S-020): no call that approves, denies, grants, changes a
    /// role, removes a device or writes recovery copies appears in this file.
    /// (The needles are split so that this test does not match itself.)
    #[test]
    fn the_service_never_approves_or_grants() {
        let src = include_str!("service.rs");
        let needles: Vec<String> = [
            [".appr", "ove("],
            [".de", "ny("],
            ["issue_", "grant"],
            ["grant_to_", "joiner"],
            ["f3_ap", "prove"],
            ["f3_de", "ny"],
            ["f3_set_", "role"],
            ["f3_re", "move"],
            ["f3_pair_", "grants"],
            ["f3_write_", "escrows"],
            ["escrow_folder_", "epoch"],
            ["start_folder_", "epoch"],
            ["answer_", "pair"],
        ]
        .iter()
        .map(|p| p.concat())
        .collect();
        for n in &needles {
            assert!(!src.contains(n.as_str()), "service.rs contains {n}");
        }
        // What it does call is the read-only listing.
        assert!(src.contains("f3_requests"));
    }

    /// Offline (spec section 79.3): after a sync that could not reach every
    /// storage, the upkeep that works on this device's own disks or only
    /// adds still runs; what checks, repairs, rebuilds or deletes waits for
    /// a full round (a storage out of reach would make its blocks look lost).
    #[test]
    fn after_a_failed_sync_only_the_local_and_adding_upkeep_runs() {
        let names = |failed: bool| upkeep_steps(failed).map(|u| u.name).collect::<Vec<_>>();
        assert_eq!(
            names(true),
            [
                "mailbox",
                "backup snapshots",
                "restic",
                "moves",
                "disk suggestions"
            ]
        );
        let full = names(false);
        for n in [
            "ledger",
            "verify",
            "scrub",
            "repair",
            "forward",
            "mailbox",
            "drains",
            "backups",
            "trash",
            "restic",
            "moves",
            "disk suggestions",
            "folder requests",
            "device details",
        ] {
            assert!(full.contains(&n), "{n} runs after a full round");
        }
        // Snapshots run once per full round (inside "backups").
        assert!(!full.contains(&"backup snapshots"));
        for n in [
            "ledger", "verify", "scrub", "repair", "drains", "backups", "trash",
        ] {
            assert!(!names(true).contains(&n), "{n} waits for a full round");
        }
    }

    /// The liveness probe tells "nothing listens" (not running) apart from
    /// an answer that is slow or an error.
    #[test]
    fn a_refused_connection_means_not_running() {
        // A port that was just free: nothing listens on it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let e = http_call_within(
            "GET",
            &format!("http://127.0.0.1:{port}/api/alive"),
            "t",
            None,
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(refused(&e), "{e:#}");
        assert!(!refused(&anyhow!("service answered 503: busy")));
        // Something listens but does not answer in time: not "refused".
        let quiet = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = quiet.local_addr().unwrap().port();
        let t = Instant::now();
        let e = http_call_within(
            "GET",
            &format!("http://127.0.0.1:{port}/api/alive"),
            "t",
            None,
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(!refused(&e), "{e:#}");
        assert!(t.elapsed() < Duration::from_secs(5));
        drop(quiet);
    }

    #[test]
    fn a_mapping_is_published_only_after_the_probe_reached_us() {
        let mut pm = varsto_core::p2p::portmap::PortMapStatus {
            state: "mapped".into(),
            tcp: Some("203.0.113.5:41000".parse().unwrap()),
            udp: Some("203.0.113.5:41001".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(published_mappings(&pm), (vec![], vec![]));
        pm.verified = true;
        let (tcp, udp) = published_mappings(&pm);
        assert_eq!(tcp, vec!["203.0.113.5:41000".parse().unwrap()]);
        assert_eq!(udp, vec!["203.0.113.5:41001".parse().unwrap()]);
    }

    use notify::event::{AccessKind, AccessMode, CreateKind, DataChange, EventKind, ModifyKind};

    fn ev(kind: EventKind, name: &str) -> notify::Event {
        notify::Event::new(kind).add_path(PathBuf::from("/folder").join(name))
    }

    #[test]
    fn reads_are_not_changes() {
        assert!(!is_change(&ev(
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            "a.txt"
        )));
        assert!(!is_change(&ev(
            EventKind::Access(AccessKind::Close(AccessMode::Read)),
            "a.txt"
        )));
        assert!(is_change(&ev(
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
            "a.txt"
        )));
        assert!(is_change(&ev(
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            "a.txt"
        )));
        assert!(is_change(&ev(EventKind::Create(CreateKind::File), "a.txt")));
        assert!(!is_change(&ev(
            EventKind::Create(CreateKind::File),
            ".varsto-tmp-1"
        )));
    }
}
