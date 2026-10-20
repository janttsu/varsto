// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The inputs of the Help page (`crate::help`): from this device's
//! configuration, the ledger view, the folder states and the cached trash,
//! plus what the background service already measured. No storage is listed
//! and no network connection is made.

use super::*;
use crate::disksuggest::DiskSuggestions;
use crate::help::{
    self, BackupIn, DiskIn, FolderIn, HelpState, Inputs, KeptAsideIn, Kit, LowSpaceIn, OrgIn,
    PausedIn, Phase, PolicyIn, ServiceIn, StorageIn,
};
use crate::policy::PolicyReport;
use crate::pool::DiskStatus;

/// What the background service knows and the engine would otherwise have
/// to work out again (or cannot know: whether syncing is paused). Every
/// field is optional; what is missing is computed here, cheaply.
#[derive(Clone, Debug, Default)]
pub struct HelpObserved {
    pub service: Option<ServiceIn>,
    pub policies: Option<Vec<PolicyReport>>,
    pub disks: Option<Vec<DiskStatus>>,
    pub disk_suggest: Option<DiskSuggestions>,
    pub repair: Option<RepairStatus>,
    pub scrub: Option<crate::scrub::ScrubStatus>,
    /// Backups whose last scheduled snapshot failed, with the reason.
    pub backup_errors: BTreeMap<String, String>,
    pub restic_text: Option<String>,
    pub quota_full: Vec<String>,
}

/// `part` of `stored`, as the same share of `logical`.
fn scale(part: u64, logical: u64, stored: u64) -> u64 {
    if stored == 0 {
        return 0;
    }
    (part as u128 * logical as u128 / stored as u128).min(logical as u128) as u64
}

/// The Help page of a device directory without an open vault: no vault
/// yet, or a vault that is locked.
pub fn help_without_vault(home: &Path) -> HelpState {
    let phase = if home.join("vault.json").exists() {
        Phase::Locked
    } else {
        Phase::NoVault
    };
    let device = crate::util::read_json::<serde_json::Value>(&home.join("vault.json"))
        .ok()
        .and_then(|v| {
            v.get("device_name")
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    help::build(&Inputs {
        phase,
        device,
        now_utc: util::now_utc(),
        ..Default::default()
    })
}

impl Engine {
    /// The Help page for this vault: situation, health and next steps.
    pub fn help_state(&mut self, observed: HelpObserved) -> Result<HelpState> {
        Ok(help::build(&self.help_inputs(observed)?))
    }

    pub fn help_inputs(&mut self, mut observed: HelpObserved) -> Result<Inputs> {
        let now = util::now_utc();
        let loc = self.data_locations()?;
        let device_names: BTreeMap<String, String> = loc
            .devices
            .iter()
            .map(|d| (d.device_id.clone(), d.name.clone()))
            .collect();
        let me = self.vault.device_id.to_string();
        let mut inputs = Inputs {
            phase: Phase::Ready,
            device: self.vault.device_name.clone(),
            now_utc: now,
            member: self.vault.member,
            removed: self.removal.is_some(),
            total_bytes: loc.total_bytes,
            copies_bytes: loc.copies.bytes,
            replicas: self.devices.replicas.len(),
            home_space: crate::pool::disk_space(&self.home).map(|s| (s.free, s.total)),
            mcp_used: self.home.join("mcp-keys.json").exists()
                || self.home.join("mcp-grants.json").exists(),
            quota_full: std::mem::take(&mut observed.quota_full),
            restic: self.restic_config().is_some(),
            restic_text: observed.restic_text.take(),
            service: observed.service.take(),
            ..Default::default()
        };
        inputs.other_devices = self
            .devices_list()
            .into_iter()
            .filter(|d| !d.this_device && !d.revoked)
            .map(|d| d.name)
            .collect();

        // Storages: bytes from the ledger view, quota and drain state.
        let quotas: BTreeMap<String, QuotaStatus> = self
            .quota_statuses()
            .unwrap_or_default()
            .into_iter()
            .map(|q| (q.storage.clone(), q))
            .collect();
        for s in loc.storages.iter().filter(|s| s.configured) {
            let q = quotas.get(&s.name);
            inputs.storages.push(StorageIn {
                name: s.name.clone(),
                kind: s.kind.clone(),
                place: s.place.clone(),
                cold: s.cold,
                carrier: s.carrier,
                bytes: s.bytes,
                quota_bytes: q.and_then(|q| q.quota_bytes),
                quota_percent: q.and_then(|q| q.percent),
                quota_state: q.map(|q| q.state.clone()).unwrap_or_else(|| "none".into()),
                drain: None,
            });
        }
        if let Ok(drains) = self.drain_statuses() {
            for d in drains {
                if let Some(s) = inputs.storages.iter_mut().find(|s| s.name == d.storage) {
                    s.drain = Some(d.phase.clone());
                }
            }
        }

        // Folders: where their bytes are.
        let records: BTreeMap<String, FolderRecord> = self
            .folders()
            .into_iter()
            .map(|(r, _)| (r.folder_id.to_string(), r))
            .collect();
        for f in &loc.folders {
            let rec = records.get(&f.folder_id);
            let mut devices: Vec<String> = f
                .devices
                .iter()
                .filter(|(_, b)| **b > 0)
                .map(|(id, _)| {
                    device_names
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| id.chars().take(8).collect())
                })
                .collect();
            // This device first.
            if let Some(pos) = f
                .devices
                .keys()
                .filter(|id| f.devices[*id] > 0)
                .position(|id| id == &me)
            {
                let mine = devices.remove(pos);
                devices.insert(0, mine);
            }
            let carriers: BTreeSet<&str> = inputs
                .storages
                .iter()
                .filter(|s| s.carrier)
                .map(|s| s.name.as_str())
                .collect();
            inputs.folders.push(FolderIn {
                name: f.name.clone(),
                attached: f.attached,
                files: 0,
                bytes: f.bytes,
                unkept_bytes: f.unkept_bytes,
                storages: f
                    .storages
                    .iter()
                    .filter(|(n, b)| **b > 0 && !carriers.contains(n.as_str()))
                    .map(|(n, b)| (n.clone(), *b))
                    .collect(),
                devices,
                strongroom: rec.is_some_and(|r| r.is_strongroom()),
                shared: rec.is_some_and(|r| r.shared),
                policy: rec.is_some_and(|r| r.effective_policy().is_some()),
            });
        }
        // File counts and sizes as the user sees them. The ledger's sizes
        // are of the encrypted, compressed blocks, so the bytes without a
        // copy are scaled to the files' size.
        let mut logical_total = 0u64;
        for (rec, _) in self.folders() {
            let (files, bytes) = self
                .load_state(&rec.folder_id)
                .map(|st| {
                    st.files
                        .values()
                        .filter(|f| !f.deleted)
                        .fold((0u64, 0u64), |(n, b), f| (n + 1, b + f.size))
                })
                .unwrap_or((0, 0));
            if let Some(f) = inputs.folders.iter_mut().find(|f| f.name == rec.name) {
                f.files = files;
                if f.bytes > 0 {
                    f.unkept_bytes = scale(f.unkept_bytes, bytes, f.bytes);
                }
                f.bytes = bytes;
                logical_total += bytes;
            }
        }
        if loc.total_bytes > 0 {
            for b in inputs.copies_bytes.iter_mut() {
                *b = scale(*b, logical_total, loc.total_bytes);
            }
        }
        inputs.total_bytes = logical_total;

        // Pool disks.
        let disks = match observed.disks.take() {
            Some(d) => d,
            None => self.disk_report().unwrap_or_default(),
        };
        inputs.disks = disks
            .iter()
            .map(|d| DiskIn {
                label: d.label.clone(),
                pool: d.pool.clone(),
                place: d.place.clone(),
                attached: d.attached,
                retired: d.retired,
            })
            .collect();
        let suggest = match observed.disk_suggest.take() {
            Some(s) => Some(s),
            None if !disks.is_empty() => self.disk_suggestions().ok(),
            None => None,
        };
        if let Some(s) = suggest {
            inputs.disks_overdue = s.overdue.clone();
            inputs.disk_next = s.top.as_ref().map(|t| t.label.clone());
        }

        // Open move jobs that wait for a disk.
        inputs.moves = crate::staged_move::list_active(&self.home)
            .into_iter()
            .filter(|j| j.state.is_open() && j.waiting.is_some() && j.bytes_remaining > 0)
            .map(|j| crate::help::MoveIn {
                disk: j.waiting.as_ref().and_then(|w| w.disk.clone()),
                id: j.id,
                folder: j.folder,
                from: j.from,
                to: j.to,
                bytes_left: j.bytes_remaining,
            })
            .collect();

        // Trash, from the cache.
        inputs.trash_days = self.trash_settings().days;
        if let Ok(t) = self.trash_status_cached() {
            inputs.trash_entries = t.entries;
            inputs.trash_bytes = t.bytes;
        }

        // Backups.
        for b in self.backups().unwrap_or_default() {
            inputs.backups.push(BackupIn {
                error: observed.backup_errors.get(&b.name).cloned(),
                name: b.name,
                snapshots: b.snapshots,
                latest_bytes: b.latest_bytes,
                latest_utc: b.latest_utc,
                this_device: b.this_device,
                stopped: b.stopped,
            });
        }

        // Policies.
        let reports = match observed.policies.take() {
            Some(p) => p,
            None => self.policy_check_at(now).unwrap_or_default(),
        };
        for r in reports {
            inputs.policies.push(PolicyIn {
                folder: r.folder.clone(),
                state: r.state,
                min_copies: r.policy.min_copies,
                chunks_short_of_copies: r.chunks_short_of_copies,
                short_places: r
                    .chunks_short_per_place
                    .iter()
                    .filter(|(_, n)| **n > 0)
                    .map(|(p, _)| p.clone())
                    .collect(),
                chunks_unverified: r.chunks_unverified_in_window,
            });
        }

        // Ledger, repair, bit-rot.
        let health = self.ledger_health();
        if !health.is_ok() {
            inputs.ledger_problem = Some(health.describe());
            inputs.ledger_command = health.suggestion.clone();
        }
        let (peer_told, acks_told): (Vec<_>, Vec<_>) = health
            .behind
            .iter()
            .filter(|b| b.pulls >= ledger_recovery::WITHHOLD_PULLS)
            .partition(|b| b.source == "peer");
        inputs.ledger_withheld = acks_told.iter().map(|b| b.name.clone()).collect();
        inputs.ledger_rolled_back = peer_told.iter().map(|b| b.name.clone()).collect();
        // Storages a writer confirmed that show less than a peer proved.
        for d in self.ledger_rollback_devices() {
            if !inputs.ledger_rolled_back.contains(&d) {
                inputs.ledger_rolled_back.push(d);
            }
        }
        let view = self.view3()?;
        inputs.forked = self.forked_self || !view.forked.is_empty();
        let repair = observed
            .repair
            .take()
            .unwrap_or_else(|| self.repair_status());
        inputs.repair_queued = repair.queued;
        inputs.repair_losses = repair.open_losses.len() as u64;
        let scrub = observed.scrub.take().unwrap_or_else(|| self.scrub_status());
        inputs.scrub_damaged = scrub.unrestored.len() as u64;

        // Recovery kit.
        match crate::recovery_guide::kit_record(&self.home) {
            Some(k) if k.key_epoch >= self.key_epoch() => {
                inputs.kit = Kit::Printed;
                inputs.kit_printed_utc = Some(k.printed_utc);
            }
            Some(k) => {
                inputs.kit = Kit::Outdated;
                inputs.kit_printed_utc = Some(k.printed_utc);
            }
            None => inputs.kit = Kit::NotPrinted,
        }

        // Organization.
        if let Some(o) = self.org_summary() {
            inputs.org = Some(OrgIn {
                name: o.name.clone(),
                admin: o.this_device_admin,
                listed: o.this_device_listed,
                pending: o.unlisted.len(),
                blocked: o.this_device_blocked.clone(),
            });
        }

        // Folders paused here, read-only folders with changes kept aside.
        for (rec, root) in self.folders() {
            let Some(root) = root else { continue };
            let Ok(state) = self.load_state(&rec.folder_id) else {
                continue;
            };
            if let Some(p) = self.pause_of(&rec, &root, &state) {
                inputs.paused.push(PausedIn {
                    folder: rec.name.clone(),
                    kind: match p.kind {
                        PauseKind::MarkerMissing => "marker_missing",
                        PauseKind::MarkerOther => "marker_other",
                        PauseKind::DeletionsHeld => "deletions_held",
                    }
                    .into(),
                    count: state.held.as_ref().map_or(0, |h| h.paths.len() as u64),
                });
            }
            if self.share_read_only(&rec) {
                let dir = self
                    .home
                    .join(KEPT_ASIDE_DIR)
                    .join(rec.name.replace(['/', '\\', ':'], "_"));
                let files = walkdir::WalkDir::new(&dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .count() as u64;
                if files > 0 {
                    inputs.kept_aside.push(KeptAsideIn {
                        folder: rec.name.clone(),
                        files,
                        dir: dir.display().to_string(),
                    });
                }
            }
        }

        // Places below their minimum free space (`freespace`).
        inputs.low_space = crate::freespace::short_places()
            .into_iter()
            .map(|l| LowSpaceIn {
                key: l.place.key,
                label: l.place.label,
                stops: l.place.stops,
                free: l.free,
            })
            .collect();
        inputs.torrents = self.torrent_help_inputs();
        Ok(inputs)
    }
}
