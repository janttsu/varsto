// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The engine side of the live visualization snapshot (`crate::viz`,
//! spec section 63): `viz_heavy` (a few passes over the ledger view, the
//! folder states and the policy check) and `viz_light` (pool indexes, small
//! state files). Read-only; no storage is listed or read.

use super::*;
use crate::viz::{
    BackupViz, CopiesViz, DeviceViz, DiskViz, DrainViz, FolderViz, Heavy, Light, MoveViz, Price,
    Schedule, StorageViz,
};

impl Engine {
    /// Devices, storages, folders, copies and policies for the visualization.
    pub fn viz_heavy(&self) -> Result<Heavy> {
        let now = util::now_utc();
        let status = self.status()?;
        let loc = self.data_locations()?;
        let quotas: BTreeMap<String, QuotaStatus> = self
            .quota_statuses()?
            .into_iter()
            .map(|q| (q.storage.clone(), q))
            .collect();
        let policies: BTreeMap<String, crate::policy::PolicyReport> = self
            .policy_check_at(now)?
            .into_iter()
            .map(|r| (r.folder.clone(), r))
            .collect();

        let mut devices: Vec<DeviceViz> = Vec::new();
        for d in self.devices_list() {
            let det = d.details.as_ref();
            devices.push(DeviceViz {
                id: d.device_id.clone(),
                name: d.name.clone(),
                role: if d.this_device { "this" } else { "peer" }.to_string(),
                platform: det.map(|x| x.platform.clone()).unwrap_or_default(),
                revoked: d.revoked,
                app_version: det.map(|x| x.app_version.clone()).unwrap_or_default(),
                last_sync_utc: det.and_then(|x| x.last_sync_utc),
            });
        }
        for (id, name) in &status.replicas {
            devices.push(DeviceViz {
                id: id.clone(),
                name: name.clone(),
                role: "replica".into(),
                ..Default::default()
            });
        }
        for (id, name) in &status.members {
            devices.push(DeviceViz {
                id: id.clone(),
                name: name.clone(),
                role: "member".into(),
                ..Default::default()
            });
        }
        devices.retain(|d| !d.revoked);

        // Storages other devices name (this device has no specification for
        // them) are left out; replica devices stay.
        let storages: Vec<StorageViz> = loc
            .storages
            .iter()
            .filter(|s| s.configured || s.kind == "replica")
            .map(|s| {
                let q = quotas.get(&s.name);
                let price = s
                    .configured
                    .then(|| self.storage_price(&s.name))
                    .flatten()
                    .filter(|p| !p.is_empty());
                StorageViz {
                    name: s.name.clone(),
                    kind: s.kind.clone(),
                    place: s.place.clone(),
                    configured: s.configured,
                    cold: s.cold,
                    carrier: s.carrier,
                    data_bytes: s.bytes,
                    verified_bytes: s.verified_bytes,
                    used_bytes: q.map_or(s.bytes, |q| q.used_bytes),
                    quota_bytes: q.and_then(|q| q.quota_bytes),
                    percent: q.and_then(|q| q.percent),
                    state: q.map_or("none", |q| q.state.as_str()).to_string(),
                    monthly_cost: s.monthly_cost,
                    read_all_cost: price.as_ref().and_then(|p| p.read_cost(s.bytes)),
                    price: price.map(|p| Price {
                        per_gb_month: p.storage_per_gb_month,
                        egress_per_gb: p.egress_per_gb,
                        retrieval_per_gb: p.retrieval_per_gb,
                        currency: p.currency.clone(),
                        source: p.source.clone(),
                    }),
                }
            })
            .collect();

        let mut folders = Vec::new();
        for f in &status.folders {
            let share = loc.folders.iter().find(|x| x.folder_id == f.folder_id);
            let pol = policies.get(&f.name);
            folders.push(FolderViz {
                name: f.name.clone(),
                bytes: f.bytes,
                files: f.files,
                blocks: f.chunks,
                mode: serde_json::to_value(f.mode)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                shared: f.shared,
                read_only: f.read_only,
                strongroom: f.strongroom.clone(),
                paused: f.paused.as_ref().map(|p| p.message.clone()),
                policy: f.policy.clone(),
                policy_state: pol
                    .map(|p| serde_json::to_value(p.state).ok())
                    .and_then(|v| v.and_then(|v| v.as_str().map(str::to_string)))
                    .unwrap_or_else(|| "none".to_string()),
                policy_reasons: pol.map(|p| p.reasons.clone()).unwrap_or_default(),
                policy_warnings: pol.map(|p| p.warnings.clone()).unwrap_or_default(),
                blocks_short_of_copies: pol.map_or(0, |p| p.chunks_short_of_copies),
                blocks_unverified_in_window: pol.map_or(0, |p| p.chunks_unverified_in_window),
                oldest_verification_days: pol.and_then(|p| p.oldest_verification_days),
                unprotected_blocks: f.chunks_without_storage_copy,
                verified_blocks: f.blocks.verified_here + f.blocks.verified_away,
                unverified_blocks: f.blocks.stored_here + f.blocks.stored_away,
                local_only_blocks: f.blocks.local_only,
                missing_blocks: f.blocks.missing,
                storages: share.map(|s| s.storages.clone()).unwrap_or_default(),
                devices: share.map(|s| s.devices.clone()).unwrap_or_default(),
                targets: self
                    .placement(&f.name)
                    .map(|p| p.targets)
                    .unwrap_or_default(),
            });
        }

        Ok(Heavy {
            utc: now,
            this_device: status.device_id.clone(),
            vault_name: status.device_name.clone(),
            key_epoch: status.key_epoch,
            member: status.member,
            forked_devices: status.forked_devices.clone(),
            ledger_state: status.ledger_health.state.clone(),
            ledger_text: status
                .ledger_health
                .problems
                .first()
                .map(|p| p.detail.clone())
                .unwrap_or_default(),
            total_bytes: loc.total_bytes,
            devices,
            storages,
            folders,
            copies: CopiesViz {
                blocks: [
                    loc.copies.none,
                    loc.copies.one,
                    loc.copies.two,
                    loc.copies.three_plus,
                ],
                bytes: loc.copies.bytes,
                average: loc.copies.average,
            },
        })
    }

    /// Disks, drains, moves, repairs, verification and backups: small state only.
    pub fn viz_light(&self) -> Result<Light> {
        let now = util::now_utc();
        let mut disks = Vec::new();
        for spec in self.pool_specs() {
            let Ok(pool) = self.open_pool(&spec) else {
                continue;
            };
            for d in pool.statuses() {
                disks.push(DiskViz {
                    pool: d.pool,
                    label: d.label,
                    place: d.place,
                    docked: d.attached,
                    retired: d.retired,
                    capacity_bytes: d.capacity_bytes,
                    used_bytes: d.used_bytes,
                    free_bytes: d.free_bytes,
                    objects: d.objects,
                    last_verified_utc: d.last_verified_utc,
                    overdue_share: d.overdue_share,
                    failing: d.failing.then(|| d.failing_reason.unwrap_or_default()),
                    reclaimable_bytes: d.reclaimable_bytes,
                });
            }
        }
        let drains = self
            .drain_statuses()?
            .into_iter()
            .map(|d| DrainViz {
                storage: d.storage,
                phase: d.phase,
                percent: d.percent,
                bytes_left: d.bytes_left,
                eta_utc: d.eta_utc,
                last_error: d.last_error,
            })
            .collect();
        let moves = self
            .move_jobs()
            .into_iter()
            .filter(|j| {
                matches!(
                    j.state,
                    crate::staged_move::JobState::Open | crate::staged_move::JobState::Paused
                )
            })
            .map(|j| MoveViz {
                id: j.id,
                folder: j.folder,
                from: j.from,
                to: j.to,
                state: j.state.label().to_string(),
                bytes_total: j.bytes_total,
                bytes_done: j.bytes_done,
                bytes_remaining: j.bytes_remaining,
                started_utc: j.started_utc,
                waiting: j.waiting.as_ref().map(|w| w.kind.clone()),
                waiting_text: j.waiting.as_ref().map(|w| w.text.clone()),
                waiting_disk: j.waiting.as_ref().and_then(|w| w.disk.clone()),
                keep_source: j.keep_source,
            })
            .collect();
        let v = self.verify_status();
        let sc = self.scrub_status();
        let rp = self.repair_status();
        let backups = self
            .backups()
            .unwrap_or_default()
            .into_iter()
            .map(|b| BackupViz {
                name: b.name,
                stopped: b.stopped,
                snapshots: b.snapshots,
                latest_utc: b.latest_utc,
                next_due_utc: b.next_due_utc,
                requested: b.snapshot_requested,
            })
            .collect();
        Ok(Light {
            utc: now,
            disks,
            drains,
            moves,
            verify: Schedule {
                enabled: v.schedule.enabled,
                last_run_utc: v.last_run_utc,
                next_run_utc: v.next_run_utc,
                last_error: v.last_error,
            },
            scrub: Schedule {
                enabled: sc.schedule.enabled,
                last_run_utc: sc.last_run_utc,
                next_run_utc: sc.next_run_utc,
                last_error: sc.last_error,
            },
            repair_queued: rp.queued,
            repair_losses: rp.open_losses.len() as u64,
            repair_error: rp.last_error,
            damaged_files: sc.unrestored.len() as u64,
            backups,
        })
    }
}
