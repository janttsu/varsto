// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The snapshot behind the live visualization page (`GET /api/viz`, spec
//! section 63). Two parts from the engine, both read from data the engine
//! already holds (the ledger view, the folder states, the pool indexes and the
//! small state files; nothing is read from a storage): `Heavy` (devices,
//! storages, folders, copies and policies; a pass over the ledger, so the
//! service caches it for a while) and `Light` (disks, drains, moves, repairs,
//! verification; cheap). `compose` joins them with what runs right now
//! (activity tasks, transfers, peer traffic, which need no engine at all)
//! into the JSON the page draws. `compose` is pure: the same input gives the
//! same JSON.

use crate::activity::{self, PeerActivity, TaskView, Unit};
use crate::p2p::traffic::TrafficReport;
use crate::progress::Progress;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Version of the JSON layout (`v`).
pub const VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Default)]
pub struct Price {
    pub per_gb_month: Option<f64>,
    pub egress_per_gb: Option<f64>,
    pub retrieval_per_gb: Option<f64>,
    pub currency: String,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct StorageViz {
    pub name: String,
    /// "directory", "s3", "rclone", "pool", "transferrer", "replica", "unknown".
    pub kind: String,
    pub place: String,
    pub configured: bool,
    pub cold: bool,
    pub carrier: bool,
    /// Bytes of current files' blocks the ledger records here.
    pub data_bytes: u64,
    /// Bytes of those that a device other than the writer has verified.
    pub verified_bytes: u64,
    /// Bytes in use against the quota (blocks plus records), when a quota is known.
    pub used_bytes: u64,
    pub quota_bytes: Option<u64>,
    pub percent: Option<u32>,
    /// "none" (no quota), "ok", "warning", "full".
    pub state: String,
    pub price: Option<Price>,
    pub monthly_cost: Option<f64>,
    /// What reading everything here back once would cost (egress and retrieval).
    pub read_all_cost: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct DeviceViz {
    pub id: String,
    pub name: String,
    /// "this", "peer", "replica" or "member".
    pub role: String,
    /// "linux", "macos", "windows", "android", "ios" or "".
    pub platform: String,
    pub revoked: bool,
    pub app_version: String,
    pub last_sync_utc: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct FolderViz {
    pub name: String,
    pub bytes: u64,
    pub files: u64,
    pub blocks: u64,
    pub mode: String,
    pub shared: bool,
    pub read_only: bool,
    pub strongroom: Option<String>,
    pub paused: Option<String>,
    /// Policy in words, its verdict (ok, at_risk, violated, unknown) and why.
    pub policy: Option<String>,
    pub policy_state: String,
    pub policy_reasons: Vec<String>,
    pub policy_warnings: Vec<String>,
    pub blocks_short_of_copies: u64,
    pub blocks_unverified_in_window: u64,
    /// Blocks stored recently and not yet verified (neutral, within the grace).
    #[serde(default)]
    pub blocks_verification_pending: u64,
    pub oldest_verification_days: Option<i64>,
    /// Blocks with no kept copy on any storage.
    pub unprotected_blocks: u64,
    /// Blocks verified by a device other than the writer.
    pub verified_blocks: u64,
    /// Blocks stored but not independently verified.
    pub unverified_blocks: u64,
    /// Blocks only on this device or nowhere.
    pub local_only_blocks: u64,
    pub missing_blocks: u64,
    /// Bytes per storage name and per device id.
    pub storages: BTreeMap<String, u64>,
    pub devices: BTreeMap<String, u64>,
    /// Storages a new block of the folder is written to on this device.
    pub targets: Vec<String>,
}

/// Blocks by kept copies: none, one, two, three or more (bytes in the same order).
#[derive(Clone, Debug, Serialize, Default)]
pub struct CopiesViz {
    pub blocks: [u64; 4],
    pub bytes: [u64; 4],
    pub average: f64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Heavy {
    pub utc: i64,
    pub this_device: String,
    pub vault_name: String,
    pub key_epoch: u32,
    pub member: bool,
    pub forked_devices: Vec<String>,
    pub ledger_state: String,
    pub ledger_text: String,
    pub total_bytes: u64,
    pub devices: Vec<DeviceViz>,
    pub storages: Vec<StorageViz>,
    pub folders: Vec<FolderViz>,
    pub copies: CopiesViz,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct DiskViz {
    pub pool: String,
    pub label: String,
    pub place: String,
    pub docked: bool,
    pub retired: bool,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: Option<u64>,
    pub objects: u64,
    pub last_verified_utc: i64,
    pub overdue_share: f64,
    pub failing: Option<String>,
    pub reclaimable_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct MoveViz {
    pub id: String,
    pub folder: String,
    pub from: String,
    pub to: String,
    /// "open" or "paused".
    pub state: String,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub bytes_remaining: u64,
    pub started_utc: i64,
    /// "disk", "room" or "place" when the job waits for something.
    pub waiting: Option<String>,
    pub waiting_text: Option<String>,
    pub waiting_disk: Option<String>,
    pub keep_source: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct DrainViz {
    pub storage: String,
    pub phase: String,
    pub percent: u32,
    pub bytes_left: u64,
    pub eta_utc: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Schedule {
    pub enabled: bool,
    pub last_run_utc: Option<i64>,
    pub next_run_utc: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct BackupViz {
    pub name: String,
    pub stopped: bool,
    pub snapshots: u64,
    pub latest_utc: Option<i64>,
    pub next_due_utc: Option<i64>,
    pub requested: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Light {
    pub utc: i64,
    pub disks: Vec<DiskViz>,
    pub drains: Vec<DrainViz>,
    pub moves: Vec<MoveViz>,
    pub verify: Schedule,
    pub scrub: Schedule,
    pub repair_queued: u64,
    pub repair_losses: u64,
    pub repair_error: Option<String>,
    pub damaged_files: u64,
    pub backups: Vec<BackupViz>,
}

/// What runs right now; none of it needs the engine.
#[derive(Clone, Debug, Default)]
pub struct LiveInput {
    pub now_utc: i64,
    pub this_device: String,
    pub this_name: String,
    pub tasks: Vec<TaskView>,
    pub peers: Vec<PeerActivity>,
    pub traffic: TrafficReport,
    pub transfers: Vec<Progress>,
}

fn eta_of(done: u64, total: u64, rate: u64, now: i64) -> Option<i64> {
    (total > done && rate > 0).then(|| now + (total - done).div_ceil(rate) as i64)
}

fn node_dev(id: &str) -> String {
    format!("d:{id}")
}
fn node_sto(name: &str) -> String {
    format!("s:{name}")
}
fn node_disk(label: &str) -> String {
    format!("p:{label}")
}

/// Join the engine parts with the live data. `heavy`/`light` are `None`
/// while the vault is locked or has not been read yet.
pub fn compose(heavy: Option<&Heavy>, light: Option<&Light>, live: &LiveInput) -> Value {
    let now = live.now_utc;
    let h_default = Heavy::default();
    let l_default = Light::default();
    let h = heavy.unwrap_or(&h_default);
    let l = light.unwrap_or(&l_default);
    let me = live.this_device.clone();

    // Devices: those of the vault, with whether they answered lately.
    let mut devices: Vec<Value> = Vec::new();
    for d in &h.devices {
        let pt = live
            .traffic
            .peers
            .iter()
            .find(|p| p.device.to_string() == d.id);
        let pa = live.peers.iter().find(|p| p.device == d.id);
        let online = d.role == "this"
            || pt.is_some_and(|p| p.last_seen_utc.is_some_and(|t| now - t < 90) || p.active > 0)
            || pa.is_some_and(|p| p.status == "ok" && !p.stale);
        devices.push(json!({
            "id": d.id, "name": d.name, "role": d.role, "platform": d.platform,
            "revoked": d.revoked, "online": online && !d.revoked,
            "app_version": d.app_version, "last_sync_utc": d.last_sync_utc,
            "path": pt.map(|p| p.path.clone()).unwrap_or_default(),
            "rx_bps": pt.map_or(0, |p| p.rx_bps), "tx_bps": pt.map_or(0, |p| p.tx_bps),
            "busy": pa.and_then(|p| p.activity.as_ref()).is_some_and(|a| a.state == "busy")
                || (d.role == "this" && !live.tasks.is_empty()),
        }));
    }
    if devices.is_empty() && !me.is_empty() {
        devices.push(
            json!({"id": me, "name": live.this_name, "role": "this", "platform": "",
            "revoked": false, "online": true, "path": "", "rx_bps": 0, "tx_bps": 0,
            "busy": !live.tasks.is_empty()}),
        );
    }

    let folder = |name: &str| h.folders.iter().find(|f| f.name == name);
    let best_source = |name: &str| -> Option<String> {
        folder(name).and_then(|f| {
            f.storages
                .iter()
                .filter(|(s, _)| h.storages.iter().any(|x| &x.name == *s && !x.carrier))
                .max_by_key(|(_, b)| **b)
                .map(|(s, _)| s.clone())
        })
    };

    let mut flows: Vec<Value> = Vec::new();
    let mut jobs: Vec<Value> = Vec::new();
    let mut busy_disks: BTreeMap<String, (String, Option<u32>, Option<i64>)> = BTreeMap::new();

    // Tasks of this device and of the peers, as jobs and (where the data
    // moves between two known places) as flows.
    let mut all: Vec<(String, String, &TaskView)> = Vec::new();
    for t in &live.tasks {
        all.push((me.clone(), live.this_name.clone(), t));
    }
    for p in &live.peers {
        if let Some(a) = &p.activity {
            for t in &a.tasks {
                all.push((p.device.clone(), p.name.clone(), t));
            }
        }
    }
    for (dev, dev_name, t) in &all {
        let dev = if dev.is_empty() {
            me.clone()
        } else {
            dev.clone()
        };
        let eta = t.eta_utc.or_else(|| eta_of(t.done, t.total, t.rate, now));
        let bytes = t.unit == Unit::Bytes;
        jobs.push(json!({
            "id": format!("{dev}:{}", t.id), "kind": t.kind, "phase": t.phase,
            "subject": t.subject, "detail": t.detail, "device": dev, "device_name": dev_name,
            "done": t.done, "total": t.total, "unit": if bytes { "bytes" } else { "items" },
            "percent": t.percent, "rate": t.rate, "eta_utc": eta, "started_utc": t.started_utc,
        }));
        let from_dev = node_dev(&dev);
        let mut add = |kind: &str, from: String, to: String, share: u64| {
            flows.push(json!({
                "id": format!("{kind}:{dev}:{}:{to}", t.id), "kind": kind, "from": from, "to": to,
                "folder": t.subject, "bps": if bytes { share } else { 0 },
                "unit": if bytes { "bytes" } else { "items" }, "rate": share,
                "done": t.done, "total": t.total,
                "remaining": if t.total > t.done { Some(t.total - t.done) } else { None },
                "eta_utc": eta, "device": dev,
            }));
        };
        match t.kind.as_str() {
            activity::UPLOAD => {
                let targets: Vec<String> = folder(&t.subject)
                    .map(|f| f.targets.clone())
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| {
                        h.storages
                            .iter()
                            .filter(|s| s.configured)
                            .map(|s| s.name.clone())
                            .collect()
                    });
                let n = targets.len().max(1) as u64;
                for s in targets {
                    add("upload", from_dev.clone(), node_sto(&s), t.rate / n);
                }
            }
            activity::DOWNLOAD | activity::RESTORE => {
                if let Some(s) = best_source(&t.subject) {
                    add("download", node_sto(&s), from_dev.clone(), t.rate);
                }
            }
            activity::DISK_FILL => {
                add("disk_fill", from_dev.clone(), node_disk(&t.subject), t.rate);
            }
            activity::DRAIN => {
                add("drain", node_sto(&t.subject), from_dev.clone(), t.rate);
            }
            activity::DATA_MOVE => {
                if let Some(m) = l
                    .moves
                    .iter()
                    .find(|m| m.folder == t.subject && m.state == "open")
                {
                    add("move", node_sto(&m.from), node_sto(&m.to), t.rate);
                }
            }
            _ => {}
        }
        if matches!(
            t.kind.as_str(),
            activity::DISK_CHECK
                | activity::DISK_FSCK
                | activity::DISK_INSERT
                | activity::DISK_FETCH
                | activity::DISK_INIT
                | activity::DISK_UNMOUNT
                | activity::DISK_FILL
        ) {
            let phase = match t.kind.as_str() {
                activity::DISK_FILL => "fill",
                activity::DISK_CHECK => "verify",
                activity::DISK_FSCK => "fsck",
                activity::DISK_INSERT => "tidy",
                activity::DISK_FETCH => "fetch",
                activity::DISK_INIT => "init",
                _ => "unmount",
            };
            busy_disks.insert(t.subject.clone(), (phase.to_string(), t.percent, eta));
        }
    }

    // Peer-to-peer traffic: bytes flowing between this device and its peers.
    for p in &live.traffic.peers {
        let id = p.device.to_string();
        if p.rx_bps > 0 {
            flows.push(json!({"id": format!("p2p:{id}:rx"), "kind": "p2p", "from": node_dev(&id),
                "to": node_dev(&me), "folder": "", "bps": p.rx_bps, "unit": "bytes", "rate": p.rx_bps,
                "done": 0, "total": 0, "remaining": null, "eta_utc": null, "path": p.path}));
        }
        if p.tx_bps > 0 {
            flows.push(json!({"id": format!("p2p:{id}:tx"), "kind": "p2p", "from": node_dev(&me),
                "to": node_dev(&id), "folder": "", "bps": p.tx_bps, "unit": "bytes", "rate": p.tx_bps,
                "done": 0, "total": 0, "remaining": null, "eta_utc": null, "path": p.path}));
        }
    }
    for r in &live.traffic.relays {
        if r.bps > 0 {
            flows.push(
                json!({"id": format!("relay:{}:{}", r.from, r.to), "kind": "relay",
                "from": node_dev(&r.from.to_string()), "to": node_dev(&r.to.to_string()),
                "folder": "", "bps": r.bps, "unit": "bytes", "rate": r.bps,
                "done": 0, "total": 0, "remaining": null, "eta_utc": null}),
            );
        }
    }
    // Disks: docked or not, and what the docked one is doing.
    let disks: Vec<Value> = l
        .disks
        .iter()
        .map(|d| {
            let busy = busy_disks.get(&d.label);
            let waiting = l.moves.iter().find(|m| {
                m.state == "open" && m.waiting.as_deref() == Some("disk") && m.to == d.pool
                    && m.waiting_disk.as_deref().is_none_or(|w| w == d.label)
            });
            let (phase, progress, eta) = match busy {
                Some((p, pr, e)) => (p.as_str(), *pr, *e),
                None if d.docked => ("idle", None, None),
                None if waiting.is_some() => ("wanted", None, None),
                None => ("away", None, None),
            };
            json!({
                "pool": d.pool, "label": d.label, "place": d.place, "docked": d.docked,
                "retired": d.retired, "capacity_bytes": d.capacity_bytes, "used_bytes": d.used_bytes,
                "free_bytes": d.free_bytes, "objects": d.objects, "last_verified_utc": d.last_verified_utc,
                "overdue_share": d.overdue_share, "failing": d.failing, "reclaimable_bytes": d.reclaimable_bytes,
                "phase": phase, "progress": progress, "eta_utc": eta,
                "wanted_by": waiting.map(|m| m.id.clone()),
            })
        })
        .collect();
    let docked_now = l
        .disks
        .iter()
        .filter(|d| d.docked)
        .map(|d| d.label.clone())
        .collect::<Vec<_>>();
    let working_on = busy_disks.keys().next().cloned();

    // Storages with their current drain.
    let storages: Vec<Value> = h
        .storages
        .iter()
        .map(|s| {
            let drain = l.drains.iter().find(|d| d.storage == s.name);
            let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
            v["drain"] = serde_json::to_value(drain).unwrap_or(Value::Null);
            v["id"] = Value::String(node_sto(&s.name));
            v
        })
        .collect();

    // Cost totals per currency; estimates, never converted.
    let mut month: BTreeMap<String, f64> = BTreeMap::new();
    let mut read_all: BTreeMap<String, f64> = BTreeMap::new();
    let mut unpriced: Vec<String> = Vec::new();
    for s in h.storages.iter().filter(|s| s.configured && !s.carrier) {
        match (&s.price, s.monthly_cost) {
            (Some(p), Some(c)) => {
                *month.entry(p.currency.clone()).or_default() += c;
                if let Some(r) = s.read_all_cost {
                    *read_all.entry(p.currency.clone()).or_default() += r;
                }
            }
            _ if s.kind != "directory" && s.kind != "pool" && s.data_bytes > 0 => {
                unpriced.push(s.name.clone())
            }
            _ => {}
        }
    }

    // Alerts.
    let mut alerts: Vec<Value> = Vec::new();
    let mut alert = |level: &str, code: &str, subject: &str, text: String| {
        alerts.push(json!({"level": level, "code": code, "subject": subject, "text": text}));
    };
    if h.ledger_state != "ok" && !h.ledger_state.is_empty() {
        alert(
            "bad",
            "ledger",
            "",
            format!("Ledger: {} {}", h.ledger_state, h.ledger_text)
                .trim()
                .to_string(),
        );
    }
    if !h.forked_devices.is_empty() {
        alert(
            "bad",
            "forked",
            "",
            format!("Forked devices: {}", h.forked_devices.join(", ")),
        );
    }
    for f in &h.folders {
        match f.policy_state.as_str() {
            "violated" => alert(
                "bad",
                "policy",
                &f.name,
                f.policy_reasons
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Policy violated".into()),
            ),
            "at_risk" => alert(
                "warn",
                "policy",
                &f.name,
                f.policy_warnings
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Policy at risk".into()),
            ),
            _ => {}
        }
        if f.missing_blocks > 0 {
            alert(
                "bad",
                "missing",
                &f.name,
                format!("{} blocks exist nowhere", f.missing_blocks),
            );
        }
        if let Some(p) = &f.paused {
            alert("warn", "paused", &f.name, p.clone());
        }
    }
    for s in &h.storages {
        match s.state.as_str() {
            "full" => alert("bad", "full", &s.name, format!("{} is full", s.name)),
            "warning" => alert(
                "warn",
                "quota",
                &s.name,
                format!("{} is almost full", s.name),
            ),
            _ => {}
        }
    }
    for d in &l.drains {
        if d.phase == "blocked" {
            alert(
                "warn",
                "drain",
                &d.storage,
                format!("Drain of {} is blocked", d.storage),
            );
        }
    }
    for d in &l.disks {
        if let Some(r) = &d.failing {
            alert(
                "bad",
                "disk",
                &d.label,
                format!("Disk {} should not be used: {r}", d.label),
            );
        }
    }
    if l.repair_losses > 0 {
        alert(
            "bad",
            "repair",
            "",
            format!("{} damaged copies could not be repaired", l.repair_losses),
        );
    } else if l.repair_queued > 0 {
        alert(
            "warn",
            "repair",
            "",
            format!("{} damaged copies wait for repair", l.repair_queued),
        );
    }
    if l.damaged_files > 0 {
        alert(
            "bad",
            "scrub",
            "",
            format!(
                "{} damaged files wait for their recorded version",
                l.damaged_files
            ),
        );
    }
    if let Some(e) = &l.repair_error {
        alert("warn", "repair", "", e.clone());
    }
    for m in l.moves.iter().filter(|m| m.state == "open") {
        if let Some(t) = &m.waiting_text {
            alert("info", "move", &m.folder, t.clone());
        }
    }
    let worst = if alerts.iter().any(|a| a["level"] == "bad") {
        "bad"
    } else if alerts.iter().any(|a| a["level"] == "warn") {
        "warn"
    } else {
        "ok"
    };

    let folders: Vec<Value> = h
        .folders
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or(Value::Null))
        .collect();
    let tr = &live.traffic.totals;
    json!({
        "v": VERSION,
        "utc": now,
        "unlocked": heavy.is_some(),
        "data_utc": heavy.map(|x| x.utc),
        "light_utc": light.map(|x| x.utc),
        "this_device": me,
        "vault_name": h.vault_name,
        "key_epoch": h.key_epoch,
        "member": h.member,
        "total_bytes": h.total_bytes,
        "devices": devices,
        "storages": storages,
        "disks": {
            "count": l.disks.len(),
            "docked": docked_now,
            "working_on": working_on,
            "list": disks,
        },
        "folders": folders,
        "copies": h.copies,
        "flows": flows,
        "jobs": jobs,
        "moves": l.moves,
        "drains": l.drains,
        "backups": l.backups,
        "alerts": alerts,
        "health": {
            "overall": worst,
            "ledger": h.ledger_state,
            "verify": l.verify,
            "scrub": l.scrub,
            "repair": {"queued": l.repair_queued, "losses": l.repair_losses, "last_error": l.repair_error},
        },
        "traffic": {"rx_bps": tr.rx_bps, "tx_bps": tr.tx_bps, "relay_bps": tr.relay_bps,
                    "active": tr.active, "history_rx": live.traffic.history.rx, "history_tx": live.traffic.history.tx},
        "cost": {
            "estimate": true,
            "month": month,
            "read_all_once": read_all,
            "unpriced": unpriced,
            "note": "Estimates from the storage prices (set by you or from the built-in price data); request fees and tax are not included.",
        },
    })
}
