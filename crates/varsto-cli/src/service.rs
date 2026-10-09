// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Background service: watches attached folders, syncs on change and on a
//! timer, serves the local API and desktop page, and writes `service.json`
//! so that the menu-bar app and the CLI can find it.
//!
//! Unlocking: the service starts locked unless the passphrase comes from the
//! `VARSTO_PASSPHRASE` environment variable or, on macOS, from the login
//! keychain (`security find-generic-password -s varsto -a <home>`), where the
//! menu-bar app can store it. The desktop page can unlock it as well.

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceFile {
    pub pid: u32,
    pub port: u16,
    pub token: String,
    pub started_utc: i64,
    pub version: String,
}

/// Runtime state of the service, shared with the API.
#[derive(Default)]
pub struct ServiceState {
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
    /// Removable disks of every pool as of the last check (every 30 seconds).
    pub disks: Vec<varsto_core::pool::DiskStatus>,
    /// NAT traversal: what STUN saw, the NAT guess, whether we are reachable,
    /// the relays we are registered with, and the path to every peer.
    pub p2p_nat: varsto_core::p2p::stun::Nat,
    pub p2p_public: Vec<std::net::SocketAddr>,
    pub p2p_reachable: bool,
    pub p2p_relays: Vec<String>,
    pub p2p_paths: Vec<varsto_core::p2p::PeerStatus>,
    pub p2p_cert_sha256: String,
    /// Automatic verification: schedule, last run and next run.
    pub auto_verify: Option<varsto_core::autoverify::VerifyStatus>,
}

impl ServiceState {
    pub fn summary(&self) -> Value {
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
            "p2p_nat": self.p2p_nat,
            "p2p_public": self.p2p_public,
            "p2p_reachable": self.p2p_reachable,
            "p2p_relays": self.p2p_relays,
            "p2p_paths": self.p2p_paths,
            "auto_verify": self.auto_verify,
            "auto_verify_text": self.auto_verify.as_ref().map(|v| v.describe()),
        })
    }
    /// Store the disk listing; log and notify when a disk appeared or went
    /// away, and ask for a sync when one appeared (pending files may be on it).
    pub fn record_disks(&mut self, disks: Vec<varsto_core::pool::DiskStatus>) {
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
                let msg = format!("{} {ev}", d.label);
                eprintln!("service: disk {msg}");
                notify("Varsto disk", &msg);
                if ev == "attached" {
                    self.sync_requested = true;
                }
            }
        }
        self.disks = disks;
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
            eprintln!("service: {a}");
            notify("Varsto durability policy", &a);
        }
    }
    /// Run automatic verification when the schedule says it is due (called
    /// after a sync, so never while paused or locked) and keep its status.
    pub fn auto_verify_if_due(&mut self, engine: &mut Engine) {
        if engine.auto_verify_due(varsto_core::util::now_utc()) {
            match engine.auto_verify() {
                Ok(r) => {
                    eprintln!(
                        "service: automatic verification: {} blocks verified, {} left for the next run",
                        r.blocks_verified, r.left_for_next_run
                    );
                    if !r.corrupt.is_empty() || !r.missing.is_empty() {
                        let msg = format!(
                            "{} blocks do not match their hash and {} are missing on a storage; run `varsto fsck --verify`",
                            r.corrupt.len(),
                            r.missing.len()
                        );
                        eprintln!("service: {msg}");
                        notify("Varsto verification", &msg);
                    }
                }
                Err(e) => eprintln!("service: automatic verification failed: {e:#}"),
            }
        }
        self.auto_verify = Some(engine.verify_status());
    }
    pub fn request_sync(&mut self) {
        self.sync_requested = true;
    }
    pub fn record_sync(&mut self, reports: &[(PullReport, PushReport)]) {
        self.last_sync_utc = Some(varsto_core::util::now_utc());
        self.syncs += 1;
        let mut updated = 0;
        let mut deleted = 0;
        let mut conflicts = 0;
        let mut uploaded = 0;
        let mut unavailable = 0;
        let mut forked = false;
        let mut disks: Vec<String> = Vec::new();
        for (pl, ps) in reports {
            self.p2p_chunks += pl.chunks_from_peers;
            updated += pl.files_updated;
            deleted += pl.files_deleted;
            conflicts += pl.conflicts;
            uploaded += ps.chunks_uploaded;
            unavailable += pl.files_unavailable.len();
            forked |= !pl.forked_devices.is_empty();
            for d in &pl.disks_needed {
                if !disks.contains(d) {
                    disks.push(d.clone());
                }
            }
        }
        self.last_result = format!("{} folders: {updated} updated, {deleted} deleted, {conflicts} conflicts, {uploaded} chunks uploaded{}{}{}", reports.len(), if unavailable > 0 { format!(", {unavailable} unavailable") } else { String::new() }, if disks.is_empty() { String::new() } else { format!(" (attach disk {})", disks.join(", ")) }, if forked { ", FORKED device" } else { "" });
        self.last_error = None;
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

/// Peer-to-peer runtime of the service: TCP listener thread, QUIC node on
/// the same port number, beacon thread, NAT probe thread, relay thread, a
/// shared snapshot of what we serve, and the peer table.
struct P2p {
    snapshot: Arc<Mutex<Option<Arc<varsto_core::p2p::Snapshot>>>>,
    lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>>,
    listen: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    quic: Option<Arc<varsto_core::p2p::quic::Node>>,
    /// Latest records of the other devices, for the relay thread.
    records: Arc<Mutex<Vec<varsto_core::p2p::PeerRecord>>>,
    nat: Arc<Mutex<NatInfo>>,
    peers: Mutex<Option<Arc<varsto_core::p2p::Peers>>>,
    last_record: Mutex<Option<varsto_core::p2p::PeerRecord>>,
    last_publish: Mutex<Option<Instant>>,
    /// Set by the relay thread when a registration succeeded: the record
    /// should go out now, so peers learn `relay_via` without waiting for a sync.
    republish: Arc<std::sync::atomic::AtomicBool>,
    /// The service's traffic counters (`State::traffic`).
    traffic: Arc<varsto_core::p2p::Traffic>,
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
        let (cfg, tag, device, identity, peer_key, traffic) = {
            let st = state.lock().unwrap();
            let e = st.engine.as_ref()?;
            let cfg = e.p2p_config();
            if !cfg.enabled {
                return None;
            }
            st.traffic.set_me(e.device_id(), e.own_device_name());
            let identity = match e.p2p_identity() {
                Ok(id) => Some(id),
                Err(err) => {
                    eprintln!("service: p2p certificate unavailable, QUIC disabled: {err:#}");
                    None
                }
            };
            (
                cfg,
                e.wire_vault_tag(),
                e.device_id().clone(),
                identity,
                e.peer_key(),
                st.traffic.clone(),
            )
        };
        let server = match varsto_core::p2p::Server::bind(([0, 0, 0, 0], cfg.port).into()) {
            Ok(s) => s.with_traffic(traffic.clone()),
            Err(e) => {
                eprintln!("service: p2p listener failed: {e:#}");
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
        let quic = identity.and_then(|id| {
            match varsto_core::p2p::quic::Node::start(
                ([0, 0, 0, 0], listen.port()).into(),
                id,
                device.clone(),
                peer_key,
                snapshot.clone(),
                traffic.clone(),
            ) {
                Ok(n) => {
                    n.start_keeper();
                    Some(n)
                }
                Err(e) => {
                    eprintln!("service: p2p QUIC listener failed, TCP only: {e:#}");
                    None
                }
            }
        });
        let cert_sha256 = quic
            .as_ref()
            .map(|n| n.identity().sha256.clone())
            .unwrap_or_default();

        let lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>> =
            Arc::new(Mutex::new(Vec::new()));
        let (lan2, stop3) = (lan_peers.clone(), stop.clone());
        match varsto_core::p2p::Beacon::new(tag, device, listen.port()) {
            Ok(beacon) => {
                let _ = std::thread::Builder::new()
                    .name("p2p-beacon".into())
                    .spawn(move || {
                        let mut heard: std::collections::BTreeMap<
                            std::net::SocketAddr,
                            (varsto_core::p2p::PeerAddr, Instant),
                        > = Default::default();
                        while !stop3.load(std::sync::atomic::Ordering::Relaxed) {
                            beacon.announce();
                            for p in beacon.listen(Duration::from_secs(5)) {
                                heard.insert(p.addr, (p, Instant::now()));
                            }
                            heard.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(60));
                            *lan2.lock().unwrap() =
                                heard.values().map(|(p, _)| p.clone()).collect();
                        }
                    });
            }
            Err(e) => eprintln!("service: LAN beacon unavailable: {e:#}"),
        }

        let nat: Arc<Mutex<NatInfo>> = Arc::new(Mutex::new(NatInfo::default()));
        let records: Arc<Mutex<Vec<varsto_core::p2p::PeerRecord>>> =
            Arc::new(Mutex::new(Vec::new()));
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
        {
            let mut st = state.lock().unwrap();
            st.service.p2p_listen = Some(listen);
            st.service.p2p_cert_sha256 = cert_sha256;
        }
        println!(
            "Varsto p2p: listening on {listen} (TCP{}; encrypted blocks only; peers need the vault key)",
            if quic.is_some() { " and QUIC" } else { "" }
        );
        Some(P2p {
            snapshot,
            lan_peers,
            listen,
            stop,
            quic,
            records,
            nat,
            peers: Mutex::new(None),
            last_record: Mutex::new(None),
            last_publish: Mutex::new(None),
            republish,
            traffic,
        })
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
                    if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
                        eprintln!(
                            "p2p: stun {:?} nat {} reachable {reachable}",
                            probe.mapped,
                            probe.nat.as_str()
                        );
                    }
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
                            eprintln!("p2p: asking STUN again (the NAT mapping may have changed)");
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
        records: Arc<Mutex<Vec<varsto_core::p2p::PeerRecord>>>,
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
                    let relays: Vec<varsto_core::p2p::PeerRecord> = records
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| r.reachable && !r.cert_sha256.is_empty())
                        .cloned()
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
                            match node.register_with(&r.device, &r.udp_addrs(), &r.cert_sha256) {
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
                                    eprintln!(
                                        "service: relay registration with {} failed: {e:#}; next try in {} s",
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

    /// Merge LAN peers with rendezvous records and hand them to the engine.
    fn refresh_before_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_mut() else { return };
        let mut lan = self.lan_peers.lock().unwrap().clone();
        // A removed device may still send beacons: it is no peer.
        lan.retain(|p| !e.is_revoked(&p.device));
        // A storage hiccup must not empty the peer table: that would stop
        // the keeper's punches (so NAT mappings lapse and peers' punches
        // steal our port) and make the QUIC server refuse every peer's
        // certificate. Keep the last good records until the next listing.
        let records = match e.peer_record_list() {
            Ok(r) => r,
            Err(err) => {
                let kept = self.records.lock().unwrap().clone();
                eprintln!(
                    "p2p: peer record listing failed, keeping {} known record(s): {err:#}",
                    kept.len()
                );
                kept
            }
        };
        let mut flat = lan.clone();
        for r in &records {
            for addr in r.addrs() {
                if !flat.iter().any(|p| p.addr == addr) {
                    flat.push(varsto_core::p2p::PeerAddr {
                        device: r.device.clone(),
                        addr,
                        name: r.name.clone(),
                    });
                }
            }
        }
        st.service.p2p_lan_peers = lan.len();
        st.service.p2p_peers = flat;
        *self.records.lock().unwrap() = records.clone();
        let p = Arc::new(
            varsto_core::p2p::Peers::build(
                e.peer_key(),
                e.device_id().clone(),
                &records,
                &lan,
                self.quic.clone(),
            )
            .with_traffic(self.traffic.clone()),
        );
        let mut slot = self.peers.lock().unwrap();
        if let Some(prev) = slot.as_ref() {
            p.inherit(prev);
        }
        *slot = Some(p.clone());
        drop(slot);
        e.set_peers(Some(p));
    }

    /// Refresh what we serve, show the paths in use, and re-publish our
    /// rendezvous record when it changed (or once an hour regardless).
    fn refresh_after_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_ref() else { return };
        match e.peer_snapshot() {
            Ok(s) => *self.snapshot.lock().unwrap() = Some(Arc::new(s)),
            Err(err) => eprintln!("service: p2p snapshot failed: {err:#}"),
        }
        self.publish_record(st);
    }

    /// Show the NAT state and the paths in use, and re-publish our rendezvous
    /// record when it changed (or once an hour regardless). Also called as
    /// soon as a relay registration succeeds, so `relay_via` spreads quickly.
    fn publish_record(&self, st: &mut State) {
        let Some(e) = st.engine.as_ref() else { return };
        let info = self.nat.lock().unwrap().clone();
        let mut rec = e.peer_record_template(self.listen.port());
        rec.udp_public = info.probe.public_addrs();
        rec.nat = info.probe.nat;
        rec.reachable |= info.reachable;
        if let Some(node) = &self.quic {
            rec.relay_via = node.registered_relays();
        }
        let records = self.records.lock().unwrap();
        st.service.p2p_relays = rec
            .relay_via
            .iter()
            .map(|d| {
                records
                    .iter()
                    .find(|r| &r.device == d)
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
        if changed || last.is_none_or(|t| t.elapsed() > RECORD_MAX_AGE) {
            if let Err(err) = e.publish_peer_record(&rec) {
                eprintln!("service: p2p record publish failed: {err:#}");
            }
            *last = Some(Instant::now());
            *last_rec = Some(rec);
        }
    }
}

impl Drop for P2p {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Best-effort desktop notification; silent where no notifier exists.
pub fn notify(title: &str, body: &str) {
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
        let _ = (title, body);
    }
}

pub fn service_file(home: &Path) -> PathBuf {
    home.join("service.json")
}

pub fn read_service_file(home: &Path) -> Option<ServiceFile> {
    let s = fs::read(service_file(home)).ok()?;
    serde_json::from_slice(&s).ok()
}

fn write_service_file(home: &Path, f: &ServiceFile) -> Result<()> {
    fs::create_dir_all(home)?;
    let p = service_file(home);
    varsto_core::util::write_atomic(&p, &serde_json::to_vec_pretty(f)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn request_quit(_state: &Shared) {
    QUIT.store(true, Ordering::SeqCst);
}

/// Passphrase from the environment or the macOS login keychain.
pub fn passphrase_from_system(home: &Path) -> Option<String> {
    if let Ok(p) = std::env::var("VARSTO_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                "varsto",
                "-a",
                &home.display().to_string(),
                "-w",
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout)
                .trim_end_matches('\n')
                .to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    let _ = home;
    None
}

pub struct Options {
    pub home: PathBuf,
    pub port: u16,
    pub interval_secs: u64,
    pub open_browser: bool,
}

/// Run the service until quit. Blocks the calling thread.
pub fn run(opts: Options) -> Result<()> {
    let (server, bound) = desktop::bind(opts.port)?;
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let port: u16 = bound.rsplit(':').next().unwrap().parse()?;
    let url = format!("http://{bound}/?token={token}");
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
                Err(e) => eprintln!("service: unlock with the stored passphrase failed: {e:#}"),
            }
        }
        if engine.is_none() {
            // Locked at start (a phone killed without locking): drop the plaintext
            // copies of folders kept "encrypted on this device".
            match Engine::wipe_encrypted_folders_locked(&opts.home) {
                Ok(n) if n > 0 => {
                    eprintln!("service: removed {n} plaintext copies of encrypted-here folders")
                }
                Ok(_) => {}
                Err(e) => eprintln!("service: could not clean encrypted-here folders: {e:#}"),
            }
        }
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
    }));
    println!("Varsto service: {url}");
    println!(
        "Only this computer can reach it. Service file: {}",
        service_file(&opts.home).display()
    );
    if opts.open_browser {
        desktop::open_in_browser(&url);
    }
    let http_state = state.clone();
    let server = Arc::new(server);
    let http_server = server.clone();
    std::thread::Builder::new()
        .name("http".into())
        .spawn(move || desktop::serve_arc(http_server, http_state))?;

    // Peer-to-peer: serve our chunks, announce on the LAN, learn peers.
    // Peer-to-peer starts as soon as the vault is open and the setting is on: a
    // phone or a tray app starts locked, so the node often comes up only after
    // the user unlocks; a failed start is retried every 30 seconds.
    let mut p2p = P2p::start(&state);
    let mut p2p_retry_at = Instant::now();

    // File watcher: sends a signal on any change under an attached folder.
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = make_watcher(tx)?;
    let mut watched: Vec<PathBuf> = Vec::new();
    let mut last_change: Option<Instant> = None;
    let mut next_sync = Instant::now();
    let debounce = Duration::from_secs(2);
    let disk_check_every = Duration::from_secs(30);
    let mut next_disk_check = Instant::now();
    // Syncs run through the local API (`POST /api/sync`, the CLI) change what
    // we can serve; the snapshot follows them as it follows our own syncs.
    let mut snapshot_syncs = 0u64;

    while !QUIT.load(Ordering::SeqCst) {
        // Removable disks: notice what was attached or taken away.
        if Instant::now() >= next_disk_check {
            next_disk_check = Instant::now() + disk_check_every;
            let mut st = state.lock().unwrap();
            let listed = st.engine.as_mut().map(|e| e.disks());
            match listed {
                Some(Ok(disks)) => st.service.record_disks(disks),
                Some(Err(e)) => eprintln!("service: disk check failed: {e:#}"),
                None => {}
            }
        }
        // Drain change notifications.
        while rx.try_recv().is_ok() {
            last_change = Some(Instant::now());
        }
        // Re-evaluate watched folders when the engine or its folders changed.
        {
            let mut st = state.lock().unwrap();
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
                            eprintln!("service: cannot watch {}: {e}", p.display());
                        }
                    }
                    watched = paths;
                }
                st.service.watching = watched.clone();
                st.service.folders_changed = false;
            }
        }
        if p2p.is_none() && Instant::now() >= p2p_retry_at {
            let wanted = {
                let st = state.lock().unwrap();
                st.engine
                    .as_ref()
                    .map(|e| e.p2p_config().enabled)
                    .unwrap_or(false)
            };
            if wanted {
                p2p = P2p::start(&state);
                if p2p.is_some() {
                    eprintln!("service: p2p started after unlock");
                } else {
                    p2p_retry_at = Instant::now() + Duration::from_secs(30);
                }
            }
        }
        if let Some(p) = &p2p {
            let mut st = state.lock().unwrap();
            // A relay registration just succeeded: tell the other devices now.
            if p.take_republish() {
                p.publish_record(&mut st);
            }
            if st.service.syncs != snapshot_syncs {
                snapshot_syncs = st.service.syncs;
                p.refresh_after_sync(&mut st);
            }
        }
        if state.lock().unwrap().service.restart_requested {
            eprintln!("service: restarting after update");
            std::thread::sleep(Duration::from_millis(300));
            break;
        }
        let due_change = last_change
            .map(|t| t.elapsed() >= debounce)
            .unwrap_or(false);
        let due_timer = Instant::now() >= next_sync;
        let (requested, paused, unlocked) = {
            let st = state.lock().unwrap();
            (
                st.service.sync_requested,
                st.service.paused,
                st.engine.is_some(),
            )
        };
        if unlocked && !paused && (due_change || due_timer || requested) {
            last_change = None;
            let mut st = state.lock().unwrap();
            st.service.sync_requested = false;
            let interval = st.service.interval_secs;
            if let Some(p) = &p2p {
                p.refresh_before_sync(&mut st);
            }
            if let Some(e) = st.engine.as_mut() {
                e.expire_strongrooms();
            }
            let result = st.engine.as_mut().map(|e| e.sync(None));
            if let Some(p) = &p2p {
                p.refresh_after_sync(&mut st);
            }
            match result {
                Some(Ok(reports)) => {
                    st.service.record_sync(&reports);
                    snapshot_syncs = st.service.syncs; // the snapshot above is current
                    let st = &mut *st;
                    if let Some(e) = st.engine.as_mut() {
                        st.service.auto_verify_if_due(e);
                        if let Err(err) = e.publish_device_details(st.service.last_sync_utc) {
                            eprintln!("service: device details not published: {err:#}");
                        }
                    }
                    let checked = st.engine.as_ref().map(|e| e.policy_check());
                    match checked {
                        Some(Ok(reps)) => st.service.record_policies(reps),
                        Some(Err(e)) => eprintln!("service: policy check failed: {e:#}"),
                        None => {}
                    }
                }
                Some(Err(e)) => {
                    st.service.last_error = Some(format!("{e:#}"));
                    eprintln!("service: sync failed: {e:#}");
                    // A wipe order was carried out: nothing of the vault is left.
                    if e.downcast_ref::<varsto_core::engine::DeviceRemoved>()
                        .is_some_and(|r| r.wiped)
                    {
                        st.engine = None;
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
    let restart = state.lock().unwrap().service.restart_requested;
    let _ = fs::remove_file(service_file(&opts.home));
    server.unblock();
    if restart {
        // Exit code 75 tells a supervisor (launchd, systemd, the tray app) to start us again.
        std::process::exit(75);
    }
    Ok(())
}

fn make_watcher(tx: mpsc::Sender<()>) -> Result<notify::RecommendedWatcher> {
    let watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                // Ignore our own temporary files.
                if ev.paths.iter().all(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().starts_with(".varsto"))
                        .unwrap_or(false)
                }) {
                    return;
                }
                let _ = tx.send(());
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(30)),
    )
    .context("start file watcher")?;
    Ok(watcher)
}

/// Is the service recorded in `service.json` still alive?
pub fn status(home: &Path) -> Option<(ServiceFile, Value)> {
    let f = read_service_file(home)?;
    let url = format!("http://127.0.0.1:{}/api/service", f.port);
    let body = http_get(&url, &f.token).ok()?;
    Some((f, serde_json::from_str(&body).unwrap_or(json!({}))))
}

/// Minimal HTTP client for talking to the local service (no extra dependency).
pub fn http_get(url: &str, token: &str) -> Result<String> {
    http_call("GET", url, token, None)
}

pub fn http_post(url: &str, token: &str, body: &str) -> Result<String> {
    http_call("POST", url, token, Some(body))
}

pub fn http_call(method: &str, url: &str, token: &str, body: Option<&str>) -> Result<String> {
    use std::io::{Read, Write};
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("http only"))?;
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = std::net::TcpStream::connect(hostport)?;
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
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

pub fn install(home: &Path, interval_secs: u64) -> Result<String> {
    let exe = std::env::current_exe()?;
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
  <key>KeepAlive</key><true/>
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
        return Ok(format!(
            "installed: {} (starts the tray app at login)",
            cmd.display()
        ));
    }
    #[allow(unreachable_code)]
    {
        let _ = (home, interval_secs, exe);
        Err(anyhow!("automatic installation is not implemented on this platform; run `varsto service run` from your login items"))
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
        return Ok("removed the startup entry".into());
    }
    #[allow(unreachable_code)]
    Err(anyhow!("not implemented on this platform"))
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
            systemctl(&["enable", "--now", UNIT])?;
            done.push(format!(
                "background service: systemd user unit {UNIT}, started and enabled at login"
            ));
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
