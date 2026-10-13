// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer discovery through the public BitTorrent Mainline DHT (BEP 5) with
//! signed mutable items (BEP 44). Each device publishes its rendezvous
//! record there, sealed, under an Ed25519 key that every device of the vault
//! can derive for every other device and day, and nobody else can: to an
//! outsider the key is random, changes every UTC day, and links neither to
//! the vault nor to the device's key of another day. Devices find each other
//! this way even when the storage is slow to list, or before a record in the
//! storage has been written.
//!
//! The DHT is a public network of millions of BitTorrent clients run by no
//! one in particular: no tracker and no vendor server is involved. It learns
//! the IP address of this device's DHT socket and that some key publishes a
//! small encrypted blob; addresses read from it are only hints, and every
//! connection is still authenticated with the vault membership proof.
//!
//! Key derivation (`peer_key` is the membership-proof key of `p2p::peer_key`,
//! so it changes with the vault key epoch and a removed device loses it):
//! - signing seed = derive(peer_key, "varsto dht v1", ["sign", vault, device, day])
//! - sealing key  = derive(peer_key, "varsto dht v1", ["seal", vault])
//! - value        = XChaCha20-Poly1305(sealing key, compact record),
//!   AAD binds vault, device and day; at most `MAX_VALUE` bytes.
//!
//! `Discovery` runs the node on a thread of its own: it publishes our record
//! when it changes, every `REPUBLISH` and at each new day, and looks up every
//! other device's records of today and yesterday every `LOOKUP_EVERY`. A
//! sync never waits for it; the service merges what it found into the peer
//! table like records from the storage (the newest wins).

use super::{stun, PeerRecord};
use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, VaultId};
use anyhow::{anyhow, bail, Result};
use futures_lite::future::block_on;
use futures_lite::StreamExt;
use mainline::async_dht::AsyncDht;
use mainline::{Dht, MutableItem, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Domain label of every key derived for the DHT.
pub const LABEL: &str = "varsto dht v1";
/// One epoch: a UTC day. Keys change at midnight UTC.
pub const DAY: i64 = 86_400;
/// Largest sealed value: bencoded as `990:<bytes>` it stays under the 1000
/// bytes BEP 44 allows for `v`.
pub const MAX_VALUE: usize = 990;
/// Addresses kept per list of the compact record; a device with more
/// interfaces than this is reached through the first ones or the storage.
const MAX_LIST: usize = 6;
/// Our item is put again this often (DHT nodes drop items after about two
/// hours), and at once when the record changes or a new day starts.
pub const REPUBLISH: Duration = Duration::from_secs(30 * 60);
/// Every other device is looked up this often, and at the earliest
/// `LOOKUP_MIN` after the last round when the list of devices changed.
pub const LOOKUP_EVERY: Duration = Duration::from_secs(10 * 60);
const LOOKUP_MIN: Duration = Duration::from_secs(60);
/// A failed bootstrap or put is tried again after this long, doubling up
/// to `RETRY_MAX`.
const RETRY_MIN: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(15 * 60);
/// A record claiming to be from further in the future than this is refused.
const MAX_SKEW: i64 = 3600;

/// The epoch (UTC day number) of a Unix time.
pub fn epoch_of(utc: i64) -> u64 {
    utc.div_euclid(DAY).max(0) as u64
}

/// The BEP 44 signing key of `device` for `epoch`.
pub fn signing_key(
    peer_key: &SecretKey,
    vault: &VaultId,
    device: &DeviceId,
    epoch: u64,
) -> SigningKey {
    let seed = peer_key.derive(
        LABEL,
        &[
            &b"sign"[..],
            vault.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &epoch.to_le_bytes(),
        ],
    );
    SigningKey::from_bytes(&seed.0)
}

/// The public key the item of `device` for `epoch` is stored under.
pub fn public_key(
    peer_key: &SecretKey,
    vault: &VaultId,
    device: &DeviceId,
    epoch: u64,
) -> [u8; 32] {
    signing_key(peer_key, vault, device, epoch)
        .verifying_key()
        .to_bytes()
}

fn seal_key(peer_key: &SecretKey, vault: &VaultId) -> SecretKey {
    peer_key.derive(LABEL, &[&b"seal"[..], vault.as_str().as_bytes()])
}

fn aad(vault: &VaultId, device: &DeviceId, epoch: u64) -> Vec<u8> {
    crypto::aad(
        "dht-record",
        &[
            vault.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &epoch.to_le_bytes(),
        ],
    )
}

/// The rendezvous record as it travels in the DHT: short keys, no device id
/// (the key says whose it is) and no name (every device has it from the
/// registry). Empty lists and defaults are left out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Compact {
    /// `updated_utc`
    t: i64,
    /// `port`
    p: u16,
    /// `lan_addrs`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    l: Vec<IpAddr>,
    /// `public_addrs`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    a: Vec<SocketAddr>,
    /// `udp_public`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    u: Vec<SocketAddr>,
    /// `udp_local`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    o: Vec<SocketAddr>,
    /// `cert_sha256`
    #[serde(default, skip_serializing_if = "String::is_empty")]
    c: String,
    /// `nat`
    #[serde(default)]
    n: stun::Nat,
    /// `relay_via`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    r: Vec<DeviceId>,
    /// `reachable`
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    x: bool,
}

impl Compact {
    fn of(rec: &PeerRecord) -> Compact {
        fn cap<T: Clone>(v: &[T]) -> Vec<T> {
            v.iter().take(MAX_LIST).cloned().collect()
        }
        Compact {
            t: rec.updated_utc,
            p: rec.port,
            l: cap(&rec.lan_addrs),
            a: cap(&rec.public_addrs),
            u: cap(&rec.udp_public),
            o: cap(&rec.udp_local),
            c: rec.cert_sha256.clone(),
            n: rec.nat,
            r: cap(&rec.relay_via),
            x: rec.reachable,
        }
    }

    fn into_record(self, device: DeviceId, name: String) -> PeerRecord {
        PeerRecord {
            version: PeerRecord::VERSION,
            device,
            name,
            port: self.p,
            lan_addrs: self.l,
            public_addrs: self.a,
            updated_utc: self.t,
            udp_public: self.u,
            udp_local: self.o,
            cert_sha256: self.c,
            nat: self.n,
            relay_via: self.r,
            reachable: self.x,
        }
    }
}

/// Seal `rec` as the DHT value of its device for `epoch`. A record too large
/// for `MAX_VALUE` loses addresses, the least useful first: own-interface
/// UDP addresses (the LAN beacon finds those), relays, LAN addresses, then
/// public ones.
pub fn seal(
    peer_key: &SecretKey,
    vault: &VaultId,
    rec: &PeerRecord,
    epoch: u64,
) -> Result<Vec<u8>> {
    let mut c = Compact::of(rec);
    loop {
        let plain = serde_json::to_vec(&c)?;
        if plain.len() + crypto::NONCE_LEN + 16 <= MAX_VALUE {
            return crypto::encrypt(
                &seal_key(peer_key, vault),
                &aad(vault, &rec.device, epoch),
                &plain,
            );
        }
        if c.o.pop().is_none()
            && c.r.pop().is_none()
            && c.l.pop().is_none()
            && c.u.pop().is_none()
            && c.a.pop().is_none()
        {
            bail!("the rendezvous record does not fit a DHT item");
        }
    }
}

/// Open the DHT value of `device` for `epoch`; `name` is the device's name
/// from the registry.
pub fn open(
    peer_key: &SecretKey,
    vault: &VaultId,
    device: &DeviceId,
    name: &str,
    epoch: u64,
    blob: &[u8],
) -> Result<PeerRecord> {
    if blob.len() > MAX_VALUE {
        bail!("DHT value too large");
    }
    let plain = crypto::decrypt(&seal_key(peer_key, vault), &aad(vault, device, epoch), blob)?;
    let c: Compact = serde_json::from_slice(&plain)?;
    if c.t > crate::util::now_utc() + MAX_SKEW {
        bail!("DHT record from the future");
    }
    Ok(c.into_record(device.clone(), name.to_string()))
}

/// Bootstrap nodes: `VARSTO_DHT_BOOTSTRAP` (`host:port,...`) when set, else
/// the configured ones; empty means the crate's public defaults.
pub fn bootstrap_nodes(configured: &[String]) -> Vec<String> {
    if let Ok(v) = std::env::var("VARSTO_DHT_BOOTSTRAP") {
        let list: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    configured.to_vec()
}

/// Where the DHT node stands, for the status displays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DhtState {
    /// Turned off, or peer-to-peer is off.
    #[default]
    Off,
    /// Asking the bootstrap nodes for a first routing table.
    Bootstrapping,
    /// In the network: publishing and looking up.
    Ok,
    /// No bootstrap node answered; tried again later.
    Failed,
}

/// One device looked up in the last round.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhtFound {
    pub device: DeviceId,
    pub name: String,
    /// `updated_utc` of the newest record found; none when nothing was found.
    pub updated_utc: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhtStatus {
    pub state: DhtState,
    /// Nodes in our routing table.
    pub nodes: usize,
    pub error: Option<String>,
    pub last_publish_utc: Option<i64>,
    /// How many DHT nodes stored our last item.
    pub stored_at: u32,
    pub last_lookup_utc: Option<i64>,
    pub found: Vec<DhtFound>,
}

impl DhtStatus {
    /// One line for `varsto p2p status` and the service log.
    pub fn describe(&self) -> String {
        let ago = |t: Option<i64>| match t {
            Some(t) => {
                let s = (crate::util::now_utc() - t).max(0);
                if s < 120 {
                    format!("{s} s ago")
                } else {
                    format!("{} min ago", s / 60)
                }
            }
            None => "not yet".to_string(),
        };
        match self.state {
            DhtState::Off => "off".to_string(),
            DhtState::Bootstrapping => "bootstrapping".to_string(),
            DhtState::Failed => format!(
                "no DHT node answered{}",
                self.error
                    .as_ref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ),
            DhtState::Ok => format!(
                "ok, {} nodes; published {}{}; looked up {}{}",
                self.nodes,
                ago(self.last_publish_utc),
                if self.last_publish_utc.is_some() {
                    format!(" (stored at {} nodes)", self.stored_at)
                } else {
                    String::new()
                },
                ago(self.last_lookup_utc),
                if self.last_lookup_utc.is_some() {
                    format!(
                        ", found {} of {} devices",
                        self.found
                            .iter()
                            .filter(|f| f.updated_utc.is_some())
                            .count(),
                        self.found.len()
                    )
                } else {
                    String::new()
                }
            ),
        }
    }
}

/// What the service hands the DHT thread, and what it found.
#[derive(Default)]
struct Shared {
    /// The membership-proof key (`Engine::peer_key`).
    key: Option<SecretKey>,
    record: Option<PeerRecord>,
    record_changed: bool,
    /// Other devices of the vault, with their names.
    targets: Vec<(DeviceId, String)>,
    targets_changed: bool,
    /// Look up at the next turn, whatever the timers say.
    lookup_now: bool,
    found: BTreeMap<DeviceId, PeerRecord>,
    status: DhtStatus,
}

struct Inner {
    vault: VaultId,
    bootstrap: Vec<String>,
    shared: Mutex<Shared>,
    stop: AtomicBool,
    /// Set when a lookup found a record newer than the one known before.
    changed: AtomicBool,
}

impl Inner {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn status(&self, f: impl FnOnce(&mut DhtStatus)) {
        f(&mut self.shared.lock().unwrap().status);
    }

    /// Sleep in quarter-second steps so a stop request is honoured promptly.
    fn pause(&self, dur: Duration) {
        let until = Instant::now() + dur;
        while Instant::now() < until && !self.stopped() {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

/// The DHT node of the service, on a thread of its own; stops when dropped.
pub struct Discovery {
    inner: Arc<Inner>,
}

impl Discovery {
    /// Start the node for `vault`. `bootstrap` overrides the public
    /// bootstrap nodes when not empty (see `bootstrap_nodes`).
    pub fn start(vault: VaultId, key: SecretKey, bootstrap: Vec<String>) -> Result<Discovery> {
        let inner = Arc::new(Inner {
            vault,
            bootstrap,
            shared: Mutex::new(Shared {
                key: Some(key),
                status: DhtStatus {
                    state: DhtState::Bootstrapping,
                    ..Default::default()
                },
                ..Default::default()
            }),
            stop: AtomicBool::new(false),
            changed: AtomicBool::new(false),
        });
        let run_inner = inner.clone();
        std::thread::Builder::new()
            .name("p2p-dht".into())
            .spawn(move || run(run_inner))
            .map_err(|e| anyhow!("could not start the DHT thread: {e}"))?;
        Ok(Discovery { inner })
    }

    /// The membership-proof key changed (a new vault key epoch): publish and
    /// look up under the new one.
    pub fn set_key(&self, key: SecretKey) {
        let mut s = self.inner.shared.lock().unwrap();
        if s.key.as_ref().is_some_and(|k| k.0 == key.0) {
            return;
        }
        s.key = Some(key);
        s.record_changed = true;
        s.targets_changed = true;
        s.found.clear();
    }

    /// Our record as it is now; published at once when it changed.
    pub fn set_record(&self, rec: PeerRecord) {
        let mut s = self.inner.shared.lock().unwrap();
        if s.record.as_ref().is_none_or(|r| !r.same_as(&rec)) {
            s.record_changed = true;
        }
        s.record = Some(rec);
    }

    /// The devices to look up: the other trusted devices of the vault.
    pub fn set_targets(&self, mut targets: Vec<(DeviceId, String)>) {
        targets.sort();
        let mut s = self.inner.shared.lock().unwrap();
        if s.targets != targets {
            s.found.retain(|d, _| targets.iter().any(|(t, _)| t == d));
            s.targets = targets;
            s.targets_changed = true;
        }
    }

    /// Look the other devices up at once (a peer stopped answering, tests).
    pub fn lookup_now(&self) {
        self.inner.shared.lock().unwrap().lookup_now = true;
    }

    /// Records found in the DHT, one per device (the newest).
    pub fn found(&self) -> Vec<PeerRecord> {
        self.inner
            .shared
            .lock()
            .unwrap()
            .found
            .values()
            .cloned()
            .collect()
    }

    /// Whether a lookup found something new since the last call.
    pub fn take_changed(&self) -> bool {
        self.inner.changed.swap(false, Ordering::SeqCst)
    }

    pub fn status(&self) -> DhtStatus {
        self.inner.shared.lock().unwrap().status.clone()
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Merge records found in the DHT into those read from the storage: per
/// device the newer one wins (the storage's on a tie), and only devices in
/// `allowed` count. The storage's name is kept when the DHT has none.
pub fn merge(stored: &[PeerRecord], found: &[PeerRecord], allowed: &[DeviceId]) -> Vec<PeerRecord> {
    let mut out: Vec<PeerRecord> = stored.to_vec();
    for f in found.iter().filter(|f| allowed.contains(&f.device)) {
        match out.iter_mut().find(|r| r.device == f.device) {
            Some(have) if have.updated_utc < f.updated_utc => {
                let name = if f.name.is_empty() {
                    have.name.clone()
                } else {
                    f.name.clone()
                };
                *have = f.clone();
                have.name = name;
            }
            Some(_) => {}
            None => out.push(f.clone()),
        }
    }
    out
}

fn build(bootstrap: &[String]) -> Result<AsyncDht> {
    let mut b = Dht::builder();
    if !bootstrap.is_empty() {
        b.bootstrap(bootstrap);
        // A network of local nodes only (tests): stay on loopback, where
        // some systems do not route from a socket bound to every interface.
        if bootstrap
            .iter()
            .all(|n| n.starts_with("127.") || n.starts_with("localhost:"))
        {
            b.bind_address(std::net::Ipv4Addr::LOCALHOST);
        }
    }
    Ok(b.build()?.as_async())
}

/// The thread: (re)build the node until it bootstraps, then serve.
fn run(inner: Arc<Inner>) {
    let mut wait = RETRY_MIN;
    while !inner.stopped() {
        inner.status(|s| s.state = DhtState::Bootstrapping);
        let dht = match build(&inner.bootstrap) {
            Ok(d) => d,
            Err(e) => {
                super::log(&format!("DHT node could not start: {e:#}"));
                inner.status(|s| {
                    s.state = DhtState::Failed;
                    s.error = Some(format!("{e:#}"));
                });
                inner.pause(wait);
                wait = (wait * 2).min(RETRY_MAX);
                continue;
            }
        };
        if !block_on(dht.bootstrapped()) {
            inner.status(|s| {
                s.state = DhtState::Failed;
                s.error = Some("no bootstrap node answered".into());
            });
            inner.pause(wait);
            wait = (wait * 2).min(RETRY_MAX);
            continue;
        }
        wait = RETRY_MIN;
        super::log("DHT node bootstrapped");
        serve(&inner, &dht);
    }
    inner.status(|s| *s = DhtStatus::default());
}

/// Publish and look up until stopped, or until the routing table stayed
/// empty for five minutes (the network went away): then the caller builds
/// a new node.
fn serve(inner: &Inner, dht: &AsyncDht) {
    let mut published: Option<(Instant, u64)> = None;
    let mut next_put = Instant::now();
    let mut put_wait = RETRY_MIN;
    let mut seq: i64 = 0;
    let mut looked_up: Option<Instant> = None;
    let mut counted: Option<Instant> = None;
    let mut empty_since: Option<Instant> = None;
    while !inner.stopped() {
        if counted.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            counted = Some(Instant::now());
            let nodes = block_on(dht.to_bootstrap()).len();
            inner.status(|s| {
                s.nodes = nodes;
                s.state = if nodes > 0 {
                    DhtState::Ok
                } else {
                    DhtState::Bootstrapping
                };
                if nodes > 0 {
                    s.error = None;
                }
            });
            if nodes > 0 {
                empty_since = None;
            } else if empty_since.get_or_insert_with(Instant::now).elapsed()
                >= Duration::from_secs(300)
            {
                super::log("DHT routing table empty; starting the node again");
                return;
            }
        }
        let now = crate::util::now_utc();
        let today = epoch_of(now);

        // Publish: a changed record, a new day, or the refresh is due.
        let job = {
            let mut s = inner.shared.lock().unwrap();
            let due = s.record_changed
                || published.is_none_or(|(t, e)| t.elapsed() >= REPUBLISH || e != today);
            match (s.key.clone(), s.record.clone()) {
                (Some(k), Some(r)) if due && Instant::now() >= next_put => {
                    s.record_changed = false;
                    Some((k, r))
                }
                _ => None,
            }
        };
        if let Some((key, rec)) = job {
            seq = now.max(seq + 1);
            match publish(dht, &inner.vault, &key, &rec, today, seq) {
                Ok(stored_at) => {
                    published = Some((Instant::now(), today));
                    put_wait = RETRY_MIN;
                    inner.status(|s| {
                        s.last_publish_utc = Some(now);
                        s.stored_at = stored_at;
                        s.error = None;
                    });
                }
                Err(e) => {
                    super::log(&format!("DHT publish failed: {e:#}"));
                    next_put = Instant::now() + put_wait;
                    put_wait = (put_wait * 2).min(RETRY_MAX);
                    let mut s = inner.shared.lock().unwrap();
                    s.record_changed = true;
                    s.status.error = Some(format!("{e:#}"));
                }
            }
        }

        // Look up: every `LOOKUP_EVERY`, sooner when the devices changed.
        let job = {
            let mut s = inner.shared.lock().unwrap();
            let due = s.lookup_now
                || match looked_up {
                    None => true,
                    Some(t) => {
                        t.elapsed() >= LOOKUP_EVERY
                            || (s.targets_changed && t.elapsed() >= LOOKUP_MIN)
                    }
                };
            match s.key.clone() {
                Some(k) if due && !s.targets.is_empty() => {
                    s.targets_changed = false;
                    s.lookup_now = false;
                    Some((k, s.targets.clone()))
                }
                _ => None,
            }
        };
        if let Some((key, targets)) = job {
            looked_up = Some(Instant::now());
            let got = lookup(dht, &inner.vault, &key, &targets, today);
            let mut s = inner.shared.lock().unwrap();
            // The key or the device list changed meanwhile: these results
            // may be stale; the next round redoes them.
            if s.key.as_ref().is_some_and(|k| k.0 == key.0) {
                let mut found = Vec::new();
                for (dev, name) in &targets {
                    let rec = got.get(dev);
                    if let Some(rec) = rec {
                        let newer = s
                            .found
                            .get(dev)
                            .is_none_or(|have| have.updated_utc < rec.updated_utc);
                        if newer && s.targets.iter().any(|(t, _)| t == dev) {
                            s.found.insert(dev.clone(), rec.clone());
                            inner.changed.store(true, Ordering::SeqCst);
                        }
                    }
                    found.push(DhtFound {
                        device: dev.clone(),
                        name: name.clone(),
                        updated_utc: rec.map(|r| r.updated_utc),
                    });
                }
                s.status.last_lookup_utc = Some(now);
                s.status.found = found;
            }
        }
        inner.pause(Duration::from_secs(1));
    }
}

/// Put our item for `epoch`; the number of nodes that stored it.
fn publish(
    dht: &AsyncDht,
    vault: &VaultId,
    key: &SecretKey,
    rec: &PeerRecord,
    epoch: u64,
    seq: i64,
) -> Result<u32> {
    let value = seal(key, vault, rec, epoch)?;
    let item = MutableItem::new(
        signing_key(key, vault, &rec.device, epoch),
        &value,
        seq,
        None,
    );
    let out = block_on(dht.put_mutable(item, None)).map_err(|e| anyhow!("DHT put: {e}"))?;
    Ok(out.stored_at)
}

/// Ask for every target's items of `today` and yesterday, all at once (the
/// node runs the queries side by side), and open what comes back. Per device
/// the newest record that opens; items that do not open are ignored.
fn lookup(
    dht: &AsyncDht,
    vault: &VaultId,
    key: &SecretKey,
    targets: &[(DeviceId, String)],
    today: u64,
) -> BTreeMap<DeviceId, PeerRecord> {
    let mut queries = Vec::new();
    for (dev, name) in targets {
        for epoch in [today, today.saturating_sub(1)] {
            let pk = public_key(key, vault, dev, epoch);
            queries.push((dev, name, epoch, dht.get_mutable(&pk, None, None)));
        }
    }
    let mut out: BTreeMap<DeviceId, PeerRecord> = BTreeMap::new();
    for (dev, name, epoch, stream) in queries {
        let items: Vec<MutableItem> = block_on(stream.collect());
        for item in items {
            let Ok(rec) = open(key, vault, dev, name, epoch, item.value()) else {
                continue;
            };
            match out.get(dev) {
                Some(have) if have.updated_utc >= rec.updated_utc => {}
                _ => {
                    out.insert(dev.clone(), rec);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(device: &DeviceId) -> PeerRecord {
        PeerRecord {
            version: PeerRecord::VERSION,
            device: device.clone(),
            name: "laptop".into(),
            port: 17893,
            lan_addrs: vec!["192.168.1.5".parse().unwrap(), "10.8.0.2".parse().unwrap()],
            public_addrs: vec!["198.51.100.20:17893".parse().unwrap()],
            updated_utc: crate::util::now_utc(),
            udp_public: vec![
                "203.0.113.7:40000".parse().unwrap(),
                "[2001:db8:1234:5678:9abc:def0:1234:5678]:17893"
                    .parse()
                    .unwrap(),
            ],
            udp_local: vec![
                "192.168.1.5:17893".parse().unwrap(),
                "10.8.0.2:17893".parse().unwrap(),
                "[fe80::1234:5678:9abc:def0]:17893".parse().unwrap(),
            ],
            cert_sha256: "ab".repeat(32),
            nat: stun::Nat::Cone,
            relay_via: vec![
                DeviceId::from_bytes(&[4u8; 16]),
                DeviceId::from_bytes(&[5u8; 16]),
            ],
            reachable: true,
        }
    }

    #[test]
    fn keys_are_the_same_for_every_device_and_change_daily() {
        let key = SecretKey::from_bytes(&[7u8; 32]).unwrap();
        let vault = VaultId::from_bytes(&[9u8; 16]);
        let (a, b) = (
            DeviceId::from_bytes(&[1u8; 16]),
            DeviceId::from_bytes(&[2u8; 16]),
        );
        let day = epoch_of(1_760_000_000);
        // Deterministic: another device of the vault derives the same key.
        assert_eq!(
            public_key(&key, &vault, &a, day),
            public_key(&key.clone(), &vault, &a, day)
        );
        assert_eq!(
            signing_key(&key, &vault, &a, day).to_bytes(),
            signing_key(&key, &vault, &a, day).to_bytes()
        );
        // Unlinkable: another day, device, vault or vault key gives another key.
        let k = public_key(&key, &vault, &a, day);
        assert_ne!(k, public_key(&key, &vault, &a, day + 1));
        assert_ne!(k, public_key(&key, &vault, &b, day));
        assert_ne!(
            k,
            public_key(&key, &VaultId::from_bytes(&[8u8; 16]), &a, day)
        );
        assert_ne!(k, public_key(&SecretKey::random(), &vault, &a, day));
        // Not the membership key itself, nor the sealing key.
        assert_ne!(signing_key(&key, &vault, &a, day).to_bytes(), key.0);
        assert_ne!(seal_key(&key, &vault).0, key.0);
        // Days are UTC days.
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(DAY - 1), 0);
        assert_eq!(epoch_of(DAY), 1);
        assert_eq!(epoch_of(-5), 0);
    }

    #[test]
    fn records_seal_open_and_fit_a_dht_item() {
        let key = SecretKey::random();
        let vault = VaultId::from_bytes(&[9u8; 16]);
        let dev = DeviceId::from_bytes(&[3u8; 16]);
        let day = epoch_of(crate::util::now_utc());
        let rec = record(&dev);
        let blob = seal(&key, &vault, &rec, day).unwrap();
        assert!(blob.len() <= MAX_VALUE, "{} bytes", blob.len());
        let back = open(&key, &vault, &dev, "laptop", day, &blob).unwrap();
        assert_eq!(back, rec);
        // The name comes from the registry, not from the DHT.
        assert_eq!(open(&key, &vault, &dev, "", day, &blob).unwrap().name, "");

        // Wrong vault, device, day or key: refused.
        let other = DeviceId::from_bytes(&[4u8; 16]);
        assert!(open(&key, &VaultId::from_bytes(&[8u8; 16]), &dev, "", day, &blob).is_err());
        assert!(open(&key, &vault, &other, "", day, &blob).is_err());
        assert!(open(&key, &vault, &dev, "", day + 1, &blob).is_err());
        assert!(open(&SecretKey::random(), &vault, &dev, "", day, &blob).is_err());
        let mut bad = blob.clone();
        bad[30] ^= 1;
        assert!(open(&key, &vault, &dev, "", day, &bad).is_err());

        // A record from far in the future is refused.
        let mut late = rec.clone();
        late.updated_utc += 2 * MAX_SKEW;
        let blob = seal(&key, &vault, &late, day).unwrap();
        assert!(open(&key, &vault, &dev, "", day, &blob).is_err());
    }

    #[test]
    fn an_oversized_record_loses_addresses_until_it_fits() {
        let key = SecretKey::random();
        let vault = VaultId::from_bytes(&[9u8; 16]);
        let dev = DeviceId::from_bytes(&[3u8; 16]);
        let mut rec = record(&dev);
        let v6 = |i: u16| -> SocketAddr {
            format!("[2001:db8:1234:5678:9abc:def0:1234:{i:x}]:17893")
                .parse()
                .unwrap()
        };
        rec.public_addrs = (0..20).map(v6).collect();
        rec.udp_public = (100..120).map(v6).collect();
        rec.udp_local = (200..220).map(v6).collect();
        rec.relay_via = (0..20u8).map(|i| DeviceId::from_bytes(&[i; 16])).collect();
        let blob = seal(&key, &vault, &rec, 1).unwrap();
        assert!(blob.len() <= MAX_VALUE);
        let back = open(&key, &vault, &dev, "", 1, &blob).unwrap();
        // Own-interface addresses go first; the port, certificate and the
        // first public addresses stay.
        assert!(back.udp_local.len() < MAX_LIST);
        assert_eq!(back.port, rec.port);
        assert_eq!(back.cert_sha256, rec.cert_sha256);
        assert_eq!(back.public_addrs.first(), rec.public_addrs.first());
        assert_eq!(back.udp_public.first(), rec.udp_public.first());
    }

    #[test]
    fn found_records_merge_newest_first_for_known_devices_only() {
        let (a, b, gone) = (
            DeviceId::from_bytes(&[1u8; 16]),
            DeviceId::from_bytes(&[2u8; 16]),
            DeviceId::from_bytes(&[3u8; 16]),
        );
        let mut stored_a = record(&a);
        stored_a.updated_utc = 100;
        stored_a.name = "desk".into();
        let mut dht_a = record(&a);
        dht_a.updated_utc = 200;
        dht_a.name = String::new();
        dht_a.udp_public = vec!["203.0.113.99:1".parse().unwrap()];
        let mut dht_b = record(&b);
        dht_b.updated_utc = 50;
        let mut stored_b = record(&b);
        stored_b.updated_utc = 60;
        let dht_gone = record(&gone);
        let allowed = vec![a.clone(), b.clone()];
        let got = merge(
            &[stored_a.clone(), stored_b.clone()],
            &[dht_a.clone(), dht_b, dht_gone],
            &allowed,
        );
        assert_eq!(got.len(), 2);
        let ga = got.iter().find(|r| r.device == a).unwrap();
        assert_eq!(ga.udp_public, dht_a.udp_public, "newer DHT record wins");
        assert_eq!(ga.name, "desk", "the storage's name stays");
        let gb = got.iter().find(|r| r.device == b).unwrap();
        assert_eq!(gb.updated_utc, 60, "newer storage record wins");
        assert!(!got.iter().any(|r| r.device == gone));
        // A device only the DHT knows is added.
        let got = merge(&[], &[dht_a], &allowed);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn bootstrap_nodes_come_from_the_environment_first() {
        // Read only: the variable is not set in the test environment unless
        // the lab sets it, and then it must win.
        let conf = vec!["127.0.0.1:6881".to_string()];
        match std::env::var("VARSTO_DHT_BOOTSTRAP") {
            Ok(v) if !v.trim().is_empty() => assert_ne!(bootstrap_nodes(&conf), conf),
            _ => assert_eq!(bootstrap_nodes(&conf), conf),
        }
    }

    #[test]
    fn status_lines_read_well() {
        let mut s = DhtStatus::default();
        assert_eq!(s.describe(), "off");
        s.state = DhtState::Ok;
        s.nodes = 140;
        assert_eq!(
            s.describe(),
            "ok, 140 nodes; published not yet; looked up not yet"
        );
        s.last_publish_utc = Some(crate::util::now_utc() - 300);
        s.stored_at = 18;
        s.last_lookup_utc = Some(crate::util::now_utc() - 300);
        s.found = vec![
            DhtFound {
                device: DeviceId::from_bytes(&[1u8; 16]),
                name: "desk".into(),
                updated_utc: Some(1),
            },
            DhtFound::default(),
        ];
        assert_eq!(
            s.describe(),
            "ok, 140 nodes; published 5 min ago (stored at 18 nodes); looked up 5 min ago, found 1 of 2 devices"
        );
    }
}
