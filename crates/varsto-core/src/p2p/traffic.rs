// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Live counters of peer-to-peer traffic, for the traffic view: what this
//! device received from each peer and sent to it, over which path, and what
//! it forwarded between two other devices as their relay.
//!
//! Every transport records here: the client side (`Peers`) when an answer
//! arrived, the TCP listener and the QUIC streams when an answer went out,
//! and the relay when it copied an answer from one device to another. Bytes
//! are object bodies (ciphertext) as the application sees them, not packets;
//! an object counts when its whole body has arrived or left, so the speed of
//! a single large object shows as a step when it completes.
//!
//! One short-held mutex guards everything: a few map lookups and additions
//! per object, against network and crypto work that takes milliseconds. Each
//! series keeps one bucket per second for the last minute; the current speed
//! is the average of the last few seconds and the history feeds a sparkline.
//! Nothing here goes over the wire.

use crate::ids::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Seconds of history kept per series (one bucket per second).
pub const HISTORY_SECS: usize = 60;
/// The current speed is the average over this many seconds.
pub const RATE_WINDOW_SECS: u64 = 5;

/// Which way bytes went, seen from this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Received from the peer (we downloaded).
    In,
    /// Sent to the peer (we served).
    Out,
}

/// Bytes per second over the last minute: a ring of one-second buckets.
#[derive(Clone, Debug)]
struct Series {
    buckets: [u64; HISTORY_SECS],
    /// The second (since the counters started) the newest bucket stands for.
    head: u64,
}

impl Default for Series {
    fn default() -> Self {
        Series {
            buckets: [0; HISTORY_SECS],
            head: 0,
        }
    }
}

impl Series {
    const N: u64 = HISTORY_SECS as u64;

    /// Move the head to `sec`, emptying the buckets skipped on the way.
    fn advance(&mut self, sec: u64) {
        if sec <= self.head {
            return;
        }
        let gap = (sec - self.head).min(Self::N);
        for i in 1..=gap {
            self.buckets[((self.head + i) % Self::N) as usize] = 0;
        }
        self.head = sec;
    }

    fn add(&mut self, sec: u64, n: u64) {
        self.advance(sec);
        // A caller that read the clock just before another one may land a
        // second behind the head: still inside the ring, so still counted.
        if self.head - sec < Self::N {
            self.buckets[(sec % Self::N) as usize] += n;
        }
    }

    /// The bucket for `sec`, or zero when it is outside the ring.
    fn at(&self, sec: u64) -> u64 {
        if sec <= self.head && self.head - sec < Self::N {
            self.buckets[(sec % Self::N) as usize]
        } else {
            0
        }
    }

    /// Bytes per second at `now_ms`: the last `RATE_WINDOW_SECS - 1` whole
    /// seconds plus the current partial one, divided by the time they cover
    /// (shorter right after the start).
    fn rate(&self, now_ms: u64) -> u64 {
        let sec = now_ms / 1000;
        let first = sec.saturating_sub(RATE_WINDOW_SECS - 1);
        let sum: u64 = (first..=sec).map(|s| self.at(s)).sum();
        let covered = ((RATE_WINDOW_SECS - 1) * 1000 + now_ms % 1000)
            .min(now_ms)
            .max(1);
        sum * 1000 / covered
    }

    /// The last `HISTORY_SECS` whole seconds before `now_ms`, oldest first.
    fn history(&self, now_ms: u64) -> Vec<u64> {
        let sec = now_ms / 1000;
        (0..Self::N)
            .rev()
            .map(|back| match sec.checked_sub(back + 1) {
                Some(s) => self.at(s),
                None => 0,
            })
            .collect()
    }
}

/// Everything known about the traffic with one peer.
#[derive(Default, Debug)]
struct PeerFlow {
    rx: Series,
    tx: Series,
    rx_total: u64,
    tx_total: u64,
    objects_in: u64,
    objects_out: u64,
    /// Requests in flight, both directions.
    active: u32,
    last_ms: Option<u64>,
    /// Path and address of the latest exchange, either direction.
    path: String,
    addr: Option<SocketAddr>,
}

/// Bytes this device forwarded from one device to another as their relay.
#[derive(Default, Debug)]
struct RelayFlow {
    series: Series,
    total: u64,
    objects: u64,
    active: u32,
    last_ms: Option<u64>,
}

#[derive(Default, Debug)]
struct Inner {
    me: Option<(DeviceId, String)>,
    names: BTreeMap<DeviceId, String>,
    peers: BTreeMap<DeviceId, PeerFlow>,
    /// Keyed by (from, to): the device the bytes came from and the one they went to.
    relays: BTreeMap<(DeviceId, DeviceId), RelayFlow>,
    rx: Series,
    tx: Series,
    relay: Series,
}

/// The traffic counters of one device. Shared (`Arc`) by the TCP listener,
/// the QUIC node, the peer table and the local API.
#[derive(Debug)]
pub struct Traffic {
    epoch: Instant,
    epoch_utc: i64,
    inner: Mutex<Inner>,
}

impl Default for Traffic {
    fn default() -> Self {
        Self::new()
    }
}

/// A request in flight; the active count drops when this is dropped.
pub struct Active<'a> {
    traffic: &'a Traffic,
    key: ActiveKey,
}

enum ActiveKey {
    Peer(DeviceId),
    Relay(DeviceId, DeviceId),
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        let mut inner = self.traffic.inner.lock().unwrap();
        match &self.key {
            ActiveKey::Peer(d) => {
                if let Some(f) = inner.peers.get_mut(d) {
                    f.active = f.active.saturating_sub(1);
                }
            }
            ActiveKey::Relay(a, b) => {
                if let Some(f) = inner.relays.get_mut(&(a.clone(), b.clone())) {
                    f.active = f.active.saturating_sub(1);
                }
            }
        }
    }
}

impl Traffic {
    pub fn new() -> Traffic {
        Traffic {
            epoch: Instant::now(),
            epoch_utc: crate::util::now_utc(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// This device, for the report.
    pub fn set_me(&self, device: &DeviceId, name: &str) {
        self.inner.lock().unwrap().me = Some((device.clone(), name.to_string()));
    }

    /// Names of the vault's devices, so peers show by name.
    pub fn learn_names<'a>(&self, names: impl IntoIterator<Item = (&'a DeviceId, &'a str)>) {
        let mut inner = self.inner.lock().unwrap();
        for (d, n) in names {
            if !n.is_empty() {
                inner.names.insert(d.clone(), n.to_string());
            }
        }
    }

    /// A request to or from `peer` starts; it counts as active until the
    /// returned guard is dropped.
    pub fn begin(&self, peer: &DeviceId) -> Active<'_> {
        self.inner
            .lock()
            .unwrap()
            .peers
            .entry(peer.clone())
            .or_default()
            .active += 1;
        Active {
            traffic: self,
            key: ActiveKey::Peer(peer.clone()),
        }
    }

    /// Forwarding from `from` to `to` starts (this device is their relay).
    pub fn begin_relay(&self, from: &DeviceId, to: &DeviceId) -> Active<'_> {
        self.inner
            .lock()
            .unwrap()
            .relays
            .entry((from.clone(), to.clone()))
            .or_default()
            .active += 1;
        Active {
            traffic: self,
            key: ActiveKey::Relay(from.clone(), to.clone()),
        }
    }

    /// `bytes` went to or came from `peer` over `path` (a `PeerStatus`
    /// label: direct-lan, direct, relayed via X) at `addr`; `object` when it
    /// was a whole object rather than an info answer or an error.
    pub fn record(
        &self,
        peer: &DeviceId,
        dir: Direction,
        bytes: u64,
        object: bool,
        path: &str,
        addr: Option<SocketAddr>,
    ) {
        self.record_at(self.now_ms(), peer, dir, bytes, object, path, addr);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_at(
        &self,
        now_ms: u64,
        peer: &DeviceId,
        dir: Direction,
        bytes: u64,
        object: bool,
        path: &str,
        addr: Option<SocketAddr>,
    ) {
        let sec = now_ms / 1000;
        let mut inner = self.inner.lock().unwrap();
        let f = inner.peers.entry(peer.clone()).or_default();
        match dir {
            Direction::In => {
                f.rx.add(sec, bytes);
                f.rx_total += bytes;
                f.objects_in += object as u64;
            }
            Direction::Out => {
                f.tx.add(sec, bytes);
                f.tx_total += bytes;
                f.objects_out += object as u64;
            }
        }
        f.last_ms = Some(now_ms);
        if !path.is_empty() {
            f.path = path.to_string();
        }
        if addr.is_some() {
            f.addr = addr;
        }
        match dir {
            Direction::In => inner.rx.add(sec, bytes),
            Direction::Out => inner.tx.add(sec, bytes),
        }
    }

    /// `bytes` were forwarded from `from` to `to` through this device.
    pub fn record_relay(&self, from: &DeviceId, to: &DeviceId, bytes: u64, object: bool) {
        self.record_relay_at(self.now_ms(), from, to, bytes, object);
    }

    fn record_relay_at(
        &self,
        now_ms: u64,
        from: &DeviceId,
        to: &DeviceId,
        bytes: u64,
        object: bool,
    ) {
        let sec = now_ms / 1000;
        let mut inner = self.inner.lock().unwrap();
        let f = inner.relays.entry((from.clone(), to.clone())).or_default();
        f.series.add(sec, bytes);
        f.total += bytes;
        f.objects += object as u64;
        f.last_ms = Some(now_ms);
        inner.relay.add(sec, bytes);
    }

    /// Everything as of now, for the API and the CLI.
    pub fn report(&self) -> TrafficReport {
        self.report_at(self.now_ms())
    }

    fn report_at(&self, now_ms: u64) -> TrafficReport {
        let inner = self.inner.lock().unwrap();
        let utc = |ms: Option<u64>| ms.map(|m| self.epoch_utc + (m / 1000) as i64);
        let name = |d: &DeviceId| inner.names.get(d).cloned().unwrap_or_default();
        let mut totals = TrafficTotals {
            rx_bps: inner.rx.rate(now_ms),
            tx_bps: inner.tx.rate(now_ms),
            relay_bps: inner.relay.rate(now_ms),
            ..Default::default()
        };
        let mut peers: Vec<PeerTraffic> = Vec::new();
        for (d, f) in &inner.peers {
            totals.rx_total += f.rx_total;
            totals.tx_total += f.tx_total;
            totals.objects_in += f.objects_in;
            totals.objects_out += f.objects_out;
            totals.active += f.active;
            peers.push(PeerTraffic {
                device: d.clone(),
                name: name(d),
                path: f.path.clone(),
                addr: f.addr,
                rx_bps: f.rx.rate(now_ms),
                tx_bps: f.tx.rate(now_ms),
                rx_total: f.rx_total,
                tx_total: f.tx_total,
                objects_in: f.objects_in,
                objects_out: f.objects_out,
                active: f.active,
                last_seen_utc: utc(f.last_ms),
                rx_history: f.rx.history(now_ms),
                tx_history: f.tx.history(now_ms),
            });
        }
        // Known devices without traffic yet still show, as idle nodes.
        for (d, n) in &inner.names {
            let is_me = inner.me.as_ref().is_some_and(|(m, _)| m == d);
            if !is_me && !inner.peers.contains_key(d) {
                peers.push(PeerTraffic {
                    device: d.clone(),
                    name: n.clone(),
                    ..PeerTraffic::idle()
                });
            }
        }
        let relays: Vec<RelayTraffic> = inner
            .relays
            .iter()
            .map(|((from, to), f)| {
                totals.relay_total += f.total;
                totals.active += f.active;
                RelayTraffic {
                    from: from.clone(),
                    from_name: name(from),
                    to: to.clone(),
                    to_name: name(to),
                    bps: f.series.rate(now_ms),
                    total: f.total,
                    objects: f.objects,
                    active: f.active,
                    last_seen_utc: utc(f.last_ms),
                    history: f.series.history(now_ms),
                }
            })
            .collect();
        TrafficReport {
            device: inner.me.as_ref().map(|(d, _)| d.clone()),
            name: inner
                .me
                .as_ref()
                .map(|(_, n)| n.clone())
                .unwrap_or_default(),
            started_utc: self.epoch_utc,
            now_utc: self.epoch_utc + (now_ms / 1000) as i64,
            window_secs: RATE_WINDOW_SECS,
            peers,
            relays,
            totals,
            history: TrafficHistory {
                rx: inner.rx.history(now_ms),
                tx: inner.tx.history(now_ms),
                relay: inner.relay.history(now_ms),
            },
        }
    }
}

/// `GET /api/p2p/traffic`: speeds are bytes per second over the last
/// `window_secs`, totals count since the service started, histories are the
/// bytes of each of the last 60 whole seconds, oldest first.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrafficReport {
    /// This device; none until peer-to-peer runs.
    pub device: Option<DeviceId>,
    pub name: String,
    pub started_utc: i64,
    pub now_utc: i64,
    pub window_secs: u64,
    pub peers: Vec<PeerTraffic>,
    /// Forwarded through this device as a relay.
    pub relays: Vec<RelayTraffic>,
    pub totals: TrafficTotals,
    pub history: TrafficHistory,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerTraffic {
    pub device: DeviceId,
    pub name: String,
    /// `direct-lan`, `direct` or `relayed via <name>`; empty before any exchange.
    pub path: String,
    pub addr: Option<SocketAddr>,
    /// Received from the peer (downloads), bytes per second.
    pub rx_bps: u64,
    /// Sent to the peer (served), bytes per second.
    pub tx_bps: u64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub objects_in: u64,
    pub objects_out: u64,
    /// Requests in flight now.
    pub active: u32,
    pub last_seen_utc: Option<i64>,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
}

impl PeerTraffic {
    fn idle() -> PeerTraffic {
        PeerTraffic {
            rx_history: vec![0; HISTORY_SECS],
            tx_history: vec![0; HISTORY_SECS],
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayTraffic {
    /// The device the bytes came from (it served them).
    pub from: DeviceId,
    pub from_name: String,
    /// The device they went to (it asked for them).
    pub to: DeviceId,
    pub to_name: String,
    pub bps: u64,
    pub total: u64,
    pub objects: u64,
    pub active: u32,
    pub last_seen_utc: Option<i64>,
    pub history: Vec<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrafficTotals {
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub relay_bps: u64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub relay_total: u64,
    pub objects_in: u64,
    pub objects_out: u64,
    pub active: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrafficHistory {
    pub rx: Vec<u64>,
    pub tx: Vec<u64>,
    pub relay: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_averages_the_window_and_starts_from_the_elapsed_time() {
        let mut s = Series::default();
        // 1000 bytes in each of seconds 0..=9.
        for sec in 0..10 {
            s.add(sec, 1000);
        }
        // At 9.5 s the window is seconds 5..=9 over 4.5 s.
        assert_eq!(s.rate(9_500), 5000 * 1000 / 4500);
        // Exactly on a second boundary the current bucket is empty and the
        // window covers four whole seconds.
        s.advance(10);
        assert_eq!(s.rate(10_000), 4000 * 1000 / 4000);
        // Right after the start only the elapsed time counts.
        let mut fresh = Series::default();
        fresh.add(0, 300);
        assert_eq!(fresh.rate(500), 600);
        assert_eq!(fresh.rate(0), 300_000); // no division by zero
                                            // Quiet for longer than the window: zero.
        assert_eq!(s.rate(20_000), 0);
    }

    #[test]
    fn ring_forgets_after_a_minute_and_history_is_oldest_first() {
        let mut s = Series::default();
        s.add(3, 7);
        s.add(4, 9);
        let h = s.history(5_200);
        assert_eq!(h.len(), HISTORY_SECS);
        assert_eq!(&h[HISTORY_SECS - 2..], &[7, 9]);
        assert!(h[..HISTORY_SECS - 2].iter().all(|&x| x == 0));
        // A long gap empties every bucket it skipped, wrapped ones included.
        s.add(4 + HISTORY_SECS as u64, 1);
        assert_eq!(s.at(4), 0);
        assert_eq!(s.at(3), 0);
        assert_eq!(
            s.history((5 + HISTORY_SECS as u64) * 1000)
                .iter()
                .sum::<u64>(),
            1
        );
        // A late writer one second behind the head still counts.
        s.add(3 + HISTORY_SECS as u64, 5);
        assert_eq!(s.at(3 + HISTORY_SECS as u64), 5);
        // One from beyond the ring does not.
        s.add(1, 100);
        assert_eq!(
            s.history((5 + HISTORY_SECS as u64) * 1000)
                .iter()
                .sum::<u64>(),
            6
        );
    }

    #[test]
    fn counters_per_peer_direction_and_relay() {
        let t = Traffic::new();
        let (me, a, b, quiet) = (
            DeviceId::from_bytes(&[1u8; 16]),
            DeviceId::from_bytes(&[2u8; 16]),
            DeviceId::from_bytes(&[3u8; 16]),
            DeviceId::from_bytes(&[4u8; 16]),
        );
        t.set_me(&me, "laptop");
        t.learn_names([
            (&me, "laptop"),
            (&a, "desk"),
            (&b, "phone"),
            (&quiet, "spare"),
        ]);
        let lan: SocketAddr = "192.168.1.9:17893".parse().unwrap();
        t.record_at(
            1_000,
            &a,
            Direction::In,
            4000,
            true,
            "direct-lan",
            Some(lan),
        );
        t.record_at(
            1_500,
            &a,
            Direction::In,
            4000,
            true,
            "direct-lan",
            Some(lan),
        );
        t.record_at(2_000, &a, Direction::Out, 100, false, "direct-lan", None);
        t.record_relay_at(2_000, &b, &a, 2500, true);
        {
            let _x = t.begin(&b);
            let _y = t.begin(&b);
            let _z = t.begin_relay(&b, &a);
            assert_eq!(t.report_at(2_500).totals.active, 3);
        }
        let r = t.report_at(2_500);
        assert_eq!(r.device.as_ref(), Some(&me));
        assert_eq!(r.name, "laptop");
        assert_eq!(r.totals.active, 0);
        let pa = r.peers.iter().find(|p| p.device == a).unwrap();
        assert_eq!(pa.name, "desk");
        assert_eq!((pa.rx_total, pa.tx_total), (8000, 100));
        assert_eq!((pa.objects_in, pa.objects_out), (2, 0));
        assert_eq!(pa.path, "direct-lan");
        assert_eq!(pa.addr, Some(lan)); // kept when a later record has none
        assert_eq!(pa.rx_bps, 8000 * 1000 / 2500);
        assert_eq!(pa.last_seen_utc, Some(r.started_utc + 2));
        // The guard-only peer and the quiet one are listed, idle.
        let pb = r.peers.iter().find(|p| p.device == b).unwrap();
        assert_eq!((pb.rx_total, pb.active), (0, 0));
        let pq = r.peers.iter().find(|p| p.device == quiet).unwrap();
        assert_eq!((pq.name.as_str(), pq.path.as_str()), ("spare", ""));
        assert_eq!(pq.rx_history.len(), HISTORY_SECS);
        assert!(r.peers.iter().all(|p| p.device != me));
        assert_eq!(r.relays.len(), 1);
        let rl = &r.relays[0];
        assert_eq!(
            (rl.from_name.as_str(), rl.to_name.as_str()),
            ("phone", "desk")
        );
        assert_eq!((rl.total, rl.objects), (2500, 1));
        assert_eq!(r.totals.rx_total, 8000);
        assert_eq!(r.totals.tx_total, 100);
        assert_eq!(r.totals.relay_total, 2500);
        assert_eq!(r.totals.objects_in, 2);
        // Overall history: second 1 got both downloads, second 2 the rest.
        let h = &r.history;
        assert_eq!(h.rx[HISTORY_SECS - 1], 8000);
        assert_eq!(h.tx.iter().sum::<u64>(), 0); // second 2 is not complete at 2.5 s
        assert_eq!(t.report_at(3_000).history.tx[HISTORY_SECS - 1], 100);
        assert_eq!(t.report_at(3_000).history.relay[HISTORY_SECS - 1], 2500);
        // Serialises for the API.
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v["peers"][0]["rx_history"].as_array().unwrap().len(),
            HISTORY_SECS
        );
    }
}
