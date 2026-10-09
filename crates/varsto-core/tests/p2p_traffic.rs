// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Traffic counters on localhost: a laptop serves its blocks over TCP to one
//! device and over QUIC to another, and a device behind "NAT" serves through
//! a relay. Both ends (and the relay) must agree on bytes, objects,
//! direction and path.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use varsto_core::chunking::ChunkerParams;
use varsto_core::ids::DeviceId;
use varsto_core::p2p::traffic::{PeerTraffic, TrafficReport};
use varsto_core::p2p::{self, quic, PeerRecord, Peers, Traffic};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
        },
        root,
        _tmp: tmp,
    }
}

impl Lab {
    fn home(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-home"))
    }
    fn dir(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-docs"))
    }
}

/// The device holding the files; the storage then loses every chunk, so
/// only peers can supply them.
fn seed(lab: &Lab, who: &str, name: &str) -> (Engine, String) {
    let (mut e, key) = Engine::init(&lab.home(who), name, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(lab.storage.clone()).unwrap();
    e.add_folder("docs", &lab.dir(who)).unwrap();
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    fs::write(lab.dir(who).join("big.bin"), big).unwrap();
    e.push("docs").unwrap();
    fs::remove_dir_all(lab.root.join("storage").join("chunks")).unwrap();
    (e, key)
}

fn join(lab: &Lab, who: &str, name: &str, key: &str) -> Engine {
    let mut e = Engine::join(&lab.home(who), name, PASS, key, lab.storage.clone()).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.attach_folder("docs", &lab.dir(who), false).unwrap();
    e
}

type Snap = Arc<Mutex<Option<Arc<p2p::Snapshot>>>>;

fn node(e: &Engine, snap: Snap, traffic: &Arc<Traffic>) -> Arc<quic::Node> {
    traffic.set_me(e.device_id(), e.own_device_name());
    quic::Node::start(
        "127.0.0.1:0".parse().unwrap(),
        e.p2p_identity().unwrap(),
        e.device_id().clone(),
        e.peer_key(),
        snap,
        traffic.clone(),
    )
    .unwrap()
}

fn record(e: &Engine, n: &quic::Node, direct: bool) -> PeerRecord {
    let mut rec = e.peer_record_template(n.local_addr.port());
    rec.lan_addrs.clear();
    rec.udp_local = if direct { vec![n.local_addr] } else { vec![] };
    rec.cert_sha256 = n.identity().sha256.clone();
    rec
}

fn served(e: &Engine) -> Snap {
    Arc::new(Mutex::new(Some(Arc::new(e.peer_snapshot().unwrap()))))
}

fn empty() -> Snap {
    Arc::new(Mutex::new(None))
}

/// The serving side records an answer once the receiver has acknowledged
/// all of it, a moment after the receiver has it: wait for `done`.
fn settle(traffic: &Traffic, done: impl Fn(&TrafficReport) -> bool) -> TrafficReport {
    for _ in 0..60 {
        let r = traffic.report();
        if done(&r) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    traffic.report()
}

fn peer<'a>(r: &'a TrafficReport, d: &DeviceId) -> &'a PeerTraffic {
    r.peers
        .iter()
        .find(|p| &p.device == d)
        .unwrap_or_else(|| panic!("{d} missing from {r:?}"))
}

#[test]
fn downloads_and_uploads_are_counted_on_both_ends_over_tcp_and_quic() {
    let lab = lab();
    let (a, key) = seed(&lab, "a", "laptop");
    let traffic_a = Arc::new(Traffic::new());
    let snap_a = served(&a);
    let node_a = node(&a, snap_a.clone(), &traffic_a);

    // TCP listener sharing the laptop's counters.
    let server = p2p::Server::bind("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .with_traffic(traffic_a.clone());
    let tcp_addr = server.addr;
    let stop = Arc::new(AtomicBool::new(false));
    let (snap2, stop2) = (snap_a.clone(), stop.clone());
    let th = std::thread::spawn(move || server.run(snap2, stop2));

    // The desk pulls over QUIC.
    let mut b = join(&lab, "b", "desk", &key);
    let traffic_b = Arc::new(Traffic::new());
    let node_b = node(&b, empty(), &traffic_b);
    let (rec_a, rec_b) = (record(&a, &node_a, true), record(&b, &node_b, true));
    let _peers_a = Peers::build(
        a.peer_key(),
        a.device_id().clone(),
        std::slice::from_ref(&rec_b),
        &[],
        Some(node_a.clone()),
    );
    let peers_b = Peers::build(
        b.peer_key(),
        b.device_id().clone(),
        std::slice::from_ref(&rec_a),
        &[],
        Some(node_b.clone()),
    );
    assert!(Arc::ptr_eq(peers_b.traffic(), &traffic_b));
    b.set_peers(Some(Arc::new(peers_b)));
    let rep_b = b.pull("docs").unwrap();
    assert!(rep_b.files_unavailable.is_empty());
    assert!(rep_b.chunks_from_peers >= 2);

    // The phone pulls over TCP only.
    let mut c = join(&lab, "c", "phone", &key);
    let traffic_c = Arc::new(Traffic::new());
    let peers_c = Peers::new(
        c.peer_key(),
        c.device_id().clone(),
        vec![p2p::PeerAddr {
            device: a.device_id().clone(),
            addr: tcp_addr,
            name: "laptop".into(),
        }],
    )
    .with_traffic(traffic_c.clone());
    c.set_peers(Some(Arc::new(peers_c)));
    let rep_c = c.pull("docs").unwrap();
    assert!(rep_c.files_unavailable.is_empty());
    assert_eq!(rep_c.chunks_from_peers, rep_b.chunks_from_peers);

    let (rb, rc) = (traffic_b.report(), traffic_c.report());
    let want = rb.totals.objects_in + rc.totals.objects_in;
    let ra = settle(&traffic_a, |r| r.totals.objects_out == want);
    assert_eq!(ra.name, "laptop");
    assert_eq!(rb.device.as_ref(), Some(b.device_id()));

    // Desk side: everything came in from the laptop over QUIC on loopback.
    let b_from_a = peer(&rb, a.device_id());
    assert_eq!(b_from_a.name, "laptop");
    assert_eq!(b_from_a.objects_in, rep_b.chunks_from_peers);
    assert_eq!((b_from_a.tx_total, b_from_a.objects_out), (0, 0));
    assert!(b_from_a.rx_total > 0);
    assert_eq!(b_from_a.path, "direct-lan");
    assert_eq!(b_from_a.addr, Some(node_a.local_addr));
    assert!(b_from_a.rx_bps > 0, "{b_from_a:?}");
    assert_eq!(b_from_a.active, 0);
    assert!(b_from_a.last_seen_utc.is_some());
    assert_eq!(rb.totals.rx_total, b_from_a.rx_total);

    // Laptop side: the same bytes went out to the desk.
    let a_to_b = peer(&ra, b.device_id());
    assert_eq!(a_to_b.tx_total, b_from_a.rx_total);
    assert_eq!(a_to_b.objects_out, b_from_a.objects_in);
    assert_eq!(a_to_b.rx_total, 0);
    assert_eq!(a_to_b.path, "direct-lan");
    assert_eq!(a_to_b.addr, Some(node_b.local_addr));

    // TCP: the phone counted what the laptop's listener counted.
    let c_from_a = peer(&rc, a.device_id());
    assert_eq!(c_from_a.objects_in, rep_c.chunks_from_peers);
    assert_eq!(c_from_a.path, "direct-lan");
    assert_eq!(c_from_a.addr, Some(tcp_addr));
    let a_to_c = peer(&ra, c.device_id());
    assert_eq!(a_to_c.tx_total, c_from_a.rx_total);
    assert_eq!(a_to_c.objects_out, c_from_a.objects_in);
    assert_eq!(a_to_c.path, "direct-lan");
    // Same objects, same ciphertext, whichever transport carried them.
    assert_eq!(c_from_a.rx_total, b_from_a.rx_total);
    assert_eq!(ra.totals.tx_total, a_to_b.tx_total + a_to_c.tx_total);
    assert_eq!(
        ra.totals.objects_out,
        a_to_b.objects_out + a_to_c.objects_out
    );
    // Once the current second is over, the minute of history holds every
    // byte (the test takes seconds).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let later = traffic_a.report();
    assert_eq!(later.history.tx.iter().sum::<u64>(), ra.totals.tx_total);
    assert_eq!(later.history.tx.len(), 60);
    assert!(ra.relays.is_empty());

    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
}

#[test]
fn relayed_transfer_is_counted_by_both_ends_and_the_relay() {
    let lab = lab();
    // B holds the data behind "NAT", R relays, A fetches.
    let (b, key) = seed(&lab, "b", "nas");
    let (traffic_a, traffic_b, traffic_r) = (
        Arc::new(Traffic::new()),
        Arc::new(Traffic::new()),
        Arc::new(Traffic::new()),
    );
    let node_b = node(&b, served(&b), &traffic_b);
    let r = join(&lab, "r", "home-server", &key);
    let node_r = node(&r, empty(), &traffic_r);
    let mut a = join(&lab, "a", "travel", &key);
    let node_a = node(&a, empty(), &traffic_a);

    let mut rec_b = record(&b, &node_b, false);
    rec_b.relay_via = vec![r.device_id().clone()];
    let mut rec_r = record(&r, &node_r, true);
    rec_r.reachable = true;
    let rec_a = record(&a, &node_a, false);
    let _peers_r = Peers::build(
        r.peer_key(),
        r.device_id().clone(),
        &[rec_a.clone(), rec_b.clone()],
        &[],
        Some(node_r.clone()),
    );
    let _peers_b = Peers::build(
        b.peer_key(),
        b.device_id().clone(),
        &[rec_r.clone(), rec_a.clone()],
        &[],
        Some(node_b.clone()),
    );
    node_b
        .register_with(r.device_id(), &[node_r.local_addr], &rec_r.cert_sha256)
        .unwrap();
    let peers_a = Peers::build(
        a.peer_key(),
        a.device_id().clone(),
        &[rec_r.clone(), rec_b.clone()],
        &[],
        Some(node_a.clone()),
    );
    a.set_peers(Some(Arc::new(peers_a)));
    let rep = a.pull("docs").unwrap();
    assert!(rep.files_unavailable.is_empty());
    assert!(rep.chunks_from_peers >= 2);

    let ra = traffic_a.report();
    let want = ra.totals.objects_in;
    let rb = settle(&traffic_b, |r| r.totals.objects_out == want);
    let rr = traffic_r.report();
    let a_from_b = peer(&ra, b.device_id());
    assert_eq!(a_from_b.path, "relayed via home-server");
    assert_eq!(a_from_b.addr, Some(node_r.local_addr));
    assert_eq!(a_from_b.objects_in, rep.chunks_from_peers);
    assert!(a_from_b.rx_total > 0 && a_from_b.rx_bps > 0);

    // B served A through the relay, and knows it.
    let b_to_a = peer(&rb, a.device_id());
    assert_eq!(b_to_a.name, "travel");
    assert_eq!(b_to_a.path, "relayed via home-server");
    assert_eq!(b_to_a.addr, Some(node_r.local_addr));
    assert_eq!(b_to_a.tx_total, a_from_b.rx_total);
    assert_eq!(b_to_a.objects_out, a_from_b.objects_in);

    // R forwarded every object from B to A; none of it is its own traffic.
    assert_eq!(rr.relays.len(), 1, "{:?}", rr.relays);
    let flow = &rr.relays[0];
    assert_eq!((&flow.from, &flow.to), (b.device_id(), a.device_id()));
    assert_eq!(
        (flow.from_name.as_str(), flow.to_name.as_str()),
        ("nas", "travel")
    );
    assert_eq!(flow.total, a_from_b.rx_total);
    assert_eq!(flow.objects, a_from_b.objects_in);
    assert!(flow.bps > 0);
    assert_eq!(rr.totals.relay_total, flow.total);
    assert!(rr
        .peers
        .iter()
        .all(|p| p.objects_out == 0 && p.objects_in == 0));
}
