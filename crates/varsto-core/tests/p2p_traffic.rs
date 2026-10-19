// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Traffic counters on localhost: a laptop serves its blocks over TLS on TCP
//! to one device and over QUIC to another, and a device behind "NAT" serves through
//! a relay. Both ends (and the relay) must agree on bytes, objects,
//! direction and path.

mod common;

use common::p2p::{empty, publish_quic, quic_node, quic_table, served, QuicDev};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use varsto_core::chunking::ChunkerParams;
use varsto_core::ids::DeviceId;
use varsto_core::p2p::traffic::{PeerTraffic, TrafficReport};
use varsto_core::p2p::{self, Traffic};
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
            min_free: None,
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

/// The device holding the files (the storage loses every block once the
/// others joined, so only peers can supply them).
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
    (e, key)
}

fn lose(lab: &Lab) {
    common::lose_all_objects(&lab.root.join("storage"));
}

fn join(lab: &Lab, who: &str, name: &str, key: &str, owner: &mut Engine) -> Engine {
    let mut e = common::join_approved(&lab.home(who), name, PASS, key, lab.storage.clone(), owner);
    e.chunker = ChunkerParams::SMALL;
    e.attach_folder("docs", &lab.dir(who), false).unwrap();
    e
}

fn node(e: &Engine, snap: common::p2p::Snap, traffic: &Arc<Traffic>) -> QuicDev {
    quic_node(e, snap, traffic.clone())
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
    let (mut a, key) = seed(&lab, "a", "laptop");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    let mut c = join(&lab, "c", "phone", &key, &mut a);
    lose(&lab);
    let traffic_a = Arc::new(Traffic::new());
    let snap_a = served(&a);
    let qa = node(&a, snap_a.clone(), &traffic_a);

    // TLS over TCP, sharing the laptop's answering side and counters.
    let tls = p2p::v3::tls::TcpTls::new(qa.node.identity(), qa.responder.clone()).unwrap();
    let server = p2p::Server::bind("127.0.0.1:0".parse().unwrap(), tls)
        .unwrap()
        .with_traffic(traffic_a.clone());
    let tcp_addr = server.addr;
    let stop = Arc::new(AtomicBool::new(false));
    let (snap2, stop2) = (snap_a.clone(), stop.clone());
    let th = std::thread::spawn(move || server.run(snap2, stop2));

    // The desk pulls over QUIC.
    let traffic_b = Arc::new(Traffic::new());
    let qb = node(&b, empty(), &traffic_b);
    publish_quic(&a, &qa, true, false, &[]);
    publish_quic(&b, &qb, true, false, &[]);
    // The phone has no listener of its own; its record names its certificate.
    common::p2p::publish(&c, 9);
    let _peers_a = quic_table(&mut a, &qa);
    let peers_b = quic_table(&mut b, &qb);
    assert!(Arc::ptr_eq(peers_b.traffic(), &traffic_b));
    b.set_peers(Some(Arc::new(peers_b)));
    let rep_b = b.pull("docs").unwrap();
    assert!(rep_b.files_unavailable.is_empty());
    assert!(rep_b.chunks_from_peers >= 2);

    // The phone pulls over TCP only, from the laptop's TLS listener.
    let mut body = a.peer_body(tcp_addr.port());
    body.lan_addrs = vec![tcp_addr.ip()];
    body.udp_local = Vec::new();
    a.publish_peer_body(&mut body).unwrap();
    let traffic_c = Arc::new(Traffic::new());
    c.refresh_devices().unwrap();
    let peers_c = c.p2p_peers_tcp().unwrap().with_traffic(traffic_c.clone());
    c.set_peers(Some(Arc::new(peers_c)));
    let rep_c = c.pull("docs").unwrap();
    assert!(rep_c.files_unavailable.is_empty());
    assert_eq!(rep_c.chunks_from_peers, rep_b.chunks_from_peers);

    // A request that lost the race to another source may still be closing.
    let (rb, rc) = (
        settle(&traffic_b, |r| r.totals.active == 0),
        settle(&traffic_c, |r| r.totals.active == 0),
    );
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
    assert_eq!(b_from_a.addr, Some(qa.node.local_addr));
    // Speeds and the per-second history depend on timing (the current second
    // is not in the history yet, and the speed window may have passed on a
    // busy machine); the byte totals are exact.
    assert_eq!(b_from_a.active, 0);
    assert!(b_from_a.last_seen_utc.is_some());
    assert_eq!(rb.totals.rx_total, b_from_a.rx_total);

    // Laptop side: the same bytes went out to the desk.
    let a_to_b = peer(&ra, b.device_id());
    assert_eq!(a_to_b.tx_total, b_from_a.rx_total);
    assert_eq!(a_to_b.objects_out, b_from_a.objects_in);
    assert_eq!(a_to_b.rx_total, 0);
    assert_eq!(a_to_b.path, "direct-lan");
    assert_eq!(a_to_b.addr, Some(qb.node.local_addr));

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
    let (mut b, key) = seed(&lab, "b", "nas");
    let mut r = join(&lab, "r", "home-server", &key, &mut b);
    let mut a = join(&lab, "a", "travel", &key, &mut b);
    lose(&lab);
    let (traffic_a, traffic_b, traffic_r) = (
        Arc::new(Traffic::new()),
        Arc::new(Traffic::new()),
        Arc::new(Traffic::new()),
    );
    let qb = node(&b, served(&b), &traffic_b);
    let qr = node(&r, empty(), &traffic_r);
    let qa = node(&a, empty(), &traffic_a);

    publish_quic(&b, &qb, false, false, &[r.device_id().clone()]);
    publish_quic(&r, &qr, true, true, &[]);
    publish_quic(&a, &qa, false, false, &[]);
    let _peers_r = quic_table(&mut r, &qr);
    let _peers_b = quic_table(&mut b, &qb);
    qb.node
        .register_with(
            r.device_id(),
            &[qr.node.local_addr],
            &qr.node.identity().sha256,
        )
        .unwrap();
    let peers_a = quic_table(&mut a, &qa);
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
    assert_eq!(a_from_b.addr, Some(qr.node.local_addr));
    assert_eq!(a_from_b.objects_in, rep.chunks_from_peers);
    assert!(a_from_b.rx_total > 0);

    // B served A through the relay, and knows it.
    let b_to_a = peer(&rb, a.device_id());
    assert_eq!(b_to_a.name, "travel");
    assert_eq!(b_to_a.path, "relayed via home-server");
    assert_eq!(b_to_a.addr, Some(qr.node.local_addr));
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

#[test]
fn many_blocks_and_small_files_share_one_quic_connection() {
    // A large file (many blocks in flight at once) and many small files
    // (fetched ahead across files) all travel over one QUIC connection. The
    // record carries no TCP address: on loopback, a LAN address, TCP would
    // be tried first.
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    let big: Vec<u8> = (0..400_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    fs::write(lab.dir("a").join("big.bin"), &big).unwrap();
    for i in 0..60u32 {
        let body: Vec<u8> = (0..900 + i * 37)
            .map(|j| (j.wrapping_mul(40_503).wrapping_add(i * 7919) >> 3) as u8)
            .collect();
        fs::write(lab.dir("a").join(format!("small-{i:02}.bin")), body).unwrap();
    }
    a.push("docs").unwrap();
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    lose(&lab);

    let traffic_a = Arc::new(Traffic::new());
    let qa = node(&a, served(&a), &traffic_a);
    let traffic_b = Arc::new(Traffic::new());
    let qb = node(&b, empty(), &traffic_b);
    publish_quic(&a, &qa, true, false, &[]);
    publish_quic(&b, &qb, true, false, &[]);
    let _peers_a = quic_table(&mut a, &qa);
    let peers_b = quic_table(&mut b, &qb);
    b.set_peers(Some(Arc::new(peers_b)));
    let rep = b.pull("docs").unwrap();
    assert!(
        rep.files_unavailable.is_empty(),
        "{:?}",
        rep.files_unavailable
    );
    assert_eq!(rep.files_updated, 61);
    assert!(rep.chunks_downloaded > 100, "{}", rep.chunks_downloaded);
    assert_eq!(rep.chunks_from_peers, rep.chunks_downloaded);
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);
    for i in 0..60u32 {
        let name = format!("small-{i:02}.bin");
        assert_eq!(
            fs::read(lab.dir("b").join(&name)).unwrap(),
            fs::read(lab.dir("a").join(&name)).unwrap()
        );
    }
    // Every request in flight shared the one connection.
    assert_eq!(qb.node.connections_opened(), 1);

    // Both ends counted the same objects and bytes.
    let rb = settle(&traffic_b, |r| r.totals.active == 0);
    let ra = settle(&traffic_a, |r| {
        r.totals.objects_out == rep.chunks_from_peers
    });
    let b_from_a = peer(&rb, a.device_id());
    let a_to_b = peer(&ra, b.device_id());
    assert_eq!(b_from_a.objects_in, rep.chunks_from_peers);
    assert_eq!(a_to_b.objects_out, rep.chunks_from_peers);
    assert_eq!(a_to_b.tx_total, b_from_a.rx_total);
}
