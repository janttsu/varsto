// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! NAT traversal pieces on localhost: QUIC transfer between two devices with
//! pinned certificates, rejection of a device whose certificate the server
//! does not know, and a relayed fetch A -> R -> B where B registers with R.
//! No real NAT is involved; the traversal logic (STUN, punching) is covered
//! by unit tests and by hand on the maintainer's own networks.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use varsto_core::chunking::ChunkerParams;
use varsto_core::ids::DeviceId;
use varsto_core::p2p::{self, quic, PeerRecord, Peers};
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

/// The first device: holds the files, pushes them, then the storage loses
/// every chunk so that only peers can supply them.
fn seed(lab: &Lab, who: &str) -> (Engine, String, Vec<u8>) {
    let (mut a, key) = Engine::init(&lab.home(who), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir(who)).unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(lab.dir(who).join("big.bin"), &big).unwrap();
    fs::write(lab.dir(who).join("note.txt"), b"over quic").unwrap();
    a.push("docs").unwrap();
    fs::remove_dir_all(lab.root.join("storage").join("chunks")).unwrap();
    (a, key, big)
}

fn join(lab: &Lab, who: &str, name: &str, key: &str) -> Engine {
    let mut e = Engine::join(&lab.home(who), name, PASS, key, lab.storage.clone()).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.attach_folder("docs", &lab.dir(who), false).unwrap();
    e
}

type Snap = Arc<Mutex<Option<Arc<p2p::Snapshot>>>>;

/// A QUIC node for `e` on a loopback port of its own, serving `snap`.
fn node(e: &Engine, snap: Snap) -> Arc<quic::Node> {
    quic::Node::start(
        "127.0.0.1:0".parse().unwrap(),
        e.p2p_identity().unwrap(),
        e.device_id().clone(),
        e.peer_key(),
        snap,
        Arc::default(),
    )
    .unwrap()
}

/// The record `e` would publish, with its node's loopback address as the
/// only UDP address (or none at all, for a device "behind NAT").
fn record(e: &Engine, n: &quic::Node, direct: bool) -> PeerRecord {
    let mut rec = e.peer_record_template(n.local_addr.port());
    rec.lan_addrs.clear();
    rec.udp_local = if direct { vec![n.local_addr] } else { vec![] };
    rec.cert_sha256 = n.identity().sha256.clone();
    rec
}

fn empty() -> Snap {
    Arc::new(Mutex::new(None))
}

#[test]
fn quic_direct_transfer_with_pinned_certificates() {
    let lab = lab();
    let (a, key, big) = seed(&lab, "a");
    let snap_a: Snap = Arc::new(Mutex::new(Some(Arc::new(a.peer_snapshot().unwrap()))));
    let node_a = node(&a, snap_a);
    let mut b = join(&lab, "b", "desk", &key);
    let node_b = node(&b, empty());
    let (rec_a, rec_b) = (record(&a, &node_a, true), record(&b, &node_b, true));
    assert_eq!(rec_a.version, PeerRecord::VERSION);
    assert_eq!(rec_a.cert_sha256.len(), 64);

    // Each side learns the other's record, as the services do from the storage.
    let _peers_a = Peers::build(
        a.peer_key(),
        a.device_id().clone(),
        std::slice::from_ref(&rec_b),
        &[],
        Some(node_a.clone()),
    );
    let peers_b = Arc::new(Peers::build(
        b.peer_key(),
        b.device_id().clone(),
        std::slice::from_ref(&rec_a),
        &[],
        Some(node_b.clone()),
    ));
    assert_eq!(peers_b.status()[0].path, "untried");
    b.set_peers(Some(peers_b.clone()));
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert!(r.chunks_from_peers >= 2, "{}", r.chunks_from_peers);
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);
    assert_eq!(
        fs::read(lab.dir("b").join("note.txt")).unwrap(),
        b"over quic"
    );
    let st = &peers_b.status()[0];
    assert_eq!(st.path, "direct-lan", "{st:?}"); // loopback counts as LAN
    assert!(st.ok);
    assert_eq!(st.addr, Some(node_a.local_addr));

    // A third vault device whose certificate the laptop has never seen in a
    // record cannot complete the handshake, even with the right token.
    let c = join(&lab, "c", "phone", &key);
    let node_c = node(&c, empty());
    let peers_c = Peers::build(
        c.peer_key(),
        c.device_id().clone(),
        std::slice::from_ref(&rec_a),
        &[],
        Some(node_c.clone()),
    );
    let name = varsto_core::ids::ObjectName::from_bytes(&[0u8; 32]);
    assert!(peers_c.get(&name).is_none());
    assert_eq!(peers_c.status()[0].path, "unreachable");

    // A record that announces the wrong certificate for the laptop makes the
    // desk refuse the laptop's real certificate.
    let mut forged = rec_a.clone();
    forged.cert_sha256 = node_c.identity().sha256.clone();
    let suspicious = Peers::build(
        b.peer_key(),
        b.device_id().clone(),
        &[forged],
        &[],
        Some(node_b.clone()),
    );
    assert!(suspicious.probe().iter().all(|s| !s.ok));

    // The request token is still checked behind the certificates.
    let stranger = Peers::build(
        varsto_core::crypto::SecretKey::random(),
        b.device_id().clone(),
        std::slice::from_ref(&rec_a),
        &[],
        Some(node_b.clone()),
    );
    assert!(stranger.get(&name).is_none());
    // The handshake succeeded (the path is known) but every answer is 403:
    // the second layer doing its job.
    let st = stranger.probe();
    assert!(st.iter().all(|s| !s.ok && s.path == "direct-lan"), "{st:?}");
}

#[test]
fn relayed_fetch_through_a_reachable_device() {
    let lab = lab();
    // B holds the data, R is reachable and relays, A fetches.
    let (b, key, big) = seed(&lab, "b");
    let snap_b: Snap = Arc::new(Mutex::new(Some(Arc::new(b.peer_snapshot().unwrap()))));
    let node_b = node(&b, snap_b);
    let mut r = join(&lab, "r", "home-server", &key);
    let node_r = node(&r, empty());
    let mut a = join(&lab, "a", "travel", &key);
    let node_a = node(&a, empty());

    let mut rec_b = record(&b, &node_b, false); // behind NAT: no direct address
    rec_b.relay_via = vec![r.device_id().clone()];
    let mut rec_r = record(&r, &node_r, true);
    rec_r.reachable = true;
    let rec_a = record(&a, &node_a, false);

    // R knows both; B knows R; A knows R and B.
    let peers_r = Arc::new(Peers::build(
        r.peer_key(),
        r.device_id().clone(),
        &[rec_a.clone(), rec_b.clone()],
        &[],
        Some(node_r.clone()),
    ));
    let _peers_b = Peers::build(
        b.peer_key(),
        b.device_id().clone(),
        std::slice::from_ref(&rec_r),
        &[],
        Some(node_b.clone()),
    );
    node_b
        .register_with(r.device_id(), &[node_r.local_addr], &rec_r.cert_sha256)
        .unwrap();
    assert_eq!(node_r.registrants(), vec![b.device_id().clone()]);
    assert_eq!(node_b.registered_relays(), vec![r.device_id().clone()]);

    let peers_a = Arc::new(Peers::build(
        a.peer_key(),
        a.device_id().clone(),
        &[rec_r.clone(), rec_b.clone()],
        &[],
        Some(node_a.clone()),
    ));
    a.set_peers(Some(peers_a.clone()));
    let rep = a.pull("docs").unwrap();
    assert!(
        rep.files_unavailable.is_empty(),
        "{:?}",
        rep.files_unavailable
    );
    assert!(rep.chunks_from_peers >= 2);
    assert_eq!(fs::read(lab.dir("a").join("big.bin")).unwrap(), big);
    let st: Vec<p2p::PeerStatus> = peers_a.status();
    let b_st = st.iter().find(|s| &s.device == b.device_id()).unwrap();
    assert_eq!(b_st.path, "relayed via home-server", "{b_st:?}");
    assert_eq!(b_st.addr, Some(node_r.local_addr));

    // The relay itself fetches from B: B has no address R could dial (as
    // behind a symmetric NAT), so the only way is B's registration with R.
    r.set_peers(Some(peers_r.clone()));
    let rep = r.pull("docs").unwrap();
    assert!(rep.files_unavailable.is_empty(), "{:?}", rep.files_unavailable);
    assert!(rep.chunks_from_peers >= 2);
    assert_eq!(fs::read(lab.dir("r").join("big.bin")).unwrap(), big);
    let st = peers_r.status();
    let b_st = st.iter().find(|s| &s.device == b.device_id()).unwrap();
    assert!(b_st.ok && b_st.path == "direct-lan", "{b_st:?}");
    assert_eq!(b_st.addr, Some(node_b.local_addr));

    // A device whose certificate differs from what R's record for it says
    // cannot register as that device.
    let mut wrong = rec_a.clone();
    wrong.cert_sha256 = node_b.identity().sha256.clone();
    let _ = Peers::build(
        r.peer_key(),
        r.device_id().clone(),
        &[wrong, rec_b.clone()],
        &[],
        Some(node_r.clone()),
    );
    let err = node_a
        .register_with(r.device_id(), &[node_r.local_addr], &rec_r.cert_sha256)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("relay refused") || err.contains("quic"),
        "{err}"
    );

    // Nobody registered under an unknown device: the relay says so.
    let ghost = DeviceId::from_bytes(&[7u8; 16]);
    let path = format!("/p2p/via/{ghost}/p2p/info");
    let auth = p2p::auth_header(&a.peer_key(), a.device_id(), "/p2p/info");
    let (status, _) = node_a
        .request(node_r.local_addr, &rec_r.cert_sha256, &path, &auth, false)
        .unwrap();
    assert_eq!(status, 502);
}

/// A server bound to the wildcard address on a multi-homed host must answer
/// from the address the request arrived on, or the client's QUIC stack drops
/// the answer as coming from a stranger. Loopback stands in for the second
/// interface: the client talks to 127.0.0.2, so a reply routed by the kernel
/// would leave as 127.0.0.1.
#[cfg(target_os = "linux")]
#[test]
fn wildcard_server_answers_from_the_address_it_was_reached_at() {
    let lab = lab();
    let (a, key, _big) = seed(&lab, "a");
    let snap_a: Snap = Arc::new(Mutex::new(Some(Arc::new(a.peer_snapshot().unwrap()))));
    let node_a = quic::Node::start(
        "0.0.0.0:0".parse().unwrap(),
        a.p2p_identity().unwrap(),
        a.device_id().clone(),
        a.peer_key(),
        snap_a,
        Arc::default(),
    )
    .unwrap();
    let b = join(&lab, "b", "desk", &key);
    let node_b = node(&b, empty());
    let (mut rec_a, rec_b) = (record(&a, &node_a, true), record(&b, &node_b, true));
    let second: std::net::SocketAddr = format!("127.0.0.2:{}", node_a.local_addr.port())
        .parse()
        .unwrap();
    rec_a.udp_local = vec![second];
    let _peers_a = Peers::build(
        a.peer_key(),
        a.device_id().clone(),
        std::slice::from_ref(&rec_b),
        &[],
        Some(node_a.clone()),
    );
    let auth = p2p::auth_header(&b.peer_key(), b.device_id(), "/p2p/info");
    let (status, _) = node_b
        .request(second, &rec_a.cert_sha256, "/p2p/info", &auth, false)
        .unwrap();
    assert_eq!(status, 200);
}
