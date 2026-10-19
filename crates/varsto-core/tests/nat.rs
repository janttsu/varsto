// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! NAT traversal pieces on localhost: QUIC transfer between two devices with
//! certificates pinned from their signed peer records, rejection of a device
//! whose certificate no accepted record names, and a relayed fetch A -> R ->
//! B where B registers with R. No real NAT is involved; the traversal logic
//! (STUN, punching) is covered by unit tests and by hand on the maintainer's
//! own networks.

mod common;

use common::p2p::{empty, publish_quic, quic_node, quic_table, served};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use varsto_core::chunking::ChunkerParams;
use varsto_core::ids::DeviceId;
use varsto_core::p2p;
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

/// The first device: holds the files and pushes them; `lose` empties the
/// storage of every block afterwards, so that only peers can supply them.
fn seed(lab: &Lab, who: &str) -> (Engine, String, Vec<u8>) {
    let (mut a, key) = Engine::init(&lab.home(who), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir(who)).unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(lab.dir(who).join("big.bin"), &big).unwrap();
    fs::write(lab.dir(who).join("note.txt"), b"over quic").unwrap();
    a.push("docs").unwrap();
    (a, key, big)
}

fn lose(lab: &Lab) {
    common::lose_all_objects(&lab.root.join("storage"));
}

/// A device that joined and was given the folder by `owner`.
fn join(lab: &Lab, who: &str, name: &str, key: &str, owner: &mut Engine) -> Engine {
    let mut e = common::join_approved(&lab.home(who), name, PASS, key, lab.storage.clone(), owner);
    e.chunker = ChunkerParams::SMALL;
    e.attach_folder("docs", &lab.dir(who), false).unwrap();
    e
}

#[test]
fn quic_direct_transfer_with_pinned_certificates() {
    let lab = lab();
    let (mut a, key, big) = seed(&lab, "a");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    let c = join(&lab, "c", "phone", &key, &mut a);
    lose(&lab);
    let qa = quic_node(&a, served(&a), Arc::default());
    let qb = quic_node(&b, empty(), Arc::default());
    let qc = quic_node(&c, empty(), Arc::default());
    // A and B publish their records; C does not.
    publish_quic(&a, &qa, true, false, &[]);
    publish_quic(&b, &qb, true, false, &[]);

    // Each side reads the other's record from the storage, as the services do.
    let _peers_a = quic_table(&mut a, &qa);
    let peers_b = Arc::new(quic_table(&mut b, &qb));
    assert_eq!(peers_b.status().len(), 1);
    assert_eq!(peers_b.status()[0].path, "untried");
    b.set_peers(Some(peers_b.clone()));
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert!(r.chunks_from_peers >= 2, "{}", r.chunks_from_peers);
    // Every block came from the laptop: the bytes say so too.
    assert_eq!(r.bytes_from_peers, r.bytes_downloaded, "{r:?}");
    assert!(r.bytes_from_peers >= 200_000, "{r:?}");
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);
    assert_eq!(
        fs::read(lab.dir("b").join("note.txt")).unwrap(),
        b"over quic"
    );
    let st = &peers_b.status()[0];
    assert_eq!(st.path, "direct-lan", "{st:?}"); // loopback counts as LAN
    assert!(st.ok);
    assert_eq!(st.addr, Some(qa.node.local_addr));

    // A third vault device whose certificate no record names (it published
    // none) cannot complete the handshake with the laptop.
    let mut c = c;
    let peers_c = quic_table(&mut c, &qc);
    let name = varsto_core::ids::ObjectName::from_bytes(&[0u8; 32]);
    assert!(peers_c.get(&name).is_none());
    let st = peers_c
        .status()
        .into_iter()
        .find(|s| &s.device == a.device_id())
        .unwrap();
    assert_eq!(st.path, "unreachable", "{st:?}");

    // The token is checked behind the certificate: one made for another
    // responder is refused on the desk's open connection.
    let path = "/p2p/info";
    let (status, _) = qb
        .node
        .request_with(
            qa.node.local_addr,
            &qa.node.identity().sha256,
            path,
            false,
            &|e| qb.client.token(e, c.device_id(), path),
        )
        .unwrap();
    assert_eq!(status, 403);
    // A request pinned to another certificate than the laptop's is not
    // talked to: the desk pins what the laptop's signed record says.
    let got = qb.node.request_with(
        qa.node.local_addr,
        &qc.node.identity().sha256,
        path,
        false,
        &|e| qb.client.token(e, a.device_id(), path),
    );
    assert!(got.is_err(), "{got:?}");
}

#[test]
fn relayed_fetch_through_a_reachable_device() {
    let lab = lab();
    // B holds the data, R is reachable and relays, A fetches.
    let (mut b, key, big) = seed(&lab, "b");
    let mut r = join(&lab, "r", "home-server", &key, &mut b);
    let mut a = join(&lab, "a", "travel", &key, &mut b);
    let x = Engine::join(&lab.home("x"), "stray", PASS, &key, lab.storage.clone()).unwrap();
    lose(&lab);
    let qb = quic_node(&b, served(&b), Arc::default());
    let qr = quic_node(&r, empty(), Arc::default());
    let qa = quic_node(&a, empty(), Arc::default());
    let qx = quic_node(&x, empty(), Arc::default());

    // B is behind NAT (no direct address) and relays through R.
    publish_quic(&b, &qb, false, false, &[r.device_id().clone()]);
    publish_quic(&r, &qr, true, true, &[]);
    publish_quic(&a, &qa, false, false, &[]);

    // Every device reads the records.
    let peers_r = Arc::new(quic_table(&mut r, &qr));
    let _peers_b = quic_table(&mut b, &qb);
    let r_cert = qr.node.identity().sha256.clone();
    qb.node
        .register_with(r.device_id(), &[qr.node.local_addr], &r_cert)
        .unwrap();
    assert_eq!(qr.node.registrants(), vec![b.device_id().clone()]);
    assert_eq!(qb.node.registered_relays(), vec![r.device_id().clone()]);

    let peers_a = Arc::new(quic_table(&mut a, &qa));
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
    assert_eq!(b_st.addr, Some(qr.node.local_addr));

    // The relay itself fetches from B: B has no address R could dial (as
    // behind a symmetric NAT), so the only way is B's registration with R.
    r.set_peers(Some(peers_r.clone()));
    let rep = r.pull("docs").unwrap();
    assert!(
        rep.files_unavailable.is_empty(),
        "{:?}",
        rep.files_unavailable
    );
    assert!(rep.chunks_from_peers >= 2);
    assert_eq!(fs::read(lab.dir("r").join("big.bin")).unwrap(), big);
    let st = peers_r.status();
    let b_st = st.iter().find(|s| &s.device == b.device_id()).unwrap();
    assert!(b_st.ok && b_st.path == "direct-lan", "{b_st:?}");
    assert_eq!(b_st.addr, Some(qb.node.local_addr));

    // A device of the vault whose certificate no accepted record names
    // cannot register with the relay at all.
    // (TLS 1.3: the client learns it when the connection is closed on it.)
    let got = qx
        .node
        .register_with(r.device_id(), &[qr.node.local_addr], &r_cert);
    assert!(got.is_err());
    assert!(!qr.node.registrants().contains(x.device_id()));

    // Nobody registered under an unknown device: the relay says so.
    let ghost = DeviceId::from_bytes(&[7u8; 16]);
    let path = format!("/p2p/via/{ghost}/p2p/info");
    let (status, _) = qa
        .node
        .request_with(qr.node.local_addr, &r_cert, &path, false, &|e| {
            qa.client.token(e, r.device_id(), &path)
        })
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
    let (mut a, key, _big) = seed(&lab, "a");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    let identity = a.p2p_identity().unwrap();
    let responder = a.p2p_responder(&identity);
    let node_a = p2p::quic::Node::start_v3(
        "0.0.0.0:0".parse().unwrap(),
        identity.clone(),
        responder.clone(),
        served(&a),
        Arc::default(),
    )
    .unwrap();
    let qb = quic_node(&b, empty(), Arc::default());
    publish_quic(&b, &qb, true, false, &[]);
    let qa = common::p2p::QuicDev {
        node: node_a.clone(),
        responder,
        client: a.p2p_client(identity.clone()),
    };
    let _peers_a = quic_table(&mut a, &qa);
    let _peers_b = quic_table(&mut b, &qb);
    let second: std::net::SocketAddr = format!("127.0.0.2:{}", node_a.local_addr.port())
        .parse()
        .unwrap();
    let path = "/p2p/info";
    let (status, _) = qb
        .node
        .request_with(second, &identity.sha256, path, false, &|e| {
            qb.client.token(e, a.device_id(), path)
        })
        .unwrap();
    assert_eq!(status, 200);
}

#[test]
fn a_device_is_never_its_own_peer() {
    let lab = lab();
    let (mut a, key, _big) = seed(&lab, "a");
    let qa = quic_node(&a, served(&a), Arc::default());
    let traffic: Arc<p2p::traffic::Traffic> = Arc::default();
    traffic.set_me(a.device_id(), a.own_device_name());

    // A TCP listener of A's own, as the service runs.
    let tls = p2p::v3::tls::TcpTls::new(qa.node.identity(), qa.responder.clone()).unwrap();
    let server = p2p::Server::bind("127.0.0.1:0".parse().unwrap(), tls)
        .unwrap()
        .with_traffic(traffic.clone());
    let port = server.addr.port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (s2, st2) = (served(&a), stop.clone());
    let th = std::thread::spawn(move || server.run(s2, st2));

    // 1. The directory never lists the own device, even with its record
    // on the storage.
    publish_quic(&a, &qa, true, false, &[]);
    assert!(quic_table(&mut a, &qa).peers.is_empty());

    // 2. A handshake with the own certificate is refused outright.
    let path = "/p2p/info";
    let err = qa
        .node
        .request_with(
            qa.node.local_addr,
            &qa.node.identity().sha256,
            path,
            false,
            &|_| String::new(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("own"), "{err:#}");

    // 3. Another device's record that lists an address of A itself: the
    // handshake pins that device's certificate, A presents its own, and
    // nothing is answered or counted for anybody.
    let d = Engine::join(&lab.home("d"), "desk", PASS, &key, lab.storage.clone()).unwrap();
    d.p2p_identity().unwrap();
    let mut body = d.peer_body(port);
    body.lan_addrs = vec!["127.0.0.1".parse().unwrap()];
    body.udp_local = Vec::new();
    d.publish_peer_body(&mut body).unwrap();
    a.refresh_devices().unwrap();
    let dir = a.peer_directory().unwrap();
    assert_eq!(dir.infos().len(), 1);
    let peers =
        p2p::Peers::build_v3(qa.client.clone(), &dir, &[], None).with_traffic(traffic.clone());
    let st = peers.probe();
    assert!(st.iter().all(|s| !s.ok), "{st:?}");
    let r = traffic.report();
    assert!(
        r.peers.iter().all(|p| p.rx_total == 0 && p.tx_total == 0),
        "{:?}",
        r.peers
    );
    assert!(r.peers.iter().all(|p| &p.device != a.device_id()));
    assert_eq!(r.totals.tx_total + r.totals.rx_total, 0);
    let again = peers.probe();
    assert_eq!(again[0].path, "unreachable", "{again:?}");

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    th.join().unwrap();
}
