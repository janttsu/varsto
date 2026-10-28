// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The rendezvous service with real engines (`alpha-0-format.md` section
//! 83.9), against the server run in-process: peer records published there
//! reach a device that asks no storage, a coordinated punch finds a peer
//! whose record has no address, a block fetched through the relay, pairing
//! through the relay by link token and by code, and with the rendezvous
//! unreachable everything works as before (LAN, storages, LAN pairing).

mod common;

use common::p2p::{empty, publish_quic, quic_node, quic_table, served, Serving};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use varsto_core::chunking::ChunkerParams;
use varsto_core::p2p::rendezvous::{Rendezvous, ServeRelayed, Setup};
use varsto_core::p2p::{self, v3};
use varsto_core::pair::{self, Bundle, BundleStorage, Connector, RvFound};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;
use varsto_rendezvous::Server;

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

fn seed(lab: &Lab, who: &str) -> (Engine, String, Vec<u8>) {
    let (mut a, key) = Engine::init(&lab.home(who), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir(who)).unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(lab.dir(who).join("big.bin"), &big).unwrap();
    a.push("docs").unwrap();
    (a, key, big)
}

fn join(lab: &Lab, who: &str, name: &str, key: &str, owner: &mut Engine) -> Engine {
    let mut e = common::join_approved(&lab.home(who), name, PASS, key, lab.storage.clone(), owner);
    e.chunker = ChunkerParams::SMALL;
    e.attach_folder("docs", &lab.dir(who), false).unwrap();
    e
}

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// The rendezvous runtime of `e` at `url`, as the service starts it.
fn runtime(
    e: &Engine,
    url: &str,
    quic: Option<Arc<p2p::quic::Node>>,
    serve: Option<ServeRelayed>,
) -> Arc<Rendezvous> {
    let vault = e.rendezvous_keys().expect("a full device");
    let owner = e.rendezvous_owner(&vault.tag());
    Rendezvous::start(Setup {
        url: url.to_string(),
        vault,
        owner,
        me: varsto_core::record::id16(e.device_id()).unwrap(),
        quic,
        serve,
    })
    .unwrap()
}

/// Give `rv` `e`'s record (the body the storages would get) and wait
/// until its slot is written and claimed.
fn seed_slot(e: &Engine, rv: &Rendezvous, port: u16) {
    e.p2p_identity().unwrap();
    let mut body = e.peer_body(port);
    body.lan_addrs.clear();
    body.udp_local.clear();
    rv.set_record(e.peer_record_parts(&mut body).unwrap());
    let until = Instant::now() + Duration::from_secs(20);
    while !rv.can_relay() {
        assert!(
            Instant::now() < until,
            "the slot was not claimed: {:?}",
            rv.status()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What the answering side of a relayed session runs (the service's
/// `p2p::serve_relayed`), for `d`'s responder and `snap`.
fn serving(d: &common::p2p::QuicDev, snap: common::p2p::Snap) -> ServeRelayed {
    let tls = v3::tls::TcpTls::new(d.node.identity(), d.responder.clone()).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let traffic: Arc<p2p::Traffic> = Arc::default();
    Arc::new(move |stream| {
        if let Err(e) = p2p::serve_relayed(&tls, stream, &snap, &stop, &traffic) {
            eprintln!("relayed session ended: {e:#}");
        }
    })
}

#[test]
fn records_at_the_rendezvous_reach_a_device_that_asks_no_storage() {
    let (url, _udp, h) = Server::spawn_for_tests();
    let lab = lab();
    let (mut a, key, _big) = seed(&lab, "a");
    let b = join(&lab, "b", "desk", &key, &mut a);
    a.p2p_identity().unwrap();
    b.p2p_identity().unwrap();
    // The two agree on the vault's tag; their slots differ.
    let (ka, kb) = (a.rendezvous_keys().unwrap(), b.rendezvous_keys().unwrap());
    assert_eq!(ka.tag(), kb.tag());
    let ida = varsto_core::record::id16(a.device_id()).unwrap();
    let idb = varsto_core::record::id16(b.device_id()).unwrap();
    assert_ne!(ka.slot(&ida), ka.slot(&idb));

    // The laptop writes its record at the rendezvous only (no storage
    // publish at all).
    let rv_a = runtime(&a, &url, None, None);
    let mut body = a.peer_body(4242);
    body.lan_addrs = vec!["192.0.2.7".parse().unwrap()];
    body.udp_local.clear();
    rv_a.set_record(a.peer_record_parts(&mut body).unwrap());
    let seq = body.seq;
    assert!(seq >= 1);

    // The desk reads the vault's slots and merges the laptop's record into
    // its saved directory: no storage is asked.
    let rv_b = runtime(&b, &url, None, None);
    let mut found = None;
    wait_until("the laptop's slot", Duration::from_secs(20), || {
        rv_b.fetch_soon();
        if let Some(f) = rv_b.take_found() {
            if !f.is_empty() {
                found = Some(f);
            }
        }
        found.is_some()
    });
    let found = found.unwrap();
    assert_eq!(found.len(), 1, "the desk's own slot is not handed back");
    assert_eq!(b.merge_rendezvous_records(found.clone()), 1);
    assert_eq!(
        b.merge_rendezvous_records(found.clone()),
        0,
        "nothing newer"
    );
    let dir = b.local_peer_directory();
    let got = dir.get(&ida).expect("the laptop's entry");
    assert_eq!(got.seq, seq);
    assert_eq!(got.port, 4242);
    assert_eq!(got.lan_addrs, body.lan_addrs);
    // A record moved into another device's slot is not taken.
    let moved: Vec<_> = found
        .into_iter()
        .map(|(_, parts)| (kb.slot(&idb), parts))
        .collect();
    let fresh = join(&lab, "c", "phone", &key, &mut a);
    assert_eq!(fresh.merge_rendezvous_records(moved), 0);
    let status = rv_b.status();
    assert_eq!(status.state, "on");
    assert_eq!(status.slots_seen, 1, "{status:?}");

    // The seq rule: an unchanged body keeps the seq of the rendezvous
    // copy, the next storage publish goes above it, and a changed body
    // after that takes the next one.
    let mut same = body.clone();
    a.peer_record_parts(&mut same).unwrap();
    assert_eq!(same.seq, seq);
    let mut stored = body.clone();
    a.publish_peer_body(&mut stored).unwrap();
    assert!(stored.seq > seq, "{} > {seq}", stored.seq);
    let mut again = stored.clone();
    a.peer_record_parts(&mut again).unwrap();
    assert_eq!(again.seq, stored.seq, "the storages' seq is reused");
    let mut changed = stored.clone();
    changed.port = 4343;
    a.peer_record_parts(&mut changed).unwrap();
    assert_eq!(changed.seq, stored.seq + 1);
    rv_a.stop();
    rv_b.stop();
    h.stop();
}

#[test]
fn a_block_comes_through_the_rendezvous_relay_when_no_address_works() {
    let (url, _udp, h) = Server::spawn_for_tests();
    let lab = lab();
    let (mut a, key, big) = seed(&lab, "a");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    common::lose_all_objects(&lab.root.join("storage"));
    let qa = quic_node(&a, served(&a), Arc::default());
    let qb = quic_node(&b, empty(), Arc::default());
    // Neither record names an address: as two devices behind NATs that
    // never let a punch through.
    publish_quic(&a, &qa, false, false, &[]);
    publish_quic(&b, &qb, false, false, &[]);
    let _peers_a = quic_table(&mut a, &qa);
    let rv_a = runtime(&a, &url, None, Some(serving(&qa, served(&a))));
    let rv_b = runtime(&b, &url, None, None);
    seed_slot(&a, &rv_a, qa.node.local_addr.port());
    seed_slot(&b, &rv_b, qb.node.local_addr.port());

    let peers = Arc::new(quic_table(&mut b, &qb).with_rendezvous(Some(rv_b.clone())));
    b.set_peers(Some(peers.clone()));
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert!(r.chunks_from_peers >= 2, "{r:?}");
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);
    let st = peers.status();
    assert_eq!(st[0].path, "relayed via rendezvous", "{st:?}");
    assert!(st[0].ok);
    assert_eq!(st[0].addr, None);
    assert_eq!(rv_b.status().relayed_peers, 1);

    // A device whose certificate the laptop's directory does not name gets
    // nothing through the relay: the pinned handshake decides, not the
    // rendezvous.
    let mut c = join(&lab, "c", "stray", &key, &mut a);
    let qc = quic_node(&c, empty(), Arc::default());
    publish_quic(&c, &qc, false, false, &[]);
    let rv_c = runtime(&c, &url, None, None);
    seed_slot(&c, &rv_c, qc.node.local_addr.port());
    let peers_c = quic_table(&mut c, &qc).with_rendezvous(Some(rv_c.clone()));
    let name = varsto_core::ids::ObjectName::from_bytes(&[0u8; 32]);
    assert!(peers_c.get(&name).is_none());
    let st = peers_c
        .status()
        .into_iter()
        .find(|s| &s.device == a.device_id())
        .unwrap();
    assert_eq!(st.path, "unreachable", "{st:?}");
    for rv in [rv_a, rv_b, rv_c] {
        rv.stop();
    }
    h.stop();
}

#[test]
fn a_coordinated_punch_finds_a_peer_whose_record_has_no_address() {
    // No relay: only the punch can work.
    let (url, _udp, h) = Server::spawn_for_tests_with(|c| c.relay = false);
    let lab = lab();
    let (mut a, key, big) = seed(&lab, "a");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    common::lose_all_objects(&lab.root.join("storage"));
    let qa = quic_node(&a, served(&a), Arc::default());
    let qb = quic_node(&b, empty(), Arc::default());
    publish_quic(&a, &qa, false, false, &[]);
    publish_quic(&b, &qb, false, false, &[]);
    let _peers_a = quic_table(&mut a, &qa);
    let rv_a = runtime(&a, &url, Some(qa.node.clone()), None);
    let rv_b = runtime(&b, &url, Some(qb.node.clone()), None);
    for (e, rv, q) in [(&a, &rv_a, &qa), (&b, &rv_b, &qb)] {
        e.p2p_identity().unwrap();
        let mut body = e.peer_body(q.node.local_addr.port());
        body.lan_addrs.clear();
        rv.set_record(e.peer_record_parts(&mut body).unwrap());
    }
    // Both sockets observed (the server saw them on loopback) and claimed.
    wait_until("both observed", Duration::from_secs(20), || {
        rv_a.can_punch() && rv_b.can_punch()
    });
    assert_eq!(rv_b.observed(), Some(qb.node.local_addr));
    assert!(!rv_b.can_relay(), "the server offers no relay");

    let peers = Arc::new(quic_table(&mut b, &qb).with_rendezvous(Some(rv_b.clone())));
    b.set_peers(Some(peers.clone()));
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);
    let st = peers.status();
    assert_eq!(st[0].path, "direct", "{st:?}");
    assert!(st[0].ok);
    assert_eq!(
        rv_b.punch_addr(a.device_id()).unwrap(),
        qa.node.local_addr,
        "the address the server saw"
    );
    rv_a.stop();
    rv_b.stop();
    h.stop();
}

fn bundle() -> Bundle {
    Bundle {
        vault_id: "v".into(),
        vault_key: String::new(),
        from: "laptop".into(),
        vault_epochs: None,
        storages: vec![BundleStorage {
            spec: StorageSpec::LocalDir {
                name: "primary".into(),
                path: "/nowhere".into(),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            },
            secret: None,
        }],
    }
}

/// A joiner on another network: nothing on the LAN answers, the offer's
/// addresses do not either; only the rendezvous works.
struct Elsewhere {
    net: pair::Net,
    log: std::sync::Mutex<Vec<String>>,
}

impl Connector for Elsewhere {
    fn fetch(
        &self,
        _code: &str,
        _keys: &v3_pair::JoinKeys<'_>,
        addr: std::net::SocketAddr,
    ) -> anyhow::Result<Bundle> {
        self.log.lock().unwrap().push(format!("fetch {addr}"));
        Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
    }
    fn discover(&self, _code: &str, _t: Duration) -> anyhow::Result<Vec<std::net::SocketAddr>> {
        self.log.lock().unwrap().push("discover".into());
        anyhow::bail!("nobody answered")
    }
    fn own_interfaces(&self) -> Vec<varsto_core::netif::Iface> {
        Vec::new()
    }
    fn has_rendezvous(&self) -> bool {
        self.net.has_rendezvous()
    }
    fn rendezvous(
        &self,
        code: &str,
        token: Option<&varsto_core::rendezvous::Token>,
    ) -> anyhow::Result<Option<RvFound>> {
        self.log.lock().unwrap().push("rendezvous".into());
        self.net.rendezvous(code, token)
    }
    fn fetch_relayed(
        &self,
        code: &str,
        keys: &v3_pair::JoinKeys<'_>,
        found: &RvFound,
    ) -> anyhow::Result<Bundle> {
        self.log.lock().unwrap().push("relay".into());
        self.net.fetch_relayed(code, keys, found)
    }
}

use varsto_core::pair::v3 as v3_pair;

fn offer(url: Option<&str>) -> pair::Offer {
    pair::Offer::start_v3_with(
        bundle(),
        varsto_core::crypto::SecretKey::random(),
        Arc::new(|_: &v3_pair::Joiner| true),
        url,
    )
    .unwrap()
}

#[test]
fn pairing_works_through_the_rendezvous_relay_by_token_and_by_code() {
    let (url, _udp, h) = Server::spawn_for_tests();
    for by_token in [true, false] {
        let o = offer(Some(&url));
        wait_until(
            "the offer at the rendezvous",
            Duration::from_secs(20),
            || o.status().rendezvous,
        );
        let st = o.status();
        let link = st.link();
        let token = match &link {
            varsto_core::qr::Link::Pair { rendezvous, .. } => rendezvous.unwrap(),
            _ => unreachable!(),
        };
        assert!(link
            .to_uri()
            .unwrap()
            .contains(&format!("rv={}", hex::encode(token))));
        let net = Elsewhere {
            net: pair::Net::new(Some(&url)),
            log: Default::default(),
        };
        let keys = v3_pair::PairingKeys::generate();
        let mut steps = Vec::new();
        let b = pair::join_with(
            &st.code,
            &keys.join_keys("phone"),
            None,
            &st.addresses,
            by_token.then_some(&token),
            &mut |s| steps.push(s),
            &net,
        )
        .unwrap();
        assert_eq!(b.from, "laptop");
        assert_eq!(b.vault_key.len(), 64, "the vault key arrived sealed to K8");
        assert!(steps.contains(&pair::Step::Rendezvous), "{steps:?}");
        assert_eq!(steps.last(), Some(&pair::Step::RendezvousRelay));
        let log = net.log.lock().unwrap().clone();
        assert_eq!(&log[log.len() - 2..], ["rendezvous", "relay"], "{log:?}");
        assert!(
            log.contains(&"discover".to_string()),
            "the LAN is asked first"
        );
        wait_until("the offer to close", Duration::from_secs(5), || {
            !o.status().open
        });
        assert_eq!(o.status().paired_with.as_deref(), Some("phone"));
        // Withdrawn: the rendezvous no longer holds it.
        wait_until("the offer to be withdrawn", Duration::from_secs(10), || {
            !o.status().rendezvous
        });
        let rv = varsto_core::rendezvous::RvClient::new(&url).unwrap();
        let digits = pair::normalize(&st.code).unwrap();
        wait_until("the slot to go", Duration::from_secs(10), || {
            varsto_core::rendezvous::find_pair_offer(&rv, &digits, Some(&token))
                .unwrap()
                .is_none()
        });
    }
    // A wrong code finds no offer and says what it tried.
    let o = offer(Some(&url));
    wait_until(
        "the offer at the rendezvous",
        Duration::from_secs(20),
        || o.status().rendezvous,
    );
    let code = o.status().code;
    let wrong = if code.starts_with('0') {
        "111-111-111"
    } else {
        "000-000-000"
    };
    let net = Elsewhere {
        net: pair::Net::new(Some(&url)),
        log: Default::default(),
    };
    let keys = v3_pair::PairingKeys::generate();
    let e = pair::join_with(
        wrong,
        &keys.join_keys("phone"),
        None,
        &[],
        None,
        &mut |_| {},
        &net,
    )
    .unwrap_err();
    let nf = e.downcast_ref::<pair::NotFound>().expect("not found");
    assert!(
        nf.tried.iter().any(|t| t.why == "no offer for this code"),
        "{:?}",
        nf.tried
    );
    o.stop();
    h.stop();
}

#[test]
fn with_the_rendezvous_unreachable_the_lan_and_the_storages_still_work() {
    // A port nobody listens on.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let lab = lab();
    let (mut a, key, big) = seed(&lab, "a");
    let mut b = join(&lab, "b", "desk", &key, &mut a);
    let mut c = join(&lab, "c", "phone", &key, &mut a);

    // The storages: the desk pulls everything from them with a dead
    // rendezvous in its peer table.
    let rv_b = runtime(&b, &dead, None, None);
    wait_until(
        "the rendezvous to be found unreachable",
        Duration::from_secs(20),
        || rv_b.status().state == "unreachable",
    );
    assert!(!rv_b.can_relay() && !rv_b.can_punch());
    let qb = quic_node(&b, empty(), Arc::default());
    publish_quic(&b, &qb, false, false, &[]);
    let peers = Arc::new(quic_table(&mut b, &qb).with_rendezvous(Some(rv_b.clone())));
    b.set_peers(Some(peers));
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert_eq!(fs::read(lab.dir("b").join("big.bin")).unwrap(), big);

    // The LAN: with the blocks gone from the storage, the phone fetches
    // them from the laptop over TLS on loopback.
    common::lose_all_objects(&lab.root.join("storage"));
    let serving = Serving::start(&mut a);
    common::p2p::publish(&c, 9);
    serving.refresh(&mut a);
    c.refresh_devices().unwrap();
    let rv_c = runtime(&c, &dead, None, None);
    let peers = c
        .p2p_peers_tcp()
        .expect("a peer")
        .with_rendezvous(Some(rv_c.clone()));
    c.set_peers(Some(Arc::new(peers)));
    let r = c.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{:?}", r.files_unavailable);
    assert!(r.chunks_from_peers >= 2, "{r:?}");
    assert_eq!(fs::read(lab.dir("c").join("big.bin")).unwrap(), big);

    // Pairing on the LAN: an offer with a dead rendezvous is found at its
    // address as before; the joiner's rendezvous is never needed.
    let o = offer(Some(&dead));
    let st = o.status();
    let addr = format!("127.0.0.1:{}", st.port);
    let keys = v3_pair::PairingKeys::generate();
    let got = pair::receive_with_rendezvous(
        &st.code,
        &keys.join_keys("tablet"),
        Some(&addr),
        &[],
        Some(&dead),
        None,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(got.from, "laptop");
    assert!(!o.status().rendezvous);
    rv_b.stop();
    rv_c.stop();
}
