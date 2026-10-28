// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of the format-3 peers and transport (design section 12, test 14,
//! and the acceptance list of work package 9).

use super::heads::{self, HeadRef, Pushed};
use super::*;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::p2p::{self, quic, stun, Peers, Server};
use crate::record::{
    self, Acceptor, KeyId, Kind, RecordBody, RecordKeys, RecordStore, RecordTrust, RecordWriter,
    RecordsRefused, StreamRef,
};
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VAULT: Id16 = [0x5a; 16];

/// A storage in memory.
#[derive(Default)]
struct Mem(Mutex<BTreeMap<String, Vec<u8>>>);

impl Storage for Mem {
    fn name(&self) -> &str {
        "mem"
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> anyhow::Result<bool> {
        let mut m = self.0.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.to_string(), data.to_vec());
        Ok(true)
    }
    fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn exists(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self.0.lock().unwrap().contains_key(key))
    }
    fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// The vault's registry and ledger keys.
struct Keys {
    registry: SecretKey,
    ledger: SecretKey,
}

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        match key_id {
            KeyId::Registry(0) => Some(self.registry.clone()),
            KeyId::Ledger(0) => Some(self.ledger.clone()),
            _ => None,
        }
    }
}

/// Trusted full devices and their K6 keys.
#[derive(Default)]
struct Trust {
    keys: HashMap<Id16, VerifyingKey>,
}

impl RecordTrust for Trust {
    fn signer_key(&self, device: &Id16, _kind: Kind, _scope: &Id16) -> Option<VerifyingKey> {
        self.keys.get(device).cloned()
    }
    fn may_write(&self, device: &Id16, kind: Kind, _scope: &Id16, _key_id: &KeyId) -> bool {
        self.keys.contains_key(device)
            && record::section9_allows(record::WriterClass::FullVault, kind)
    }
}

/// One device: id, K6, TLS identity.
struct Dev {
    id: Id16,
    sk: SigningKey,
    tls: quic::Identity,
}

impl Dev {
    fn new(n: u8) -> Dev {
        Dev {
            id: [n; 16],
            sk: SigningKey::generate(),
            tls: quic::Identity::generate().unwrap(),
        }
    }
    fn device(&self) -> DeviceId {
        DeviceId::from_bytes(&self.id)
    }
    fn cert(&self) -> [u8; 32] {
        let mut c = [0u8; 32];
        hex::decode_to_slice(&self.tls.sha256, &mut c).unwrap();
        c
    }
    fn body(&self, port: u16) -> PeerBody {
        PeerBody {
            device: self.id,
            seq: 0,
            name: format!("dev{}", self.id[0]),
            port,
            lan_addrs: vec!["127.0.0.1".parse().unwrap()],
            public_addrs: Vec::new(),
            udp_public: Vec::new(),
            udp_local: Vec::new(),
            mapped_tcp: Vec::new(),
            mapped_udp: Vec::new(),
            cert_sha256: self.cert(),
            nat: stun::Nat::Unknown,
            relay_via: Vec::new(),
            reachable: false,
            heads: Vec::new(),
            pushed: Vec::new(),
        }
    }
}

fn keys() -> Keys {
    Keys {
        registry: SecretKey::random(),
        ledger: SecretKey::random(),
    }
}

fn publish(storage: &dyn Storage, keys: &Keys, dev: &Dev, body: &mut PeerBody) -> u64 {
    let signer = record::DeviceSigner {
        device: dev.id,
        key: &dev.sk,
    };
    let w = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys,
    };
    peer::publish(storage, &w, body, 0, 0).unwrap()
}

fn read_dir(
    storage: &dyn Storage,
    keys: &Keys,
    trust: &Trust,
    me: &Dev,
    devices: &[Id16],
    counter: &mut RecordsRefused,
) -> PeerDirectory {
    let store = RecordStore {
        storage,
        acceptor: Acceptor {
            vault: VAULT,
            keys,
            trust,
        },
    };
    PeerDirectory::read(&store, devices.iter().copied(), me.id, me.cert(), counter).unwrap()
}

fn trust_of(devs: &[&Dev]) -> Trust {
    Trust {
        keys: devs.iter().map(|d| (d.id, d.sk.public())).collect(),
    }
}

fn snapshot(me: &Dev) -> Snapshot {
    Snapshot {
        vault_id: crate::ids::VaultId::from_bytes(&VAULT),
        device_id: me.device(),
        folder_keys: BTreeMap::new(),
        pieces: BTreeMap::new(),
        local_roots: Vec::new(),
        packed: BTreeMap::new(),
        revoked: Default::default(),
        activity_audience: None,
        heads: Vec::new(),
        ledger_dir: None,
    }
}

fn now() -> i64 {
    crate::util::now_utc()
}

// ----- peer records and the directory -----------------------------------------

#[test]
fn newest_peer_record_wins_and_untrusted_own_and_copied_certificates_are_left_out() {
    let (a, b, c, d) = (Dev::new(1), Dev::new(2), Dev::new(3), Dev::new(4));
    let st = Mem::default();
    let k = keys();
    let mut bb = b.body(4000);
    assert_eq!(publish(&st, &k, &b, &mut bb), 1);
    bb.port = 4001;
    assert_eq!(publish(&st, &k, &b, &mut bb), 2);
    bb.port = 4002;
    assert_eq!(publish(&st, &k, &b, &mut bb), 3);
    // The stream keeps the newest two.
    let names = st.list("vault/peers/").unwrap();
    assert_eq!(names.len(), 2, "{names:?}");
    // C is not a trusted device; D names A's own certificate.
    publish(&st, &k, &c, &mut c.body(5000));
    let mut dd = d.body(6000);
    dd.cert_sha256 = a.cert();
    publish(&st, &k, &d, &mut dd);
    publish(&st, &k, &a, &mut a.body(7000));

    let trust = trust_of(&[&a, &b, &d]);
    let mut counter = RecordsRefused::default();
    let dir = read_dir(&st, &k, &trust, &a, &[a.id, b.id, c.id, d.id], &mut counter);
    assert_eq!(dir.get(&b.id).unwrap().port, 4002, "newest seq wins");
    assert!(dir.get(&c.id).is_none(), "untrusted signer");
    assert!(counter.get(Kind::Peer) >= 1, "{counter:?}");
    assert!(
        dir.get(&d.id).is_none(),
        "a record carrying our own certificate"
    );
    assert!(dir.get(&a.id).is_none(), "never our own device");
    assert_eq!(dir.device_for_cert(&b.cert()), Some(b.id));
    assert_eq!(dir.device_for_cert(&a.cert()), None);
    assert_eq!(dir.device_for_cert(&c.cert()), None);
    let infos = dir.infos();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].cert_sha256, b.tls.sha256);
    assert_eq!(
        infos[0].tcp,
        vec!["127.0.0.1:4002".parse::<SocketAddr>().unwrap()]
    );

    // A record signed under another vault's registry key does not open.
    let other = keys();
    let st2 = Mem::default();
    publish(&st2, &other, &b, &mut b.body(1));
    let mut counter = RecordsRefused::default();
    let dir = read_dir(&st2, &k, &trust, &a, &[b.id], &mut counter);
    assert!(dir.get(&b.id).is_none());
    assert_eq!(counter.total(), 1);
}

#[test]
fn a_certificate_two_devices_claim_admits_neither() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let st = Mem::default();
    let k = keys();
    publish(&st, &k, &b, &mut b.body(1));
    let mut cc = c.body(2);
    cc.cert_sha256 = b.cert();
    publish(&st, &k, &c, &mut cc);
    let trust = trust_of(&[&a, &b, &c]);
    let dir = read_dir(
        &st,
        &k,
        &trust,
        &a,
        &[b.id, c.id],
        &mut RecordsRefused::default(),
    );
    assert_eq!(dir.device_for_cert(&b.cert()), None);
    assert!(dir.infos().is_empty());
}

// ----- the directory kept on the device -------------------------------------------

fn load(
    saved: &SavedDirectory,
    keys: &Keys,
    trust: &Trust,
    me: &Dev,
    devices: &[Id16],
) -> (PeerDirectory, RecordsRefused) {
    let acceptor = Acceptor {
        vault: VAULT,
        keys,
        trust,
    };
    let mut counter = RecordsRefused::default();
    let dir = PeerDirectory::from_saved(saved, &acceptor, devices, me.id, me.cert(), &mut counter);
    (dir, counter)
}

#[test]
fn a_saved_directory_is_checked_again_on_load() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let st = Mem::default();
    let k = keys();
    let mut bb = b.body(4000);
    publish(&st, &k, &b, &mut bb);
    let trust = trust_of(&[&a, &b]);
    let dir = read_dir(&st, &k, &trust, &a, &[b.id], &mut RecordsRefused::default());
    let saved = dir.saved();
    assert_eq!(saved.records.len(), 1);
    // Through the file format and back: the same entry, nothing asked of
    // any storage.
    let json = serde_json::to_vec(&saved).unwrap();
    let saved: SavedDirectory = serde_json::from_slice(&json).unwrap();
    let (back, counter) = load(&saved, &k, &trust, &a, &[b.id]);
    assert_eq!(back.get(&b.id), dir.get(&b.id));
    assert_eq!(back.device_for_cert(&b.cert()), Some(b.id));
    assert_eq!(counter.total(), 0);
    // Saved again unchanged: what was read is what is kept.
    assert_eq!(back.saved(), saved);

    // A device no longer among the trusted full devices drops out.
    let (gone, _) = load(&saved, &k, &trust, &a, &[]);
    assert!(gone.get(&b.id).is_none());
    // A signer the membership no longer trusts is refused.
    let (refused, counter) = load(&saved, &k, &trust_of(&[&a, &c]), &a, &[b.id]);
    assert!(refused.get(&b.id).is_none());
    assert!(counter.total() >= 1, "{counter:?}");
    // Without the registry key (another vault's) the record does not open.
    let (closed, _) = load(&saved, &keys(), &trust, &a, &[b.id]);
    assert!(closed.get(&b.id).is_none());
    // A changed byte in the file is refused, never trusted.
    let mut tampered = saved.clone();
    let hexed = &mut tampered.records[0].parts[0].1;
    let mid = hexed.len() / 2;
    let flip = if &hexed[mid..mid + 1] == "0" {
        "1"
    } else {
        "0"
    };
    hexed.replace_range(mid..mid + 1, flip);
    let (bad, _) = load(&tampered, &k, &trust, &a, &[b.id]);
    assert!(bad.get(&b.id).is_none());
    // Junk that is not hex is skipped.
    let mut junk = saved.clone();
    junk.records[0].parts[0].1 = "not hex".into();
    assert!(load(&junk, &k, &trust, &a, &[b.id]).0.get(&b.id).is_none());
}

#[test]
fn an_empty_or_failed_listing_keeps_the_saved_entries_and_a_newer_record_replaces_them() {
    let (a, b) = (Dev::new(1), Dev::new(2));
    let st = Mem::default();
    let k = keys();
    let trust = trust_of(&[&a, &b]);
    let mut bb = b.body(4000);
    publish(&st, &k, &b, &mut bb);
    let saved = read_dir(&st, &k, &trust, &a, &[b.id], &mut RecordsRefused::default()).saved();
    let (mut dir, _) = load(&saved, &k, &trust, &a, &[b.id]);
    // A storage that answered with nothing (an outage that lists empty).
    let empty = read_dir(
        &Mem::default(),
        &k,
        &trust,
        &a,
        &[b.id],
        &mut RecordsRefused::default(),
    );
    dir.merge(empty);
    assert_eq!(dir.get(&b.id).map(|r| r.port), Some(4000));
    assert_eq!(dir.saved(), saved, "nothing to save anew");
    // B moves: its newer record wins, and is what is saved from now on.
    bb.port = 4001;
    publish(&st, &k, &b, &mut bb);
    dir.merge(read_dir(
        &st,
        &k,
        &trust,
        &a,
        &[b.id],
        &mut RecordsRefused::default(),
    ));
    assert_eq!(dir.get(&b.id).map(|r| r.port), Some(4001));
    let (again, _) = load(&dir.saved(), &k, &trust, &a, &[b.id]);
    assert_eq!(again.get(&b.id).map(|r| r.port), Some(4001));
    // An older record read later (a lagging storage) changes nothing.
    let old = Mem::default();
    let mut stale = b.body(3999);
    publish(&old, &k, &b, &mut stale);
    dir.merge(read_dir(
        &old,
        &k,
        &trust,
        &a,
        &[b.id],
        &mut RecordsRefused::default(),
    ));
    assert_eq!(dir.get(&b.id).map(|r| r.port), Some(4001));
}

#[test]
fn routes_are_raced_so_a_dead_first_address_costs_no_timeout() {
    let (a, b) = (Dev::new(1), Dev::new(2));
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let mut body = a.body(srv.addr.port());
    body.seq = 1;
    // First a TEST-NET address that never answers (a peer's address on
    // another network), then the live one.
    body.lan_addrs = vec!["192.0.2.1".parse().unwrap(), "127.0.0.1".parse().unwrap()];
    let peers = Peers::build_v3(
        Client::new(b.device(), b.tls.clone()),
        &dir_with(&b, vec![body]),
        &[],
        None,
    );
    let t = std::time::Instant::now();
    let (s, _) = peers.ask(&a.device(), "/p2p/info").unwrap();
    assert_eq!(s, 200);
    // One at a time the dead address would cost its 1.5 s timeout first.
    assert!(
        t.elapsed() < Duration::from_millis(1400),
        "{:?}",
        t.elapsed()
    );
    // The route that answered is kept: the next request goes straight to it.
    let status = peers.status();
    assert_eq!(status[0].addr, Some(srv.addr), "{status:?}");
}

// ----- tokens -------------------------------------------------------------------

fn responder_for(me: &Dev, others: &[&Dev]) -> Arc<Responder> {
    let r = Responder::new(me.device(), &me.tls.sha256);
    let mut dir = PeerDirectory::new(me.id, me.cert());
    for o in others {
        let mut body = o.body(1);
        body.seq = 1;
        dir.offer(record::Record {
            meta: record::RecordMeta {
                kind: Kind::Peer,
                vault: VAULT,
                scope: [0; 16],
                device: o.id,
                seq: 1,
                parts: 1,
                key_id: KeyId::Registry(0),
                body_hash: [0; 32],
                epoch: None,
                recipient: None,
                size: 0,
            },
            body,
        });
    }
    r.set_directory(dir);
    r
}

#[test]
fn a_token_for_another_responder_connection_device_or_path_or_a_replay_is_refused() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let r = responder_for(&a, &[&b, &c]);
    let snap = snapshot(&a);
    let exp = [7u8; 32];
    let ci = ConnInfo {
        cert: Some(b.cert()),
        exporter: Some(exp),
        registration: false,
    };
    let path = "/p2p/info";
    let ask = |ci: &ConnInfo, tok: &str| r.handle(Some(&snap), ci, path, tok, "").0;
    let good = token::make(&exp, &b.id, &a.id, path, now());
    assert_eq!(ask(&ci, &good), 200);
    assert_eq!(ask(&ci, &good), 403, "replayed");
    assert_eq!(
        ask(&ci, &token::make(&exp, &b.id, &c.id, path, now())),
        403,
        "another responder"
    );
    assert_eq!(
        ask(&ci, &token::make(&[8u8; 32], &b.id, &a.id, path, now())),
        403,
        "made for another connection"
    );
    assert_eq!(
        ask(&ci, &token::make(&exp, &c.id, &a.id, path, now())),
        403,
        "another device than the certificate"
    );
    assert_eq!(
        ask(&ci, &token::make(&exp, &b.id, &a.id, "/p2p/other", now())),
        403,
        "another path"
    );
    assert_eq!(
        ask(&ci, &token::make(&exp, &b.id, &a.id, path, now() - 3600)),
        403,
        "stale"
    );
    assert_eq!(ask(&ci, "garbage"), 403);
    // A certificate nobody named, or none at all.
    let stranger = Dev::new(9);
    let ci_s = ConnInfo {
        cert: Some(stranger.cert()),
        ..ci.clone()
    };
    assert_eq!(
        ask(&ci_s, &token::make(&exp, &stranger.id, &a.id, path, now())),
        403
    );
    let ci_none = ConnInfo {
        cert: None,
        ..ci.clone()
    };
    assert_eq!(
        ask(&ci_none, &token::make(&exp, &b.id, &a.id, path, now())),
        403
    );
    // Our own certificate is told apart (and never served).
    let ci_own = ConnInfo {
        cert: Some(a.cert()),
        ..ci.clone()
    };
    let (s, body, peer) = r.handle(
        Some(&snap),
        &ci_own,
        path,
        &token::make(&exp, &a.id, &a.id, path, now()),
        "",
    );
    assert_eq!((s, body.as_slice(), peer), (403, p2p::SELF_ANSWER, None));
    // `X-Varsto-For` counts only on a registration connection.
    let t = token::make(&exp, &b.id, &a.id, path, now());
    assert_eq!(
        r.handle(Some(&snap), &ci, path, &t, &c.device().to_string())
            .0,
        403
    );
    let reg = ConnInfo {
        registration: true,
        ..ci.clone()
    };
    let t = token::make(&exp, &b.id, &a.id, path, now());
    let (s, _, peer) = r.handle(Some(&snap), &reg, path, &t, &c.device().to_string());
    assert_eq!((s, peer), (200, Some(c.device())));
    let t = token::make(&exp, &b.id, &a.id, path, now());
    assert_eq!(
        r.handle(Some(&snap), &reg, path, &t, &stranger.device().to_string())
            .0,
        403,
        "a relay speaks only for devices of the directory"
    );
}

#[test]
fn nonces_are_spent_once_and_bounded() {
    let w = token::NonceWindow::default();
    assert!(w.spend([1; 16], 100));
    assert!(!w.spend([1; 16], 100));
    for i in 0..(token::MAX_NONCES as u32 + 10) {
        let mut n = [0u8; 16];
        n[..4].copy_from_slice(&i.to_le_bytes());
        n[15] = 9;
        w.spend(n, 100);
    }
    assert!(w.len() <= token::MAX_NONCES);
}

// ----- TLS over TCP -------------------------------------------------------------

struct TcpServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn tls_server(me: &Dev, r: Arc<Responder>) -> TcpServer {
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        tls::TcpTls::new(&me.tls, r).unwrap(),
    )
    .unwrap();
    let addr = server.addr;
    let snap = Arc::new(Mutex::new(Some(Arc::new(snapshot(me)))));
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    std::thread::spawn(move || server.run(snap, stop2));
    TcpServer { addr, stop }
}

#[test]
fn tls_admits_only_certificates_named_by_an_accepted_peer_record() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let t = Duration::from_secs(3);
    let client_b = Client::new(b.device(), b.tls.clone());
    let (s, body) = client_b
        .tcp_get(srv.addr, &a.tls.sha256, &a.device(), "/p2p/info", t)
        .unwrap();
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    // Kept alive: a second request reuses the session.
    let (s, _) = client_b
        .tcp_get(srv.addr, &a.tls.sha256, &a.device(), "/p2p/info", t)
        .unwrap();
    assert_eq!(s, 200);
    // C's certificate is in no peer record of A's directory.
    let client_c = Client::new(c.device(), c.tls.clone());
    let got = client_c.tcp_get(srv.addr, &a.tls.sha256, &a.device(), "/p2p/info", t);
    assert!(!matches!(got, Ok((200, _))), "{got:?}");
    // A server that is not the pinned one is not talked to.
    let got = client_b.tcp_get(srv.addr, &c.tls.sha256, &a.device(), "/p2p/info", t);
    assert!(got.is_err());
}

#[test]
fn an_unknown_certificate_asks_for_the_records_to_be_read_again() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let r = responder_for(&a, &[&b]);
    let srv = tls_server(&a, r.clone());
    let t = Duration::from_secs(3);
    assert!(!r.take_unknown());
    // A device of the directory knocks: nothing to read again.
    Client::new(b.device(), b.tls.clone())
        .tcp_get(srv.addr, &a.tls.sha256, &a.device(), "/p2p/info", t)
        .unwrap();
    assert!(!r.take_unknown());
    // C published its record after A's last read: its knock is noted once.
    let got = Client::new(c.device(), c.tls.clone()).tcp_get(
        srv.addr,
        &a.tls.sha256,
        &a.device(),
        "/p2p/info",
        t,
    );
    assert!(!matches!(got, Ok((200, _))));
    assert!(r.take_unknown());
    assert!(!r.take_unknown());
    // The asking side rests only briefly after such a refusal.
    let e = format!("{:#}", got.err().unwrap());
    assert!(crate::p2p::refused_us(&e), "{e}");
}

#[test]
fn a_connection_that_never_finishes_its_handshake_is_closed_at_the_deadline() {
    use std::io::{Read, Write};
    let (a, b) = (Dev::new(1), Dev::new(2));
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let mut buf = [0u8; 8];
    // A connection that never sends a byte, and one that trickles the
    // start of a handshake, are both closed at the handshake deadline.
    let mut mute = std::net::TcpStream::connect(srv.addr).unwrap();
    let mut trickle = std::net::TcpStream::connect(srv.addr).unwrap();
    trickle.write_all(&[0x16, 0x03, 0x01]).unwrap();
    for s in [&mut mute, &mut trickle] {
        s.set_read_timeout(Some(tls::HANDSHAKE_DEADLINE + Duration::from_secs(4)))
            .unwrap();
    }
    let started = std::time::Instant::now();
    assert_eq!(mute.read(&mut buf).unwrap_or(0), 0);
    let _ = trickle.read(&mut buf);
    assert!(
        started.elapsed() < tls::HANDSHAKE_DEADLINE + Duration::from_secs(3),
        "closed after {:?}",
        started.elapsed()
    );
    // Meanwhile a device of the directory is served as usual.
    let client = Client::new(b.device(), b.tls.clone());
    let (s, _) = client
        .tcp_get(
            srv.addr,
            &a.tls.sha256,
            &a.device(),
            "/p2p/info",
            Duration::from_secs(3),
        )
        .unwrap();
    assert_eq!(s, 200);
}

#[test]
fn a_token_of_another_tls_connection_is_refused() {
    let (a, b) = (Dev::new(1), Dev::new(2));
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let t = Duration::from_secs(3);
    let (s1, e1) = tls::connect(&b.tls, srv.addr, &a.tls.sha256, t).unwrap();
    let (s2, e2) = tls::connect(&b.tls, srv.addr, &a.tls.sha256, t).unwrap();
    assert_ne!(e1, e2);
    let path = "/p2p/info";
    let tok1 = token::make(&e1, &b.id, &a.id, path, now());
    let hdr = |t: &str| format!("X-Varsto-Auth: {t}\r\n");
    let (status, _, _) = p2p::exchange(s2, srv.addr, path, &hdr(&tok1)).unwrap();
    assert_eq!(status, 403, "token of connection 1 on connection 2");
    let (status, _, _) = p2p::exchange(s1, srv.addr, path, &hdr(&tok1)).unwrap();
    assert_eq!(status, 200);
}

#[test]
fn a_plain_tcp_client_gets_a_tls_alert_and_no_protocol_bytes() {
    let (a, b) = (Dev::new(1), Dev::new(2));
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let got = tls::plain_probe(
        srv.addr,
        b"GET /p2p/info HTTP/1.1\r\nHost: x\r\nX-Varsto-Peer: a:1:b:c\r\n\r\n",
    )
    .unwrap();
    assert!(!got.is_empty(), "the server answers with an alert");
    assert_eq!(got[0], 0x15, "a TLS alert record: {got:?}");
    assert!(!got.windows(4).any(|w| w == b"HTTP"), "{got:?}");
    assert!(!got.windows(3).any(|w| w == b"p2p"));
}

#[test]
fn the_own_certificate_is_refused_both_ways() {
    let (a, b) = (Dev::new(1), Dev::new(2));
    // Dialling: the client never pins its own certificate.
    let e = tls::client_config(&a.tls, &a.tls.sha256).err().unwrap();
    assert!(e.to_string().contains("own"), "{e}");
    // Accepting: a client presenting the server's own certificate fails the
    // handshake, however it got the key.
    let srv = tls_server(&a, responder_for(&a, &[&b]));
    let prov = quic::provider();
    let mut cfg = quinn::rustls::ClientConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(quic::PinnedServer {
            expected: a.tls.sha256.clone(),
            algs: prov.signature_verification_algorithms,
        }))
        .with_client_auth_cert(
            vec![quinn::rustls::pki_types::CertificateDer::from(
                a.tls.cert.clone(),
            )],
            quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(a.tls.key.clone().into()),
        )
        .unwrap();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut sock = std::net::TcpStream::connect(srv.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut conn = quinn::rustls::ClientConnection::new(
        Arc::new(cfg),
        quinn::rustls::pki_types::ServerName::try_from("varsto").unwrap(),
    )
    .unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).unwrap();
    }
    let exp = conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .unwrap();
    let stream = quinn::rustls::StreamOwned::new(conn, sock);
    let tok = token::make(&exp, &a.id, &a.id, "/p2p/info", now());
    let got = p2p::exchange(
        stream,
        srv.addr,
        "/p2p/info",
        &format!("X-Varsto-Auth: {tok}\r\n"),
    );
    assert!(got.is_err(), "the server closed the session with an alert");
    // And over QUIC: the node does not admit or dial its own certificate.
    let ra = responder_for(&a, &[&b]);
    let node = quic::Node::start_v3(
        "127.0.0.1:0".parse().unwrap(),
        a.tls.clone(),
        ra,
        Arc::new(Mutex::new(Some(Arc::new(snapshot(&a))))),
        Arc::default(),
    )
    .unwrap();
    let e = node
        .request_with(node.local_addr, &a.tls.sha256, "/p2p/info", false, &|_| {
            String::new()
        })
        .err()
        .unwrap();
    assert!(e.to_string().contains("own"), "{e}");
    // The reachability self-probe is the one exchange its own certificate
    // may make, in format 3 as in format 2.
    assert!(node.probe_self(node.local_addr));
}

// ----- QUIC in format-3 mode ----------------------------------------------------------

fn quic_node(me: &Dev, r: Arc<Responder>) -> Arc<quic::Node> {
    quic::Node::start_v3(
        "127.0.0.1:0".parse().unwrap(),
        me.tls.clone(),
        r,
        Arc::new(Mutex::new(Some(Arc::new(snapshot(me))))),
        Arc::default(),
    )
    .unwrap()
}

fn quic_body(d: &Dev, node: &quic::Node) -> PeerBody {
    let mut b = d.body(node.local_addr.port());
    b.lan_addrs.clear();
    b.udp_local = vec![node.local_addr];
    b.seq = 1;
    b
}

fn dir_with(me: &Dev, bodies: Vec<PeerBody>) -> PeerDirectory {
    let mut dir = PeerDirectory::new(me.id, me.cert());
    for body in bodies {
        dir.offer(record::Record {
            meta: record::RecordMeta {
                kind: Kind::Peer,
                vault: VAULT,
                scope: [0; 16],
                device: body.device,
                seq: body.seq,
                parts: 1,
                key_id: KeyId::Registry(0),
                body_hash: [0; 32],
                epoch: None,
                recipient: None,
                size: 0,
            },
            body,
        });
    }
    dir
}

#[test]
fn quic_v3_serves_devices_of_the_directory_with_connection_bound_tokens() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let ra = Responder::new(a.device(), &a.tls.sha256);
    let rb = Responder::new(b.device(), &b.tls.sha256);
    let rc = Responder::new(c.device(), &c.tls.sha256);
    let na = quic_node(&a, ra.clone());
    let nb = quic_node(&b, rb.clone());
    let nc = quic_node(&c, rc.clone());
    ra.set_directory(dir_with(&a, vec![quic_body(&b, &nb)]));
    na.set_known(ra.directory().infos());
    let dir_b = dir_with(&b, vec![quic_body(&a, &na)]);
    rb.set_directory(dir_b.clone());
    let peers_b = Peers::build_v3(
        Client::new(b.device(), b.tls.clone()),
        &dir_b,
        &[],
        Some(nb.clone()),
    );
    let (s, body) = peers_b.ask(&a.device(), "/p2p/info").unwrap();
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    // C knows A, but A's directory does not name C: the handshake fails.
    let dir_c = dir_with(&c, vec![quic_body(&a, &na)]);
    let peers_c = Peers::build_v3(
        Client::new(c.device(), c.tls.clone()),
        &dir_c,
        &[],
        Some(nc.clone()),
    );
    assert!(!matches!(
        peers_c.ask(&a.device(), "/p2p/info"),
        Some((200, _))
    ));
    // A token of the right device made for another connection is refused.
    let got = nb
        .request_with(na.local_addr, &a.tls.sha256, "/p2p/info", false, &|_| {
            token::make(&[3u8; 32], &b.id, &a.id, "/p2p/info", now())
        })
        .unwrap();
    assert_eq!(got.0, 403);
}

#[test]
fn a_relay_checks_the_askers_token_and_asks_with_its_own() {
    let (a, b, r) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let (ra, rb, rr) = (
        Responder::new(a.device(), &a.tls.sha256),
        Responder::new(b.device(), &b.tls.sha256),
        Responder::new(r.device(), &r.tls.sha256),
    );
    let (na, nb, nr) = (
        quic_node(&a, ra.clone()),
        quic_node(&b, rb.clone()),
        quic_node(&r, rr.clone()),
    );
    let (ba, bb, br) = (quic_body(&a, &na), quic_body(&b, &nb), quic_body(&r, &nr));
    ra.set_directory(dir_with(&a, vec![bb.clone(), br.clone()]));
    rb.set_directory(dir_with(&b, vec![ba.clone(), br.clone()]));
    rr.set_directory(dir_with(&r, vec![ba.clone(), bb.clone()]));
    for (n, resp) in [(&na, &ra), (&nb, &rb), (&nr, &rr)] {
        n.set_known(resp.directory().infos());
    }
    na.register_with(&r.device(), &[nr.local_addr], &r.tls.sha256)
        .unwrap();
    assert_eq!(nr.registrants(), vec![a.device()]);
    // B asks A through R: its token is for R and this connection.
    let via = format!("/p2p/via/{}/p2p/info", a.device());
    let ask = |tok: &dyn Fn(&[u8; 32]) -> String| {
        nb.request_with(nr.local_addr, &r.tls.sha256, &via, false, tok)
            .unwrap()
            .0
    };
    let client_b = Client::new(b.device(), b.tls.clone());
    assert_eq!(ask(&|e| client_b.token(e, &r.device(), &via)), 200);
    // A token naming A (the final responder) is not one for the relay.
    assert_eq!(ask(&|e| client_b.token(e, &a.device(), &via)), 403);
    // Through the peer table: A has no address of its own, only R.
    let mut a_hidden = ba.clone();
    a_hidden.udp_local.clear();
    a_hidden.relay_via = vec![r.id];
    let peers_b = Peers::build_v3(
        client_b.clone(),
        &dir_with(&b, vec![a_hidden, br.clone()]),
        &[],
        Some(nb.clone()),
    );
    let (s, _) = peers_b.ask(&a.device(), "/p2p/info").unwrap();
    assert_eq!(s, 200);
}

#[test]
fn a_beacon_only_adds_an_address_to_a_device_with_a_record() {
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let dir = dir_with(&a, vec![b.body(4000)]);
    let lan = vec![
        p2p::PeerAddr {
            device: b.device(),
            addr: "192.168.1.20:4000".parse().unwrap(),
            name: String::new(),
        },
        p2p::PeerAddr {
            device: c.device(),
            addr: "192.168.1.30:4000".parse().unwrap(),
            name: String::new(),
        },
    ];
    let peers = Peers::build_v3(Client::new(a.device(), a.tls.clone()), &dir, &lan, None);
    assert_eq!(peers.peers.len(), 1, "no record, no peer");
    assert_eq!(peers.peers[0].tcp[0], lan[0].addr);
    assert_eq!(peers.peers[0].cert_sha256, b.tls.sha256);
}

// ----- signed beacons ------------------------------------------------------------------

#[test]
fn unsigned_forged_foreign_or_replayed_beacons_are_ignored() {
    use beacon::{encode, BeaconBook, Ignored};
    let (a, b, c) = (Dev::new(1), Dev::new(2), Dev::new(3));
    let tag = "aabbccddeeff00112233aabb";
    let keys: HashMap<Id16, VerifyingKey> = [(b.id, b.sk.public())].into_iter().collect();
    let key_of = |d: &Id16| keys.get(d).cloned();
    let ip = "192.168.1.20".parse().unwrap();
    let mut book = BeaconBook::default();
    let m5 = encode(tag, &b.id, 4000, 5, &b.sk);
    let got = book.accept(&m5, ip, tag, &a.id, &key_of).unwrap();
    assert_eq!(got.device, b.device());
    assert_eq!(got.addr, "192.168.1.20:4000".parse().unwrap());
    assert_eq!(
        book.accept(&m5, ip, tag, &a.id, &key_of),
        Err(Ignored::Replayed)
    );
    let m4 = encode(tag, &b.id, 4000, 4, &b.sk);
    assert_eq!(
        book.accept(&m4, ip, tag, &a.id, &key_of),
        Err(Ignored::Replayed)
    );
    let m6 = encode(tag, &b.id, 4000, 6, &b.sk);
    assert!(book.accept(&m6, ip, tag, &a.id, &key_of).is_ok());
    // Format 2's unsigned beacon, a changed port, another signer, C unknown.
    let unsigned = format!("VARSTO1 {tag} {} 4000", hex::encode(b.id));
    assert_eq!(
        book.accept(&unsigned, ip, tag, &a.id, &key_of),
        Err(Ignored::Malformed)
    );
    let moved = encode(tag, &b.id, 4000, 9, &b.sk).replace(" 4000 ", " 4001 ");
    assert_eq!(
        book.accept(&moved, ip, tag, &a.id, &key_of),
        Err(Ignored::BadSignature)
    );
    let forged = encode(tag, &b.id, 4000, 10, &c.sk);
    assert_eq!(
        book.accept(&forged, ip, tag, &a.id, &key_of),
        Err(Ignored::BadSignature)
    );
    let unknown = encode(tag, &c.id, 4000, 1, &c.sk);
    assert_eq!(
        book.accept(&unknown, ip, tag, &a.id, &key_of),
        Err(Ignored::UnknownDevice)
    );
    let other_vault = encode("0011", &b.id, 4000, 11, &b.sk);
    assert_eq!(
        book.accept(&other_vault, ip, tag, &a.id, &key_of),
        Err(Ignored::OtherVault)
    );
    let own = encode(tag, &a.id, 4000, 1, &a.sk);
    assert_eq!(
        book.accept(&own, ip, tag, &a.id, &key_of),
        Err(Ignored::Own)
    );
    // A forged beacon did not raise the seq: the real next one counts.
    let m7 = encode(tag, &b.id, 4000, 7, &b.sk);
    assert!(book.accept(&m7, ip, tag, &a.id, &key_of).is_ok());
    assert!(m7.len() < 300, "fits a small datagram: {}", m7.len());
}

// ----- head exchange and batch fetch ---------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestBatch {
    n: u64,
}

impl RecordBody for TestBatch {}

/// Batches by (device, seq), encoded.
#[derive(Default)]
struct Ledger {
    batches: Mutex<BTreeMap<(Id16, u64), Vec<u8>>>,
}

impl Ledger {
    fn add(&self, dev: &Dev, keys: &Keys, seq: u64) -> [u8; 32] {
        let signer = record::DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let w = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys,
        };
        let sealed = w
            .seal(
                &StreamRef::new(Kind::Batch, [0; 16], dev.id),
                seq,
                seq,
                &KeyId::Ledger(0),
                &TestBatch { n: seq },
            )
            .unwrap();
        let (_, bytes) = sealed.parts[0].clone();
        self.batches.lock().unwrap().insert((dev.id, seq), bytes);
        sealed.published.body_hash
    }
}

impl BatchSource for Ledger {
    fn heads(&self) -> Vec<HeadRef> {
        let m = self.batches.lock().unwrap();
        let mut out: BTreeMap<Id16, HeadRef> = BTreeMap::new();
        for ((d, seq), bytes) in m.iter() {
            let env = record::SignedRecord::decode(bytes).unwrap();
            out.insert(
                *d,
                HeadRef {
                    device: *d,
                    seq: *seq,
                    hash: env.body_hash,
                },
            );
        }
        out.into_values().collect()
    }
    fn batch(&self, device: &Id16, seq: u64) -> Option<Vec<u8>> {
        self.batches.lock().unwrap().get(&(*device, seq)).cloned()
    }
}

/// A sink that keeps what it is given, in order.
#[derive(Default)]
struct Sink {
    heads: BTreeMap<Id16, u64>,
    got: Vec<String>,
}

impl heads::BatchSink for Sink {
    fn head(&self, device: &Id16) -> u64 {
        self.heads.get(device).copied().unwrap_or(0)
    }
    fn ingest(&mut self, name: &str, _record: &[u8]) -> anyhow::Result<()> {
        let n = record::RecordName::parse_as(Kind::Batch, name).unwrap();
        self.heads.insert(n.device.unwrap(), n.seq);
        self.got.push(name.to_string());
        Ok(())
    }
}

/// A (serving, with batches of A up to 3) and B (asking), over TLS on TCP.
struct HeadsSetup {
    a: Dev,
    b: Dev,
    keys: Keys,
    ledger: Arc<Ledger>,
    ra: Arc<Responder>,
    _srv: TcpServer,
    peers_b: Peers,
    trust: Trust,
}

fn heads_setup() -> HeadsSetup {
    let (a, b) = (Dev::new(1), Dev::new(2));
    let keys = keys();
    let ledger = Arc::new(Ledger::default());
    for seq in 1..=3 {
        ledger.add(&a, &keys, seq);
    }
    let ra = responder_for(&a, &[&b]);
    ra.set_batches(ledger.clone());
    let srv = tls_server(&a, ra.clone());
    let mut body_a = a.body(srv.addr.port());
    body_a.seq = 1;
    let dir_b = dir_with(&b, vec![body_a]);
    let peers_b = Peers::build_v3(Client::new(b.device(), b.tls.clone()), &dir_b, &[], None);
    let trust = trust_of(&[&a, &b]);
    HeadsSetup {
        a,
        b,
        keys,
        ledger,
        ra,
        _srv: srv,
        peers_b,
        trust,
    }
}

#[test]
fn head_exchange_proves_a_withheld_batch_and_the_peer_hands_it_over() {
    let s = heads_setup();
    let key_of = |d: &Id16| s.trust.keys.get(d).cloned();
    let acceptor = Acceptor {
        vault: VAULT,
        keys: &s.keys,
        trust: &s.trust,
    };
    // B holds A's batch 1 only (every storage withholds 2 and 3).
    let b1 = record::SignedRecord::decode(&s.ledger.batch(&s.a.id, 1).unwrap()).unwrap();
    let mine = vec![HeadRef {
        device: s.a.id,
        seq: 1,
        hash: b1.body_hash,
    }];
    let mut watch = Watch::default();
    let mut sink = Sink::default();
    sink.heads.insert(s.a.id, 1);
    let r = heads::catch_up::<TestBatch>(
        &s.peers_b, &mine, &VAULT, &acceptor, &key_of, &mut watch, &mut sink, 100,
    );
    assert_eq!(r.proofs, 1, "{r:?}");
    assert_eq!(r.fetched, 2, "{r:?}");
    assert_eq!(r.refused, 0);
    assert_eq!(sink.heads[&s.a.id], 3);
    assert_eq!(
        sink.got,
        vec![heads::batch_name(&s.a.id, 2), heads::batch_name(&s.a.id, 3)]
    );
    let p = watch.get(&s.a.id).unwrap();
    assert_eq!((p.seq, p.source.as_str()), (3, "envelope"));
    assert_eq!(p.peer, hex::encode(s.a.id));
    // A heard B's list on /p2p/heads.
    let heard = s.ra.take_heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].from, s.b.device());
    assert_eq!(heard[0].heads[0].seq, 1);
}

#[test]
fn heads_ride_on_changed_and_in_the_peer_record() {
    let s = heads_setup();
    let key_of = |d: &Id16| s.trust.keys.get(d).cloned();
    // /p2p/changed with B's list: the answer proves A's head.
    p2p::take_change_heard();
    let answers = notify_changed(&s.peers_b, &[]);
    assert_eq!(answers.len(), 1);
    assert!(p2p::take_change_heard(), "the change was heard");
    let mut watch = Watch::default();
    let proofs = heads::take_answer(&answers[0].1, &s.a.id, &VAULT, &key_of, &mut watch, 50);
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].seq, 3);
    assert_eq!(answers[0].1.heads.len(), 1);
    // A proof is the envelope without its body.
    assert!(answers[0].1.proofs[0].len() < 4096);
    // The peer record: A's own head in its signed record proves it too.
    let mut body = s.a.body(1);
    body.heads = s.ledger.heads();
    body.pushed = vec![Pushed {
        storage: [9; 16],
        seq: 3,
    }];
    let mut w2 = Watch::default();
    assert!(w2.note_peer_record(&body, 60));
    assert_eq!(w2.get(&s.a.id).unwrap().source, "peer record");
    assert!(!w2.note_peer_record(&body, 61), "not newer");
    // A body naming only another device's head proves nothing about it.
    let mut other = s.b.body(1);
    other.heads = s.ledger.heads();
    assert!(!Watch::default().note_peer_record(&other, 1));
}

#[test]
fn forged_or_foreign_proofs_and_mismatched_batches_are_refused() {
    let s = heads_setup();
    let key_of = |d: &Id16| s.trust.keys.get(d).cloned();
    let rec = s.ledger.batch(&s.a.id, 3).unwrap();
    let proof = heads::strip_body(&rec).unwrap();
    assert_eq!(heads::verify_proof(&proof, &VAULT, &key_of).unwrap().seq, 3);
    // A raised seq, a changed hash, another vault, an unknown signer.
    let mut env = record::SignedRecord::decode(&proof).unwrap();
    env.seq = 4;
    assert!(heads::verify_proof(&env.encode(), &VAULT, &key_of).is_err());
    let mut env = record::SignedRecord::decode(&proof).unwrap();
    env.body_hash[0] ^= 1;
    assert!(heads::verify_proof(&env.encode(), &VAULT, &key_of).is_err());
    assert!(heads::verify_proof(&proof, &[1; 16], &key_of).is_err());
    assert!(heads::verify_proof(&proof, &VAULT, &|_| None).is_err());
    // A batch the peer hands over must be the one proved, under its name.
    let acceptor = Acceptor {
        vault: VAULT,
        keys: &s.keys,
        trust: &s.trust,
    };
    let h3 = record::SignedRecord::decode(&rec).unwrap().body_hash;
    assert!(
        heads::check_fetched::<TestBatch>(&acceptor, &s.a.id, 3, rec.clone(), Some(&h3)).is_ok()
    );
    let r2 = s.ledger.batch(&s.a.id, 2).unwrap();
    assert!(
        heads::check_fetched::<TestBatch>(&acceptor, &s.a.id, 3, r2.clone(), None).is_err(),
        "another seq than its name"
    );
    assert!(
        heads::check_fetched::<TestBatch>(&acceptor, &s.a.id, 2, r2, Some(&h3)).is_err(),
        "not the batch proved"
    );
    let mut bad = record::SignedRecord::decode(&rec).unwrap();
    let last = bad.body.len() - 1;
    bad.body[last] ^= 1;
    assert!(heads::check_fetched::<TestBatch>(&acceptor, &s.a.id, 3, bad.encode(), None).is_err());
    // Over the wire: the path, and a batch nobody holds.
    let (st, body) = s
        .peers_b
        .ask(&s.a.device(), &heads::ledger_path(&s.a.id, 2))
        .unwrap();
    assert_eq!(st, 200);
    assert_eq!(body, s.ledger.batch(&s.a.id, 2).unwrap());
    let (st, _) = s
        .peers_b
        .ask(&s.a.device(), &heads::ledger_path(&s.a.id, 9))
        .unwrap();
    assert_eq!(st, 404);
}

#[test]
fn head_lists_round_trip_in_paths_and_answers_are_bounded() {
    let list: Vec<HeadRef> = (0..256u64)
        .map(|i| HeadRef {
            device: [i as u8; 16],
            seq: i * 1000,
            hash: [7; 32],
        })
        .collect();
    let p = heads::list_path(heads::CHANGED_PREFIX, &list).unwrap();
    assert!(p.len() <= heads::MAX_PATH);
    assert_eq!(
        heads::list_of_path(&p, heads::CHANGED_PREFIX).unwrap(),
        list
    );
    assert_eq!(
        heads::list_of_path("/p2p/changed", heads::CHANGED_PREFIX),
        Some(Vec::new())
    );
    assert!(heads::list_of_path("/p2p/changed/@@", heads::CHANGED_PREFIX).is_none());
    let mut too_many = list.clone();
    too_many.push(list[0]);
    assert!(heads::list_path(heads::HEADS_PREFIX, &too_many).is_none());
    assert_eq!(
        heads::parse_ledger_path(&heads::ledger_path(&[3; 16], 42)),
        Some(([3; 16], 42))
    );
}

// ----- the rollback warning -----------------------------------------------------------

#[test]
fn rollback_warning_after_two_pulls_only_for_a_storage_the_writer_confirmed() {
    use heads::{Expectation, Proved, RollbackJudge, StorageView};
    let d: Id16 = [1; 16];
    let s1: Id16 = [0xa1; 16];
    let s2: Id16 = [0xa2; 16];
    let names = |id: &Id16| format!("dev{}", id[0]);
    let view = |s: Id16, shown: u64, reachable: bool| StorageView {
        storage: s,
        name: format!("st{:x}", s[0]),
        reachable,
        shown: [(d, shown)].into_iter().collect(),
    };
    let proofs: BTreeMap<String, Proved> = [(
        hex::encode(d),
        Proved {
            seq: 9,
            hash: String::new(),
            peer: hex::encode([2u8; 16]),
            source: "envelope".into(),
            utc: 10,
        },
    )]
    .into_iter()
    .collect();
    // D confirmed batch 8 on S1; S2 it never used.
    let expected = [Expectation {
        storage: s1,
        device: d,
        seq: 8,
    }];
    let mut j = RollbackJudge::default();
    let views = [view(s1, 5, true), view(s2, 1, true)];
    assert!(j
        .after_pull(100, &views, &expected, &proofs, &names, 100)
        .is_empty());
    let w = j.after_pull(200, &views, &expected, &proofs, &names, 200);
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!((w[0].storage, w[0].shown, w[0].proved), (s1, 5, 8));
    assert!(w[0].notify);
    assert_eq!(
        w[0].text,
        "storage sta1 may be withholding or rolled back: it shows ledger batches of dev1 up to 5, but device dev2 proved 8"
    );
    // Once a day as a notification, every pull as a warning.
    let w = j.after_pull(300, &views, &expected, &proofs, &names, 300);
    assert!(!w[0].notify);
    // Unreachable: not judged, kept.
    let off = [view(s1, 0, false)];
    assert!(j
        .after_pull(400, &off, &expected, &proofs, &names, 400)
        .is_empty());
    assert_eq!(j.suspects.len(), 1);
    // The storage shows the batch: cleared.
    let fixed = [view(s1, 8, true)];
    assert!(j
        .after_pull(500, &fixed, &expected, &proofs, &names, 500)
        .is_empty());
    assert!(j.suspects.is_empty());
    // A proof newer than the pull does not count yet.
    let mut j = RollbackJudge::default();
    for t in [1, 2, 3] {
        assert!(j
            .after_pull(t, &views, &expected, &proofs, &names, t)
            .is_empty());
    }
    // The writer's record stops listing the storage: cleared.
    let mut j = RollbackJudge::default();
    j.after_pull(100, &views, &expected, &proofs, &names, 100);
    assert_eq!(j.suspects.len(), 1);
    j.after_pull(200, &views, &[], &proofs, &names, 200);
    assert!(j.suspects.is_empty());
}
