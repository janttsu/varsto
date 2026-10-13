// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer discovery through a Mainline DHT, on a testnet of local DHT nodes
//! (no public network): two devices of one vault find each other's
//! rendezvous records, and a node with another vault key finds nothing.

use std::path::PathBuf;
use std::time::{Duration, Instant};
use varsto_core::crypto::SecretKey;
use varsto_core::p2p::dht::{DhtState, Discovery};
use varsto_core::p2p::PeerRecord;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

/// Poll `ok` every 200 ms for up to a minute.
fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(60);
    while Instant::now() < until {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

/// The record `e` would publish, with a made-up public address to look for.
fn record(e: &Engine, public: &str) -> PeerRecord {
    let mut rec = e.peer_record_template(17893);
    rec.udp_public = vec![public.parse().unwrap()];
    rec
}

#[test]
fn two_devices_find_each_other_through_a_local_dht() {
    let testnet = mainline::Testnet::builder(10).build().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().to_path_buf();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
    };
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &root.join("a-docs")).unwrap();
    std::fs::write(root.join("a-docs").join("note.txt"), b"hello").unwrap();
    a.push("docs").unwrap();
    let b = Engine::join(&root.join("b-home"), "desk", PASS, &key, storage).unwrap();
    assert_eq!(
        a.peer_key().0,
        b.peer_key().0,
        "one membership key per vault"
    );
    let vault = a.vault_id().clone();

    // A publishes first; B starts once A's item is out, so B's first
    // lookup (right after it joins the network) finds it.
    let dht_a = Discovery::start(vault.clone(), a.peer_key(), testnet.bootstrap.clone()).unwrap();
    let rec_a = record(&a, "203.0.113.7:40000");
    dht_a.set_record(rec_a.clone());
    dht_a.set_targets(vec![(b.device_id().clone(), "desk".into())]);
    wait_for("A's publish", || dht_a.status().last_publish_utc.is_some());
    let st = dht_a.status();
    assert_eq!(st.state, DhtState::Ok);
    assert!(st.stored_at > 0, "{st:?}");

    let dht_b = Discovery::start(vault.clone(), b.peer_key(), testnet.bootstrap.clone()).unwrap();
    let rec_b = record(&b, "198.51.100.9:40001");
    dht_b.set_record(rec_b.clone());
    dht_b.set_targets(vec![(a.device_id().clone(), "laptop".into())]);
    wait_for("B to find A", || !dht_b.found().is_empty());
    let found = dht_b.found();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].device, *a.device_id());
    assert_eq!(found[0].name, "laptop", "the name comes from the registry");
    assert_eq!(found[0].udp_public, rec_a.udp_public);
    assert_eq!(found[0].cert_sha256, rec_a.cert_sha256);
    assert_eq!(found[0].updated_utc, rec_a.updated_utc);
    assert!(dht_b.take_changed());
    assert!(!dht_b.take_changed());

    // A asks again now that B has published.
    wait_for("B's publish", || dht_b.status().last_publish_utc.is_some());
    dht_a.lookup_now();
    wait_for("A to find B", || !dht_a.found().is_empty());
    assert_eq!(dht_a.found()[0].udp_public, rec_b.udp_public);

    // A new address is published at once and found at the next lookup.
    let mut moved = rec_a.clone();
    moved.udp_public = vec!["203.0.113.8:40000".parse().unwrap()];
    moved.updated_utc += 1;
    let published = dht_a.status().last_publish_utc;
    dht_a.set_record(moved.clone());
    wait_for("A's second publish", || {
        dht_a.status().last_publish_utc != published && dht_a.status().error.is_none()
    });
    dht_b.lookup_now();
    wait_for("B to see A's new address", || {
        dht_b
            .found()
            .first()
            .is_some_and(|r| r.udp_public == moved.udp_public)
    });

    // Another vault's key derives other DHT keys: nothing to find, and
    // nothing it could open.
    let stranger = Discovery::start(vault, SecretKey::random(), testnet.bootstrap.clone()).unwrap();
    stranger.set_targets(vec![(a.device_id().clone(), "laptop".into())]);
    wait_for("the stranger's lookup", || {
        stranger.status().last_lookup_utc.is_some()
    });
    assert!(stranger.found().is_empty());
    assert_eq!(stranger.status().found[0].updated_utc, None);
}
