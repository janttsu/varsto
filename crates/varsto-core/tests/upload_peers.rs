// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A long upload with peers (spec section 77.23): the uploading device
//! publishes its file list before the upload and the packs it stored so
//! far while the upload runs, so another device gets the new files from
//! the uploader peer to peer, and sees the stored packs claimed, before the
//! upload to a slow storage ends.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::EarlyPublish;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

fn files_in(root: &Path) -> BTreeMap<String, Vec<u8>> {
    match fs::read_dir(root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .filter(|(n, _)| n.ends_with(".bin"))
            .collect(),
        Err(_) => BTreeMap::new(),
    }
}

/// What the desk saw while the laptop uploaded.
#[derive(Debug, Default)]
struct Seen {
    /// When every new file was there, complete, and how many blocks had
    /// come from peers by then.
    files_at: Option<Instant>,
    from_peers: u64,
    /// When the desk first saw packs of the upload claimed on the storage.
    packs_at: Option<Instant>,
}

#[test]
fn peers_get_a_long_upload_from_the_uploader_before_it_ends() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let spec = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("box"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(spec.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("docs", &a_dir).unwrap();
    a.sync(None).unwrap();
    let mut b = common::join_approved(&root.join("b-home"), "desk", PASS, &key, spec, &mut a);
    b.chunker = ChunkerParams::SMALL;
    let b_dir = root.join("b-docs");
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();

    // Both online: the laptop serves (as the service does, from the
    // snapshot sink the push refreshes) and knows the desk as a peer.
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    common::p2p::meet(&mut a);
    a.set_snapshot_sink(Some(serving.sink()));

    // A slow storage: one pack at a time, 250 ms each; small packs, so
    // 4 MiB make about 16 of them, and the upload takes seconds.
    a.set_pack_target_for_tests(Some(256 << 10));
    let one_at_a_time = Arc::new(Mutex::new(()));
    a.set_pack_write_hook(Some(Arc::new(move |name: &str| {
        if name == "box" {
            let _g = one_at_a_time.lock().unwrap();
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    })));
    a.set_early_publish(EarlyPublish {
        bytes: 64 << 20,
        secs: 0,
    });
    let mut wanted = BTreeMap::new();
    for i in 0..4u64 {
        let data = pseudo_random(1 << 20, 100 + i);
        fs::write(a_dir.join(format!("f{i}.bin")), &data).unwrap();
        wanted.insert(format!("f{i}.bin"), data);
    }

    // The desk pulls again and again while the laptop pushes.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let b_dir2 = b_dir.clone();
    let desk = std::thread::spawn(move || {
        let mut seen = Seen::default();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(120) {
            let r = b.pull("docs").unwrap();
            seen.from_peers += r.chunks_from_peers;
            if seen.files_at.is_none() && files_in(&b_dir2) == wanted {
                seen.files_at = Some(Instant::now());
            }
            if seen.packs_at.is_none() && !b.packs_on_storage("box").unwrap().is_empty() {
                seen.packs_at = Some(Instant::now());
            }
            if (seen.files_at.is_some() && seen.packs_at.is_some())
                || stop2.load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        (b, seen)
    });

    let started = Instant::now();
    let push = a.push("docs").unwrap();
    let ended = Instant::now();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (mut b, seen) = desk.join().unwrap();
    drop(serving);

    assert!(
        ended - started > Duration::from_secs(2),
        "the upload is slow: {:?}",
        ended - started
    );
    assert!(push.chunks_uploaded > 0, "{push:?}");
    let files_at = seen.files_at.expect("the desk got the new files");
    assert!(
        files_at < ended,
        "the files arrived {:?} after the upload ended",
        files_at - ended
    );
    assert!(
        seen.from_peers > 0,
        "from the laptop peer to peer: {seen:?}"
    );
    let packs_at = seen
        .packs_at
        .expect("the desk saw the packs stored during the upload");
    assert!(
        packs_at < ended,
        "the packs were claimed {:?} after the upload ended",
        packs_at - ended
    );

    // At the end every block is claimed on the storage, and the desk reads
    // the files from there alone (the laptop is gone).
    b.set_peers(None);
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    let st = a.status().unwrap();
    assert_eq!(st.folders[0].chunks_without_storage_copy, 0);
    let mut c = common::join_approved(
        &root.join("c-home"),
        "tablet",
        PASS,
        &key,
        StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("box"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        },
        &mut a,
    );
    let c_dir = root.join("c-docs");
    c.attach_folder("docs", &c_dir, false).unwrap();
    let r = c.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(r.chunks_from_peers, 0);
    let mut want = BTreeMap::new();
    for i in 0..4u64 {
        want.insert(format!("f{i}.bin"), pseudo_random(1 << 20, 100 + i));
    }
    assert_eq!(files_in(&c_dir), want);
}
