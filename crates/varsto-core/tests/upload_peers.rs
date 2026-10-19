// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A long upload with peers (spec section 77.23): the uploading device
//! publishes its file list before the upload and the packs it stored so
//! far while the upload runs, so another device gets the new files from
//! the uploader peer to peer, and sees the stored packs claimed, while the
//! storage still holds back the rest of the upload.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
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

/// What the desk saw while the laptop uploaded, with the number of packs
/// the storage had taken at that moment.
#[derive(Debug, Default)]
struct Seen {
    /// Every new file was there, complete.
    files: bool,
    packs_written_at_files: usize,
    /// Packs of the upload were claimed on the storage.
    packs: bool,
    packs_written_at_packs: usize,
    /// Blocks that came from peers.
    from_peers: u64,
}

/// The storage's hold on the upload.
#[derive(Clone, Debug, Default)]
struct Gate {
    /// Packs written so far.
    written: usize,
    /// The desk saw what it waited for (or the wait timed out).
    released: bool,
    timed_out: bool,
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

    // A storage that holds the upload: after `HELD_AFTER` packs it takes
    // no more until the desk has seen what the push must show it during
    // the upload (or a minute passes), so "before the upload ended" is a
    // fact of the test, not a race with the clock. Small packs: 4 MiB
    // make about 16 of them.
    const HELD_AFTER: usize = 2;
    a.set_pack_target_for_tests(Some(256 << 10));
    let gate = Arc::new((Mutex::new(Gate::default()), Condvar::new()));
    let gate2 = gate.clone();
    a.set_pack_write_hook(Some(Arc::new(move |name: &str| {
        if name != "box" {
            return Ok(());
        }
        let (lock, cv) = &*gate2;
        let mut g = lock.lock().unwrap();
        if g.written >= HELD_AFTER && !g.released {
            let (got, timeout) = cv
                .wait_timeout_while(g, Duration::from_secs(60), |g| !g.released)
                .unwrap();
            g = got;
            if timeout.timed_out() {
                g.timed_out = true;
                g.released = true;
                cv.notify_all();
            }
        }
        g.written += 1;
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

    // The desk pulls again and again while the laptop pushes, and lets the
    // storage go on once it has every file and sees packs claimed.
    let gate3 = gate.clone();
    let b_dir2 = b_dir.clone();
    let desk = std::thread::spawn(move || {
        let mut seen = Seen::default();
        let t0 = Instant::now();
        let (lock, cv) = &*gate3;
        while t0.elapsed() < Duration::from_secs(120) && !lock.lock().unwrap().released {
            let r = b.pull("docs").unwrap();
            seen.from_peers += r.chunks_from_peers;
            let mut g = lock.lock().unwrap();
            if g.released {
                break;
            }
            if !seen.files && files_in(&b_dir2) == wanted {
                seen.files = true;
                seen.packs_written_at_files = g.written;
            }
            if !seen.packs && !b.packs_on_storage("box").unwrap().is_empty() {
                seen.packs = true;
                seen.packs_written_at_packs = g.written;
            }
            if seen.files && seen.packs {
                g.released = true;
                cv.notify_all();
                break;
            }
            drop(g);
            std::thread::sleep(Duration::from_millis(100));
        }
        (b, seen)
    });

    let push = a.push("docs").unwrap();
    let (mut b, seen) = desk.join().unwrap();
    let g = gate.0.lock().unwrap().clone();
    drop(serving);

    assert!(push.chunks_uploaded > 0, "{push:?}");
    assert!(
        !g.timed_out,
        "the desk did not get the files and see packs claimed while the storage held the upload: {seen:?}"
    );
    assert!(seen.files && seen.packs, "{seen:?}");
    // Both happened while packs of the upload were still to be written.
    assert!(
        g.written > seen.packs_written_at_files.max(seen.packs_written_at_packs),
        "{seen:?} {g:?}"
    );
    assert!(
        seen.from_peers > 0,
        "from the laptop peer to peer: {seen:?}"
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
