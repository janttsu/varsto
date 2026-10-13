// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Live activity between two devices on localhost: the laptop verifies
//! every block of its storage (`fsck --verify`, slowed down by the test
//! hook), and the desktop, watching, sees that task with its progress over
//! `/p2p/activity`.

use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use varsto_core::activity::{self, PeerCache};
use varsto_core::chunking::ChunkerParams;
use varsto_core::p2p::{self, PeerAddr, Peers};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_device_sees_another_devices_long_task_with_its_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let (mut laptop, key) = Engine::init(&root.join("laptop-home"), "laptop", PASS).unwrap();
    laptop.chunker = ChunkerParams::SMALL;
    laptop.add_storage(storage.clone()).unwrap();
    let docs = root.join("laptop-docs");
    fs::create_dir_all(&docs).unwrap();
    for i in 0..200u32 {
        fs::write(
            docs.join(format!("f{i}.txt")),
            format!("file {i} ").repeat(50),
        )
        .unwrap();
    }
    laptop.add_folder("docs", &docs).unwrap();
    laptop.push("docs").unwrap();
    activity::set_identity(laptop.device_id(), laptop.own_device_name());
    let desktop = Engine::join(&root.join("desktop-home"), "desktop", PASS, &key, storage).unwrap();

    // The laptop serves its snapshot over TCP.
    let server = p2p::Server::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = server.addr;
    let snap: Arc<Mutex<Option<Arc<p2p::Snapshot>>>> =
        Arc::new(Mutex::new(Some(Arc::new(laptop.peer_snapshot().unwrap()))));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (snap.clone(), stop.clone());
    let serving = std::thread::spawn(move || server.run(s2, st2));

    // The desktop watches.
    let laptop_id = laptop.device_id().clone();
    let peers = Arc::new(Peers::new(
        desktop.peer_key(),
        desktop.device_id().clone(),
        vec![PeerAddr {
            device: laptop_id.clone(),
            addr,
            name: "laptop".into(),
        }],
    ));
    let cache: &'static PeerCache = Box::leak(Box::default());
    cache.set_peers(Some(peers), None);
    let done = Arc::new(AtomicBool::new(false));
    let done2 = done.clone();
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let t0 = Instant::now();
        while !done2.load(Ordering::Relaxed) && t0.elapsed() < Duration::from_secs(120) {
            cache.watch();
            cache.poll();
            for p in cache.report() {
                if let Some(a) = p.activity.filter(|_| p.status == "ok") {
                    for t in a.tasks {
                        seen.push((a.device.clone(), a.name.clone(), t));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        seen
    });

    // A long operation on the laptop: every block read back and hashed,
    // 50 ms per block (10 s; the desktop asks every 2.5 s).
    activity::set_test_delay_ms(50);
    let report = laptop.fsck(true).unwrap();
    activity::set_test_delay_ms(0);
    done.store(true, Ordering::Relaxed);
    let seen = watcher.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    serving.join().unwrap();

    assert!(report.objects_verified_now > 150, "{report:?}");
    let verify: Vec<_> = seen
        .iter()
        .filter(|(_, _, t)| t.kind == "fsck" && t.phase == "verify")
        .collect();
    assert!(
        !verify.is_empty(),
        "the desktop never saw the fsck: {seen:?}"
    );
    let (dev, name, last) = verify.last().unwrap();
    assert_eq!(
        (dev.as_str(), name.as_str()),
        (laptop_id.as_str(), "laptop")
    );
    assert!(
        last.total > 150 && last.done > 0 && last.done <= last.total,
        "{last:?}"
    );
    assert!(last.percent.is_some());
    // The progress moved while the desktop watched, and a rate showed up.
    let first = verify.first().unwrap();
    assert!(last.done > first.2.done, "{verify:?}");
    assert!(
        verify
            .iter()
            .any(|(_, _, t)| t.rate > 0 && t.eta_utc.is_some()),
        "{verify:?}"
    );
    // Nothing is left once the operation is over.
    assert!(activity::tasks().iter().all(|t| t.kind != "fsck"));
}
