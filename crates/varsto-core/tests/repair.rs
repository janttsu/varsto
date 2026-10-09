// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic repair: a missing or corrupt copy on one of this device's
//! storages is written again from another storage, from this device's plain
//! file, or from a peer; a cold storage is read only when asked; a loss that
//! nothing can repair is reported once with the reason.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto;
use varsto_core::engine::{DamageKind, RepairOptions};
use varsto_core::ids::ObjectName;
use varsto_core::p2p;
use varsto_core::storage::{StorageCalls, StorageSpec};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path, cold: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold,
        carrier: false,
        place: String::new(),
    }
}

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

/// Chunk object files under a storage directory.
fn objects(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = walkdir::WalkDir::new(root.join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    out.sort();
    out
}

fn intact(path: &Path) -> bool {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    fs::read(path)
        .map(|b| ObjectName::from_bytes(&crypto::hash(&b)).as_str() == name)
        .unwrap_or(false)
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        Lab {
            root: tmp.path().to_path_buf(),
            _tmp: tmp,
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

/// Device A with the given storages and a folder "docs" holding one
/// multi-chunk file, pushed everywhere.
fn device(lab: &Lab, storages: &[StorageSpec]) -> (Engine, String) {
    let (mut a, key) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    for s in storages {
        a.add_storage(s.clone()).unwrap();
    }
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    fs::write(lab.p("a-docs/big.bin"), pseudo_random(200_000, 7)).unwrap();
    a.sync(None).unwrap();
    (a, key)
}

#[test]
fn missing_copy_is_rewritten_from_another_storage() {
    let lab = Lab::new();
    let (mut a, _) = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            dir("spare", &lab.p("spare"), false),
        ],
    );
    let all = objects(&lab.p("box"));
    assert!(all.len() >= 3, "a multi-chunk file");
    // Two objects disappear from "box"; another storage is the first source
    // tried after the block cache.
    fs::remove_file(&all[0]).unwrap();
    fs::remove_file(&all[1]).unwrap();

    let preview = a
        .repair(&RepairOptions {
            dry_run: true,
            ..RepairOptions::manual()
        })
        .unwrap();
    assert_eq!(preview.repaired.len(), 2, "{preview:?}");
    assert!(!all[0].exists(), "a dry run writes nothing");

    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert_eq!(r.repaired.len(), 2, "{r:?}");
    assert!(r.unrepairable.is_empty());
    for c in &r.repaired {
        assert_eq!(c.storage, "box");
        assert_eq!(c.source, "storage spare");
        assert_eq!(c.kind, DamageKind::Missing);
    }
    assert!(intact(&all[0]) && intact(&all[1]));
    // Nothing left: fsck is clean and the queue is empty.
    let f = a.fsck(false).unwrap();
    assert_eq!(f.claims_without_object, 0);
    assert_eq!(f.repairs_queued, 0);
    let st = a.repair_status();
    assert_eq!(st.queued, 0);
    assert_eq!(st.total_repaired, 2);
    assert!(
        st.describe().contains("2 copies repaired"),
        "{}",
        st.describe()
    );
}

#[test]
fn corrupt_copy_is_rewritten_from_the_local_file() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let all = objects(&lab.p("box"));
    fs::write(&all[1], b"bit rot").unwrap();
    fs::remove_file(&all[2]).unwrap();

    // fsck --verify finds both and queues them.
    let f = a.fsck(true).unwrap();
    assert_eq!(f.objects_corrupt.len(), 1);
    assert_eq!(f.repairs_queued, 2, "{f:?}");
    assert!(a.repair_due(varsto_core::util::now_utc()));

    // The service's run: queue only, within its budget.
    let r = a.repair(&RepairOptions::service()).unwrap();
    assert_eq!(r.repaired.len(), 2, "{r:?}");
    let kinds: BTreeSet<DamageKind> = r.repaired.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        BTreeSet::from([DamageKind::Missing, DamageKind::Corrupt])
    );
    assert!(r.repaired.iter().all(|c| c.source == "local file"), "{r:?}");
    assert!(intact(&all[1]) && intact(&all[2]));
    assert!(!a.repair_due(varsto_core::util::now_utc()));
    assert!(a.fsck(true).unwrap().objects_corrupt.is_empty());
}

#[test]
fn verification_queues_damage_and_another_device_repairs_it() {
    let lab = Lab::new();
    let (_a, key) = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let mut b = Engine::join(
        &lab.p("b-home"),
        "desk",
        PASS,
        &key,
        dir("box", &lab.p("box"), false),
    )
    .unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.p("b-docs"), false).unwrap();
    b.sync(None).unwrap();
    let all = objects(&lab.p("box"));
    fs::write(&all[0], b"damaged").unwrap();
    // B checked every block when it downloaded them: look 40 days ahead,
    // when they are due again.
    let v = b
        .auto_verify_at(varsto_core::util::now_utc() + 40 * 86400)
        .unwrap();
    assert_eq!(v.corrupt.len(), 1, "{v:?}");
    assert_eq!(v.queued_for_repair, 1);
    let r = b.repair(&RepairOptions::service()).unwrap();
    assert_eq!(r.repaired.len(), 1, "{r:?}");
    assert_eq!(r.repaired[0].kind, DamageKind::Corrupt);
    assert!(intact(&all[0]));
}

#[test]
fn missing_copy_is_rewritten_from_a_peer() {
    let lab = Lab::new();
    let (a, key) = device(&lab, &[dir("box", &lab.p("box"), false)]);
    // The phone keeps placeholders only: it has no plain copy.
    let mut b = Engine::join(
        &lab.p("b-home"),
        "phone",
        PASS,
        &key,
        dir("box", &lab.p("box"), false),
    )
    .unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.p("b-docs"), true).unwrap();
    b.sync(None).unwrap();
    let all = objects(&lab.p("box"));
    fs::remove_file(&all[0]).unwrap();

    // Without a peer nothing can repair it.
    let r = b.repair(&RepairOptions::manual()).unwrap();
    assert_eq!(r.unrepairable.len(), 1, "{r:?}");

    // The laptop serves its blocks over TCP.
    let server = p2p::Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.addr;
    let snap = Arc::new(Mutex::new(Some(Arc::new(a.peer_snapshot().unwrap()))));
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let th = std::thread::spawn(move || server.run(snap, stop2));
    b.set_peers(Some(Arc::new(p2p::Peers::new(
        b.peer_key(),
        b.device_id().clone(),
        vec![p2p::PeerAddr {
            device: a.device_id().clone(),
            addr,
            name: "laptop".into(),
        }],
    ))));
    let r = b.repair(&RepairOptions::manual()).unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = th.join();
    assert_eq!(r.repaired.len(), 1, "{r:?}");
    assert!(r.repaired[0].source.starts_with("peer "), "{r:?}");
    assert!(intact(&all[0]));
    assert!(b.repair_status().open_losses.is_empty());
}

#[test]
fn cold_storage_is_read_only_when_asked() {
    let lab = Lab::new();
    let (mut a, _) = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            dir("deep", &lab.p("deep"), true),
        ],
    );
    assert!(!objects(&lab.p("deep")).is_empty(), "cold storage written");
    let all = objects(&lab.p("box"));
    fs::remove_file(&all[0]).unwrap();
    fs::remove_file(lab.p("a-docs/big.bin")).unwrap();

    let calls = Arc::new(StorageCalls::default());
    a.count_storage_calls(calls.clone());
    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert!(r.repaired.is_empty(), "{r:?}");
    assert_eq!(r.unrepairable.len(), 1);
    assert!(
        r.unrepairable[0].reason.contains("cold storage deep"),
        "{r:?}"
    );
    // One read: the damaged copy itself, nothing from the cold storage.
    let c = calls.snapshot();
    assert_eq!(c.chunk_gets, 1, "{c:?}");
    assert!(!all[0].exists());

    let r = a
        .repair(&RepairOptions {
            from_cold: true,
            ..RepairOptions::manual()
        })
        .unwrap();
    assert_eq!(r.repaired.len(), 1, "{r:?}");
    assert_eq!(r.repaired[0].source, "cold storage deep");
    assert!(intact(&all[0]));
}

#[test]
fn unrepairable_loss_is_reported_once() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let all = objects(&lab.p("box"));
    fs::remove_file(&all[0]).unwrap();
    fs::remove_file(lab.p("a-docs/big.bin")).unwrap();

    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert!(r.repaired.is_empty());
    assert_eq!(r.unrepairable.len(), 1, "{r:?}");
    assert!(r.unrepairable[0].reason.contains("no intact copy"));
    assert_eq!(r.new_losses, 1);
    let st = a.repair_status();
    assert_eq!(st.open_losses.len(), 1);
    assert!(
        st.describe()
            .contains("1 could not be repaired: no intact copy"),
        "{}",
        st.describe()
    );
    // Not due again until the retry time; a manual run tries again but
    // does not count it as new.
    assert!(!a.repair_due(varsto_core::util::now_utc()));
    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert_eq!(r.unrepairable.len(), 1);
    assert_eq!(r.new_losses, 0);
}

#[test]
fn transferrers_are_not_repaired() {
    let lab = Lab::new();
    let (mut a, _) = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            StorageSpec::LocalDir {
                name: "stick".into(),
                path: lab.p("stick"),
                cold: false,
                carrier: true,
                place: String::new(),
            },
        ],
    );
    let stick = objects(&lab.p("stick"));
    assert!(!stick.is_empty(), "nobody else has the blocks yet");
    fs::write(&stick[0], b"scratched").unwrap();
    let f = a.fsck(true).unwrap();
    assert_eq!(f.objects_corrupt.len(), 1, "{f:?}");
    assert_eq!(f.repairs_queued, 0, "transferrers are not queued");
    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert!(r.repaired.is_empty(), "{r:?}");
    assert!(!intact(&stick[0]), "a transferrer is never written");
}

#[test]
fn moved_blocks_are_not_repaired_back() {
    let lab = Lab::new();
    let (mut a, _) = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            dir("spare", &lab.p("spare"), false),
        ],
    );
    let all = objects(&lab.p("box"));
    fs::remove_file(&all[0]).unwrap();
    // fsck queues the missing copy on "box"...
    assert_eq!(a.fsck(false).unwrap().repairs_queued, 1);
    // ...then the folder's data is moved off "box" on purpose.
    let moved = a
        .move_data(&varsto_core::placement::MoveRequest {
            folder: "docs".into(),
            from: "box".into(),
            to: "spare".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert!(moved.blocks_dropped > 0, "{moved:?}");
    assert!(objects(&lab.p("box")).is_empty());

    let r = a.repair(&RepairOptions::manual()).unwrap();
    assert!(r.repaired.is_empty(), "{r:?}");
    assert!(r.unrepairable.is_empty(), "{r:?}");
    assert!(r.not_needed >= 1, "{r:?}");
    assert!(objects(&lab.p("box")).is_empty(), "nothing written back");
    assert_eq!(a.repair_status().queued, 0);
}
