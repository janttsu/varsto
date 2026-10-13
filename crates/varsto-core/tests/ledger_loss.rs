// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Losing ledger copies: a storage that lost its ledger objects (S1), a
//! device whose local `ledger/` directory was deleted or damaged (S2), a
//! device restored from an old backup (S3), the ledger lost everywhere
//! (S4) and a damaged cached view (S5). These tests record how the engine
//! behaved before ledger recovery existed.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
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

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

/// A with a folder of two files synced to the storage, B joined and synced.
fn two_devices(lab: &Lab) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&lab.root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.root.join("a-docs")).unwrap();
    fs::write(lab.root.join("a-docs/one.txt"), b"first file").unwrap();
    fs::write(lab.root.join("a-docs/two.bin"), vec![7u8; 50_000]).unwrap();
    a.sync(None).unwrap();
    let mut b = Engine::join(&lab.root.join("b"), "phone", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.root.join("b-docs"), false)
        .unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    (a, b)
}

/// S2 before recovery: with the local `ledger/` directory gone, the next
/// action that signs reuses sequence number 1 and the device is stuck.
#[test]
fn before_recovery_lost_local_ledger_signs_a_fork() {
    let lab = lab();
    let (a, b) = two_devices(&lab);
    let home = a.home().to_path_buf();
    drop((a, b));
    fs::remove_dir_all(home.join("ledger")).unwrap();
    let mut a = open(&home);
    let r = a.add_folder("more", &lab.root.join("a-more"));
    assert!(r.is_err(), "signing after the loss collides with the storage");
    let msg = format!("{:#}", r.unwrap_err());
    assert!(msg.contains("fork"), "{msg}");
}

/// S2 before recovery: a damaged heads file stops the device from opening.
#[test]
fn before_recovery_damaged_heads_file_stops_opening() {
    let lab = lab();
    let (a, b) = two_devices(&lab);
    let home = a.home().to_path_buf();
    drop((a, b));
    fs::write(home.join("ledger/heads.json"), b"{ not json").unwrap();
    assert!(Engine::open(&home, PASS).is_err());
}

/// S3 before recovery: a device restored from an old backup fences itself
/// and cannot sync until it is paired again.
#[test]
fn before_recovery_restored_device_is_fenced() {
    let lab = lab();
    let (mut a, b) = two_devices(&lab);
    let home = a.home().to_path_buf();
    let backup = lab.root.join("a-backup");
    copy_tree(&home, &backup);
    fs::write(lab.root.join("a-docs/three.txt"), b"third").unwrap();
    a.sync(None).unwrap();
    drop((a, b));
    fs::remove_dir_all(&home).unwrap();
    copy_tree(&backup, &home);
    let mut a = open(&home);
    fs::write(lab.root.join("a-docs/four.txt"), b"fourth").unwrap();
    assert!(a.sync(None).is_err());
}

/// S5: a damaged cached view is rebuilt from the batches.
#[test]
fn damaged_view_cache_is_rebuilt() {
    let lab = lab();
    let (a, b) = two_devices(&lab);
    let home = a.home().to_path_buf();
    let before = a.view().unwrap();
    drop((a, b));
    fs::write(home.join("ledger/view.enc"), b"garbage").unwrap();
    let a = open(&home);
    assert_eq!(a.view().unwrap(), before);
}

fn copy_tree(from: &Path, to: &Path) {
    for e in walkdir::WalkDir::new(from)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = e.path().strip_prefix(from).unwrap();
        let dst = to.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&dst).unwrap();
        } else {
            fs::copy(e.path(), &dst).unwrap();
        }
    }
}
