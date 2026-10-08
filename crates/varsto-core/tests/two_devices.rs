// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Two devices that are never online at the same time converge through one
//! shared storage. This is the first scenario of plan section 6.19 and of
//! section 8's blocking question on offline convergence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
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

struct Lab {
    _tmp: tempfile::TempDir,
    storage: StorageSpec,
    a_home: PathBuf,
    b_home: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
        },
        a_home: root.join("a-home"),
        b_home: root.join("b-home"),
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        _tmp: tmp,
    }
}

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

#[test]
fn devices_never_online_together_converge() {
    let lab = lab();
    // Device A creates the vault, a storage and a folder with files, then pushes.
    let (mut a, vault_key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::create_dir_all(lab.a_dir.join("sub")).unwrap();
    fs::write(lab.a_dir.join("hello.txt"), b"hello from a").unwrap();
    fs::write(lab.a_dir.join("sub/big.bin"), pseudo_random(150_000, 3)).unwrap();
    fs::write(lab.a_dir.join("copy.bin"), pseudo_random(150_000, 3)).unwrap(); // duplicate content
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    assert!(push.chunks_uploaded > 1);
    assert_eq!(push.manifest_seq, Some(1));
    drop(a); // A goes offline.

    // Device B joins later through the storage only.
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &vault_key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let folders = b.folders();
    assert_eq!(
        folders.len(),
        1,
        "folder record must arrive through the storage"
    );
    b.attach_folder("docs", &lab.b_dir).unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 3);
    assert_eq!(pull.conflicts, 0);
    assert!(pull.files_unavailable.is_empty());
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // Duplicate content was uploaded once: both files share every chunk.
    let dupes = b.dupes("docs").unwrap();
    assert_eq!(dupes.len(), 1);
    assert_eq!(
        dupes[0].paths,
        vec!["copy.bin".to_string(), "sub/big.bin".to_string()]
    );

    // B edits, deletes and adds, then pushes; B's pull verified A's chunks.
    fs::write(lab.b_dir.join("hello.txt"), b"hello from b").unwrap();
    fs::remove_file(lab.b_dir.join("copy.bin")).unwrap();
    fs::write(lab.b_dir.join("new.txt"), b"new on b").unwrap();
    let push = b.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    let status = b.status().unwrap();
    let docs = &status.folders[0];
    assert_eq!(docs.files, 3);
    assert_eq!(docs.chunks_without_storage_copy, 0);
    assert!(
        docs.chunks_verified_elsewhere > 0,
        "B verified A's chunks when it fetched them"
    );
    assert_eq!(status.devices.len(), 2);
    drop(b);

    // A comes back alone and pulls.
    let mut a = open(&lab.a_home);
    let pull = a.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 2);
    assert_eq!(pull.files_deleted, 1);
    assert_eq!(pull.conflicts, 0);
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(
        fs::read(lab.a_dir.join("hello.txt")).unwrap(),
        b"hello from b"
    );
    // The deleted file went to the trash, not into the void (F-025).
    let trash = walkdir::WalkDir::new(lab.a_home.join("trash"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(trash, 1);

    // fsck: every referenced chunk has a storage copy and verified status.
    let fsck = a.fsck(true).unwrap();
    assert!(fsck.chunks_missing.is_empty());
    assert!(fsck.objects_corrupt.is_empty());
    assert_eq!(fsck.claims_without_object, 0);
    assert!(fsck.forked_devices.is_empty());
    assert_eq!(fsck.chunks_referenced, fsck.chunks_with_storage_copy);
    let status = a.status().unwrap();
    assert!(status.forked_devices.is_empty());
    assert!(status.ledger_batches >= 4);
}

#[test]
fn concurrent_edits_keep_both_versions() {
    let lab = lab();
    let (mut a, vault_key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("report.txt"), b"v1").unwrap();
    a.push("docs").unwrap();
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &vault_key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir).unwrap();
    b.pull("docs").unwrap();

    // Both edit offline.
    fs::write(lab.a_dir.join("report.txt"), b"edited on A").unwrap();
    fs::write(lab.b_dir.join("report.txt"), b"edited on B").unwrap();
    a.push("docs").unwrap();
    b.push("docs").unwrap();

    // Each pulls the other's manifest; both end with the same two files.
    let pa = a.pull("docs").unwrap();
    let pb = b.pull("docs").unwrap();
    assert_eq!(pa.conflicts, 1);
    assert_eq!(pb.conflicts, 1);
    a.push("docs").unwrap();
    b.push("docs").unwrap();
    a.pull("docs").unwrap();
    b.pull("docs").unwrap();
    let ta = tree(&lab.a_dir);
    let tb = tree(&lab.b_dir);
    assert_eq!(
        ta, tb,
        "both devices must hold the same files after a conflict"
    );
    assert_eq!(
        ta.len(),
        2,
        "winner plus one conflict copy: {:?}",
        ta.keys().collect::<Vec<_>>()
    );
    let mut contents: Vec<&[u8]> = ta.values().map(|v| v.as_slice()).collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![b"edited on A".as_slice(), b"edited on B".as_slice()]
    );
    assert!(ta.keys().any(|k| k.contains(".conflict-")));
}

#[test]
fn restored_device_is_fenced() {
    let lab = lab();
    let (mut a, _key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("one.txt"), b"one").unwrap();
    a.push("docs").unwrap();
    // Snapshot A's home (like a backup), then keep working.
    let snapshot = lab.a_home.with_file_name("a-home-backup");
    copy_dir(&lab.a_home, &snapshot);
    fs::write(lab.a_dir.join("two.txt"), b"two").unwrap();
    a.push("docs").unwrap();
    drop(a);
    // Restore the backup and try to continue: the mailbox already holds newer
    // batches of this device, so the restored copy must refuse to sign more.
    fs::remove_dir_all(&lab.a_home).unwrap();
    copy_dir(&snapshot, &lab.a_home);
    let mut restored = open(&lab.a_home);
    fs::write(lab.a_dir.join("three.txt"), b"three").unwrap();
    let pull = restored.pull("docs");
    let fenced = match pull {
        Ok(r) => !r.forked_devices.is_empty(),
        Err(_) => true,
    };
    assert!(fenced, "a restored device must be detected as forked");
    assert!(
        restored.push("docs").is_err(),
        "a forked device must not append to its ledger"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    for e in walkdir::WalkDir::new(from)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = e.path().strip_prefix(from).unwrap();
        let dest = to.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&dest).unwrap();
        } else {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::copy(e.path(), &dest).unwrap();
        }
    }
}
