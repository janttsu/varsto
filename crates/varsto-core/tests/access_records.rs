// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Last-accessed times across devices (`access` records, kind 20 of storage
//! format 3): each device publishes the times it recorded as one record per
//! folder, replaced as a whole, and reads the other devices' newest ones;
//! the merged time of a file is the newest of them. The records are sealed
//! under the folder's keys: no path or time is readable on the storage.

mod common;

use std::fs;
use std::path::PathBuf;
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
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    Lab {
        _tmp: tmp,
        root,
        storage,
    }
}

fn access_records(lab: &Lab) -> Vec<PathBuf> {
    walkdir::WalkDir::new(lab.root.join("storage").join("access"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

#[test]
fn last_access_is_merged_across_devices() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    let a_dir = lab.root.join("a-project");
    a.add_folder("project", &a_dir).unwrap();
    fs::write(a_dir.join("plan.txt"), b"the plan").unwrap();
    a.sync(None).unwrap();

    // B keeps placeholders only: it never used plan.txt itself.
    let mut b = common::join_approved(
        &lab.root.join("b-home"),
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("project", &lab.root.join("b-project"), true)
        .unwrap();
    b.sync(None).unwrap();
    let used_on_a = a.list_files("project").unwrap()[0]
        .last_accessed_utc
        .unwrap();
    // A published its record with its first sync, B read it with its own.
    assert_eq!(a.exchange_access_records().unwrap().published, 0);
    let after = b.list_files("project").unwrap();
    assert_eq!(after[0].state, "placeholder");
    assert_eq!(after[0].last_accessed_utc, Some(used_on_a));
    // Nothing new: an exchange reads nothing.
    assert_eq!(b.exchange_access_records().unwrap().received, 0);
    // Sealed: no path in the clear on the storage.
    let records = access_records(&lab);
    assert_eq!(records.len(), 1);
    let raw = fs::read(&records[0]).unwrap();
    assert!(!raw.windows(8).any(|w| w == b"plan.txt"));

    // One record per device and folder: a new one replaces the old.
    a.read_file("project", "plan.txt").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    a.read_file("project", "plan.txt").unwrap();
    assert_eq!(a.exchange_access_records().unwrap().published, 1);
    assert_eq!(access_records(&lab).len(), 1);
    assert_eq!(b.exchange_access_records().unwrap().received, 1);
    assert!(
        b.list_files("project").unwrap()[0]
            .last_accessed_utc
            .unwrap()
            > used_on_a
    );
}
