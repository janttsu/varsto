// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Two devices that create a folder under one name while they cannot see
//! each other's records end up with two folders of that name, with
//! different ids. Every device shows the older one under the name and the
//! newer one numbered ("Photos (2)"), the same on every device; each
//! device keeps syncing its own directory.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

/// Folder id -> (name shown, directory on this device).
fn folders(e: &Engine) -> BTreeMap<String, (String, Option<PathBuf>)> {
    e.folders()
        .into_iter()
        .map(|(r, p)| (r.folder_id.as_str().to_string(), (r.name.clone(), p)))
        .collect()
}

fn status_names(e: &Engine) -> BTreeMap<String, String> {
    e.status()
        .unwrap()
        .folders
        .into_iter()
        .map(|f| (f.folder_id, f.name))
        .collect()
}

fn canonical(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap()
}

#[test]
fn a_folder_made_twice_under_one_name_while_apart_is_numbered_on_every_device() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hub = root.join("hub");
    let spec = StorageSpec::LocalDir {
        name: "hub".into(),
        path: hub.clone(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(spec.clone()).unwrap();
    let mut b = common::join_approved(&root.join("b-home"), "desk", PASS, &key, spec, &mut a);
    b.chunker = ChunkerParams::SMALL;

    // The laptop makes "Photos".
    let a_dir = root.join("a-photos");
    let a_id = a.add_folder("Photos", &a_dir).unwrap();
    fs::write(a_dir.join("beach.jpg"), b"laptop picture").unwrap();
    a.sync(None).unwrap();

    // The desk cannot see the laptop's folder records (as if offline) and
    // makes a "Photos" of its own, a second later.
    let records = hub.join("vault").join("folders").join(a_id.as_str());
    let aside = root.join("aside");
    fs::rename(&records, &aside).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let b_dir = root.join("b-photos");
    let b_id = b.add_folder("Photos", &b_dir).unwrap();
    fs::write(b_dir.join("forest.jpg"), b"desk picture").unwrap();
    b.sync(None).unwrap();
    assert_ne!(a_id, b_id);

    // Both records are there again: every device reads both folders.
    fs::rename(&aside, &records).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    a.refresh_devices().unwrap();

    let expected = BTreeMap::from([
        (a_id.as_str().to_string(), "Photos".to_string()),
        (b_id.as_str().to_string(), "Photos (2)".to_string()),
    ]);
    for e in [&a, &b] {
        let names: BTreeMap<String, String> = folders(e)
            .into_iter()
            .map(|(id, (name, _))| (id, name))
            .collect();
        assert_eq!(names, expected, "{}", e.own_device_name());
    }
    // Each device keeps its own directory, and its status shows the name.
    assert_eq!(
        folders(&a)[a_id.as_str()].1.as_deref(),
        Some(canonical(&a_dir).as_path())
    );
    assert_eq!(folders(&a)[b_id.as_str()].1, None);
    assert_eq!(
        folders(&b)[b_id.as_str()].1.as_deref(),
        Some(canonical(&b_dir).as_path())
    );
    assert_eq!(status_names(&b)[b_id.as_str()], "Photos (2)");
    assert_eq!(status_names(&a)[a_id.as_str()], "Photos");

    // The numbered folder is found under its new name and keeps syncing.
    fs::write(b_dir.join("lake.jpg"), b"another one").unwrap();
    let r = b.push("Photos (2)").unwrap();
    assert!(r.files_changed >= 1, "{r:?}");
    let r = a.pull("Photos").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(
        fs::read(a_dir.join("beach.jpg")).unwrap(),
        b"laptop picture"
    );
    assert!(!a_dir.join("lake.jpg").exists(), "the folders stay apart");
    // A third folder cannot take either name.
    assert!(a.add_folder("photos (2)", &root.join("third")).is_err());
}
