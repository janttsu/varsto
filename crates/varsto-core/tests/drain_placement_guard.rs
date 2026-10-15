// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A storage a folder is still written to cannot be drained, and a storage
//! being drained cannot become a folder's placement: both orders are refused.

use std::fs;
use std::path::Path;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::DrainOptions;
use varsto_core::placement::Placement;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path, place: &str) -> StorageSpec {
    fs::create_dir_all(path).unwrap();
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: place.into(),
        min_free: None,
    }
}

fn setup(t: &Path) -> Engine {
    let (mut e, _) = Engine::init(&t.join("a"), "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    for (n, p) in [("home", "home"), ("s3-a", "cloud"), ("s3-b", "cloud")] {
        e.add_storage(dir(n, &t.join(n), p)).unwrap();
    }
    let files = t.join("files");
    fs::create_dir_all(&files).unwrap();
    e.add_folder("camera", &files).unwrap();
    fs::write(files.join("one.bin"), vec![3u8; 30_000]).unwrap();
    e.sync(None).unwrap();
    e
}

fn only(name: &str) -> Placement {
    Placement {
        storages: vec![name.into()],
        ..Default::default()
    }
}

#[test]
fn a_storage_named_by_a_placement_cannot_be_drained() {
    let t = tempfile::tempdir().unwrap();
    let mut e = setup(t.path());
    e.set_placement("camera", Some(only("s3-a"))).unwrap();
    let err = e
        .drain_start("s3-a", &DrainOptions::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("camera") && err.contains("placement"), "{err}");
    // Once the folder is placed elsewhere the drain may start.
    e.set_placement("camera", Some(only("s3-b"))).unwrap();
    e.drain_start("s3-a", &DrainOptions::default()).unwrap();
}

#[test]
fn a_draining_storage_cannot_become_a_placement() {
    let t = tempfile::tempdir().unwrap();
    let mut e = setup(t.path());
    e.drain_start("s3-a", &DrainOptions::default()).unwrap();
    let err = e
        .set_placement("camera", Some(only("s3-a")))
        .unwrap_err()
        .to_string();
    assert!(err.contains("drained"), "{err}");
    e.set_placement("camera", Some(only("s3-b"))).unwrap();
}
