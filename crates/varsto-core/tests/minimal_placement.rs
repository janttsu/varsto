// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The default placement writes the fewest storages that keep the folder's
//! policy: one external storage for the default policy, two when the policy
//! asks for two; an explicit placement is left alone.

mod common;

use std::fs;
use std::path::Path;
use varsto_core::chunking::ChunkerParams;
use varsto_core::placement::Placement;
use varsto_core::policy::Policy;
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
    let (mut e, _) = Engine::init(&t.join("a"), "phone", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(dir("home", &t.join("home"), "home")).unwrap();
    e.add_storage(dir("s3-a", &t.join("s3a"), "cloud")).unwrap();
    e.add_storage(dir("s3-b", &t.join("s3b"), "cloud")).unwrap();
    let files = t.join("files");
    fs::create_dir_all(&files).unwrap();
    e.add_folder("camera", &files).unwrap();
    fs::write(files.join("one.bin"), vec![7u8; 50_000]).unwrap();
    e
}

#[test]
fn the_default_policy_writes_one_external_storage_and_the_home_copy() {
    let t = tempfile::tempdir().unwrap();
    let mut e = setup(t.path());
    e.sync(None).unwrap();
    let (a, b) = (
        common::object_count(&t.path().join("s3a")),
        common::object_count(&t.path().join("s3b")),
    );
    assert!(common::object_count(&t.path().join("home")) > 0);
    assert!(
        (a > 0) != (b > 0),
        "exactly one of the two S3 storages gets the blocks: {a} / {b}"
    );
    let info = e.placement("camera").unwrap();
    assert_eq!(info.targets.len(), 2, "{:?}", info.targets);
}

#[test]
fn a_policy_with_two_external_copies_writes_both() {
    let t = tempfile::tempdir().unwrap();
    let mut e = setup(t.path());
    e.set_policy(
        "camera",
        Some(Policy {
            min_copies: 3,
            min_per_place: [("cloud".to_string(), 2), ("home".to_string(), 1)]
                .into_iter()
                .collect(),
            verified_within_days: None,
        }),
    )
    .unwrap();
    e.sync(None).unwrap();
    assert!(common::object_count(&t.path().join("s3a")) > 0);
    assert!(common::object_count(&t.path().join("s3b")) > 0);
}

#[test]
fn an_explicit_placement_is_kept() {
    let t = tempfile::tempdir().unwrap();
    let mut e = setup(t.path());
    e.set_placement(
        "camera",
        Some(Placement {
            storages: vec!["s3-a".into(), "s3-b".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    e.sync(None).unwrap();
    assert!(common::object_count(&t.path().join("s3a")) > 0);
    assert!(common::object_count(&t.path().join("s3b")) > 0);
    assert_eq!(common::object_count(&t.path().join("home")), 0);
}
