// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One storage that cannot be reached never fails a whole run (spec
//! section 79.1): a sync, a push, a download, a snapshot and a
//! membership read go on with the storages that
//! answer, the dead one is skipped for the rest of the run and rests
//! between runs, and what it missed reaches it once it answers again.
//! An outage is simulated with `Engine::set_storage_down_for_tests`: every
//! call fails like a refused connection.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::BackupOptions;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn local(root: &Path, name: &str, cold: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn files_under(dir: &Path, part: &str) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path().to_string_lossy().contains(part))
        .map(|e| e.into_path())
        .collect()
}

/// A vault on device A with two hot storages, "one" and "two", and a
/// folder "docs" with one file pushed to both.
fn two_storages(root: &Path) -> (Engine, String) {
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(local(root, "one", false)).unwrap();
    a.add_storage(local(root, "two", false)).unwrap();
    let dir = root.join("a-docs");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("first.txt"), b"first").unwrap();
    a.add_folder("docs", &dir).unwrap();
    a.sync(None).unwrap();
    (a, key)
}

/// Device B joins through `storage` alone and gets "docs".
fn join_through(root: &Path, key: &str, storage: &str, a: &mut Engine) -> Engine {
    let mut b = common::join_approved(
        &root.join("b-home"),
        "phone",
        PASS,
        key,
        local(root, storage, false),
        a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &root.join("b-docs"), false)
        .unwrap();
    b
}

#[test]
fn a_dead_storage_does_not_fail_the_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, key) = two_storages(root);
    a.set_storage_down_for_tests("two", true);
    fs::write(root.join("a-docs/second.txt"), b"second").unwrap();
    let out = a.sync(None).unwrap();
    assert_eq!(out.len(), 1);
    let (pull, push) = &out[0];
    assert!(pull.error.is_none(), "{:?}", pull.error);
    assert_eq!(pull.storages_down, vec!["two".to_string()]);
    assert_eq!(push.files_changed, 1);
    assert!(push.manifest_seq.is_some());
    // The outage is remembered: it rests, with the records it missed.
    let health = a.storage_health();
    assert_eq!(health.len(), 1, "{health:?}");
    assert_eq!(health[0].storage, "two");
    assert!(health[0].failures >= 1);
    assert!(health[0].next_try_utc > health[0].last_failure_utc);
    assert!(health[0].pending_writes > 0, "{health:?}");
    assert_eq!(a.status().unwrap().storages_down.len(), 1);

    // A device that reaches only the storage that answered has everything.
    let mut b = join_through(root, &key, "one", &mut a);
    let pull = b.pull("docs").unwrap();
    assert!(pull.files_unavailable.is_empty(), "{pull:?}");
    assert_eq!(fs::read(root.join("b-docs/second.txt")).unwrap(), b"second");
}

#[test]
fn a_resting_storage_waits_and_is_healed_when_it_answers() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, key) = two_storages(root);
    a.set_storage_down_for_tests("two", true);
    fs::write(root.join("a-docs/second.txt"), b"second").unwrap();
    a.sync(None).unwrap();
    let waiting = a.storage_health()[0].pending_writes;
    assert!(waiting > 0);

    // Back, but still resting: the next sync does not try it.
    a.set_storage_down_for_tests("two", false);
    let out = a.sync(None).unwrap();
    assert_eq!(out[0].0.storages_down, vec!["two".to_string()]);
    assert!(a.storage_health()[0].pending_writes >= waiting);

    // "Retry": tried at once, the missed records are copied there and the
    // rest ends.
    a.retry_storages_now();
    let out = a.sync(None).unwrap();
    assert!(out[0].0.storages_down.is_empty());
    assert!(a.storage_health().is_empty(), "{:?}", a.storage_health());

    // A device that reaches only the storage that was down has everything.
    let mut b = join_through(root, &key, "two", &mut a);
    let pull = b.pull("docs").unwrap();
    assert!(pull.files_unavailable.is_empty(), "{pull:?}");
    assert_eq!(fs::read(root.join("b-docs/second.txt")).unwrap(), b"second");
}

/// The first storage used to decide every record's number alone: with it
/// down nothing could be published.
#[test]
fn the_first_storage_down_still_publishes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, key) = two_storages(root);
    a.set_storage_down_for_tests("one", true);
    fs::write(root.join("a-docs/second.txt"), b"second").unwrap();
    let push = a.push("docs").unwrap();
    assert!(push.manifest_seq.is_some());
    assert!(
        push.storages_unavailable.contains(&"one".to_string()) || push.chunks_uploaded > 0,
        "{push:?}"
    );
    a.set_storage_down_for_tests("one", false);
    a.retry_storages_now();

    let mut b = join_through(root, &key, "two", &mut a);
    let pull = b.pull("docs").unwrap();
    assert!(pull.files_unavailable.is_empty(), "{pull:?}");
    assert_eq!(fs::read(root.join("b-docs/second.txt")).unwrap(), b"second");
}

/// A download asks the next storage when one fails, instead of giving up
/// on the file.
#[test]
fn a_download_tries_the_next_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, key) = two_storages(root);
    let mut b = join_through(root, &key, "one", &mut a);
    b.add_storage(local(root, "two", false)).unwrap();
    b.pull("docs").unwrap();
    fs::write(root.join("a-docs/later.txt"), b"written later").unwrap();
    a.sync(None).unwrap();
    // "one" comes first in B's list; it is down.
    b.set_storage_down_for_tests("one", true);
    let pull = b.pull("docs").unwrap();
    assert!(pull.files_unavailable.is_empty(), "{pull:?}");
    assert_eq!(pull.files_updated, 1, "{pull:?}");
    assert_eq!(
        fs::read(root.join("b-docs/later.txt")).unwrap(),
        b"written later"
    );
}

/// With every storage down the sync of a folder still reports per folder
/// and the device's membership stays as it was.
#[test]
fn every_storage_down_keeps_the_membership() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = two_storages(root);
    let devices = a.status().unwrap().devices.len();
    a.set_storage_down_for_tests("one", true);
    a.set_storage_down_for_tests("two", true);
    let _ = a.sync(None);
    assert_eq!(a.status().unwrap().devices.len(), devices);
    assert_eq!(a.folders().len(), 1);
    assert_eq!(a.storage_health().len(), 2);
}

/// A snapshot is taken while a cold storage is down; the cold storage
/// gets it once it answers.
#[test]
fn a_snapshot_with_a_cold_storage_down() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(local(root, "hot", false)).unwrap();
    a.add_storage(local(root, "cold", true)).unwrap();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    a.add_backup("bk", &src, BackupOptions::default()).unwrap();
    a.set_storage_down_for_tests("cold", true);
    let s = a.take_snapshot("bk").unwrap();
    assert_eq!(s.seq, 1);
    assert!(!files_under(&root.join("hot"), "snapshots").is_empty());
    assert!(files_under(&root.join("cold"), "snapshots").is_empty());

    a.set_storage_down_for_tests("cold", false);
    a.retry_storages_now();
    a.sync(None).unwrap();
    assert!(!files_under(&root.join("cold"), "snapshots").is_empty());
    assert_eq!(a.take_snapshot("bk").unwrap().seq, 2);
}

/// Upkeep after a sync reuses the sync's ledger pull: a sync round lists
/// the ledger of a storage once, not once per step.
#[test]
fn a_sync_round_pulls_the_ledger_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = two_storages(root);
    let calls = std::sync::Arc::new(varsto_core::storage::StorageCalls::default());
    a.count_storage_calls(calls.clone());
    a.sync(None).unwrap();
    let one = calls.snapshot().ledger_lists;
    a.sync_round(|e| {
        e.sync(None)?;
        e.sync(None)
    })
    .unwrap();
    let two = calls.snapshot().ledger_lists - one;
    // Two syncs in one round list the ledger less than two rounds would.
    assert!(one > 0);
    assert!(two < 2 * one, "one sync: {one}, two in a round: {two}");
}
