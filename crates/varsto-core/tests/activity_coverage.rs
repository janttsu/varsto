// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Long operations started from the interface show up as activity tasks
//! (and so in the progress bar at the top): fetching one large file, and
//! deleting a removed folder's data. Each is slowed down by the test hook
//! so that it outlives the quiet period, and a watcher thread records what
//! `activity::tasks` lists meanwhile.

mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use varsto_core::activity::{self, TaskView};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn pseudo_random(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

/// Run `op` slowed down while a thread collects the tasks listed.
fn watch<T>(op: impl FnOnce() -> T) -> (T, Vec<TaskView>) {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        while !s2.load(Ordering::Relaxed) {
            seen.extend(activity::tasks());
            std::thread::sleep(Duration::from_millis(100));
        }
        seen
    });
    activity::set_test_delay_ms(12);
    let out = op();
    activity::set_test_delay_ms(0);
    stop.store(true, Ordering::Relaxed);
    (out, watcher.join().unwrap())
}

#[test]
#[ignore = "f3-switch: port in part B (membership)"]
// Waits for remove_folder with purge in format 3.
fn fetching_a_file_and_purging_a_folder_are_tasks() {
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
    let (mut a, key) = Engine::init(&root.join("a"), "a", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let docs = root.join("docs-a");
    fs::create_dir_all(&docs).unwrap();
    let big = pseudo_random(1 << 20, 7);
    fs::write(docs.join("big.bin"), &big).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();

    let mut b = common::join_approved(&root.join("b"), "b", PASS, &key, storage, &mut a);
    b.attach_folder("docs", &root.join("docs-b"), true).unwrap();
    b.sync(Some("docs")).unwrap();
    assert!(!root.join("docs-b/big.bin").exists(), "a placeholder first");

    let (r, seen) = watch(|| b.fetch_file("docs", "big.bin"));
    r.unwrap();
    assert_eq!(fs::read(root.join("docs-b/big.bin")).unwrap(), big);
    let fetch: Vec<&TaskView> = seen
        .iter()
        .filter(|t| t.kind == "download" && t.phase == "file" && t.subject == "docs")
        .collect();
    assert!(!fetch.is_empty(), "no fetch task among {seen:?}");
    assert!(fetch.iter().all(|t| t.total == big.len() as u64));
    assert!(
        fetch.iter().any(|t| t.done > 0 && t.percent.is_some()),
        "{fetch:?}"
    );

    let (r, seen) = watch(|| a.remove_folder("docs", true));
    assert!(r.unwrap() > 100);
    let purge: Vec<&TaskView> = seen.iter().filter(|t| t.kind == "folder_purge").collect();
    assert!(!purge.is_empty(), "no purge task among {seen:?}");
    assert!(purge.iter().any(|t| t.total > 0 && t.done > 0), "{purge:?}");
    assert!(activity::tasks().is_empty(), "nothing is left");
}
