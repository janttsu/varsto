// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Block sizes follow the file size: a big file is cut into larger blocks,
//! and the same blocks come out again when a storage added later needs
//! copies of them.

use rand::RngCore;
use std::fs;
use std::path::Path;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
    }
}

fn on_storage(e: &Engine, storage: &str) -> usize {
    e.view()
        .unwrap()
        .chunks
        .values()
        .filter(|c| c.storages.contains_key(storage))
        .count()
}

#[test]
fn size_tiers() {
    assert_eq!(ChunkerParams::for_size(10 << 20), ChunkerParams::DEFAULT);
    assert_eq!(ChunkerParams::for_size(32 << 20), ChunkerParams::MEDIUM);
    assert_eq!(ChunkerParams::for_size(50 << 30), ChunkerParams::LARGE);
}

#[test]
fn big_files_get_big_blocks_and_are_cut_again_the_same_way() {
    let t = tempfile::tempdir().unwrap();
    let (s1, s2, files) = (
        t.path().join("s1"),
        t.path().join("s2"),
        t.path().join("files"),
    );
    for d in [&s1, &s2, &files] {
        fs::create_dir_all(d).unwrap();
    }
    let (mut a, _) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("one", &s1)).unwrap();
    a.add_folder("media", &files).unwrap();
    let mut big = vec![0u8; 40 << 20];
    rand::thread_rng().fill_bytes(&mut big);
    fs::write(files.join("video.bin"), &big).unwrap();
    fs::write(files.join("note.txt"), b"small").unwrap();
    a.sync(None).unwrap();
    // 40 MiB: blocks of about 1 MiB (the default sizes would give ~160).
    let blocks = on_storage(&a, "one");
    assert!((15..=80).contains(&blocks), "{blocks} blocks");

    // A storage added later gets every block, cut again from the file.
    a.add_storage(dir("two", &s2)).unwrap();
    a.sync(None).unwrap();
    assert_eq!(on_storage(&a, "two"), blocks);
}
