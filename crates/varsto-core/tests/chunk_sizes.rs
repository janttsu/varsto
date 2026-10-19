// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Block sizes follow the file size: a big file is cut into larger blocks,
//! and the same blocks come out again when a storage added later needs
//! copies of them.

mod common;

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
        min_free: None,
    }
}

/// The blocks a storage directory holds.
fn on_storage(root: &Path) -> usize {
    common::object_count(root)
}

/// The sizes of the blocks (stored bytes) of one folder's packs in a
/// storage directory, ascending.
fn block_sizes(e: &Engine, root: &Path, folder: &varsto_core::ids::FolderId) -> Vec<u64> {
    let view = e.ledger_view().unwrap();
    let fb: [u8; 16] = hex::decode(folder.as_str()).unwrap().try_into().unwrap();
    let mut out = Vec::new();
    for (_, id) in common::pack_files(root) {
        let pack: [u8; 32] = hex::decode(&id).unwrap().try_into().unwrap();
        if view.pack_folder(&pack) == Some(fb) {
            out.extend(
                varsto_core::packs::debug_registry::members_on(root, &id)
                    .into_iter()
                    .map(|(_, loc)| loc.len),
            );
        }
    }
    out.sort();
    out
}

#[test]
fn size_tiers() {
    let seed = [1; 32];
    assert!(ChunkerParams::for_size(10 << 20, &seed).same_sizes(&ChunkerParams::DEFAULT));
    assert!(ChunkerParams::for_size(32 << 20, &seed).same_sizes(&ChunkerParams::MEDIUM));
    assert!(ChunkerParams::for_size(50 << 30, &seed).same_sizes(&ChunkerParams::LARGE));
    assert!(ChunkerParams::for_size(100 << 10, &seed).same_sizes(&ChunkerParams::ONE_BLOCK));
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
    // 40 MiB: blocks of about 4 MiB (1 to 16 MiB), and the small note one.
    let blocks = on_storage(&s1);
    assert!((4..=40).contains(&blocks), "{blocks} blocks");

    // A storage added later gets every block, cut again from the file.
    a.add_storage(dir("two", &s2)).unwrap();
    a.sync(None).unwrap();
    assert_eq!(on_storage(&s2), blocks);
}

#[test]
fn the_same_file_is_cut_differently_in_two_folders() {
    let t = tempfile::tempdir().unwrap();
    let (s1, f1, f2) = (
        t.path().join("s1"),
        t.path().join("f1"),
        t.path().join("f2"),
    );
    for d in [&s1, &f1, &f2] {
        fs::create_dir_all(d).unwrap();
    }
    let (mut a, _) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("one", &s1)).unwrap();
    let mut data = vec![0u8; 10 << 20];
    rand::thread_rng().fill_bytes(&mut data);
    fs::write(f1.join("same.bin"), &data).unwrap();
    fs::write(f2.join("same.bin"), &data).unwrap();
    let first = a.add_folder("first", &f1).unwrap();
    let second = a.add_folder("second", &f2).unwrap();
    a.sync(None).unwrap();
    let sizes = |e: &Engine, folder: &varsto_core::ids::FolderId| block_sizes(e, &s1, folder);
    let (one, two) = (sizes(&a, &first), sizes(&a, &second));
    assert!(one.len() >= 3 && two.len() >= 3, "{one:?} {two:?}");
    // Keyed Gear tables: other cut points, so other block sizes.
    assert_ne!(one, two);
    // A copy in the same folder is cut the same way: no new blocks.
    fs::write(f1.join("copy.bin"), &data).unwrap();
    a.sync(None).unwrap();
    assert_eq!(sizes(&a, &first).len(), one.len());
}
