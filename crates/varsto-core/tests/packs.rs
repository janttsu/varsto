// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Format 2 stores every block in a pack: a storage sees pack sizes only,
//! never a block of its own, and the same file pushed to two folders is
//! cut and packed differently. Packs that are mostly dead are rewritten,
//! and another device still finds every block.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
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

fn random(len: usize, seed: u64) -> Vec<u8> {
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

/// Every file under `root`, relative path, except the storage's packs.
fn files(root: &Path) -> BTreeSet<String> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            e.path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn the_same_file_in_two_folders_gives_other_packs_and_no_block_objects() {
    let t = tempfile::tempdir().unwrap();
    let (store, f1, f2) = (t.path().join("s"), t.path().join("f1"), t.path().join("f2"));
    for d in [&f1, &f2] {
        fs::create_dir_all(d).unwrap();
    }
    let (mut a, _) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("box", &store)).unwrap();
    let data = random(10 << 20, 7);
    fs::write(f1.join("same.bin"), &data).unwrap();
    fs::write(f2.join("same.bin"), &data).unwrap();
    let first = a.add_folder("first", &f1).unwrap();
    a.sync(None).unwrap();
    let after_first: BTreeSet<String> = common::pack_files(&store)
        .into_iter()
        .map(|(_, id)| id)
        .collect();
    let second = a.add_folder("second", &f2).unwrap();
    a.sync(None).unwrap();
    // No block is an object of its own: only packs, records and indexes.
    let all = files(&store);
    assert!(all.iter().all(|f| !f.starts_with("chunks/")), "{all:?}");
    assert!(all.iter().any(|f| f.starts_with("packs/index/")), "{all:?}");
    // Each folder's push wrote its own packs, laid out differently.
    let packs = common::pack_files(&store);
    let new: Vec<String> = packs
        .iter()
        .map(|(_, id)| id.clone())
        .filter(|id| !after_first.contains(id))
        .collect();
    assert!(!after_first.is_empty() && !new.is_empty());
    let layout = |ids: &mut dyn Iterator<Item = &String>| -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = ids
            .flat_map(|id| varsto_core::packs::debug_registry::members_on(&store, id))
            .map(|(_, l)| (l.offset, l.len))
            .collect();
        v.sort();
        v
    };
    let one = layout(&mut after_first.iter());
    let two = layout(&mut new.iter());
    assert!(one.len() >= 3 && two.len() >= 3, "{one:?} {two:?}");
    assert_ne!(one, two);
    // Every block of both folders is in a pack the ledger places.
    let view = a.view().unwrap();
    for ((folder, _), rec) in &view.chunks {
        if *folder == first || *folder == second {
            let loc = rec.storages.get("box").expect("a copy on the storage");
            assert!(loc.pack.is_some(), "no pack place for {}", rec.object);
        }
    }
}

#[test]
fn a_mostly_dead_pack_is_rewritten_and_every_device_still_reads() {
    let t = tempfile::tempdir().unwrap();
    let (store, a_dir, b_dir) = (
        t.path().join("s"),
        t.path().join("a-docs"),
        t.path().join("b-docs"),
    );
    let (mut a, key) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("box", &store)).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    for i in 0..6u64 {
        // Distinct seeds (`random` sets the low bit): six different files.
        fs::write(
            a_dir.join(format!("f{i}.bin")),
            random(200_000, 100 + 2 * i),
        )
        .unwrap();
    }
    a.sync(None).unwrap();
    let before = common::pack_files(&store);
    assert_eq!(before.len(), 1, "one push, one pack: {before:?}");
    let before_len = fs::metadata(&before[0].0).unwrap().len();
    // Five of six files go for good: their blocks die in the pack.
    for i in 1..6u64 {
        fs::remove_file(a_dir.join(format!("f{i}.bin"))).unwrap();
    }
    a.sync(None).unwrap();
    let purged = a.trash_purge(None, &[], true).unwrap();
    assert!(purged.blocks_dropped >= 5, "{purged:?}");
    // The dead blocks are listed in an encrypted tombstone list.
    assert!(files(&store)
        .iter()
        .any(|f| f.starts_with("packs/tombstones/")));
    let r = a.pack_upkeep().unwrap();
    assert_eq!(r.blocks_moved, 1, "{r:?}");
    let after = common::pack_files(&store);
    assert_eq!(after.len(), 1);
    assert_ne!(after[0].1, before[0].1, "the old pack went");
    assert!(fs::metadata(&after[0].0).unwrap().len() * 4 < before_len);
    // A device that joins now reads the moved block from the new pack.
    let mut b = Engine::join(&t.path().join("b"), "phone", PASS, &key, dir("box", &store)).unwrap();
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(b_dir.join("f0.bin")).unwrap(),
        random(200_000, 100)
    );
    // Nothing more to rewrite.
    assert_eq!(a.pack_upkeep().unwrap().blocks_moved, 0);
}
