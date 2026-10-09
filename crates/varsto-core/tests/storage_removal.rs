// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Removing a storage: blocks keep enough copies elsewhere (copied first when
//! needed), the retirement is in the ledger, and the last storage stays.

use std::fs;
use std::path::Path;
use varsto_core::policy::Policy;
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

fn objects(path: &Path) -> usize {
    walkdir::WalkDir::new(path.join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
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
fn storages_are_removed_only_with_enough_copies_elsewhere() {
    let t = tempfile::tempdir().unwrap();
    let (s1, s2, s3, files) = (
        t.path().join("s1"),
        t.path().join("s2"),
        t.path().join("s3"),
        t.path().join("files"),
    );
    for d in [&s1, &s2, &s3, &files] {
        fs::create_dir_all(d).unwrap();
    }
    let (mut a, _) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("one", &s1)).unwrap();
    // The last storage never goes.
    let plan = a.plan_storage_removal("one").unwrap();
    assert!(plan.blocked.unwrap().contains("last storage"));
    assert!(a.remove_storage("one", false).is_err());

    a.add_storage(dir("two", &s2)).unwrap();
    a.add_folder("docs", &files).unwrap();
    fs::write(files.join("a.txt"), b"alpha").unwrap();
    fs::write(files.join("b.txt"), vec![7u8; 50_000]).unwrap();
    a.sync(None).unwrap();
    let blocks = on_storage(&a, "one");
    assert!(blocks > 0);
    assert_eq!(on_storage(&a, "two"), blocks);

    // Two copies required: with "one" gone only "two" holds the blocks, so a
    // third storage must receive them before "one" may go.
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 2,
            ..Default::default()
        }),
    )
    .unwrap();
    a.add_storage(dir("three", &s3)).unwrap();
    assert_eq!(objects(&s3), 0);
    let plan = a.plan_storage_removal("one").unwrap();
    assert!(plan.blocked.is_none(), "{:?}", plan.blocked);
    assert_eq!(plan.blocks as usize, blocks);
    assert_eq!(plan.copies.len(), blocks);
    assert_eq!(plan.targets, vec!["three".to_string()]);

    let r = a.remove_storage("one", true).unwrap();
    assert_eq!(r.blocks_copied as usize, blocks);
    assert_eq!(objects(&s3), blocks);
    assert_eq!(objects(&s1), 0, "data deleted on request");
    assert!(a.storages().iter().all(|s| s.name() != "one"));
    // Retired: no device counts it as a copy any more.
    assert_eq!(on_storage(&a, "one"), 0);
    assert_eq!(on_storage(&a, "three"), blocks);

    // Now only two storages remain and the policy needs both.
    let plan = a.plan_storage_removal("two").unwrap();
    assert!(plan.blocked.unwrap().contains("needs 2 copies"));

    // Without a policy, one copy elsewhere is enough: nothing to copy.
    a.set_policy("docs", None).unwrap();
    let plan = a.plan_storage_removal("two").unwrap();
    assert!(plan.blocked.is_none());
    assert!(plan.copies.is_empty());
    assert_eq!(plan.blocks_ok as usize, blocks);
    a.remove_storage("two", false).unwrap();
    assert_eq!(objects(&s2), blocks, "data kept unless asked");
    // A sync afterwards still works with the remaining storage.
    fs::write(files.join("c.txt"), b"gamma").unwrap();
    a.sync(None).unwrap();
    assert_eq!(on_storage(&a, "two"), 0);
}
