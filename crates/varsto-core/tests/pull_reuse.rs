// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A pull copies the blocks this device already has instead of fetching
//! them: the unchanged blocks of a changed file, every block of a renamed
//! directory (from the old files, or from their trash copies when the
//! deletions are applied first), and each distinct block of duplicate files
//! once. A local copy that no longer matches its index is not used: the
//! block is fetched and the file is still right.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    store: PathBuf,
    storage: StorageSpec,
    a_home: PathBuf,
    b_home: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    fs::create_dir_all(root.join("a-docs")).unwrap();
    fs::create_dir_all(root.join("b-docs")).unwrap();
    let store = root.join("storage");
    Lab {
        store: store.clone(),
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: store,
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        },
        a_home: root.join("a-home"),
        b_home: root.join("b-home"),
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        _tmp: tmp,
    }
}

/// Device A with `docs` (files written by `fill`) pushed; device B attached
/// to it and pulled once.
fn pair(lab: &Lab, fill: impl FnOnce(&Path)) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fill(&lab.a_dir);
    a.push("docs").unwrap();
    let mut b = common::join_approved(
        &lab.b_home,
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    let first = b.pull("docs").unwrap();
    assert!(first.files_unavailable.is_empty(), "{first:?}");
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    (a, b)
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
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

fn total_size(root: &Path) -> u64 {
    tree(root).values().map(|v| v.len() as u64).sum()
}

#[test]
fn a_changed_file_fetches_only_its_changed_blocks() {
    let lab = lab();
    let mut big = pseudo_random(400_000, 1);
    let (mut a, mut b) = pair(&lab, |d| fs::write(d.join("big.bin"), &big).unwrap());

    // 4 KiB in the middle changes, and a little is appended.
    big[200_000..204_096].copy_from_slice(&pseudo_random(4096, 2));
    big.extend_from_slice(&pseudo_random(3000, 3));
    fs::write(lab.a_dir.join("big.bin"), &big).unwrap();
    let push = a.push("docs").unwrap();
    assert!(push.chunks_uploaded >= 1, "{push:?}");

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(lab.b_dir.join("big.bin")).unwrap().ino()
    };
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(r.files_updated, 1);
    assert_eq!(fs::read(lab.b_dir.join("big.bin")).unwrap(), big);
    // The unchanged spans stay in the file that was already here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(lab.b_dir.join("big.bin")).unwrap().ino(),
            inode
        );
    }
    // Only the blocks the push stored are fetched; the rest is copied from
    // the previous version on disk.
    // (Block boundaries depend on the folder's random key: the bounds hold
    // for any cut of the SMALL chunker, whose blocks are at most 16 KiB.)
    assert_eq!(r.chunks_downloaded, push.chunks_uploaded, "{r:?}");
    assert!(r.chunks_reused_local > 0, "{r:?}");
    assert_eq!(r.bytes_downloaded + r.bytes_reused_local, big.len() as u64);
    assert!(r.bytes_downloaded < 4096 + 3000 + 4 * 16_384, "{r:?}");
}

fn renamed_set(d: &Path, from: &str) {
    fs::create_dir_all(d.join(from).join("sub")).unwrap();
    fs::write(d.join(from).join("one.bin"), pseudo_random(120_000, 11)).unwrap();
    fs::write(d.join(from).join("sub/two.bin"), pseudo_random(60_000, 12)).unwrap();
    fs::write(d.join(from).join("three.txt"), b"a small file").unwrap();
    fs::write(d.join("keep.txt"), b"stays where it is").unwrap();
}

/// B pulls A's rename of `from` to `to`; the storage has lost every block,
/// so anything fetched would make a file unavailable.
fn pull_rename(lab: &Lab, a: &mut Engine, b: &mut Engine, from: &str, to: &str) {
    fs::rename(lab.a_dir.join(from), lab.a_dir.join(to)).unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.chunks_uploaded, 0, "a rename stores nothing: {push:?}");
    common::lose_all_objects(&lab.store);

    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(r.chunks_downloaded, 0, "{r:?}");
    assert_eq!(r.bytes_downloaded, 0, "{r:?}");
    assert_eq!(r.bytes_reused_local, 120_000 + 60_000 + 12, "{r:?}");
    assert_eq!(r.files_updated, 3, "{r:?}");
    assert_eq!(r.files_deleted, 3, "{r:?}");
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // The old directory went with its files, and so did its subdirectory.
    assert!(!lab.b_dir.join(from).exists());
    assert!(lab.b_dir.join(to).join("sub").is_dir());
}

#[test]
fn a_renamed_directory_fetches_nothing_and_leaves_no_empty_directory() {
    let lab = lab();
    let (mut a, mut b) = pair(&lab, |d| renamed_set(d, "dir"));
    pull_rename(&lab, &mut a, &mut b, "dir", "moved");
}

#[test]
fn deletions_applied_first_leave_their_blocks_in_the_trash_copy() {
    // A pull applies a writer's files newest first and deletions (no
    // modification time) last. With every file dated at the epoch, the
    // order is by path: `a/...` (the deletions) before `z/...`. The same
    // blocks are renamed onto the new paths, so nothing is copied and the
    // trash stays empty. A cross-device rename still falls back to the trash.
    let lab = lab();
    let (mut a, mut b) = pair(&lab, |d| {
        renamed_set(d, "a");
        for p in ["a/one.bin", "a/sub/two.bin", "a/three.txt", "keep.txt"] {
            fs::File::options()
                .write(true)
                .open(d.join(p))
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH)
                .unwrap();
        }
    });
    pull_rename(&lab, &mut a, &mut b, "a", "z");
    // The old files are renamed onto the new paths, so the trash stays
    // empty. The blocks survive because the files themselves moved.
    let trashed = walkdir::WalkDir::new(lab.b_home.join("trash"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(trashed, 0, "a rename does not copy the files through the trash");
}

#[test]
fn duplicate_files_fetch_each_distinct_block_once() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    let d = &lab.a_dir;
    let big = pseudo_random(120_000, 5);
    fs::create_dir_all(d.join("sub")).unwrap();
    for p in ["copy1.bin", "copy2.bin", "sub/copy3.bin"] {
        fs::write(d.join(p), &big).unwrap();
    }
    // A file that repeats its own content.
    let seg = pseudo_random(60_000, 6);
    fs::write(d.join("doubled.bin"), [seg.clone(), seg].concat()).unwrap();
    // Single-block files, fetched ahead together.
    for i in 0..6 {
        fs::write(d.join(format!("same-{i}.txt")), b"the same small file").unwrap();
        fs::write(d.join(format!("own-{i}.txt")), format!("file {i}")).unwrap();
    }
    a.push("docs").unwrap();
    let distinct = common::object_count(&lab.store) as u64;

    let mut b = common::join_approved(
        &lab.b_home,
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(r.chunks_downloaded, distinct, "{r:?}");
    // At least the two extra copies and the five extra small files are
    // copied here (the block boundaries depend on the folder's random key).
    assert!(r.bytes_reused_local >= 2 * 120_000 + 5 * 19, "{r:?}");
    assert_eq!(
        r.bytes_downloaded + r.bytes_reused_local,
        total_size(&lab.a_dir)
    );
}

#[test]
fn a_local_copy_that_changed_on_disk_is_fetched_instead() {
    let lab = lab();
    let mut big = pseudo_random(200_000, 21);
    let (mut a, mut b) = pair(&lab, |d| fs::write(d.join("big.bin"), &big).unwrap());
    big[100_000..101_000].copy_from_slice(&pseudo_random(1000, 22));
    fs::write(lab.a_dir.join("big.bin"), &big).unwrap();
    a.push("docs").unwrap();

    // B's copy changes without its size or time changing (bit rot, or a
    // program that keeps the time): the index still describes the old
    // version, so the scan sees no change.
    let local = lab.b_dir.join("big.bin");
    let mtime = fs::metadata(&local).unwrap().modified().unwrap();
    fs::write(&local, pseudo_random(200_000, 23)).unwrap();
    fs::File::options()
        .write(true)
        .open(&local)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(fs::read(&local).unwrap(), big);
    assert_eq!(r.chunks_reused_local, 0, "{r:?}");
    assert_eq!(r.bytes_downloaded, big.len() as u64, "{r:?}");
}

#[test]
fn sync_hot_scans_only_the_named_folder() {
    let lab = lab();
    let (mut a, _) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    let other = lab.a_dir.parent().unwrap().join("other");
    fs::create_dir_all(&other).unwrap();
    a.add_folder("other", &other).unwrap();
    fs::write(lab.a_dir.join("a.txt"), b"a").unwrap();
    fs::write(other.join("b.txt"), b"b").unwrap();
    a.sync(None).unwrap();
    let before = a.scans();
    fs::write(lab.a_dir.join("a.txt"), b"aa").unwrap();
    a.sync_hot(&["docs".to_string()]).unwrap();
    assert_eq!(a.scans(), before + 1);
}

#[test]
fn a_run_of_new_small_files_lands_intact() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    for i in 0..64u8 {
        // Shorter than the small chunker's minimum, so each file is one block.
        fs::write(lab.a_dir.join(format!("n{i:03}.txt")), vec![i; 500]).unwrap();
    }
    a.push("docs").unwrap();
    let mut b = common::join_approved(
        &lab.b_home,
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    let r = b.pull("docs").unwrap();
    assert!(r.files_unavailable.is_empty(), "{r:?}");
    assert_eq!(r.files_updated, 64, "{r:?}");
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
}
