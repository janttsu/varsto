// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Engine bugs the lab scenarios found (scripts/test/lab/scenarios.py), each
//! reproduced here on local storages.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn data(len: usize, seed: u64) -> Vec<u8> {
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

fn local(name: &str, path: PathBuf) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path,
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

fn files_under(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir::WalkDir::new(root)
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
        .filter(|p| !p.starts_with(".varsto"))
        .collect();
    out.sort();
    out
}

/// A folder of `n` small files and one larger one.
fn fill(dir: &Path, n: usize) {
    for i in 0..n {
        let d = dir.join(format!("dir{}", i % 7));
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join(format!("note-{i}.txt")),
            format!("note {i} ").repeat(1 + i % 40),
        )
        .unwrap();
    }
    fs::write(dir.join("big.bin"), data(200_000, 9)).unwrap();
}

/// `folder detach` and `folder attach` of the same folder at another path on
/// the same device: the new path gets every file (or placeholder) the
/// folder has, not only what changed since the detach.
#[test]
fn attach_after_detach_gets_every_file_again() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = local("box", root.join("storage"));
    let (mut a, words) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("docs", &a_dir).unwrap();
    fill(&a_dir, 160);
    a.sync(None).unwrap();
    let expect = files_under(&a_dir);
    assert_eq!(expect.len(), 161);

    let mut b = common::join_approved(&root.join("b"), "pub", PASS, &words, storage, &mut a);
    b.chunker = ChunkerParams::SMALL;
    let first = root.join("b-docs");
    b.attach_folder("docs", &first, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(files_under(&first), expect);

    // Elsewhere, selective: a placeholder for every file.
    b.detach_folder("docs").unwrap();
    let sel = root.join("sel");
    b.attach_folder("docs", &sel, true).unwrap();
    b.sync(None).unwrap();
    let got = files_under(&sel);
    let placeholders: Vec<&String> = got
        .iter()
        .filter(|p| p.ends_with(".varsto-placeholder"))
        .collect();
    assert_eq!(
        placeholders.len(),
        expect.len(),
        "placeholders after attaching again: {got:?}"
    );
    assert_eq!(
        placeholders.len(),
        got.len(),
        "real files in a selective folder"
    );

    // And once more in full, after a restart of the engine.
    b.detach_folder("docs").unwrap();
    drop(b);
    let mut b = open(&root.join("b"));
    let again = root.join("again");
    b.attach_folder("docs", &again, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(files_under(&again), expect);
    for p in &expect {
        assert_eq!(
            fs::read(again.join(p)).unwrap(),
            fs::read(a_dir.join(p)).unwrap(),
            "{p}"
        );
    }
}

fn packs_in(storage: &Path) -> std::collections::BTreeMap<String, PathBuf> {
    common::pack_files(storage)
        .into_iter()
        .map(|(p, id)| (id, p))
        .collect()
}

fn fsck_clean(e: &mut Engine, what: &str) {
    let r = e.fsck(true).unwrap();
    let f3 = r.format3.as_ref().expect("a format-3 report");
    assert!(f3.is_clean(), "fsck --verify {what}: {}", f3.describe());
}

fn two_devices(root: &Path) -> (Engine, Engine, PathBuf, PathBuf) {
    let storage = local("box", root.join("storage"));
    let (mut a, words) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("docs", &a_dir).unwrap();
    fill(&a_dir, 20);
    a.sync(None).unwrap();
    let mut b = common::join_approved(&root.join("b"), "desktop", PASS, &words, storage, &mut a);
    b.chunker = ChunkerParams::SMALL;
    let b_dir = root.join("b-docs");
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    (a, b, a_dir, b_dir)
}

/// `repair` and at once `fsck --verify`: the repaired packs are what the
/// fsck sees, without a sync in between.
#[test]
fn fsck_right_after_repair_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _b, a_dir, _) = two_devices(root);
    let store = root.join("storage");
    fsck_clean(&mut a, "before the damage");
    // A pack of the laptop's own file, lost; the big first pack, damaged.
    let before = packs_in(&store);
    fs::write(a_dir.join("repair-probe.bin"), data(3000, 77)).unwrap();
    a.push("docs").unwrap();
    let after = packs_in(&store);
    let new: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    assert_eq!(new.len(), 1, "the probe made {} packs", new.len());
    let gone = after[new[0]].clone();
    let victim = before
        .values()
        .max_by_key(|p| fs::metadata(p).unwrap().len())
        .unwrap()
        .clone();
    let mut bytes = fs::read(&victim).unwrap();
    bytes[4096] ^= 0xff;
    fs::write(&victim, bytes).unwrap();
    fs::remove_file(&gone).unwrap();
    let r = a.fsck(true).unwrap();
    let f3 = r.format3.unwrap();
    assert!(
        !f3.corrupt_copies.is_empty() && !f3.missing_copies.is_empty(),
        "{}",
        f3.describe()
    );
    let rep = a
        .repair(&varsto_core::engine::RepairOptions::manual())
        .unwrap();
    assert!(rep.unrepairable.is_empty(), "{rep:?}");
    fsck_clean(&mut a, "right after the repair");
    // And after a restart.
    drop(a);
    let mut a = open(&root.join("a"));
    fsck_clean(&mut a, "after a restart");
}

/// A pack the desktop wrote, of an edit the laptop holds only as one side
/// of a conflict: the laptop rebuilds it from its own file. `laptop_first`:
/// the laptop's edit reaches the storage first and the desktop's becomes the
/// conflict copy (made on the desktop); otherwise the laptop makes the copy.
fn rebuild_after_conflict(laptop_first: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, mut b, a_dir, b_dir) = two_devices(root);
    let store = root.join("storage");
    let theirs = data(5000, 501);
    fs::write(a_dir.join("dir1/note-1.txt"), data(4000, 502)).unwrap();
    fs::write(b_dir.join("dir1/note-1.txt"), &theirs).unwrap();
    if laptop_first {
        a.push("docs").unwrap();
    }
    let before = packs_in(&store);
    b.sync(None).unwrap();
    let after = packs_in(&store);
    let new: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    assert_eq!(new.len(), 1, "the desktop's sync made {} packs", new.len());
    let gone = after[new[0]].clone();
    a.sync(None).unwrap();
    let files = files_under(&a_dir);
    let copies: Vec<&String> = files.iter().filter(|p| p.contains(".conflict-")).collect();
    assert_eq!(copies.len(), 1, "{files:?}");
    assert!(
        files
            .iter()
            .any(|p| p.contains("note-1.") && fs::read(a_dir.join(p)).unwrap() == theirs),
        "the desktop's version is not on the laptop"
    );
    drop(b);
    fs::remove_file(&gone).unwrap();
    let rep = a
        .repair(&varsto_core::engine::RepairOptions::manual())
        .unwrap();
    assert!(rep.unrepairable.is_empty(), "{rep:?}");
    assert!(!rep.repaired.is_empty(), "{rep:?}");
    fsck_clean(&mut a, "after rebuilding the desktop's pack");
}

#[test]
fn a_lost_pack_is_rebuilt_from_a_conflict_copy() {
    rebuild_after_conflict(true);
}

#[test]
fn a_lost_pack_is_rebuilt_from_the_side_of_a_conflict_kept_here() {
    rebuild_after_conflict(false);
}

/// The lab's gc-settling: ten files in one pack, seven deleted, their trash
/// day passes. The owner's upkeep marks them dead and waits for the other
/// writers; each of them runs `sync` and then `trash upkeep` (the service's
/// order), or (`sync_first` false) only `trash upkeep`, which reads the
/// marks too and so must acknowledge them as a sync would. The seven blocks
/// are collected (by whichever writer gets there first) and no upkeep keeps
/// waiting for a writer that has read the marks.
fn gc_settles_with_helpers_running_upkeep(helpers: &[&str], sync_first: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let store = root.join("storage");
    let storage = local("box", store.clone());
    let (mut a, words) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("docs", &a_dir).unwrap();
    a.trash_set(Some(1), None, None).unwrap();
    fs::write(a_dir.join("keep.txt"), b"keep").unwrap();
    a.sync(None).unwrap();
    let mut others = Vec::new();
    for name in helpers {
        let mut e = common::join_approved(
            &root.join(name),
            name,
            PASS,
            &words,
            storage.clone(),
            &mut a,
        );
        e.chunker = ChunkerParams::SMALL;
        e.attach_folder("docs", &root.join(format!("{name}-docs")), false)
            .unwrap();
        e.sync(None).unwrap();
        others.push(e);
    }
    let gc = a_dir.join("gc");
    fs::create_dir_all(&gc).unwrap();
    for i in 0..10u64 {
        fs::write(gc.join(format!("f{i}.bin")), data(30_000, 60 + i)).unwrap();
    }
    a.sync(None).unwrap();
    for e in &mut others {
        e.sync(None).unwrap();
    }
    let with_ten = packs_in(&store);
    for i in 0..7 {
        fs::remove_file(gc.join(format!("f{i}.bin"))).unwrap();
    }
    a.sync(None).unwrap();
    for e in &mut others {
        e.sync(None).unwrap();
    }
    let later = varsto_core::util::now_utc() + 2 * 86_400;
    let first = a.trash_upkeep_at(later).unwrap();
    assert_eq!(first.blocks_dropped, 0, "{first:?}");
    assert!(
        first.notes.iter().any(|n| n.contains("freed once")),
        "{first:?}"
    );
    let collected = |now: &std::collections::BTreeMap<String, PathBuf>| {
        with_ten.keys().any(|k| !now.contains_key(k))
    };
    let mut last = Vec::new();
    for _ in 0..3 {
        last.clear();
        for e in &mut others {
            if sync_first {
                e.sync(None).unwrap();
            }
            last.push(e.trash_upkeep_at(later).unwrap());
        }
        last.push(a.trash_upkeep_at(later).unwrap());
        if collected(&packs_in(&store)) {
            break;
        }
    }
    assert!(
        collected(&packs_in(&store)),
        "no pack was collected: {last:?}"
    );
    // One more round: nobody waits for anybody.
    for e in &mut others {
        e.sync(None).unwrap();
        let r = e.trash_upkeep_at(later).unwrap();
        assert!(!r.notes.iter().any(|n| n.contains("freed once")), "{r:?}");
    }
    let r = a.trash_upkeep_at(later).unwrap();
    assert!(!r.notes.iter().any(|n| n.contains("freed once")), "{r:?}");
    // The three files left read on a device that joins afterwards.
    let mut late = common::join_approved(&root.join("late"), "late", PASS, &words, storage, &mut a);
    late.chunker = ChunkerParams::SMALL;
    let late_dir = root.join("late-docs");
    late.attach_folder("docs", &late_dir, false).unwrap();
    late.sync(None).unwrap();
    for i in 7..10 {
        assert_eq!(
            fs::read(late_dir.join(format!("gc/f{i}.bin"))).unwrap(),
            fs::read(gc.join(format!("f{i}.bin"))).unwrap()
        );
    }
    assert!(!late_dir.join("gc/f0.bin").exists());
}

#[test]
fn gc_settles_when_the_other_writer_runs_upkeep_after_sync() {
    gc_settles_with_helpers_running_upkeep(&["desktop"], true);
}

#[test]
fn gc_settles_when_two_other_writers_run_upkeep_after_sync() {
    gc_settles_with_helpers_running_upkeep(&["desktop", "pub"], true);
}

#[test]
fn gc_settles_when_the_other_writers_run_only_upkeep() {
    gc_settles_with_helpers_running_upkeep(&["desktop", "pub"], false);
}
