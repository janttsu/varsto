// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Bit-rot checks (scrub): damaged and missing objects on a storage (in
//! packs, written by this very device), on a pool disk, and synced
//! files on this device whose content changed under an unchanged size and
//! time; the budget, the rolling pass, and cold storage left out unless
//! included.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use varsto_core::engine::{RepairOptions, ScrubOptions};
use varsto_core::pool::{self, DiskSpace};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const GIB: u64 = 1 << 30;

fn dir(name: &str, path: &Path, cold: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
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

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        Lab {
            root: tmp.path().to_path_buf(),
            _tmp: tmp,
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

/// Device A with the given storages and a folder "docs": one large file
/// (several blocks) and small ones (one block each), all in one pack.
fn device(lab: &Lab, storages: &[StorageSpec]) -> Engine {
    let (mut a, _) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    for s in storages {
        a.add_storage(s.clone()).unwrap();
    }
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    fs::write(lab.p("a-docs/big.bin"), pseudo_random(2 << 20, 7)).unwrap();
    for i in 0..6 {
        fs::write(
            lab.p(&format!("a-docs/note-{i}.txt")),
            pseudo_random(3_000 + i * 100, 100 + i as u64),
        )
        .unwrap();
    }
    a.sync(None).unwrap();
    a
}

/// Block objects of a storage directory (all in packs).
fn objects(root: &Path) -> Vec<String> {
    common::object_names(root).into_iter().collect()
}

/// Copy a directory tree (files only, no clobber of other files).
fn copy_tree(from: &Path, to: &Path) {
    for e in walkdir::WalkDir::new(from).into_iter().flatten() {
        let rel = e.path().strip_prefix(from).unwrap();
        let dest = to.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&dest).unwrap();
        } else {
            fs::copy(e.path(), &dest).unwrap();
        }
    }
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

fn set_mtime(path: &Path, t: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

#[test]
fn damaged_objects_this_device_wrote_are_found_and_repaired() {
    let lab = Lab::new();
    let mut a = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            dir("spare", &lab.p("spare"), false),
        ],
    );
    // Every block is in a pack: two are damaged in place.
    let all = objects(&lab.p("box"));
    assert!(all.len() >= 5, "objects: {all:?}");
    assert!(!lab.p("box").join("chunks").exists());
    common::corrupt_object(&lab.p("box"), &all[0]);
    common::corrupt_object(&lab.p("box"), &all[1]);
    let total = common::object_count(&lab.p("box")) as u64;
    let batches = a.ledger_entries().unwrap().len();

    let r = a
        .scrub(&ScrubOptions {
            storages: vec!["box".into()],
            full: true,
            ..Default::default()
        })
        .unwrap();
    // Every object the ledger places on "box", all written by this device.
    assert_eq!(r.objects_checked, total, "{r:?}");
    assert_eq!(r.corrupt.len(), 2, "{r:?}");
    assert_eq!(r.missing.len(), 0, "{r:?}");
    assert_eq!(r.queued_for_repair, 2);
    assert_eq!(r.files_checked, 0, "--storage alone reads no local files");
    // Nothing recorded: the writer's own check is no verification.
    assert_eq!(a.ledger_entries().unwrap().len(), batches);
    assert_eq!(a.repair_status().queued, 2);

    let rep = a.repair(&RepairOptions::service()).unwrap();
    assert_eq!(rep.repaired.len(), 2, "{rep:?}");
    for o in [&all[0], &all[1]] {
        assert!(common::intact(&lab.p("box"), o), "{o} not repaired");
    }
    let again = a
        .scrub(&ScrubOptions {
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(again.problems(), 0, "{again:?}");
    // Both storages and the folder were read.
    assert!(again.targets.iter().any(|t| t.label == "storage spare"));
    assert!(again.files_checked >= 7);
    let st = a.scrub_status();
    assert_eq!(st.totals.problems_found, 2);
    assert!(st.targets.contains_key("storage:box"));
}

#[test]
fn the_budget_spreads_a_pass_over_several_runs() {
    let lab = Lab::new();
    let mut a = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let total = common::object_count(&lab.p("box")) as u64;
    let mut s = a.scrub_schedule().clone();
    // One byte: every run reads its first object only.
    s.max_local_bytes = 1;
    a.set_scrub_schedule(s).unwrap();
    let only_box = ScrubOptions {
        storages: vec!["box".into()],
        ..Default::default()
    };
    let mut runs = 0;
    loop {
        let r = a.scrub(&only_box).unwrap();
        runs += 1;
        let t = &r.targets[0];
        assert_eq!(t.checked, 1, "{r:?}");
        if t.pass_done {
            break;
        }
        assert_eq!(t.left_in_pass, total - runs);
        assert!(runs < 100);
    }
    assert_eq!(runs, total);
    let st = a.scrub_status();
    let box_pass = &st.targets["storage:box"];
    assert!(box_pass.last_pass_done_utc.is_some());
    assert_eq!(box_pass.cursor, None);
    // A narrower run does not move the schedule.
    assert_eq!(st.last_run_utc, None);

    // A scheduled run checks a share: with 90 days and a run a day, a
    // small part of the next pass.
    let mut s = a.scrub_schedule().clone();
    s.max_local_bytes = 1 << 30;
    a.set_scrub_schedule(s).unwrap();
    let r = a.scrub(&ScrubOptions::service()).unwrap();
    let t = r.targets.iter().find(|t| t.label == "storage box").unwrap();
    assert!(t.checked >= 1 && t.checked < total, "{t:?}");
    assert!(a.scrub_status().last_run_utc.is_some());
    assert!(!a.scrub_due(varsto_core::util::now_utc()));
}

#[test]
fn cold_storage_is_read_only_when_included() {
    let lab = Lab::new();
    let mut a = device(
        &lab,
        &[
            dir("box", &lab.p("box"), false),
            dir("deep", &lab.p("deep"), true),
        ],
    );
    assert!(common::object_count(&lab.p("deep")) > 0);
    common::corrupt_object(&lab.p("deep"), &objects(&lab.p("deep"))[0]);
    let r = a
        .scrub(&ScrubOptions {
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert!(
        r.skipped.iter().any(|s| s.starts_with("deep (cold")),
        "{r:?}"
    );
    assert!(!r.targets.iter().any(|t| t.label == "storage deep"));
    assert_eq!(r.problems(), 0);

    // Included for one run with the confirmation.
    let r = a
        .scrub(&ScrubOptions {
            storages: vec!["deep".into()],
            include_cold: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.corrupt.len(), 1, "{r:?}");

    // Opted in for scheduled runs: only with the confirmation.
    assert!(a.set_scrub_cold("deep", true, false).is_err());
    assert!(a.set_scrub_cold("box", true, true).is_err(), "not cold");
    a.set_scrub_cold("deep", true, true).unwrap();
    let mut s = a.scrub_schedule().clone();
    s.cold.insert("other".into());
    assert!(
        a.set_scrub_schedule(s).is_err(),
        "cold storages need their own confirmation"
    );
    let r = a
        .scrub(&ScrubOptions {
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert!(r.targets.iter().any(|t| t.label == "storage deep"), "{r:?}");
    a.set_scrub_cold("deep", false, false).unwrap();
    assert!(a.scrub_schedule().cold.is_empty());
}

#[test]
fn a_damaged_local_file_is_moved_aside_and_restored() {
    let lab = Lab::new();
    let mut a = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let path = lab.p("a-docs/note-2.txt");
    let good = fs::read(&path).unwrap();
    let when = mtime(&path);
    // Bit rot: one byte flips, size and time stay.
    let mut bad = good.clone();
    bad[100] ^= 0x01;
    fs::write(&path, &bad).unwrap();
    set_mtime(&path, when);

    let r = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.objects_checked, 0, "--local alone reads no storage");
    assert_eq!(r.files_checked, 7);
    assert_eq!(r.damaged_files.len(), 1, "{r:?}");
    let d = &r.damaged_files[0];
    assert!(d.restored, "{d:?}");
    assert_eq!(d.path, "note-2.txt");
    let aside = d.moved_to.clone().unwrap();
    let date = varsto_core::util::format_date(varsto_core::util::now_utc()).replace('-', "");
    assert_eq!(aside, format!("note-2.damaged-{date}.txt"));
    // The recorded version is back, with its time; the damaged one is kept.
    assert_eq!(fs::read(&path).unwrap(), good);
    assert_eq!(mtime(&path), when);
    assert_eq!(fs::read(lab.p("a-docs").join(&aside)).unwrap(), bad);

    // The restored file is the synced version: the next sync changes
    // nothing for it, and the damaged copy is synced as a file of its own.
    let hash_of = |a: &Engine, p: &str| {
        a.list_files("docs")
            .unwrap()
            .into_iter()
            .find(|f| f.path == p)
            .map(|f| f.content_hash)
    };
    let before = hash_of(&a, "note-2.txt");
    a.sync(None).unwrap();
    assert_eq!(
        hash_of(&a, "note-2.txt"),
        before,
        "no new version of the restored file"
    );
    assert!(
        hash_of(&a, &aside).is_some(),
        "the damaged copy is a file of its own"
    );
    let again = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert!(again.damaged_files.is_empty(), "{again:?}");
    assert_eq!(again.files_checked, 8);
    assert_eq!(a.scrub_status().totals.files_restored, 1);
}

#[test]
fn an_edited_file_is_not_touched() {
    let lab = Lab::new();
    let mut a = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let path = lab.p("a-docs/note-3.txt");
    let mut edited = fs::read(&path).unwrap();
    edited[10] ^= 0x20;
    let when = mtime(&path);
    fs::write(&path, &edited).unwrap();
    set_mtime(&path, when + Duration::from_secs(60));

    let r = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert!(r.damaged_files.is_empty(), "{r:?}");
    assert_eq!(fs::read(&path).unwrap(), edited);
    let names: Vec<String> = fs::read_dir(lab.p("a-docs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(!names.iter().any(|n| n.contains("damaged")), "{names:?}");
    // The edit goes out with the next sync as usual.
    let hash = |a: &Engine| {
        a.list_files("docs")
            .unwrap()
            .into_iter()
            .find(|f| f.path == "note-3.txt")
            .map(|f| f.content_hash)
    };
    let before = hash(&a);
    a.sync(None).unwrap();
    assert_ne!(hash(&a), before);
}

#[test]
fn a_damaged_file_without_a_good_copy_is_left_in_place() {
    let lab = Lab::new();
    let mut a = device(&lab, &[dir("box", &lab.p("box"), false)]);
    let path = lab.p("a-docs/note-1.txt");
    let when = mtime(&path);
    let good = fs::read(&path).unwrap();
    let mut bad = good.clone();
    bad[5] ^= 0x80;
    fs::write(&path, &bad).unwrap();
    set_mtime(&path, when);
    // No good copy anywhere: the storage lost every block.
    copy_tree(&lab.p("box"), &lab.p("box-saved"));
    common::lose_all_objects(&lab.p("box"));

    let r = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.damaged_files.len(), 1);
    assert!(!r.damaged_files[0].restored);
    assert_eq!(
        fs::read(&path).unwrap(),
        bad,
        "never moved without a good copy"
    );
    assert_eq!(a.scrub_status().unrestored.len(), 1);

    // Once the blocks are back, the next run restores it first.
    copy_tree(&lab.p("box-saved"), &lab.p("box"));
    let r = a
        .scrub(&ScrubOptions {
            local: true,
            ..Default::default()
        })
        .unwrap();
    assert!(r.damaged_files.iter().any(|d| d.restored), "{r:?}");
    assert!(a.scrub_status().unrestored.is_empty());
    assert_eq!(fs::read(&path).unwrap(), good);
}

#[test]
fn a_bad_copy_on_a_pool_disk_is_dropped_and_written_again() {
    let lab = Lab::new();
    let mounts = lab.p("mounts");
    fs::create_dir_all(&mounts).unwrap();
    let d1 = mounts.join("d1");
    fs::create_dir_all(&d1).unwrap();
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
    let (mut a, _) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    a.add_storage(dir("box", &lab.p("box"), false)).unwrap();
    a.add_storage(StorageSpec::Pool {
        name: "shelf".into(),
        place: "shelf".into(),
        reserve_percent: 5,
        min_reserve_bytes: 2 * GIB,
        disks: vec![],
        scan_roots: vec![mounts.clone()],
        copies: 1,
        verify_after_days: varsto_core::pool::DEFAULT_VERIFY_AFTER_DAYS,
    })
    .unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    fs::write(lab.p("a-docs/one.bin"), pseudo_random(600_000, 3)).unwrap();
    a.sync(None).unwrap();
    let on_disk: Vec<PathBuf> = walkdir::WalkDir::new(d1.join(pool::DATA_DIR).join("packs"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    assert!(!on_disk.is_empty());
    let victim = &on_disk[0];
    let mut bytes = fs::read(victim).unwrap();
    bytes[0] ^= 0xff;
    fs::write(victim, &bytes).unwrap();

    let r = a
        .scrub(&ScrubOptions {
            storages: vec!["shelf".into()],
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.objects_checked, on_disk.len() as u64, "{r:?}");
    assert_eq!(r.corrupt.len(), 1, "{r:?}");
    assert!(r.corrupt[0].starts_with("shelf/data-01:"));
    assert_eq!(r.queued_for_repair, 1);
    assert!(!victim.exists(), "the bad copy is dropped from the disk");
    let rep = a.repair(&RepairOptions::service()).unwrap();
    assert_eq!(rep.repaired.len(), 1, "{rep:?}");
    // The block is written again in a new pack (other padding, so another
    // id); the damaged pack is gone.
    assert!(!victim.exists());
    let packs: Vec<PathBuf> = walkdir::WalkDir::new(d1.join(pool::DATA_DIR).join("packs"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    assert_eq!(packs.len(), on_disk.len(), "{packs:?}");
    for p in &packs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let back = fs::read(p).unwrap();
        assert_eq!(hex::encode(varsto_core::crypto::hash(&back)), name);
    }

    // The disk goes away; long after, the run reports it.
    fs::rename(&d1, lab.p("away")).unwrap();
    let later = varsto_core::util::now_utc() + 200 * 86_400;
    let r = a
        .scrub_at(
            &ScrubOptions {
                storages: vec!["shelf".into()],
                ..Default::default()
            },
            later,
        )
        .unwrap();
    assert!(r.offline > 0);
    assert_eq!(r.disks_away.len(), 1, "{r:?}");
    assert!(r.disks_away[0].starts_with("data-01"));
}

#[test]
fn a_corrupt_block_cache_object_is_dropped_and_fetched_again() {
    let lab = Lab::new();
    let mut a = device(&lab, &[dir("box", &lab.p("box"), false)]);
    // The folder is kept encrypted on this device from now on.
    a.set_encrypted_here("docs", true).unwrap();
    a.sync(None).unwrap();
    let cache = lab.p("a-home").join("block-cache").join("chunks");
    let mut cached: Vec<PathBuf> = walkdir::WalkDir::new(&cache)
        .min_depth(2)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    cached.sort();
    assert!(cached.len() >= 2, "{cached:?}");
    let damage = |p: &Path| {
        let mut b = fs::read(p).unwrap();
        b[3] ^= 0x10;
        fs::write(p, b).unwrap();
    };
    damage(&cached[0]);
    let r = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.files_checked, 0, "no plain files here");
    assert_eq!(r.cache_checked, cached.len() as u64);
    assert_eq!(r.cache_dropped, 1, "{r:?}");
    // Fetched again from the storage, intact.
    let name = cached[0].file_name().unwrap().to_string_lossy().to_string();
    let back = fs::read(&cached[0]).unwrap();
    assert_eq!(hex::encode(varsto_core::crypto::hash(&back)), name);

    // Not on the storage either: the files that need it are no longer
    // counted as cached here (the next sync fetches them when it can).
    damage(&cached[1]);
    let object = cached[1].file_name().unwrap().to_string_lossy().to_string();
    common::lose_object(&lab.p("box"), &object);
    let r = a
        .scrub(&ScrubOptions {
            local: true,
            full: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.cache_dropped, 1, "{r:?}");
    assert!(!cached[1].exists());
    let files = a.list_files("docs").unwrap();
    assert!(files.iter().any(|f| f.state != "local"), "{files:?}");
}
