// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Removable-disk pool (plan 6.35, 6.41): disks are temporary directories
//! under a scan root; capacity is simulated through the free-space hook.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::Engine;
use varsto_core::pool::{self, DiskIndex, DiskMarker, DiskSpace, PoolError};
use varsto_core::storage::StorageSpec;

const PASS: &str = "correct horse battery staple";
const GIB: u64 = 1 << 30;

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
    mounts: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let mounts = root.join("mounts");
        fs::create_dir_all(&mounts).unwrap();
        Lab {
            root,
            mounts,
            _tmp: tmp,
        }
    }
    fn pool_spec(&self, name: &str) -> StorageSpec {
        StorageSpec::Pool {
            name: name.into(),
            place: "shelf".into(),
            reserve_percent: 5,
            min_reserve_bytes: 2 * GIB,
            disks: vec![],
            scan_roots: vec![self.mounts.clone()],
            copies: 1,
            verify_after_days: pool::DEFAULT_VERIFY_AFTER_DAYS,
        }
    }
    fn box_spec(&self) -> StorageSpec {
        StorageSpec::LocalDir {
            name: "box".into(),
            path: self.root.join("box"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        }
    }
    /// A mounted disk directory with a simulated size.
    fn mount(&self, name: &str, free: u64, total: u64) -> PathBuf {
        let m = self.mounts.join(name);
        fs::create_dir_all(&m).unwrap();
        pool::set_fake_space(&m, Some(DiskSpace { free, total }));
        m
    }
}

fn engine(home: &Path, name: &str) -> (Engine, String) {
    let (mut e, key) = Engine::init(home, name, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    (e, key)
}

/// Folder `docs` at `docs` whose blocks go to the pool only: the vault's
/// records live on `box` (a pool holds packs, never records).
fn pool_folder(a: &mut Engine, lab: &Lab, docs: &Path) {
    a.add_storage(lab.box_spec()).unwrap();
    a.add_folder("docs", docs).unwrap();
    a.set_placement(
        "docs",
        Some(varsto_core::placement::Placement {
            storages: vec!["shelf".into()],
            ..Default::default()
        }),
    )
    .unwrap();
}

/// The packs on a disk (every block is in one, `varsto_core::packs`).
fn objects_under(mount: &Path) -> Vec<PathBuf> {
    common::pack_files(&mount.join(pool::DATA_DIR))
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

#[test]
fn objects_go_to_the_disk_with_most_free_space_within_the_reserve() {
    let lab = Lab::new();
    let (mut a, _) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let d2 = lab.mount("d2", 20 * GIB, 100 * GIB);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    a.disk_add(&d2, "shelf", "data-02").unwrap();
    assert!(DiskMarker::path(&d1).is_file());
    let marker = DiskMarker::read(&d1).unwrap();
    assert_eq!(marker.label, "data-01");
    assert_eq!(marker.format, 1);
    assert!(!marker.vault_tag.contains(&a.vault_id().to_string()));

    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(150_000, 1)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    let push = a.push("docs").unwrap();
    assert!(push.chunks_uploaded > 1);
    assert!(push.storages_unavailable.is_empty());
    // Everything landed on the disk with the most free space.
    assert!(!objects_under(&d1).is_empty());
    assert!(objects_under(&d2).is_empty());

    // Reserve: 5 % of 100 GiB is 5 GiB. A disk with 5 GiB + 100 bytes free
    // takes nothing (every chunk is at least 1 KiB) even though it has more
    // free space than the other, smaller disk, which takes everything.
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 5 * GIB + 100,
            total: 100 * GIB,
        }),
    );
    pool::set_fake_space(
        &d2,
        Some(DiskSpace {
            free: 3 * GIB,
            total: 10 * GIB,
        }),
    );
    fs::write(docs.join("two.bin"), pseudo_random(150_000, 4)).unwrap();
    let before_d1 = objects_under(&d1).len();
    a.push("docs").unwrap();
    assert_eq!(objects_under(&d1).len(), before_d1);
    assert!(!objects_under(&d2).is_empty());

    // No disk has room: the push still succeeds; the pool is reported
    // unavailable and the objects are written on a later push.
    pool::set_fake_space(
        &d2,
        Some(DiskSpace {
            free: 2 * GIB,
            total: 10 * GIB,
        }),
    );
    fs::write(docs.join("three.bin"), pseudo_random(150_000, 6)).unwrap();
    let before = objects_under(&d1).len() + objects_under(&d2).len();
    let push = a.push("docs").unwrap();
    assert_eq!(push.storages_unavailable, vec!["shelf".to_string()]);
    assert_eq!(objects_under(&d1).len() + objects_under(&d2).len(), before);
    pool::set_fake_space(
        &d2,
        Some(DiskSpace {
            free: 20 * GIB,
            total: 100 * GIB,
        }),
    );
    let push = a.push("docs").unwrap();
    assert!(push.storages_unavailable.is_empty());
    assert!(objects_under(&d1).len() + objects_under(&d2).len() > before);

    // Listings.
    let disks = a.disks().unwrap();
    assert_eq!(disks.len(), 2);
    assert!(disks
        .iter()
        .all(|d| d.attached && d.pool == "shelf" && d.place == "shelf"));
    let s = a.status().unwrap();
    assert!(s.storages.iter().any(|s| s.kind() == "pool"));
}

#[test]
fn detached_disk_is_reported_and_recognised_again_elsewhere() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let (mut a, vault_key) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("big.bin"), pseudo_random(200_000, 7)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    // The box carries records, ledger and manifests but loses its chunks:
    // the disk is the only place that has them.
    common::lose_all_objects(&lab.root.join("box"));
    a.disk_eject("data-01").unwrap();
    let idx = DiskIndex::read(&d1).expect("eject writes the disk index");
    assert!(!idx.objects.is_empty());
    assert_eq!(idx.label, "data-01");
    // Device B joins through the box, adds a pool of the same name and adopts
    // the attached disk from its index.
    let b_home = lab.root.join("b-home");
    let mut b = common::join_approved(&b_home, "desk", PASS, &vault_key, lab.box_spec(), &mut a);
    drop(a);
    b.chunker = ChunkerParams::SMALL;
    b.add_storage(lab.pool_spec("shelf")).unwrap();
    let disks = b.disks().unwrap();
    assert_eq!(
        disks.len(),
        1,
        "B adopts the disk from its marker and index"
    );
    assert_eq!(disks[0].label, "data-01");
    assert!(disks[0].attached);
    assert_eq!(disks[0].objects as usize, idx.objects.len());
    assert!(b_home
        .join(format!(
            "pool-{}.json",
            DiskMarker::read(&d1).unwrap().pool_id
        ))
        .is_file());

    // Detach: the mount directory goes away. Pulling now reports the disk.
    let away = lab.root.join("away");
    fs::create_dir_all(&away).unwrap();
    fs::rename(&d1, away.join("d1")).unwrap();
    let b_docs = lab.root.join("b-docs");
    b.attach_folder("docs", &b_docs, false).unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 0);
    assert_eq!(pull.disks_needed, vec!["data-01 (shelf)".to_string()]);
    assert!(pull.files_unavailable[0].contains("attach disk data-01 (shelf)"));
    let disks = b.disks().unwrap();
    assert!(!disks[0].attached);

    // Reading an object of the disk returns the typed error; the index still
    // lists it.
    let key = idx.objects.keys().next().unwrap().clone();
    {
        let pool = b.open_storage("shelf").unwrap();
        assert!(pool.exists(&key).unwrap());
        let err = pool.get(&key).unwrap_err();
        match pool::pool_error(&err) {
            Some(PoolError::NeedsDisk { label, place, .. }) => {
                assert_eq!(label, "data-01");
                assert_eq!(place, "shelf");
            }
            other => panic!("expected NeedsDisk, got {other:?} ({err:#})"),
        }
        assert_eq!(err.to_string(), "attach disk data-01 (shelf)");
    }

    // Reattached under a different name and path: recognised by the marker,
    // and the pending file arrives on the next pull.
    let d1_new = lab.mounts.join("usb-dock-slot-2");
    fs::rename(away.join("d1"), &d1_new).unwrap();
    pool::set_fake_space(
        &d1_new,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 1);
    assert!(pull.disks_needed.is_empty());
    assert_eq!(
        fs::read(b_docs.join("big.bin")).unwrap(),
        pseudo_random(200_000, 7)
    );
    let disks = b.disks().unwrap();
    assert!(disks[0].attached);
    assert_eq!(disks[0].mount.as_deref(), Some(d1_new.as_path()));

    // Free the file (the pool counts as a durable copy), take the disk away:
    // fetching names the disk, and fsck counts the offline objects instead of failing.
    b.free_file("docs", "big.bin").unwrap();
    fs::rename(&d1_new, away.join("d1")).unwrap();
    let err = b.fetch_file("docs", "big.bin").unwrap_err();
    assert_eq!(err.to_string(), "attach disk data-01 (shelf)");
    assert!(matches!(
        pool::pool_error(&err),
        Some(PoolError::NeedsDisk { .. })
    ));
    let r = b.fsck(true).unwrap();
    assert!(r.objects_offline > 0);
    assert!(r.objects_corrupt.is_empty());
    assert_eq!(
        r.disks_offline,
        vec!["data-01 (shelf), last verified never".to_string()]
    );
}

#[test]
fn delete_while_detached_is_queued_and_applied_by_check() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let (mut a, _) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(100_000, 11)).unwrap();
    pool_folder(&mut a, &lab, &docs);
    a.push("docs").unwrap();
    let files = objects_under(&d1);
    assert!(!files.is_empty());
    let key = {
        let rel = files[0].strip_prefix(d1.join(pool::DATA_DIR)).unwrap();
        rel.to_string_lossy().replace('\\', "/")
    };

    let away = lab.root.join("away");
    fs::rename(&d1, &away).unwrap();
    {
        let pool = a.open_storage("shelf").unwrap();
        assert!(pool.list("packs/").unwrap().contains(&key));
        pool.delete(&key).unwrap();
        assert!(!pool.exists(&key).unwrap());
        assert!(pool.get(&key).unwrap().is_none());
    }
    let disks = a.disks().unwrap();
    assert!(!disks[0].attached);
    assert_eq!(disks[0].pending_deletes, 1);
    assert!(
        a.disk_check("data-01", false).is_err(),
        "check needs the disk"
    );

    fs::rename(&away, &d1).unwrap();
    let r = a.disk_check("data-01", true).unwrap();
    assert_eq!(r.objects_removed, 1);
    assert!(r.bytes_removed > 0);
    assert!(r.bad.is_empty());
    // The blocks are still referenced by a current file, so the check put
    // them back (in a pack again).
    assert!(r.objects_added >= 1);
    assert!(!objects_under(&d1).is_empty());
    let disks = a.disks().unwrap();
    assert_eq!(disks[0].pending_deletes, 0);
    assert!(disks[0].last_verified_utc > 0);

    // A corrupted object is found by a full check and replaced from the local file.
    let victim = &objects_under(&d1)[0];
    fs::write(victim, b"rotten").unwrap();
    let r = a.disk_check("data-01", true).unwrap();
    assert_eq!(r.bad.len(), 1);
    assert!(r.objects_added >= 1);
    assert!(objects_under(&d1).iter().all(|f| intact(f)));
}

#[test]
fn retired_disk_receives_nothing() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 80 * GIB, 100 * GIB);
    let d2 = lab.mount("d2", 20 * GIB, 100 * GIB);
    let (mut a, _) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    a.disk_add(&d2, "shelf", "data-02").unwrap();
    let only_here = a.disk_retire("data-01").unwrap();
    assert_eq!(only_here, 0);
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(120_000, 5)).unwrap();
    pool_folder(&mut a, &lab, &docs);
    a.push("docs").unwrap();
    assert!(
        objects_under(&d1).is_empty(),
        "retired disk must stay empty"
    );
    assert!(!objects_under(&d2).is_empty());
    // Objects that live only on a disk are counted when it is retired.
    let n = a.disk_retire("data-02").unwrap();
    assert_eq!(n as usize, objects_under(&d2).len());
    let disks = a.disks().unwrap();
    assert!(disks.iter().all(|d| d.retired));
    // With every disk retired the pool takes nothing and says so.
    fs::write(docs.join("two.bin"), pseudo_random(120_000, 6)).unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.storages_unavailable, vec!["shelf".to_string()]);
}

#[test]
fn index_files_are_written_and_eject_says_where() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let home = lab.root.join("a-home");
    let (mut a, _) = engine(&home, "laptop");
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(100_000, 9)).unwrap();
    pool_folder(&mut a, &lab, &docs);
    a.push("docs").unwrap();
    // The pool index in the device directory maps every object to the disk.
    let marker = DiskMarker::read(&d1).unwrap();
    let pool_index: serde_json::Value = serde_json::from_slice(
        &fs::read(home.join(format!("pool-{}.json", marker.pool_id))).unwrap(),
    )
    .unwrap();
    let objects = pool_index["objects"].as_object().unwrap();
    assert_eq!(objects.len(), objects_under(&d1).len());
    assert!(objects.values().all(|v| v["disk"] == marker.disk_id));
    // The disk's own index lists the same objects after the push.
    let idx = DiskIndex::read(&d1).unwrap();
    assert_eq!(idx.objects.len(), objects.len());
    assert_eq!(idx.pool_id, marker.pool_id);
    let mount = a.disk_eject("data-01").unwrap();
    assert_eq!(mount, d1.canonicalize().unwrap());
    // The configuration mirrors the registry (config.json has no secrets).
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join("config.json")).unwrap()).unwrap();
    let pool = config["storages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "pool")
        .unwrap();
    assert_eq!(pool["disks"][0]["label"], "data-01");
    assert_eq!(pool["disks"][0]["id"], marker.disk_id);
    // Adding the same mount again is refused; a foreign marker as well.
    assert!(a.disk_add(&d1, "shelf", "again").is_err());
    let foreign = lab.mount("foreign", 50 * GIB, 100 * GIB);
    fs::write(
        DiskMarker::path(&foreign),
        serde_json::to_vec(&DiskMarker {
            pool_id: "0".repeat(32),
            disk_id: "1".repeat(32),
            label: "x".into(),
            vault_tag: "2".repeat(32),
            created_utc: 0,
            format: 1,
            mac_hex: String::new(),
        })
        .unwrap(),
    )
    .unwrap();
    let err = a.disk_add(&foreign, "shelf", "foreign").unwrap_err();
    assert!(err.to_string().contains("another vault"));
    assert!(a.disks().unwrap().iter().all(|d| d.label == "data-01"));
}

#[test]
fn policy_counts_an_offline_disk_at_its_last_verification() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let (mut a, _) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(100_000, 4)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    a.set_policy(
        "docs",
        Some(varsto_core::policy::Policy {
            min_copies: 2,
            min_per_place: [("shelf".to_string(), 1)].into_iter().collect(),
            verified_within_days: Some(30),
        }),
    )
    .unwrap();
    // The full check verifies the disk; the policy is satisfied.
    a.disk_check("data-01", true).unwrap();
    let reports = a.policy_check().unwrap();
    assert_eq!(
        reports[0].state,
        varsto_core::policy::PolicyState::Ok,
        "{:?}",
        reports[0]
    );
    // Away: still two copies, but the margin is zero and one copy cannot be read.
    fs::rename(&d1, lab.root.join("away")).unwrap();
    let reports = a.policy_check().unwrap();
    assert_eq!(
        reports[0].state,
        varsto_core::policy::PolicyState::AtRisk,
        "{:?}",
        reports[0]
    );
    // Forty days later the disk's verification has aged out.
    let later = varsto_core::util::now_utc() + 40 * 86_400;
    let reports = a.policy_check_at(later).unwrap();
    assert_eq!(
        reports[0].state,
        varsto_core::policy::PolicyState::Violated,
        "{:?}",
        reports[0]
    );
    assert!(reports[0].chunks_unverified_in_window > 0);
}

/// The object's file still hashes to its name.
fn intact(path: &Path) -> bool {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    hex::encode(varsto_core::crypto::hash(&fs::read(path).unwrap())) == name
}

fn pool_index_path(home: &Path, mount: &Path) -> PathBuf {
    let marker = DiskMarker::read(mount).unwrap();
    home.join(format!("pool-{}.json", marker.pool_id))
}

#[test]
fn every_write_is_read_back_and_a_disk_that_lies_twice_is_given_up() {
    let lab = Lab::new();
    let home = lab.root.join("a-home");
    let (mut a, _) = engine(&home, "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(150_000, 21)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    // No disk yet: the blocks go to the box only.
    a.push("docs").unwrap();

    // The disk returns wrong bytes for the first block twice: the fill stops
    // there, says the disk may be failing, and leaves no bad copy behind.
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    pool::corrupt_writes_under(&d1, 2);
    let (r, fill) = a
        .disk_add_with(&d1, "shelf", "data-01", "", &mut |_| {})
        .unwrap();
    let why = fill.failed.expect("the fill should stop");
    assert!(why.contains("data-01") && why.contains("failing"), "{why}");
    assert_eq!(r.objects_added, 0);
    assert!(objects_under(&d1).is_empty());
    assert!(a
        .disk_add(&lab.mount("d9", 50 * GIB, 100 * GIB), "shelf", "data-01")
        .is_err());

    // One bad read-back is retried; afterwards every copy hashes right.
    pool::corrupt_writes_under(&d1, 1);
    let mut phases = Vec::new();
    let r = a
        .disk_insert("data-01", Default::default(), &mut |p| {
            if phases.last() != Some(&p.phase) {
                phases.push(p.phase);
            }
        })
        .unwrap();
    assert_eq!(phases, ["tidy", "verify", "fill"]);
    assert!(r.fill.failed.is_none());
    assert!(r.fill.objects > 1);
    // The blocks go to the disk in packs.
    let files = objects_under(&d1);
    assert!(!files.is_empty() && files.len() as u64 <= r.fill.objects);
    assert!(files.iter().all(|f| intact(f)));
    // Written and read back now: nothing is due for a check.
    let again = a
        .disk_insert("data-01", Default::default(), &mut |_| {})
        .unwrap();
    assert_eq!(again.verified_objects, 0);
    assert_eq!(again.fill.objects, 0);
}

#[test]
fn insert_tidies_from_listings_rehashes_only_stale_copies_and_fills_within_the_reserve() {
    let lab = Lab::new();
    let home = lab.root.join("a-home");
    let (mut a, _) = engine(&home, "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    a.add_folder("docs", &docs).unwrap();
    // One small file (one block) per push: one pack each.
    for i in 0..6 {
        fs::write(
            docs.join(format!("one-{i}.bin")),
            pseudo_random(900, 31 + 2 * i),
        )
        .unwrap();
        a.push("docs").unwrap();
    }
    let mut files = objects_under(&d1);
    files.sort();
    assert!(files.len() >= 6);

    // Unneeded: an object nothing references, and a leftover temporary
    // file of a write that died an hour ago (a fresh one is left alone).
    let stray_name = hex::encode(varsto_core::crypto::hash(b"stray"));
    let stray = d1
        .join(pool::DATA_DIR)
        .join("packs")
        .join(&stray_name[..2])
        .join(&stray_name);
    fs::create_dir_all(stray.parent().unwrap()).unwrap();
    fs::write(&stray, b"stray").unwrap();
    let dir = files[0].parent().unwrap().to_path_buf();
    let old_tmp = dir.join(".x.tmp-1-1");
    let new_tmp = dir.join(".y.tmp-1-2");
    fs::write(&old_tmp, b"half").unwrap();
    fs::write(&new_tmp, b"half").unwrap();
    fs::File::options()
        .write(true)
        .open(&old_tmp)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7200))
        .unwrap();

    // Half of the copies were last checked long ago; one of those and one
    // fresh copy are damaged on the disk.
    let idx_path = pool_index_path(&home, &d1);
    let mut idx: serde_json::Value = serde_json::from_slice(&fs::read(&idx_path).unwrap()).unwrap();
    let disk_id = DiskMarker::read(&d1).unwrap().disk_id;
    let key_of = |f: &Path| {
        f.strip_prefix(d1.join(pool::DATA_DIR))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
    };
    let stale: Vec<&PathBuf> = files.iter().step_by(2).collect();
    for f in &stale {
        idx["objects"][key_of(f)]["checked"][&disk_id] = serde_json::json!(1_000);
    }
    fs::write(&idx_path, serde_json::to_vec(&idx).unwrap()).unwrap();
    let rotten_stale = stale[0].clone();
    let rotten_fresh = files[1].clone();
    for f in [&rotten_stale, &rotten_fresh] {
        let mut b = fs::read(f).unwrap();
        b[0] ^= 0xff;
        fs::write(f, b).unwrap();
    }
    // A new file to fill, but the disk has no room above its reserve yet.
    fs::write(docs.join("two.bin"), pseudo_random(60_000, 32)).unwrap();
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 5 * GIB,
            total: 100 * GIB,
        }),
    );
    {
        // The push cannot use the full disk either.
        let push = a.push("docs").unwrap();
        assert_eq!(push.storages_unavailable, vec!["shelf".to_string()]);
    }
    let r = a
        .disk_insert("data-01", Default::default(), &mut |_| {})
        .unwrap();
    assert_eq!(r.tidy.unneeded_removed, 1);
    assert_eq!(r.tidy.temp_removed, 1);
    assert!(!stray.exists() && !old_tmp.exists() && new_tmp.exists());
    assert_eq!(r.verified_objects as usize, stale.len() - 1);
    assert_eq!(r.bad, vec![key_of(&rotten_stale)]);
    assert!(!rotten_stale.exists(), "a bad copy is removed");
    // Only stale copies were read: the damaged fresh one is still there.
    assert!(rotten_fresh.exists() && !intact(&rotten_fresh));
    // No room: nothing written, the bad copy is not replaced yet.
    assert_eq!(r.fill.objects, 0);

    // With room the next insert re-hashes nothing and fills the lacking
    // blocks: the bad copy again and the new file.
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
    let r = a
        .disk_insert("data-01", Default::default(), &mut |_| {})
        .unwrap();
    assert_eq!(r.verified_objects, 0);
    assert!(r.fill.objects >= 2, "{:?}", r.fill);
    // The bad copy's block and the new file's blocks went into one new pack.
    let now = objects_under(&d1);
    assert_eq!(now.len(), files.len());
    assert!(now
        .iter()
        .filter(|f| **f != rotten_fresh)
        .all(|f| intact(f)));
    let disks = a.disks().unwrap();
    assert!(disks[0].last_verified_utc > 1_000);

    // verify_after_days 0: every copy is re-hashed, and the damaged fresh one is found.
    a.set_pool_verify_after_days("shelf", 0).unwrap();
    let r = a
        .disk_insert("data-01", Default::default(), &mut |_| {})
        .unwrap();
    assert_eq!(r.bad, vec![key_of(&rotten_fresh)]);
    assert_eq!(r.fill.objects, 1);
    assert!(objects_under(&d1)
        .iter()
        .filter(|f| f != &&new_tmp)
        .all(|f| intact(f)));
    // --no-verify --no-fill: only the tidy phase.
    let r = a
        .disk_insert(
            "data-01",
            varsto_core::engine::InsertOptions {
                verify: false,
                fill: false,
            },
            &mut |_| {},
        )
        .unwrap();
    assert_eq!(r.verified_objects + r.fill.objects, 0);
}

fn row(e: &mut Engine, label: &str) -> varsto_core::pool::DiskStatus {
    e.disk_report()
        .unwrap()
        .into_iter()
        .find(|d| d.label == label)
        .unwrap()
}

#[test]
fn bookkeeping_follows_add_check_fill_and_eject_and_the_overdue_disk_is_suggested() {
    use varsto_core::blockdev::{FsckOutcome, FsckVerdict};
    use varsto_core::diskconf::{self, DiskConf, Drive};
    let lab = Lab::new();
    let home = lab.root.join("a-home");
    let (mut a, _) = engine(&home, "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    a.disk_add(&d1, "shelf", "Blue 4TB").unwrap();
    // Add: measured.
    let r = row(&mut a, "Blue 4TB");
    assert_eq!(
        (r.free_bytes, r.capacity_bytes),
        (Some(50 * GIB), 100 * GIB)
    );
    assert_eq!(r.reserve_bytes, 5 * GIB);
    assert!(r.space_measured_utc > 0);
    assert_eq!(r.verify_after_days, pool::DEFAULT_VERIFY_AFTER_DAYS);

    let docs = lab.root.join("a-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("one.bin"), pseudo_random(120_000, 41)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    // A second push: a second pack, of one small block.
    fs::write(docs.join("one-b.bin"), pseudo_random(1_000, 43)).unwrap();
    a.push("docs").unwrap();
    let r = row(&mut a, "Blue 4TB");
    assert!(r.objects >= 1);
    assert_eq!(r.copies_overdue, 0, "written and read back just now");
    assert_eq!(r.only_copy_objects, Some(0), "the box holds them too");
    assert_eq!(r.lacking_bytes, Some(0));
    assert_eq!(r.reclaimable_bytes, 0);

    // Check: measured again.
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 40 * GIB,
            total: 100 * GIB,
        }),
    );
    a.disk_check("Blue 4TB", false).unwrap();
    let recorded = |mount: &Path| -> (u64, i64) {
        let idx: serde_json::Value =
            serde_json::from_slice(&fs::read(pool_index_path(&home, mount)).unwrap()).unwrap();
        let id = DiskMarker::read(mount).unwrap().disk_id;
        let d = &idx["disks"][&id];
        (
            d["free_bytes"].as_u64().unwrap(),
            d["space_measured_utc"].as_i64().unwrap(),
        )
    };
    assert_eq!(recorded(&d1).0, 40 * GIB);
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 41 * GIB,
            total: 100 * GIB,
        }),
    );
    // Fill (a second disk added and filled; the insert routine measures at its end).
    let d2 = lab.mount("d2", 30 * GIB, 60 * GIB);
    a.disk_add(&d2, "shelf", "Red 2TB").unwrap();
    fs::write(docs.join("two.bin"), pseudo_random(60_000, 42)).unwrap();
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 5 * GIB,
            total: 100 * GIB,
        }),
    );
    a.push("docs").unwrap();
    pool::set_fake_space(
        &d2,
        Some(DiskSpace {
            free: 29 * GIB,
            total: 60 * GIB,
        }),
    );
    let ins = a
        .disk_insert("Red 2TB", Default::default(), &mut |_| {})
        .unwrap();
    assert_eq!(
        ins.fill.objects, 0,
        "the push already wrote two.bin to Red 2TB"
    );
    assert_eq!(recorded(&d2).0, 29 * GIB);

    // Eject: measured; away, the last measurement stays.
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 45 * GIB,
            total: 100 * GIB,
        }),
    );
    a.disk_eject("Blue 4TB").unwrap();
    let away = lab.root.join("away");
    fs::create_dir_all(&away).unwrap();
    fs::rename(&d1, away.join("d1")).unwrap();
    let before = row(&mut a, "Blue 4TB");
    assert!(!before.attached);
    assert_eq!(before.free_bytes, Some(45 * GIB));
    assert!(before.space_measured_utc > 0);

    // Its copies were last checked long ago; one of its blocks was deleted while away.
    let idx_path = pool_index_path(&home, &away.join("d1"));
    let mut idx: serde_json::Value = serde_json::from_slice(&fs::read(&idx_path).unwrap()).unwrap();
    let disk_id = DiskMarker::read(&away.join("d1")).unwrap().disk_id;
    // The smallest pack first: the one block deleted below.
    let mut keys: Vec<(u64, String)> = idx["objects"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, e)| e["disk"] == serde_json::json!(disk_id))
        .map(|(k, e)| (e["size"].as_u64().unwrap_or(0), k.clone()))
        .collect();
    keys.sort();
    let keys: Vec<String> = keys.into_iter().map(|(_, k)| k).collect();
    for k in &keys {
        idx["objects"][k]["checked"][&disk_id] = serde_json::json!(1_000);
    }
    fs::write(&idx_path, serde_json::to_vec(&idx).unwrap()).unwrap();
    {
        let pool = a.open_storage("shelf").unwrap();
        pool.delete(&keys[0]).unwrap();
    }
    let r = row(&mut a, "Blue 4TB");
    assert_eq!(r.copies_overdue, r.objects);
    assert_eq!(r.overdue_share, 1.0);
    assert_eq!(r.oldest_check_utc, Some(1_000));
    assert_eq!(r.pending_deletes, 1);
    assert!(r.reclaimable_bytes > 0 && r.reclaimable_bytes == r.pending_delete_bytes);
    // The deleted block is still referenced: the pool lacks it, Red 2TB can take it.
    let red = row(&mut a, "Red 2TB");
    assert!(red.lacking_bytes.unwrap() > 0);
    assert_eq!(red.fill_potential_bytes, red.lacking_bytes);

    let s = a.disk_suggestions().unwrap();
    let top = s.top.as_ref().expect("the overdue disk is suggested");
    assert_eq!(top.label, "Blue 4TB");
    assert_eq!(top.reasons[0].kind, "overdue");
    assert!(
        top.summary.starts_with("«Blue 4TB»: 100 % of its copies"),
        "{}",
        top.summary
    );
    assert!(top.summary.contains("(oldest 1970-01-01)"));
    assert_eq!(top.command, "varsto disk insert \"Blue 4TB\"");
    assert_eq!(s.overdue, vec!["Blue 4TB".to_string()]);
    assert_eq!(s.attached.len(), 1);
    assert_eq!(s.attached[0].label, "Red 2TB");
    // The weekly reminder: once, then not again within the week; off when turned off.
    let now = varsto_core::util::now_utc();
    let msg = a.disk_overdue_reminder(&s, now).expect("first reminder");
    assert!(msg.contains("varsto disk insert \"Blue 4TB\""), "{msg}");
    assert!(a.disk_overdue_reminder(&s, now + 86_400).is_none());
    assert!(a.disk_overdue_reminder(&s, now + 8 * 86_400).is_some());
    let mut st = a.disk_suggest_settings();
    st.notify_overdue = false;
    a.set_disk_suggest_settings(st).unwrap();
    assert!(a.disk_overdue_reminder(&s, now + 30 * 86_400).is_none());

    // A file system check that left errors: listed apart, never suggested.
    let uuid = "0a1b2c3d-0000-4000-8000-00000000abcd";
    let mut conf = DiskConf::load(&home).unwrap();
    conf.upsert(Drive {
        partuuid: uuid.into(),
        pool: "shelf".into(),
        label: "Blue 4TB".into(),
    })
    .unwrap();
    conf.save(&home).unwrap();
    diskconf::record_check(
        &home,
        uuid,
        &FsckOutcome {
            partition: "/dev/sdx1".into(),
            code: 4,
            verdict: FsckVerdict::Uncorrected,
            summary: String::new(),
            stderr: String::new(),
            checked_utc: now,
        },
    )
    .unwrap();
    let r = row(&mut a, "Blue 4TB");
    assert!(r.failing);
    assert_eq!(r.fsck.as_ref().unwrap().verdict, FsckVerdict::Uncorrected);
    let s = a.disk_suggestions().unwrap();
    assert!(s.top.is_none());
    assert_eq!(s.excluded.len(), 1);
    assert!(
        s.excluded[0].warning.contains("could not be repaired"),
        "{}",
        s.excluded[0].warning
    );
    // The cheap listing carries the file system check as well.
    let cheap = a.disks().unwrap();
    assert!(cheap.iter().any(|d| d.label == "Blue 4TB" && d.failing));
}

#[test]
fn a_disk_with_a_copied_marker_is_not_adopted_until_the_user_adds_it() {
    let lab = Lab::new();
    let d1 = lab.mount("d1", 50 * GIB, 100 * GIB);
    let (mut a, vault_key) = engine(&lab.root.join("a-home"), "laptop");
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec("shelf")).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    // Anyone who holds the disk can read its marker, which has no secret in
    // it, and put the same fields on another disk under an id of their own.
    let forged = lab.mount("forged", 80 * GIB, 100 * GIB);
    let mut m = DiskMarker::read(&d1).unwrap();
    m.disk_id = "f".repeat(32);
    m.label = "data-02".into();
    m.mac_hex.clear();
    fs::create_dir_all(forged.join("varsto")).unwrap();
    fs::write(DiskMarker::path(&forged), serde_json::to_vec(&m).unwrap()).unwrap();
    drop(a);

    // Another device of the vault sees the real disk and not the forged one:
    // it would otherwise be the favourite write target (most free space).
    let mut b = Engine::join(
        &lab.root.join("b-home"),
        "desk",
        PASS,
        &vault_key,
        lab.box_spec(),
    )
    .unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.add_storage(lab.pool_spec("shelf")).unwrap();
    let labels: Vec<String> = b.disks().unwrap().into_iter().map(|d| d.label).collect();
    assert_eq!(labels, ["data-01"]);
    let unknown = b.unknown_pool_disks();
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].0, "shelf");
    assert_eq!(unknown[0].2, "data-02");
    let docs = lab.root.join("b-docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("x.bin"), pseudo_random(50_000, 3)).unwrap();
    b.add_folder("docs", &docs).unwrap();
    b.push("docs").unwrap();
    assert!(
        objects_under(&forged).is_empty(),
        "nothing is written to it"
    );
    assert!(!objects_under(&d1).is_empty());
    // The user can take it in on purpose; it then has a MAC of the vault.
    b.disk_add(&forged, "shelf", "data-02").unwrap();
    assert!(b.unknown_pool_disks().is_empty());
    assert!(!DiskMarker::read(&forged).unwrap().mac_hex.is_empty());
    assert_eq!(b.disks().unwrap().len(), 2);
}
