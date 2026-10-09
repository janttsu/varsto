// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Removable-disk pool (plan 6.35, 6.41): disks are temporary directories
//! under a scan root; capacity is simulated through the free-space hook.

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
        }
    }
    fn box_spec(&self) -> StorageSpec {
        StorageSpec::LocalDir {
            name: "box".into(),
            path: self.root.join("box"),
            cold: false,
            carrier: false,
            place: String::new(),
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

fn objects_under(mount: &Path) -> Vec<PathBuf> {
    let data = mount.join(pool::DATA_DIR).join("chunks");
    if !data.exists() {
        return vec![];
    }
    walkdir::WalkDir::new(&data)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
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
    fs::remove_dir_all(lab.root.join("box/chunks")).unwrap();
    a.disk_eject("data-01").unwrap();
    let idx = DiskIndex::read(&d1).expect("eject writes the disk index");
    assert!(!idx.objects.is_empty());
    assert_eq!(idx.label, "data-01");
    drop(a);

    // Device B joins through the box, adds a pool of the same name and adopts
    // the attached disk from its index.
    let b_home = lab.root.join("b-home");
    let mut b = Engine::join(&b_home, "desk", PASS, &vault_key, lab.box_spec()).unwrap();
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
    a.add_folder("docs", &docs).unwrap();
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
        assert!(pool.list("chunks/").unwrap().contains(&key));
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
    // The object is still referenced by a current file, so the check put it back.
    assert_eq!(r.objects_added, 1);
    assert!(d1.join(pool::DATA_DIR).join(&key).exists());
    let disks = a.disks().unwrap();
    assert_eq!(disks[0].pending_deletes, 0);
    assert!(disks[0].last_verified_utc > 0);

    // A corrupted object is found by a full check and replaced from the local file.
    let victim = &objects_under(&d1)[0];
    fs::write(victim, b"rotten").unwrap();
    let r = a.disk_check("data-01", true).unwrap();
    assert_eq!(r.bad.len(), 1);
    assert_eq!(r.objects_added, 1);
    assert_ne!(fs::read(victim).unwrap(), b"rotten");
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
    a.add_folder("docs", &docs).unwrap();
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
    a.add_folder("docs", &docs).unwrap();
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
