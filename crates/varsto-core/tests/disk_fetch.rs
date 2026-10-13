// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pool disks as a source for large fetches, and fills that keep files
//! whole: plans compare the disks with the network, run disk by disk
//! through a driver (here: directories moved in and out of a scan root),
//! and the files come out byte-identical.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{
    DiskFetchSettings, DiskStep, Engine, FetchPlan, InsertAnswer, PlanDriver,
};
use varsto_core::pool::{self, DiskSpace};
use varsto_core::price::StoragePrice;
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
    shelf: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let mounts = root.join("mounts");
        let shelf = root.join("shelf");
        fs::create_dir_all(&mounts).unwrap();
        fs::create_dir_all(&shelf).unwrap();
        Lab {
            root,
            mounts,
            shelf,
            _tmp: tmp,
        }
    }
    fn pool_spec(&self) -> StorageSpec {
        StorageSpec::Pool {
            name: "shelf".into(),
            place: "home".into(),
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
            place: "cloud".into(),
            min_free: None,
        }
    }
    /// A mounted disk with `room` bytes above the pool's reserve (5 GiB of 100).
    fn mount(&self, name: &str, room: u64) -> PathBuf {
        let m = self.mounts.join(name);
        fs::create_dir_all(&m).unwrap();
        pool::set_fake_space(
            &m,
            Some(DiskSpace {
                free: 5 * GIB + room,
                total: 100 * GIB,
            }),
        );
        m
    }
    /// Take a disk off to the shelf, or plug it in again.
    fn unplug(&self, name: &str) {
        fs::rename(self.mounts.join(name), self.shelf.join(name)).unwrap();
    }
    fn plug(&self, name: &str) {
        fs::rename(self.shelf.join(name), self.mounts.join(name)).unwrap();
    }
}

fn engine(home: &Path) -> Engine {
    let (mut e, _) = Engine::init(home, "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

fn priced(e: &mut Engine, egress: f64) {
    e.set_storage_price(
        "box",
        Some(StoragePrice {
            egress_per_gb: Some(egress),
            currency: "EUR".into(),
            ..Default::default()
        }),
    )
    .unwrap();
}

/// A vault with a box and a pool, a folder `docs` with the given files
/// pushed to the box only.
fn setup(lab: &Lab, files: &[(&str, usize, u64)]) -> (Engine, PathBuf) {
    let mut a = engine(&lab.root.join("home"));
    a.add_storage(lab.box_spec()).unwrap();
    a.add_storage(lab.pool_spec()).unwrap();
    let docs = lab.root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    for (name, len, seed) in files {
        fs::write(docs.join(name), pseudo_random(*len, *seed)).unwrap();
    }
    a.add_folder("docs", &docs).unwrap();
    let push = a.push("docs").unwrap();
    if !files.is_empty() {
        assert_eq!(push.storages_unavailable, vec!["shelf".to_string()]);
    }
    (a, docs)
}

#[test]
fn a_fill_keeps_files_whole_and_splits_only_to_use_the_last_space() {
    let lab = Lab::new();
    let (mut a, _) = setup(
        &lab,
        &[
            ("big.bin", 70_000, 1),
            ("mid.bin", 50_000, 3),
            ("small.bin", 20_000, 5),
        ],
    );
    // 100 kB above the reserve: big and small fit whole; mid does not fit
    // after big, so it is the one split to use the space that is left.
    let d1 = lab.mount("d1", 100_000);
    let (_, fill) = a
        .disk_add_with(&d1, "shelf", "d1", "", &mut |_| {})
        .unwrap();
    assert_eq!((fill.files_whole, fill.files_split), (2, 1), "{fill:?}");
    assert!(fill.bytes <= 100_000);
    // The next disk takes the rest of mid.bin, whole.
    let d2 = lab.mount("d2", 10 * GIB);
    let (_, fill) = a
        .disk_add_with(&d2, "shelf", "d2", "", &mut |_| {})
        .unwrap();
    assert_eq!((fill.files_whole, fill.files_split), (1, 0), "{fill:?}");
    // With room for everything nothing is split.
    let lab = Lab::new();
    let (mut a, _) = setup(&lab, &[("big.bin", 70_000, 1), ("mid.bin", 50_000, 3)]);
    let d = lab.mount("d", GIB);
    let (_, fill) = a.disk_add_with(&d, "shelf", "d", "", &mut |_| {}).unwrap();
    assert_eq!((fill.files_whole, fill.files_split), (2, 0));
}

#[test]
fn a_large_costly_fetch_proposes_the_disk_and_a_small_one_stays_remote() {
    let lab = Lab::new();
    let (mut a, _) = setup(&lab, &[("big.bin", 300_000, 7), ("small.bin", 5_000, 9)]);
    let d1 = lab.mount("d1", GIB);
    a.disk_add(&d1, "shelf", "d1").unwrap();
    lab.unplug("d1");
    priced(&mut a, 0.09);
    a.set_disk_fetch_settings(DiskFetchSettings {
        threshold_bytes: 100_000,
        ..Default::default()
    })
    .unwrap();
    let plan = a.fetch_plan("docs", &["big.bin".to_string()]).unwrap();
    assert_eq!(plan.recommend, "disks", "{plan:?}");
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].label, "d1");
    assert!(!plan.steps[0].attached);
    assert_eq!(plan.steps[0].bytes, plan.total_bytes);
    assert_eq!(plan.remote_part_bytes, 0);
    assert!(plan.remote.possible);
    assert!(plan.remote.cost.unwrap() > 0.0);
    assert_eq!(plan.remote.currency, "EUR");
    assert!(plan.reason.contains("cheaper"), "{}", plan.reason);
    // Below the threshold: the network, as before.
    let plan = a.fetch_plan("docs", &["small.bin".to_string()]).unwrap();
    assert_eq!(plan.recommend, "remote");
    assert!(plan.steps.is_empty());
    assert!(plan.reason.contains("below"), "{}", plan.reason);
    // Free network and a slow walk to the shelf: remote, even when large.
    priced(&mut a, 0.0);
    a.set_disk_fetch_settings(DiskFetchSettings {
        threshold_bytes: 100_000,
        overhead_secs: 600,
        ..Default::default()
    })
    .unwrap();
    let plan = a.fetch_plan("docs", &["big.bin".to_string()]).unwrap();
    assert_eq!(plan.recommend, "remote", "{plan:?}");
}

/// Disks that each hold one file: every file is pushed while only its
/// disk is plugged in.
fn one_file_per_disk(lab: &Lab, a: &mut Engine, docs: &Path, files: &[(&str, usize, u64, &str)]) {
    for (name, len, seed, disk) in files {
        let m = lab.mount(disk, GIB);
        a.disk_add(&m, "shelf", disk).unwrap();
        fs::write(docs.join(name), pseudo_random(*len, *seed)).unwrap();
        let push = a.push("docs").unwrap();
        assert!(push.storages_unavailable.is_empty());
        lab.unplug(disk);
    }
}

#[test]
fn disks_are_ordered_attached_first_then_by_the_bytes_they_hold() {
    let lab = Lab::new();
    let (mut a, docs) = setup(&lab, &[]);
    one_file_per_disk(
        &lab,
        &mut a,
        &docs,
        &[
            ("c.bin", 20_000, 23, "d1"),
            ("b.bin", 60_000, 25, "d2"),
            ("a.bin", 30_000, 27, "d3"),
        ],
    );
    lab.plug("d3");
    priced(&mut a, 0.09);
    a.set_disk_fetch_settings(DiskFetchSettings {
        threshold_bytes: 1,
        ..Default::default()
    })
    .unwrap();
    let all: Vec<String> = ["a.bin", "b.bin", "c.bin"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let plan = a.fetch_plan("docs", &all).unwrap();
    assert_eq!(plan.recommend, "disks");
    let order: Vec<(&str, bool)> = plan
        .steps
        .iter()
        .map(|s| (s.label.as_str(), s.attached))
        .collect();
    assert_eq!(
        order,
        [("d3", true), ("d2", false), ("d1", false)],
        "{plan:?}"
    );
}

/// Plays the user: plugs the asked disk in, unplugs it when told to.
struct Shelf<'a> {
    lab: &'a Lab,
    asked: Vec<String>,
    released: Vec<String>,
    said: Vec<String>,
    /// Answer "skip" for this label.
    skip: Option<&'static str>,
}

impl PlanDriver for Shelf<'_> {
    fn ask(&mut self, plan: &FetchPlan, k: usize) -> anyhow::Result<InsertAnswer> {
        let label = plan.steps[k].label.clone();
        self.asked.push(label.clone());
        if self.skip == Some(label.as_str()) {
            return Ok(InsertAnswer::Skip);
        }
        Ok(InsertAnswer::Inserted)
    }
    fn attach(&mut self, step: &DiskStep) -> anyhow::Result<bool> {
        if self.lab.shelf.join(&step.label).exists() {
            self.lab.plug(&step.label);
        }
        Ok(self.lab.mounts.join(&step.label).exists())
    }
    fn release(&mut self, step: &DiskStep, mount: &Path) -> anyhow::Result<()> {
        assert!(mount.ends_with(&step.label));
        self.lab.unplug(&step.label);
        self.released.push(step.label.clone());
        Ok(())
    }
    fn say(&mut self, message: &str) {
        self.said.push(message.to_string());
    }
}

#[test]
fn a_file_on_two_disks_is_fetched_disk_by_disk_byte_identical() {
    let lab = Lab::new();
    let (mut a, docs) = setup(&lab, &[("film.bin", 200_000, 29)]);
    let original = fs::read(docs.join("film.bin")).unwrap();
    // The file is larger than d1's room: split over d1 and d2.
    let d1 = lab.mount("d1", 120_000);
    let (_, f1) = a
        .disk_add_with(&d1, "shelf", "d1", "", &mut |_| {})
        .unwrap();
    assert_eq!(f1.files_split, 1);
    let d2 = lab.mount("d2", GIB);
    a.disk_add(&d2, "shelf", "d2").unwrap();
    lab.unplug("d1");
    lab.unplug("d2");
    priced(&mut a, 0.09);
    a.set_disk_fetch_settings(DiskFetchSettings {
        threshold_bytes: 100_000,
        ..Default::default()
    })
    .unwrap();
    let mut plan = a.fetch_plan("docs", &["film.bin".to_string()]).unwrap();
    assert_eq!(plan.steps.len(), 2, "{plan:?}");
    assert!(plan.steps.iter().all(|s| !s.attached));
    // Nothing comes from the network: its copies are gone.
    common::lose_all_objects(&lab.root.join("box"));
    fs::remove_file(docs.join("film.bin")).unwrap();
    let mut shelf = Shelf {
        lab: &lab,
        asked: vec![],
        released: vec![],
        said: vec![],
        skip: None,
    };
    let r = a.run_fetch_plan(&mut plan, &mut shelf).unwrap();
    assert!(r.files_failed.is_empty(), "{r:?}");
    assert_eq!(r.files_done, vec!["film.bin".to_string()]);
    assert_eq!(fs::read(docs.join("film.bin")).unwrap(), original);
    assert_eq!(shelf.asked, shelf.released);
    assert_eq!(shelf.released.len(), 2);
    assert!(
        shelf
            .said
            .iter()
            .all(|m| m.contains("you can now remove it")),
        "{:?}",
        shelf.said
    );
    // Both disks are back on the shelf, and the staging area is gone.
    assert!(!lab.mounts.join("d1").exists() && !lab.mounts.join("d2").exists());
    assert!(!lab.root.join("home").join("disk-fetch").exists());
    assert!(a.load_fetch_plan().is_none());
}

#[test]
fn a_skipped_disk_leaves_its_file_for_the_network_and_the_others_are_written() {
    let lab = Lab::new();
    let (mut a, docs) = setup(&lab, &[]);
    one_file_per_disk(
        &lab,
        &mut a,
        &docs,
        &[("one.bin", 60_000, 31, "d1"), ("two.bin", 60_000, 33, "d2")],
    );
    priced(&mut a, 0.09);
    a.set_disk_fetch_settings(DiskFetchSettings {
        threshold_bytes: 1,
        ..Default::default()
    })
    .unwrap();
    let both = vec!["one.bin".to_string(), "two.bin".to_string()];
    let mut plan = a.fetch_plan("docs", &both).unwrap();
    assert_eq!(plan.steps.len(), 2);
    let skipped = plan.steps[1].label.clone();
    let originals: Vec<Vec<u8>> = both
        .iter()
        .map(|p| fs::read(docs.join(p)).unwrap())
        .collect();
    for p in &both {
        fs::remove_file(docs.join(p)).unwrap();
    }
    let skip: &'static str = if skipped == "d1" { "d1" } else { "d2" };
    let mut shelf = Shelf {
        lab: &lab,
        asked: vec![],
        released: vec![],
        said: vec![],
        skip: Some(skip),
    };
    // The box still has every block: the skipped disk's file comes from it.
    let r = a.run_fetch_plan(&mut plan, &mut shelf).unwrap();
    assert!(r.files_failed.is_empty(), "{r:?}");
    assert_eq!(shelf.released.len(), 1);
    for (p, want) in both.iter().zip(originals) {
        assert_eq!(fs::read(docs.join(p)).unwrap(), want);
    }
}
