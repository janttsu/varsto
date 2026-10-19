// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Staged moves to a disk pool: a folder moves, disk by disk, from a
//! storage to a pool whose disks are docked one at a time. Pools are
//! directories ("attach" = a mount directory appears under the scan root);
//! a disk's size is simulated with a capacity that shrinks as it fills.

mod common;

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{Engine, JobRunLimits, MoveJobRequest};
use varsto_core::placement::Placement;
use varsto_core::pool;
use varsto_core::staged_move::JobState;
use varsto_core::storage::StorageSpec;

const PASS: &str = "correct horse battery staple";

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
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
    home: PathBuf,
}

impl Lab {
    /// An engine with a source storage `box`, a pool `shelf` (no reserve)
    /// with `copies`, and a folder `docs` of three files in two
    /// directories, pushed to `box` only.
    fn new(copies: u32) -> (Lab, Engine) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let mounts = root.join("mounts");
        fs::create_dir_all(&mounts).unwrap();
        let home = root.join("home");
        let lab = Lab {
            home: home.clone(),
            mounts: mounts.clone(),
            root: root.clone(),
            _tmp: tmp,
        };
        let (mut a, _) = Engine::init(&home, "laptop", PASS).unwrap();
        a.chunker = ChunkerParams::SMALL;
        a.add_storage(StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("box"),
            cold: false,
            carrier: false,
            place: "cloud".into(),
            min_free: None,
        })
        .unwrap();
        a.add_storage(StorageSpec::Pool {
            name: "shelf".into(),
            place: "shelf".into(),
            reserve_percent: 0,
            min_reserve_bytes: 0,
            disks: vec![],
            scan_roots: vec![mounts],
            copies,
            verify_after_days: pool::DEFAULT_VERIFY_AFTER_DAYS,
        })
        .unwrap();
        let docs = root.join("docs");
        fs::create_dir_all(docs.join("sub")).unwrap();
        fs::create_dir_all(docs.join("other")).unwrap();
        a.add_folder("docs", &docs).unwrap();
        a.set_policy("docs", None).unwrap();
        // The pool is not written by pushes or disk fills: only the job fills it.
        a.set_placement(
            "docs",
            Some(Placement {
                storages: vec!["box".into()],
                ..Default::default()
            }),
        )
        .unwrap();
        // One push per file: a pack of its own each, so a job has several
        // packs (groups) to work through.
        for (path, seed) in [("sub/x.bin", 1), ("sub/y.bin", 2), ("other/z.bin", 3)] {
            fs::write(docs.join(path), pseudo_random(6_000_000, seed)).unwrap();
            a.push("docs").unwrap();
        }
        (lab, a)
    }

    fn reopen(&self) -> Engine {
        let mut e = Engine::open(&self.home, PASS).unwrap();
        e.chunker = ChunkerParams::SMALL;
        e
    }

    /// A mounted, empty disk directory of `capacity` bytes.
    fn mount(&self, name: &str, capacity: u64) -> PathBuf {
        let m = self.mounts.join(name);
        fs::create_dir_all(&m).unwrap();
        pool::set_fake_capacity(&m, Some(capacity));
        m
    }

    /// Take a disk away (unmount) and bring it back.
    fn detach(&self, name: &str) -> PathBuf {
        let away = self.root.join("away");
        fs::create_dir_all(&away).unwrap();
        fs::rename(self.mounts.join(name), away.join(name)).unwrap();
        away.join(name)
    }
    fn attach(&self, name: &str) {
        fs::rename(self.root.join("away").join(name), self.mounts.join(name)).unwrap();
    }
}

/// Blocks (and bytes) of the folder the ledger shows on a storage: a live
/// place of each in a pack held there.
fn on(e: &Engine, storage: &str) -> (usize, u64) {
    (
        e.objects_on_storage3(storage).unwrap().len(),
        e.block_bytes_on_storage3(storage).unwrap(),
    )
}

/// Every block of the folder (all on "box" at the start).
fn total_blocks(e: &Engine) -> (usize, u64) {
    on(e, "box")
}

/// Every block of the folder is physically on a storage the ledger names.
fn every_block_present(e: &Engine) {
    let names: Vec<String> = e.storages().iter().map(|s| s.name().to_string()).collect();
    let mut all: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for n in &names {
        for o in e.objects_on_storage3(n).unwrap() {
            all.entry(o).or_default().push(n.clone());
        }
    }
    assert!(!all.is_empty());
    for (o, holders) in all {
        let key = format!("chunks/{}/{}", &o[..2], o);
        let there = holders.iter().any(|n| {
            e.open_storage(n)
                .unwrap()
                .get(&key)
                .ok()
                .flatten()
                .is_some_and(|b| hex::encode(varsto_core::crypto::hash(&b)) == o)
        });
        assert!(there, "block {} has no readable copy", &o[..8]);
    }
}
fn request(folder: &str) -> MoveJobRequest {
    MoveJobRequest {
        folder: folder.into(),
        from: "box".into(),
        to: "shelf".into(),
        ..Default::default()
    }
}

fn run(e: &mut Engine, id: &str) -> varsto_core::engine::MoveJobRun {
    e.move_job_run(id, &JobRunLimits::default()).unwrap()
}

#[test]
fn a_folder_moves_to_the_pool_one_disk_at_a_time() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    assert!(bytes > 16 << 20, "{bytes} bytes: more than one group");
    assert_eq!(on(&a, "box"), (blocks, bytes));
    let third = bytes / 3 + 20_000;

    // Disk 1 has room for about a third.
    let d1 = lab.mount("d1", third);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    assert_eq!(
        on(&a, "shelf").0,
        0,
        "adding a disk does not fill from the folder"
    );
    let plan = a.move_job_plan(&request("docs")).unwrap();
    assert_eq!((plan.blocks as usize, plan.bytes), (blocks, bytes));
    let (job, existing) = a.move_job_start(&request("docs")).unwrap();
    assert!(!existing);
    assert_eq!(job.bytes_total, bytes);
    // The same request is the same job.
    assert_eq!(a.move_job_start(&request("docs")).unwrap().0.id, job.id);

    let r = run(&mut a, &job.id);
    assert!(r.ran);
    let (on_shelf, shelf_bytes) = on(&a, "shelf");
    assert!(
        on_shelf > 0 && shelf_bytes <= third,
        "{on_shelf} blocks, {shelf_bytes} bytes"
    );
    // About a third of the room is usable once packs are padded to their
    // size classes.
    assert!(
        shelf_bytes * 5 > bytes,
        "about a third moved: {shelf_bytes} of {bytes}"
    );

    // What moved left the box; the rest is still there.
    assert_eq!(on(&a, "box"), (blocks - on_shelf, bytes - shelf_bytes));
    assert_eq!(r.job.state, JobState::Open);
    assert_eq!(r.job.bytes_done, shelf_bytes);
    assert_eq!(r.job.bytes_remaining, bytes - shelf_bytes);
    assert_eq!(r.job.disks_used, vec!["data-01".to_string()]);
    let w = r.job.waiting.clone().expect("the job waits");
    assert_eq!(w.kind, "disk");
    assert!(w.text.contains("new disk"), "{}", w.text);
    every_block_present(&a);

    // Nothing to do until a disk comes or changes: the service does not run it.
    assert!(a.move_jobs_ready(true).is_empty());
    // No known disk has room: a new disk is needed.
    let s = a.disk_suggestions().unwrap();
    assert_eq!(s.moves.len(), 1);
    assert_eq!(s.new_disk_needed.len(), 1);
    assert!(s.new_disk_needed[0].text.contains("a new disk is needed"));
    assert!(s.new_disk_needed[0].command.contains("disk init"));

    // Disk 2 is known but on the shelf: it is the one to dock.
    let d2 = lab.mount("d2", third);
    a.disk_add(&d2, "shelf", "data-02").unwrap();
    let away2 = lab.detach("d2");
    pool::set_fake_capacity(&away2, None);
    let s = a.disk_suggestions().unwrap();
    let top = s.top.expect("a disk is suggested");
    assert_eq!(top.label, "data-02");
    assert!(
        top.reasons.iter().any(|r| r.kind == "move"
            && r.text.starts_with("continue the move of docs: ")
            && r.text.contains(" left; this disk has ")),
        "{:?}",
        top.reasons
    );
    assert!(s.new_disk_needed.is_empty());
    assert!(a.move_jobs()[0].waiting.is_some());
    // Docked, it continues the job.
    lab.attach("d2");
    assert_eq!(a.move_jobs_ready(false), vec![job.id.clone()]);
    let runs = a.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].job.state, JobState::Open);
    assert_eq!(
        runs[0].job.disks_used,
        vec!["data-01".to_string(), "data-02".to_string()]
    );
    let (_, shelf2) = on(&a, "shelf");
    assert!(shelf2 > shelf_bytes && shelf2 <= 2 * third);
    // Waiting again for a disk: nothing runs until something changes.
    assert!(a.move_jobs_ready(true).is_empty());

    // Disk 3 holds the rest.
    let d3 = lab.mount("d3", bytes * 4);
    a.disk_add(&d3, "shelf", "data-03").unwrap();
    let runs = a.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs.len(), 1);
    let job = &runs[0].job;
    assert_eq!(job.state, JobState::Done, "{:?}", job);
    assert_eq!(job.bytes_done, bytes);
    assert_eq!(job.bytes_remaining, 0);
    assert!(job.waiting.is_none() && job.finished_utc > 0);
    assert_eq!(job.disks_used.len(), 3);
    // The box holds none of the folder's blocks; the pool holds all of them.
    assert_eq!(on(&a, "box"), (0, 0));
    assert_eq!(on(&a, "shelf"), (blocks, bytes));
    assert_eq!(common::object_count(&lab.root.join("box")), 0);
    every_block_present(&a);
    // A whole-folder move makes the pool the folder's place for new blocks.
    assert_eq!(
        a.placement("docs").unwrap().targets,
        vec!["shelf".to_string()]
    );
    // Running it again does nothing; it survives a restart as done.
    assert!(!run(&mut a, &job.id).ran);
    let a = lab.reopen();
    assert_eq!(a.move_jobs()[0].state, JobState::Done);
    assert!(a.move_waits().is_empty());
}

#[test]
fn keep_source_copies_without_dropping() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    let d1 = lab.mount("d1", bytes / 2 + 20_000);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let (job, _) = a
        .move_job_start(&MoveJobRequest {
            keep_source: true,
            ..request("docs")
        })
        .unwrap();
    let r = run(&mut a, &job.id);
    assert_eq!(r.job.state, JobState::Open);
    let (on_shelf, shelf_bytes) = on(&a, "shelf");
    assert!(on_shelf > 0 && on_shelf < blocks);
    // The box keeps everything.
    assert_eq!(on(&a, "box"), (blocks, bytes));
    assert_eq!(r.job.bytes_done, shelf_bytes);
    let d2 = lab.mount("d2", bytes * 4);
    a.disk_add(&d2, "shelf", "data-02").unwrap();
    let runs = a.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs[0].job.state, JobState::Done);
    assert_eq!(on(&a, "shelf"), (blocks, bytes));
    assert_eq!(on(&a, "box"), (blocks, bytes));
    // The placement is left alone when the source is kept.
    assert_eq!(
        a.placement("docs").unwrap().targets,
        vec!["box".to_string()]
    );
}

#[test]
fn paths_limit_the_job_to_files_under_them() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    let d1 = lab.mount("d1", bytes * 4);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    // A missing path is refused; an absolute path inside the folder works.
    let mut bad = request("docs");
    bad.paths = vec!["nowhere".into()];
    assert!(a
        .move_job_start(&bad)
        .unwrap_err()
        .to_string()
        .contains("no file"));
    let mut req = request("docs");
    req.paths = vec![lab.root.join("docs/sub").display().to_string()];
    let (job, _) = a.move_job_start(&req).unwrap();
    assert_eq!(job.paths, vec!["sub".to_string()]);
    let r = run(&mut a, &job.id);
    assert_eq!(r.job.state, JobState::Done, "{:?}", r.job);
    let (on_shelf, shelf_bytes) = on(&a, "shelf");
    let (left, left_bytes) = on(&a, "box");
    assert_eq!(on_shelf + left, blocks);
    assert_eq!(shelf_bytes + left_bytes, bytes);
    // Two of three files moved; the third stays.
    assert!(shelf_bytes > left_bytes && left > 0);
    assert_eq!(r.job.bytes_total, shelf_bytes);
    // A path job does not change the folder's placement.
    assert_eq!(
        a.placement("docs").unwrap().targets,
        vec!["box".to_string()]
    );
    // One file, by relative path.
    let mut one = request("docs");
    one.paths = vec!["other/z.bin".into()];
    let (job2, _) = a.move_job_start(&one).unwrap();
    assert_ne!(job2.id, job.id);
    assert_eq!(run(&mut a, &job2.id).job.state, JobState::Done);
    assert_eq!(on(&a, "box"), (0, 0));
    every_block_present(&a);
}

#[test]
fn a_disk_group_rule_needs_two_places_before_the_source_is_dropped() {
    let (lab, mut a) = Lab::new(2);
    let (blocks, bytes) = total_blocks(&a);
    let d1 = lab.mount("d1", bytes * 4);
    a.disk_add_at(&d1, "shelf", "home-01", "home").unwrap();
    let (job, _) = a.move_job_start(&request("docs")).unwrap();
    let r = run(&mut a, &job.id);
    // Copied to the only disk, but one place is not enough: nothing dropped.
    assert_eq!(r.job.state, JobState::Open);
    assert_eq!(r.job.bytes_done, 0);
    assert_eq!(r.job.need_second_place_bytes, bytes);
    assert_eq!(r.job.waiting.as_ref().unwrap().kind, "place");
    assert!(r.job.line().contains("need a second place"));
    assert_eq!(on(&a, "box"), (blocks, bytes));
    assert_eq!(on(&a, "shelf"), (blocks, bytes));
    // Nothing to do until another disk is docked.
    assert!(a.move_jobs_ready(true).is_empty());

    let d2 = lab.mount("d2", bytes * 4);
    a.disk_add_at(&d2, "shelf", "off-01", "offsite").unwrap();
    // `disk add` fills nothing for this folder: the job places the copies.
    let runs = a.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs.len(), 1);
    let job = &runs[0].job;
    assert_eq!(job.state, JobState::Done, "{job:?}");
    assert_eq!(job.need_second_place_bytes, 0);
    assert_eq!(job.bytes_done, bytes);
    assert!(job.disks_used.contains(&"off-01".to_string()));
    assert_eq!(on(&a, "box"), (0, 0));
    let groups = a.disk_groups().unwrap();
    assert_eq!(groups[0].objects_short, 0);
    every_block_present(&a);
}

#[test]
fn pause_resume_and_cancel_leave_the_data_consistent() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    let d1 = lab.mount("d1", bytes * 4);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let (job, _) = a.move_job_start(&request("docs")).unwrap();

    // One group (up to 15 MiB, one pack), then stop.
    let r = a
        .move_job_run(
            &job.id,
            &JobRunLimits {
                max_groups: Some(1),
            },
        )
        .unwrap();
    assert_eq!(r.job.state, JobState::Open);
    assert!(r.report.stopped_early);
    let (moved, moved_bytes) = on(&a, "shelf");
    assert!(moved > 0 && moved < blocks, "{moved} of {blocks}");
    assert_eq!(r.job.bytes_done, moved_bytes);

    // Paused jobs do not run; resume opens them again.
    a.move_job_set_state(&job.id, JobState::Paused).unwrap();
    assert!(!run(&mut a, &job.id).ran);
    assert!(a.move_jobs_ready(true).is_empty());
    assert!(a.move_waits().is_empty() || a.move_job(&job.id).unwrap().state == JobState::Paused);
    a.move_job_set_state(&job.id, JobState::Open).unwrap();

    // Cancel: nothing is deleted, nothing moves back; what moved stays moved.
    let c = a.move_job_set_state(&job.id, JobState::Cancelled).unwrap();
    assert_eq!(c.state, JobState::Cancelled);
    assert!(c.finished_utc > 0);
    assert!(!run(&mut a, &job.id).ran);
    assert_eq!(on(&a, "shelf"), (moved, moved_bytes));
    assert_eq!(on(&a, "box"), (blocks - moved, bytes - moved_bytes));
    every_block_present(&a);
    assert!(a.move_job_set_state(&job.id, JobState::Open).is_err());
    assert!(a.move_waits().is_empty());
    // The folder's policy and sync still work; a new job picks up the rest.
    let (job2, existing) = a.move_job_start(&request("docs")).unwrap();
    assert!(!existing && job2.id != job.id);
    assert_eq!(job2.bytes_total, bytes - moved_bytes);
    assert_eq!(run(&mut a, &job2.id).job.state, JobState::Done);
    assert_eq!(on(&a, "shelf"), (blocks, bytes));
}

#[test]
fn a_job_resumes_after_the_engine_is_dropped_between_groups() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    let d1 = lab.mount("d1", bytes * 4);
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let (job, _) = a.move_job_start(&request("docs")).unwrap();
    let r = a
        .move_job_run(
            &job.id,
            &JobRunLimits {
                max_groups: Some(1),
            },
        )
        .unwrap();
    let (moved, moved_bytes) = on(&a, "shelf");
    assert!(moved > 0 && moved < blocks, "{moved} of {blocks}");
    assert_eq!(r.job.bytes_done, moved_bytes);
    drop(a);

    // A new process: the job is on disk with its progress, no lock is held.
    let mut a = lab.reopen();
    let j = a.move_job(&job.id).unwrap();
    assert_eq!(j.state, JobState::Open);
    assert_eq!(j.bytes_done, moved_bytes);
    assert_eq!(j.bytes_remaining, bytes - moved_bytes);
    assert!(!lab
        .home
        .join("state/moves")
        .join(format!("{}.lock", job.id))
        .exists());
    let r = run(&mut a, &job.id);
    assert_eq!(r.job.state, JobState::Done);
    assert_eq!(r.job.runs, 2);
    assert_eq!(r.job.bytes_done, bytes);
    assert_eq!(on(&a, "shelf"), (blocks, bytes));
    assert_eq!(on(&a, "box"), (0, 0));
    every_block_present(&a);
}

#[test]
fn a_job_to_an_ordinary_storage_runs_after_each_sync_and_two_runs_do_not_overlap() {
    let (lab, mut a) = Lab::new(1);
    let (blocks, bytes) = total_blocks(&a);
    a.add_storage(StorageSpec::LocalDir {
        name: "far".into(),
        path: lab.root.join("far"),
        cold: false,
        carrier: false,
        place: "far".into(),
        min_free: None,
    })
    .unwrap();
    let (job, _) = a
        .move_job_start(&MoveJobRequest {
            to: "far".into(),
            ..request("docs")
        })
        .unwrap();
    // Not for the disk triggers; ready after a sync.
    assert!(a.move_jobs_ready(false).is_empty());
    assert_eq!(a.move_jobs_ready(true), vec![job.id.clone()]);
    // A run in another process holds the lock.
    let lock = varsto_core::staged_move::JobLock::acquire(&lab.home, &job.id).unwrap();
    let r = run(&mut a, &job.id);
    assert!(!r.ran && r.note.unwrap().contains("another process"));
    drop(lock);
    let runs = a.move_jobs_run_ready(true, &JobRunLimits::default());
    assert_eq!(runs[0].job.state, JobState::Done);
    assert_eq!(on(&a, "far"), (blocks, bytes));
    assert_eq!(on(&a, "box"), (0, 0));
}
