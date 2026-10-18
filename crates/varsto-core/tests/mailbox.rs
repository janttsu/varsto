// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The mailbox for offline pool disks (spec section 78). One dock: disk A
//! holds the only copy of blocks that disk B (another place of the same
//! pool, or another pool) should hold too, and the two are never docked at
//! the same time. The dock host stages what B needs while A is docked and
//! writes it when B is docked. Pools are directories ("docked" = the mount
//! directory is under the pool's scan root); the device directory's free
//! space is simulated (`pool::set_fake_space`).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{JobRunLimits, MailboxOptions, MoveJobRequest};
use varsto_core::mailbox::MailboxSettings;
use varsto_core::placement::Placement;
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::pool::{self, DiskSpace};
use varsto_core::staged_move::JobState;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const TB: u64 = 1_000_000_000_000;

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

fn dir(name: &str, path: &Path, place: &str) -> StorageSpec {
    fs::create_dir_all(path).unwrap();
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: place.into(),
        min_free: None,
    }
}

fn pool_spec(name: &str, place: &str, copies: u32, scan: &Path) -> StorageSpec {
    fs::create_dir_all(scan).unwrap();
    StorageSpec::Pool {
        name: name.into(),
        place: place.into(),
        reserve_percent: 0,
        min_reserve_bytes: 0,
        disks: vec![],
        scan_roots: vec![scan.to_path_buf()],
        copies,
        verify_after_days: pool::DEFAULT_VERIFY_AFTER_DAYS,
    }
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
    /// The dock of a host: its pools scan this directory.
    fn dock(&self, host: &str) -> PathBuf {
        self.p(&format!("{host}-dock"))
    }
    /// A new, empty disk docked at `host`.
    fn new_disk(&self, host: &str, name: &str) -> PathBuf {
        let m = self.dock(host).join(name);
        fs::create_dir_all(&m).unwrap();
        pool::set_fake_capacity(&m, Some(TB));
        m
    }
    /// Take a disk out of whichever dock holds it, to the shelf.
    fn undock(&self, name: &str) {
        let shelf = self.p("shelf");
        fs::create_dir_all(&shelf).unwrap();
        for host in ["dock-1", "dock-2"] {
            let at = self.dock(host).join(name);
            if at.exists() {
                fs::rename(&at, shelf.join(name)).unwrap();
                return;
            }
        }
        panic!("disk {name} is not docked");
    }
    /// Put a disk from the shelf into a host's dock.
    fn dock_at(&self, host: &str, name: &str) -> PathBuf {
        let to = self.dock(host).join(name);
        fs::create_dir_all(self.dock(host)).unwrap();
        fs::rename(self.p("shelf").join(name), &to).unwrap();
        to
    }
    fn hub(&self) -> StorageSpec {
        dir("hub", &self.p("hub"), "home")
    }
}

/// A big device directory with plenty of room (the real temporary
/// directory may be small, and the default rule keeps 15 % or 50 GB).
fn roomy(home: &Path) {
    fs::create_dir_all(home).unwrap();
    pool::set_fake_space(
        home,
        Some(DiskSpace {
            free: TB / 2,
            total: TB,
        }),
    );
}

/// The dock host "dock-1": the hub and a pool `shelf` with a disk group
/// rule of two places, disks A (home) and B (offsite), B on the shelf; a
/// folder `docs` written to the pool only, three files pushed one by one
/// (three packs), so they are on A alone.
fn group_lab() -> (Lab, Engine, String) {
    let lab = Lab::new();
    let home = lab.p("dock-1-home");
    roomy(&home);
    let (mut e, key) = Engine::init(&home, "dock-1", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(lab.hub()).unwrap();
    e.add_storage(pool_spec("shelf", "home", 2, &lab.dock("dock-1")))
        .unwrap();
    let a = lab.new_disk("dock-1", "disk-a");
    e.disk_add_at(&a, "shelf", "disk-a", "home").unwrap();
    let b = lab.new_disk("dock-1", "disk-b");
    e.disk_add_at(&b, "shelf", "disk-b", "offsite").unwrap();
    lab.undock("disk-b");
    let docs = lab.p("docs");
    fs::create_dir_all(&docs).unwrap();
    e.add_folder("docs", &docs).unwrap();
    e.set_policy(
        "docs",
        Some(Policy {
            min_copies: 1,
            min_per_place: [("offsite".to_string(), 1)].into_iter().collect(),
            verified_within_days: None,
        }),
    )
    .unwrap();
    e.set_placement(
        "docs",
        Some(Placement {
            storages: vec!["shelf".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    for (i, name) in ["x.bin", "y.bin", "z.bin"].iter().enumerate() {
        fs::write(docs.join(name), pseudo_random(150_000, i as u64 + 1)).unwrap();
        e.push("docs").unwrap();
    }
    (lab, e, key)
}

/// Pack files on a disk directory: (key, path).
fn packs_on(mount: &Path) -> Vec<(String, PathBuf)> {
    let root = mount.join("varsto");
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root.join("packs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.len() == 64 {
            let rel = e.path().strip_prefix(&root).unwrap();
            out.push((rel.to_string_lossy().replace('\\', "/"), e.path().into()));
        }
    }
    out.sort();
    out
}

/// Objects in a device's outbox.
fn outbox(home: &Path) -> Vec<PathBuf> {
    let dir = home.join("outbox");
    if !dir.exists() {
        return Vec::new();
    }
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn intact(path: &Path) -> bool {
    let bytes = fs::read(path).unwrap();
    path.file_name().unwrap().to_string_lossy() == hex::encode(varsto_core::crypto::hash(&bytes))
}

fn docs_policy(e: &Engine) -> varsto_core::policy::PolicyReport {
    e.policy_check()
        .unwrap()
        .into_iter()
        .find(|r| r.folder == "docs")
        .unwrap()
}

fn run(e: &mut Engine) -> varsto_core::mailbox::MailboxReport {
    e.mailbox_run(&MailboxOptions::manual()).unwrap()
}

#[test]
fn blocks_only_on_disk_a_reach_disk_b_through_the_outbox() {
    let (lab, mut e, _) = group_lab();
    let home = lab.p("dock-1-home");
    let a = lab.dock("dock-1").join("disk-a");
    let on_a = packs_on(&a);
    assert_eq!(on_a.len(), 3, "three packs on disk A");
    let policy = docs_policy(&e);
    assert_eq!(policy.state, PolicyState::Violated, "{policy:?}");

    // A is docked, B is away: what B needs is staged.
    let r = run(&mut e);
    assert_eq!(r.staged, 3, "{r:?}");
    assert_eq!(r.delivered, 0);
    let staged = outbox(&home);
    assert_eq!(staged.len(), 3);
    assert!(staged.iter().all(|p| intact(p)));
    let s = e.mailbox_status();
    assert_eq!(s.held_objects, 3);
    assert_eq!(s.groups.len(), 1, "{:?}", s.groups);
    let g = &s.groups[0];
    assert!(
        g.text
            .contains("from disk «disk-a» waiting for disk «disk-b» (staged on this device)"),
        "{}",
        g.text
    );
    assert!(s.describe().starts_with("mailbox: "), "{}", s.describe());

    // The staged copies do not count: the folder is still short, in transit.
    let policy = docs_policy(&e);
    assert_eq!(policy.state, PolicyState::Violated, "{policy:?}");
    assert!(policy.chunks_in_transit > 0, "{policy:?}");
    assert!(
        policy.reasons.iter().any(|r| r.contains("in transit")),
        "{:?}",
        policy.reasons
    );

    // B is the disk to dock next, for the staged data.
    let sug = e.disk_suggestions().unwrap();
    let top = sug.top.expect("a disk is suggested");
    assert_eq!(top.label, "disk-b");
    assert!(
        top.reasons.iter().any(|r| r.kind == "mailbox"),
        "{:?}",
        top.reasons
    );

    // A second run with nothing new docked stages nothing again.
    let r = run(&mut e);
    assert_eq!((r.staged, r.delivered), (0, 0), "{r:?}");

    // Swap: A away, B docked. The staged packs are written to B.
    lab.undock("disk-a");
    let b = lab.dock_at("dock-1", "disk-b");
    assert!(e.mailbox_due(false), "a disk change makes a run due");
    let r = run(&mut e);
    assert_eq!(r.delivered, 3, "{r:?}");
    assert_eq!(r.direct, 0, "from the outbox, not from A");
    assert!(outbox(&home).is_empty(), "staged copies go once delivered");
    let on_b = packs_on(&b);
    assert_eq!(
        on_b.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        on_a.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()
    );
    assert!(on_b.iter().all(|(_, p)| intact(p)));
    let s = e.mailbox_status();
    assert!(s.groups.is_empty() && s.held_objects == 0, "{s:?}");
    assert_eq!(s.total_delivered, 3);
    assert_eq!(e.disk_groups().unwrap()[0].objects_short, 0);
    let policy = docs_policy(&e);
    assert_eq!(policy.state, PolicyState::Ok, "{policy:?}");
    assert_eq!(policy.chunks_in_transit, 0);
}

#[test]
fn the_free_space_rule_limits_staging_and_staged_copies_go_first() {
    let (lab, mut e, _) = group_lab();
    let home = lab.p("dock-1-home");
    let a = lab.dock("dock-1").join("disk-a");
    let sizes: Vec<u64> = packs_on(&a)
        .iter()
        .map(|(_, p)| fs::metadata(p).unwrap().len())
        .collect();
    // The default rule on a 1 TB disk keeps 150 GB (15 % beats 50 GB): room
    // for one pack above it.
    let keep = MailboxSettings::default().keep_free_bytes(TB);
    assert_eq!(keep, 150_000_000_000);
    let one = *sizes.iter().max().unwrap();
    pool::set_fake_space(
        &home,
        Some(DiskSpace {
            free: keep + one + 10,
            total: TB,
        }),
    );
    let r = run(&mut e);
    assert_eq!(r.staged, 1, "{r:?}");
    assert!(r.room_needed_bytes > 0, "{r:?}");
    assert!(
        r.notes.iter().any(|n| n.contains("free space here")),
        "{:?}",
        r.notes
    );
    // A full outbox says what to do: keep A attached, free space, or dock B.
    let s = e.mailbox_status();
    let waiting = s
        .groups
        .iter()
        .find(|g| g.state == "waiting_for_source")
        .expect("objects still to read");
    assert!(waiting.source_attached);
    assert!(waiting.keep_attached_minutes.is_some());
    assert!(
        waiting.text.contains("keep it attached for about")
            && waiting.text.contains("more free space"),
        "{}",
        waiting.text
    );
    let sug = e.disk_suggestions().unwrap();
    let attached_a = sug
        .attached
        .iter()
        .find(|s| s.label == "disk-a")
        .expect("A is attached");
    assert!(
        attached_a
            .reasons
            .iter()
            .any(|r| r.kind == "keep_attached" && r.text.contains("keep it attached")),
        "{:?}",
        attached_a.reasons
    );

    // The device needs its space: the staged copy goes first; A keeps its copy.
    pool::set_fake_space(
        &home,
        Some(DiskSpace {
            free: keep - 1,
            total: TB,
        }),
    );
    let (n, bytes) = e.mailbox_make_room();
    assert_eq!(n, 1);
    assert!(bytes > 0);
    assert!(outbox(&home).is_empty());
    assert_eq!(packs_on(&a).len(), 3, "the source is never evicted");
    let s = e.mailbox_status();
    assert_eq!(s.held_objects, 0);
    assert!(s.groups.iter().all(|g| g.state == "waiting_for_source"));

    // A rule of its own: 10 GB is enough with this much free.
    e.set_mailbox_settings(MailboxSettings {
        enabled: true,
        keep_free: vec![varsto_core::freespace::MinFree::parse("10GB").unwrap()],
    })
    .unwrap();
    pool::set_fake_space(
        &home,
        Some(DiskSpace {
            free: 20_000_000_000,
            total: TB,
        }),
    );
    let r = run(&mut e);
    assert_eq!(r.staged, 3, "{r:?}");
    assert_eq!(r.room_needed_bytes, 0);
}

#[test]
fn a_run_resumes_after_the_engine_is_dropped_and_bad_objects_are_refused() {
    let (lab, mut e, _) = group_lab();
    let home = lab.p("dock-1-home");
    // One object, then the process ends.
    let r = e
        .mailbox_run(&MailboxOptions {
            max_bytes: u64::MAX,
            max_objects: 1,
        })
        .unwrap();
    assert_eq!(r.staged, 1);
    drop(e);
    // An interrupted write left a temporary file behind.
    let staged = outbox(&home);
    let tmp = staged[0].parent().unwrap().join(".tmp-interrupted");
    fs::write(&tmp, b"half").unwrap();
    fs::File::options()
        .write(true)
        .open(&tmp)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7200))
        .unwrap();

    let mut e = Engine::open(&home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    let s = e.mailbox_status();
    assert_eq!(s.held_objects, 1, "the task file says what is held");
    let r = run(&mut e);
    assert_eq!(r.staged, 2, "only what was not staged yet: {r:?}");
    assert!(!tmp.exists(), "leftovers of interrupted writes are removed");
    assert_eq!(outbox(&home).len(), 3);

    // A staged object rots in the outbox: refused when B is docked.
    let rotten = outbox(&home)[0].clone();
    fs::write(&rotten, b"not what was staged").unwrap();
    lab.undock("disk-a");
    let b = lab.dock_at("dock-1", "disk-b");
    let r = run(&mut e);
    assert_eq!(r.rejected, 1, "{r:?}");
    assert_eq!(r.delivered, 2, "{r:?}");
    assert_eq!(packs_on(&b).len(), 2);
    assert!(packs_on(&b).iter().all(|(_, p)| intact(p)));
    let s = e.mailbox_status();
    let g = s
        .groups
        .iter()
        .find(|g| g.state == "waiting_for_source")
        .unwrap();
    assert!(
        g.text.contains("waiting for disk «disk-a» to be docked"),
        "{}",
        g.text
    );
    assert_eq!(g.objects, 1);

    // With A docked again (a second dock, both at once), it is copied directly.
    let _a = lab.dock_at("dock-1", "disk-a");
    let r = run(&mut e);
    assert_eq!((r.delivered, r.direct), (1, 1), "{r:?}");
    assert_eq!(packs_on(&b).len(), 3);
    assert!(e.mailbox_status().groups.is_empty());

    // A pack that is damaged on the source disk is not staged.
    let (lab, mut e, _) = group_lab();
    let a = lab.dock("dock-1").join("disk-a");
    let (_, bad) = packs_on(&a)[0].clone();
    fs::write(&bad, b"bit rot").unwrap();
    let r = run(&mut e);
    assert_eq!((r.staged, r.rejected), (2, 1), "{r:?}");
}

#[test]
fn a_move_drops_the_source_on_a_only_after_the_copy_on_b_is_checked() {
    let lab = Lab::new();
    let home = lab.p("dock-1-home");
    roomy(&home);
    let (mut e, _) = Engine::init(&home, "dock-1", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(lab.hub()).unwrap();
    e.add_storage(pool_spec("old", "home", 1, &lab.dock("dock-1")))
        .unwrap();
    e.add_storage(pool_spec("new", "offsite", 1, &lab.dock("dock-1")))
        .unwrap();
    let a = lab.new_disk("dock-1", "disk-a");
    e.disk_add(&a, "old", "disk-a").unwrap();
    let b = lab.new_disk("dock-1", "disk-b");
    e.disk_add(&b, "new", "disk-b").unwrap();
    lab.undock("disk-b");
    let docs = lab.p("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("x.bin"), pseudo_random(300_000, 7)).unwrap();
    e.add_folder("docs", &docs).unwrap();
    e.set_policy("docs", None).unwrap();
    e.set_placement(
        "docs",
        Some(Placement {
            storages: vec!["old".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    e.push("docs").unwrap();
    // Packs (the mailbox stages and moves whole packs) and blocks claimed.
    let claims = |e: &Engine, s: &str| e.packs_on_storage3(s).unwrap().len();
    let blocks = claims(&e, "old");
    assert!(blocks >= 1);
    let objects = e.objects_on_storage3("old").unwrap().len();
    assert!(objects > 1);
    // The job cannot write to B: it waits.
    let (job, _) = e
        .move_job_start(&MoveJobRequest {
            folder: "docs".into(),
            from: "old".into(),
            to: "new".into(),
            ..Default::default()
        })
        .unwrap();
    let r = e.move_job_run(&job.id, &JobRunLimits::default()).unwrap();
    assert_eq!(r.job.state, JobState::Open);
    assert!(r.job.waiting.is_some());

    // While A is docked the mailbox keeps the blocks for the move.
    let r = run(&mut e);
    assert_eq!(r.staged as usize, blocks, "{r:?}");
    assert_eq!(outbox(&home).len(), blocks);
    // Nothing is dropped from A yet, nothing is on B.
    assert_eq!(claims(&e, "old"), blocks);
    assert_eq!(claims(&e, "new"), 0);
    let view = e.ledger_view3().unwrap();
    assert!(view.packs.keys().all(|p| !view.dropped_from(p, "old")));
    // A away, B docked: the job reads the outbox, writes B, checks, drops A.
    lab.undock("disk-a");
    lab.dock_at("dock-1", "disk-b");
    let runs = e.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].job.state, JobState::Done, "{:?}", runs[0].job);
    assert_eq!(runs[0].report.blocks_verified as usize, objects);
    assert_eq!(claims(&e, "new"), blocks);
    assert_eq!(claims(&e, "old"), 0);
    let me: [u8; 16] = hex::decode(e.device_id().as_str())
        .unwrap()
        .try_into()
        .unwrap();
    let view = e.ledger_view3().unwrap();
    for id in e.packs_on_storage3("new").unwrap().keys() {
        let id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        let c = view.copies(&id);
        assert!(
            c.iter()
                .any(|c| c.storage == "new" && c.verified_by.contains(&me)),
            "the copy on B was read back"
        );
        assert!(view.dropped_from(&id, "old"));
    }
    // A is away: its copies are deleted at its next insert.
    let rows = e.disks().unwrap();
    let row_a = rows.iter().find(|d| d.label == "disk-a").unwrap();
    assert!(row_a.pending_deletes > 0, "{row_a:?}");
    // The mailbox lets the staged copies go.
    let r = run(&mut e);
    assert_eq!(r.finished as usize, blocks, "{r:?}");
    assert!(outbox(&home).is_empty());
}

#[test]
fn a_move_waits_for_its_source_disk_instead_of_leaving_blocks_behind() {
    let lab = Lab::new();
    let home = lab.p("dock-1-home");
    roomy(&home);
    let (mut e, _) = Engine::init(&home, "dock-1", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(lab.hub()).unwrap();
    e.add_storage(pool_spec("old", "home", 1, &lab.dock("dock-1")))
        .unwrap();
    e.add_storage(pool_spec("new", "offsite", 1, &lab.dock("dock-1")))
        .unwrap();
    let a = lab.new_disk("dock-1", "disk-a");
    e.disk_add(&a, "old", "disk-a").unwrap();
    let b = lab.new_disk("dock-1", "disk-b");
    e.disk_add(&b, "new", "disk-b").unwrap();
    let docs = lab.p("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("x.bin"), pseudo_random(200_000, 9)).unwrap();
    e.add_folder("docs", &docs).unwrap();
    e.set_policy("docs", None).unwrap();
    e.set_placement(
        "docs",
        Some(Placement {
            storages: vec!["old".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    e.push("docs").unwrap();
    // A is away, nothing staged; the file is not here either.
    lab.undock("disk-a");
    fs::remove_file(docs.join("x.bin")).ok();
    let (job, _) = e
        .move_job_start(&MoveJobRequest {
            folder: "docs".into(),
            from: "old".into(),
            to: "new".into(),
            ..Default::default()
        })
        .unwrap();
    let r = e.move_job_run(&job.id, &JobRunLimits::default()).unwrap();
    assert_eq!(r.job.state, JobState::Open, "{:?}", r.job);
    let w = r.job.waiting.clone().unwrap();
    assert_eq!(w.kind, "source");
    assert_eq!(w.disk.as_deref(), Some("disk-a"));
    assert_eq!(r.job.kept_blocks, 0);
    // The disk suggestion asks for A.
    let sug = e.disk_suggestions().unwrap();
    let top = sug.top.expect("a disk is suggested");
    assert_eq!(top.label, "disk-a");
    assert!(top.reasons.iter().any(|r| r.kind == "mailbox_source"));
    // Docked, the job is ready and finishes.
    assert!(e.move_jobs_ready(false).is_empty());
    lab.dock_at("dock-1", "disk-a");
    assert_eq!(e.move_jobs_ready(false), vec![job.id.clone()]);
    let runs = e.move_jobs_run_ready(false, &JobRunLimits::default());
    assert_eq!(runs[0].job.state, JobState::Done, "{:?}", runs[0].job);
}

#[test]
fn two_dock_hosts_stage_each_block_once() {
    let (lab, mut x, key) = group_lab();
    // The second dock host knows the pool and both disks.
    let home_z = lab.p("dock-2-home");
    roomy(&home_z);
    let mut z = Engine::join(&home_z, "dock-2", PASS, &key, lab.hub()).unwrap();
    z.chunker = ChunkerParams::SMALL;
    z.add_storage(pool_spec("shelf", "home", 2, &lab.dock("dock-2")))
        .unwrap();
    lab.dock_at("dock-2", "disk-b");
    assert_eq!(z.disks().unwrap().len(), 1, "B adopted by dock-2");
    lab.undock("disk-b");

    // dock-1 stages while A is docked there, and publishes what it holds.
    let r = run(&mut x);
    assert_eq!(r.staged, 3, "{r:?}");
    // A goes to dock-2: it sees that dock-1 holds the packs and stages none.
    lab.undock("disk-a");
    lab.dock_at("dock-2", "disk-a");
    z.sync(None).unwrap();
    let r = run(&mut z);
    assert_eq!(r.staged, 0, "{r:?}");
    assert_eq!(r.held_elsewhere, 3, "{r:?}");
    assert!(outbox(&home_z).is_empty());
    let s = z.mailbox_status();
    let g = s.groups.iter().find(|g| !g.here).expect("held on dock-1");
    assert_eq!(g.held_on, "dock-1");
    assert!(g.text.contains("(staged on dock-1)"), "{}", g.text);
    assert_eq!(g.objects, 3);

    // While another host holds the staging lease, nothing is staged either.
    let hub = lab.p("hub");
    for e in walkdir::WalkDir::new(hub.join("vault").join("mailbox"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        fs::remove_file(e.path()).unwrap();
    }
    let slot = varsto_core::util::now_utc().div_euclid(varsto_core::engine::LEASE_SLOT_SECS);
    let leases = hub.join("vault").join("mailbox-leases");
    fs::create_dir_all(&leases).unwrap();
    fs::write(
        leases.join(format!("{slot:012}.json")),
        serde_json::json!({"device": x.device_id().as_str(), "taken_utc": varsto_core::util::now_utc()})
            .to_string(),
    )
    .unwrap();
    let r = run(&mut z);
    assert_eq!(r.staged, 0, "{r:?}");
    assert_eq!(r.busy.as_deref(), Some("dock-1"), "{r:?}");
}

/// `from` serves its blocks (and its outbox) over TLS on TCP to `to`.
fn serve(from: &mut Engine, _name: &str, to: &mut Engine) -> common::p2p::Serving {
    let serving = common::p2p::Serving::start(from);
    common::p2p::connect(from, &serving, &mut [to]);
    serving
}

#[test]
fn the_device_where_b_is_docked_takes_the_staged_blocks_over_peer_to_peer() {
    let lab = Lab::new();
    let home = lab.p("dock-1-home");
    roomy(&home);
    let (mut x, key) = Engine::init(&home, "dock-1", PASS).unwrap();
    x.chunker = ChunkerParams::SMALL;
    x.add_storage(lab.hub()).unwrap();
    x.add_storage(pool_spec("home-pool", "home", 1, &lab.dock("dock-1")))
        .unwrap();
    x.add_storage(pool_spec("off-pool", "offsite", 1, &lab.dock("dock-1")))
        .unwrap();
    let a = lab.new_disk("dock-1", "disk-a");
    x.disk_add(&a, "home-pool", "disk-a").unwrap();
    let b = lab.new_disk("dock-1", "disk-b");
    x.disk_add(&b, "off-pool", "disk-b").unwrap();
    lab.undock("disk-b");
    let docs = lab.p("docs");
    fs::create_dir_all(&docs).unwrap();
    for (i, name) in ["x.bin", "y.bin"].iter().enumerate() {
        fs::write(docs.join(name), pseudo_random(120_000, i as u64 + 20)).unwrap();
    }
    x.add_folder("docs", &docs).unwrap();
    x.set_policy(
        "docs",
        Some(Policy {
            min_copies: 1,
            min_per_place: [("offsite".to_string(), 1)].into_iter().collect(),
            verified_within_days: None,
        }),
    )
    .unwrap();
    x.set_placement(
        "docs",
        Some(Placement {
            storages: vec!["home-pool".into(), "off-pool".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    x.push("docs").unwrap();
    // The mailbox stages whole packs.
    let blocks = x.packs_on_storage3("home-pool").unwrap().len();

    assert_eq!(docs_policy(&x).state, PolicyState::Violated);

    // dock-1 stages the blocks for off-pool (its disk B is away).
    let r = run(&mut x);
    assert_eq!(r.staged as usize, blocks, "{r:?}");
    let st = x.mailbox_status();
    assert!(st
        .groups
        .iter()
        .any(|g| g.kind == "storage" && g.text.contains("waiting for disk «disk-b»")));

    // dock-2 knows off-pool and B, keeps the folder selective; B is docked there.
    let home_z = lab.p("dock-2-home");
    roomy(&home_z);
    let mut z = common::join_approved(&home_z, "dock-2", PASS, &key, lab.hub(), &mut x);
    z.chunker = ChunkerParams::SMALL;
    z.add_storage(pool_spec("off-pool", "offsite", 1, &lab.dock("dock-2")))
        .unwrap();
    z.attach_folder("docs", &lab.p("z-docs"), true).unwrap();
    z.sync(None).unwrap();
    lab.undock("disk-a");
    lab.dock_at("dock-2", "disk-b");
    assert_eq!(z.disks().unwrap().len(), 1);

    // Without dock-1 online nothing can be done.
    let r = run(&mut z);
    assert_eq!(r.delivered, 0, "{r:?}");
    let sug = z.disk_suggestions().unwrap();
    assert!(
        sug.mailbox.iter().any(|w| w.role == "target"),
        "{:?}",
        sug.mailbox
    );

    // dock-1 is online: dock-2 takes the staged blocks from its outbox.
    let served = serve(&mut x, "dock-1", &mut z);
    let r = run(&mut z);
    assert_eq!(r.pulled_from_peers as usize, blocks, "{r:?}");
    assert_eq!(r.delivered_to.get("off-pool"), Some(&(blocks as u64)));
    drop(served);
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    let zid: [u8; 16] = hex::decode(z.device_id().as_str())
        .unwrap()
        .try_into()
        .unwrap();
    let view = z.ledger_view3().unwrap();
    for id in z.packs_on_storage3("off-pool").unwrap().keys() {
        let id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        for c in view
            .copies(&id)
            .into_iter()
            .filter(|c| c.storage == "off-pool")
        {
            assert!(c.claimed_by.contains(&zid));
            *by.entry("off-pool".into()).or_default() += 1;
        }
    }
    assert_eq!(by.get("off-pool"), Some(&blocks));
    assert_eq!(docs_policy(&z).state, PolicyState::Ok);

    // dock-1 sees the copies and lets its staged ones go.
    x.sync(None).unwrap();
    let r = run(&mut x);
    assert_eq!(r.finished as usize, blocks, "{r:?}");
    assert!(outbox(&home).is_empty());
    assert!(x
        .mailbox_status()
        .groups
        .iter()
        .all(|g| g.state != "held" || !g.here));
}
