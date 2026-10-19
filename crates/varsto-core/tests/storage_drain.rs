// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Draining a storage and storage quotas: blocks leave only once the copies
//! that stay (checked by reading them back) keep every folder's policy, a
//! drain that cannot keep a policy stops and says what is missing, the
//! records follow the blocks, a drain survives interruption and can remove
//! the storage at the end; quotas route writes to other storages, make
//! them wait when no storage has room, bound what a drain copies, and are
//! the same on every device.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{DrainOptions, DrainRunLimits};
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::storage::StorageSpec;
use varsto_core::storage_settings::DrainPhase;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path, place: &str) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: place.into(),
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

/// Objects of every block the ledger counts on `storage`.
fn claimed(e: &Engine, storage: &str) -> Vec<String> {
    e.objects_on_storage(storage).unwrap().into_iter().collect()
}

/// Bytes the ledger counts on `storage`: the size classes of the packs
/// claimed there (what a quota counts).
fn block_bytes(e: &Engine, storage: &str) -> u64 {
    e.packs_on_storage(storage)
        .unwrap()
        .values()
        .map(|c| 256u64 << 10 << (2 * u64::from(*c)))
        .sum()
}

fn rank(s: PolicyState) -> u8 {
    match s {
        PolicyState::Ok => 0,
        PolicyState::AtRisk => 1,
        PolicyState::Unknown => 2,
        PolicyState::Violated => 3,
    }
}

/// Per folder: (state rank, blocks short of copies, blocks short per place).
fn policy_marks(e: &Engine) -> BTreeMap<String, (u8, u64, u64)> {
    e.policy_check()
        .unwrap()
        .into_iter()
        .map(|r| {
            (
                r.folder.clone(),
                (
                    rank(r.state),
                    r.chunks_short_of_copies,
                    r.chunks_short_per_place.values().sum(),
                ),
            )
        })
        .collect()
}

/// Files under a storage directory that are not blocks (records, ledger
/// batches, manifests), as relative paths.
fn records(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("chunks/")
            || rel.starts_with("packs/")
            || rel == "vault/storage-id.json"
            || rel.split('/').any(|p| p.starts_with('.'))
        {
            continue;
        }
        out.push(rel);
    }
    out.sort();
    out
}

struct Lab {
    _t: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_path_buf();
        Lab { _t: t, root }
    }
    fn path(&self, n: &str) -> PathBuf {
        let p = self.root.join(n);
        fs::create_dir_all(&p).unwrap();
        p
    }
}

/// A device with a folder of files of several blocks each.
fn device(lab: &Lab, storages: &[(&str, &str)]) -> (Engine, String) {
    let (mut a, key) = Engine::init(&lab.root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    for (name, place) in storages {
        a.add_storage(dir(name, &lab.path(name), place)).unwrap();
    }
    let files = lab.path("files");
    a.add_folder("docs", &files).unwrap();
    // These tests are about spreading blocks over all storages of a place.
    let mut places: Vec<String> = storages.iter().map(|(_, p)| p.to_string()).collect();
    places.sort();
    places.dedup();
    a.set_placement(
        "docs",
        Some(varsto_core::placement::Placement {
            places,
            ..Default::default()
        }),
    )
    .unwrap();
    // One sync per file: each push writes a pack of its own, so a drain
    // has several packs to work through.
    for i in 0..6u64 {
        fs::write(
            files.join(format!("f{i}.bin")),
            pseudo_random(40_000 + 9_000 * i as usize, i + 1),
        )
        .unwrap();
        a.sync(None).unwrap();
    }
    fs::write(files.join("small.txt"), b"a small file").unwrap();
    a.sync(None).unwrap();
    (a, key)
}

#[test]
fn a_drain_moves_every_block_checked_and_never_weakens_a_policy() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[("old", "cloud"), ("home", "home")]);
    let blocks = claimed(&a, "old");
    assert!(blocks.len() > 8, "{}", blocks.len());
    // The new provider arrives empty.
    a.add_storage(dir("new", &lab.path("new"), "cloud"))
        .unwrap();
    assert_eq!(common::object_count(&lab.path("new")), 0);

    let plan = a.drain_start("old", &DrainOptions::default()).unwrap();
    assert_eq!(plan.policy, "ok", "{}", plan.summary);
    assert_eq!(plan.blocks as usize, blocks.len());
    assert_eq!(plan.blocks_to_copy as usize, blocks.len());
    assert_eq!(
        plan.targets.keys().cloned().collect::<Vec<_>>(),
        vec!["new".to_string()]
    );

    let mut marks = policy_marks(&a);
    let mut runs = 0;
    loop {
        let r = a
            .drain_run(
                "old",
                &DrainRunLimits {
                    max_items: Some(3),
                    max_bytes: None,
                },
            )
            .unwrap();
        runs += 1;
        // Never weaker after any batch.
        let now = policy_marks(&a);
        for (folder, (state, short, short_place)) in &now {
            let (s0, c0, p0) = marks[folder];
            assert!(*state <= s0, "{folder}: policy got worse after run {runs}");
            assert!(
                *short <= c0 && *short_place <= p0,
                "{folder}: copies short after run {runs}"
            );
        }
        marks = now;
        // Every block gone from "old" is on "new", intact (its pack was
        // read back whole and checked against its id before the drop).
        let (on_old, on_new) = (claimed(&a, "old"), claimed(&a, "new"));
        for o in blocks.iter().filter(|o| !on_old.contains(o)) {
            assert!(on_new.contains(o), "copied before the drop");
            assert!(common::intact(&lab.path("new"), o));
            assert!(!common::object_names(&lab.path("old")).contains(o));
        }
        if r.drained {
            break;
        }
        assert!(runs < 50, "the drain does not finish: {}", r.summary);
    }
    assert!(runs > 2, "several runs");
    assert!(claimed(&a, "old").is_empty());
    assert_eq!(common::object_count(&lab.path("old")), 0);
    assert_eq!(
        a.storage_settings("old").drain.unwrap().phase,
        DrainPhase::Drained
    );
    // The records on "old" are on the other storages too.
    let theirs = records(&lab.path("new"));
    for k in records(&lab.path("old")) {
        assert!(theirs.contains(&k), "{k} only on the drained storage");
    }
    let status = a.drain_statuses().unwrap();
    assert_eq!(status[0].phase, "drained");
    assert_eq!(status[0].percent, 100);
    // Still configured, written to by nobody; the policy holds everywhere.
    fs::write(
        lab.path("files").join("after.bin"),
        pseudo_random(20_000, 7),
    )
    .unwrap();
    a.sync(None).unwrap();
    assert!(claimed(&a, "old").is_empty());
    for r in a.policy_check().unwrap() {
        assert_eq!(r.chunks_short_of_copies, 0, "{:?}", r.reasons);
    }
    // Stopping makes it an ordinary storage again: new blocks go there
    // (blocks moved away stay away).
    a.drain_stop("old").unwrap();
    fs::write(
        lab.path("files").join("again.bin"),
        pseudo_random(20_000, 8),
    )
    .unwrap();
    a.sync(None).unwrap();
    assert!(!claimed(&a, "old").is_empty());
    assert!(claimed(&a, "old").iter().all(|o| !blocks.contains(o)));
}

#[test]
fn a_drain_that_cannot_keep_the_policy_stops_and_says_what_is_missing() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[("c1", "cloud"), ("c2", "cloud"), ("h", "home")]);
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 2,
            min_per_place: [("cloud".to_string(), 2)].into_iter().collect(),
            verified_within_days: None,
        }),
    )
    .unwrap();
    let before = common::object_count(&lab.path("c1"));
    let plan = a.drain_start("c1", &DrainOptions::default()).unwrap();
    assert_eq!(plan.policy, "blocked");
    assert!(
        plan.blocked
            .iter()
            .any(|b| b.contains("add another cloud storage or lower the policy")),
        "{:?}",
        plan.blocked
    );
    let r = a.drain_run("c1", &DrainRunLimits::default()).unwrap();
    assert!(!r.drained);
    assert_eq!(r.blocks_dropped, 0);
    assert!(r.blocks_kept > 0);
    assert_eq!(
        common::object_count(&lab.path("c1")),
        before,
        "nothing left c1"
    );
    let st = &a.drain_statuses().unwrap()[0];
    assert_eq!(st.phase, "blocked");
    assert!(st.summary.contains("lower the policy"), "{}", st.summary);
    // While it drains, new files go to the other storages only, and the
    // policy report says why their copies are short.
    let on_c1 = claimed(&a, "c1");
    fs::write(lab.path("files").join("new.bin"), pseudo_random(10_000, 5)).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        claimed(&a, "c1"),
        on_c1,
        "nothing new on a draining storage"
    );
    let rep = a.policy_check().unwrap();
    assert!(
        rep[0]
            .reasons
            .iter()
            .any(|r| r.contains("c1 is being drained")),
        "{:?}",
        rep[0].reasons
    );

    // Another cloud storage: the drain goes through.
    a.add_storage(dir("c3", &lab.path("c3"), "cloud")).unwrap();
    let r = a.drain_run("c1", &DrainRunLimits::default()).unwrap();
    assert!(r.drained, "{}", r.summary);
    assert_eq!(common::object_count(&lab.path("c1")), 0);
    a.sync(None).unwrap();
    for r in a.policy_check().unwrap() {
        assert_eq!(r.state, PolicyState::Ok, "{:?}", r.reasons);
    }
}

#[test]
fn a_drain_resumes_after_interruption_and_removes_the_storage_when_empty() {
    let lab = Lab::new();
    let (mut a, _) = device(
        &lab,
        &[("old", "cloud"), ("home", "home"), ("new", "cloud")],
    );
    let blocks = claimed(&a, "old").len();
    a.drain_start(
        "old",
        &DrainOptions {
            remove_when_empty: true,
            ..Default::default()
        },
    )
    .unwrap();
    let r = a
        .drain_run(
            "old",
            &DrainRunLimits {
                max_items: Some(2),
                max_bytes: None,
            },
        )
        .unwrap();
    // Two packs, and every live block in them.
    assert!(r.blocks_dropped > 0);
    assert!(r.blocks_left_for_later > 0);
    let dropped = r.blocks_dropped as usize;

    // Interrupted: the device stops and comes back.
    drop(a);
    let mut a = Engine::open(&lab.root.join("a"), PASS).unwrap();
    let st = &a.drain_statuses().unwrap()[0];
    assert!(st.percent < 100, "{}", st.percent);
    assert_eq!(st.blocks_left as usize, blocks - dropped);

    assert!(a.drains_to_run().contains(&"old".to_string()));
    let r = a.drain_run("old", &DrainRunLimits::default()).unwrap();
    assert!(r.drained && r.removed, "{}", r.summary);
    assert!(a.storages().iter().all(|s| s.name() != "old"));
    assert!(a.drain_statuses().unwrap().is_empty());
    assert_eq!(common::object_count(&lab.path("old")), 0);
    // The other storages keep every block and the vault syncs on.
    fs::write(lab.path("files").join("x.bin"), pseudo_random(5_000, 3)).unwrap();
    a.sync(None).unwrap();
    for r in a.policy_check().unwrap() {
        assert_eq!(r.chunks_short_of_copies, 0);
    }
}

#[test]
fn a_quota_routes_writes_elsewhere_and_without_room_they_wait() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[("a", "cloud"), ("b", "cloud")]);
    let used = a.quota_status("a").unwrap().used_bytes;
    // Room for one more pack of the smallest class (256 KiB) on "a", not
    // two (a quota counts the size classes of the packs).
    let quota = (used + 300_000) * 100 / 99 + 1;

    let q = a.set_storage_quota("a", Some(Some(quota)), None).unwrap();
    assert_eq!(q.quota_bytes, Some(quota));
    assert!(q.state == "ok" || q.state == "warning", "{q:?}");
    let files = lab.path("files");
    for i in 0..4u64 {
        fs::write(
            files.join(format!("n{i}.bin")),
            pseudo_random(100_000, 50 + i),
        )
        .unwrap();
    }
    let reports = a.sync(None).unwrap();
    let full: Vec<&String> = reports.iter().flat_map(|(_, p)| &p.storages_full).collect();
    assert!(
        full.iter().any(|m| m.contains("storage a is at its quota")),
        "{full:?}"
    );
    assert!(block_bytes(&a, "a") <= quota);
    let q = a.quota_status("a").unwrap();
    assert!(q.state == "full" || q.state == "warning", "{q:?}");
    // What did not fit went to "b".
    let on_a = claimed(&a, "a");
    let on_b = claimed(&a, "b");
    assert!(on_b.len() > on_a.len());
    assert!(on_a.iter().all(|o| on_b.contains(o)));
    let st = a.status().unwrap();
    assert_eq!(st.folders[0].chunks_without_storage_copy, 0);

    // No room anywhere: the new blocks wait on this device.
    let used_b = a.quota_status("b").unwrap().used_bytes;
    a.set_storage_quota("b", Some(Some(used_b + 1)), None)
        .unwrap();
    fs::write(files.join("waits.bin"), pseudo_random(30_000, 77)).unwrap();
    let reports = a.sync(None).unwrap();
    let full: Vec<&String> = reports.iter().flat_map(|(_, p)| &p.storages_full).collect();
    assert!(
        full.iter().any(|m| m.contains("storage b is at its quota")),
        "{full:?}"
    );
    let st = a.status().unwrap();
    assert!(st.folders[0].chunks_without_storage_copy > 0);
    let rep = a.policy_check().unwrap();
    assert!(
        rep[0].reasons.iter().any(|r| r.contains("is at its quota")),
        "{:?}",
        rep[0].reasons
    );
    // Room again: the waiting blocks go out at the next sync.
    a.set_storage_quota("b", Some(None), None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        a.status().unwrap().folders[0].chunks_without_storage_copy,
        0
    );
    // A quota of nothing is refused (clearing is how it goes).
    assert!(a.set_storage_quota("a", Some(Some(0)), None).is_err());
}

#[test]
fn a_drain_respects_the_quota_of_the_storages_it_fills() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[("old", "cloud"), ("home", "home")]);
    a.add_storage(dir("new", &lab.path("new"), "cloud"))
        .unwrap();
    // "new" has room for its records and a little more only.
    let used = a.quota_status("new").unwrap().used_bytes;
    a.set_storage_quota("new", Some(Some((used + 30_000) * 100 / 99)), None)
        .unwrap();
    let plan = a.drain_start("old", &DrainOptions::default()).unwrap();
    assert_eq!(plan.policy, "blocked", "{}", plan.summary);
    assert!(
        plan.blocked
            .iter()
            .any(|b| b.contains("storage new is at its quota")),
        "{:?}",
        plan.blocked
    );
    assert!(plan.bytes_to_copy <= 31_000, "{}", plan.bytes_to_copy);
    let r = a.drain_run("old", &DrainRunLimits::default()).unwrap();
    assert!(!r.drained);
    assert!(r.bytes_copied <= 31_000, "{}", r.bytes_copied);
    assert!(!claimed(&a, "old").is_empty());
    // More room: the rest follows.
    a.set_storage_quota("new", Some(None), None).unwrap();
    let r = a.drain_run("old", &DrainRunLimits::default()).unwrap();
    assert!(r.drained, "{}", r.summary);
}

#[test]
fn quotas_and_drains_are_the_same_on_every_device() {
    let lab = Lab::new();
    let (mut a, key) = device(&lab, &[("s1", "cloud"), ("s2", "cloud")]);
    let used = a.quota_status("s1").unwrap().used_bytes;
    let quota = (used + 20_000) * 100 / 99;
    a.set_storage_quota("s1", Some(Some(quota)), None).unwrap();

    // B names the storages differently: the settings follow the storage.
    let mut b = common::join_approved(
        &lab.root.join("b"),
        "phone",
        PASS,
        &key,
        dir("box", &lab.path("s1"), "cloud"),
        &mut a,
    );

    b.chunker = ChunkerParams::SMALL;
    b.add_storage(dir("s2", &lab.path("s2"), "cloud")).unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.storage_settings("box").quota_bytes, Some(quota));
    assert_eq!(b.storage_settings("s2").quota_bytes, None);
    let bdir = lab.path("b-files");
    b.attach_folder("docs", &bdir, false).unwrap();
    b.sync(None).unwrap();
    for i in 0..3u64 {
        fs::write(
            bdir.join(format!("b{i}.bin")),
            pseudo_random(40_000, 200 + i),
        )
        .unwrap();
    }
    let reports = b.sync(None).unwrap();
    assert!(reports
        .iter()
        .flat_map(|(_, p)| &p.storages_full)
        .any(|m| m.contains("storage box is at its quota")));
    assert!(block_bytes(&b, "box") <= quota);

    // A drains s1; B stops writing there after its next sync.
    a.drain_start("s1", &DrainOptions::default()).unwrap();
    b.sync(None).unwrap();
    assert!(b.storage_settings("box").closed());
    let before = claimed(&b, "box");
    fs::write(bdir.join("late.bin"), pseudo_random(10_000, 300)).unwrap();
    b.sync(None).unwrap();
    assert_eq!(claimed(&b, "box"), before);
    // A finishes the drain; B learns it is drained.
    a.sync(None).unwrap();
    let r = a.drain_run("s1", &DrainRunLimits::default()).unwrap();
    assert!(r.drained, "{}", r.summary);
    // B's blocks there, claimed under B's name for it, left too.
    assert_eq!(common::object_count(&lab.path("s1")), 0);
    b.sync(None).unwrap();
    assert!(b.storage_settings("box").drained());
    assert!(claimed(&b, "box").is_empty());
    assert_eq!(
        b.status().unwrap().folders[0].chunks_without_storage_copy,
        0
    );
    // A clears the quota; B follows.
    a.set_storage_quota("s1", Some(None), None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.storage_settings("box").quota_bytes, None);
}

#[test]
fn after_a_drain_no_file_and_no_status_lists_the_storage() {
    let lab = Lab::new();
    let (mut a, _) = device(&lab, &[("old", "cloud"), ("home", "home")]);
    a.add_storage(dir("new", &lab.path("new"), "cloud"))
        .unwrap();
    a.drain_start("old", &DrainOptions::default()).unwrap();
    for _ in 0..50 {
        if a.drain_run("old", &DrainRunLimits::default())
            .unwrap()
            .drained
        {
            break;
        }
    }
    // Neither the ledger view ...
    assert!(claimed(&a, "old").is_empty());
    assert!(a.packs_on_storage("old").unwrap().is_empty());
    // ... nor the "where your data is" status lists it.
    let loc = a.data_locations().unwrap();
    let old = loc.storages.iter().find(|s| s.name == "old").unwrap();
    assert_eq!((old.bytes, old.blocks), (0, 0));
    assert!(loc.folders.iter().all(|f| !f.storages.contains_key("old")));
    // A later sync does not bring it back.
    a.sync(None).unwrap();
    assert!(a.packs_on_storage("old").unwrap().is_empty());
}
