// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Upkeep the background service does or offers: automatic verification by
//! another device, storage prices, and carrying out a placement suggestion.

mod common;

use std::fs;
use std::path::PathBuf;
use varsto_core::autoverify::VerifySchedule;
use varsto_core::chunking::ChunkerParams;
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::price::StoragePrice;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const DAY: i64 = 86_400;

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: dir_storage("box", &root.join("storage"), false),
        root,
        _tmp: tmp,
    }
}

fn dir_storage(name: &str, path: &std::path::Path, cold: bool) -> StorageSpec {
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

/// Device A with folder "docs" holding a few multi-chunk files, pushed.
fn writer(lab: &Lab) -> (Engine, String) {
    let (mut a, key) = Engine::init(&lab.root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    let dir = lab.root.join("a-docs");
    fs::create_dir_all(&dir).unwrap();
    a.add_folder("docs", &dir).unwrap();
    fs::write(dir.join("big.bin"), pseudo_random(150_000, 7)).unwrap();
    fs::write(dir.join("note.txt"), b"a short note").unwrap();
    a.push("docs").unwrap();
    (a, key)
}

fn chunks_of(e: &Engine) -> u64 {
    e.status().unwrap().folders[0].chunks
}

fn verified_elsewhere(e: &Engine) -> u64 {
    e.status().unwrap().folders[0].chunks_verified_elsewhere
}

/// Storage format 3: automatic verification reads whole packs that other
/// devices wrote and records `pack_verified`; a device that joined with the
/// vault words alone (no folder key) verifies too, under its own name for
/// the storage.
#[test]
fn another_device_verifies_packs_automatically() {
    let lab = lab();
    let (mut a, key) = writer(&lab);
    // A second push: a second pack.
    fs::write(lab.root.join("a-docs/more.bin"), pseudo_random(90_000, 8)).unwrap();
    a.push("docs").unwrap();
    let packs = common::pack_files(&lab.root.join("storage")).len() as u64;
    assert_eq!(packs, 2);
    let chunks = chunks_of(&a);
    // The writer's own run has nothing to do: its own copies do not count.
    let r = a.auto_verify().unwrap();
    assert_eq!((r.due, r.blocks_verified), (0, 0));
    assert_eq!(verified_elsewhere(&a), 0);

    let renamed = dir_storage("primary", &lab.root.join("storage"), false);
    let mut b = Engine::join(&lab.root.join("b-home"), "nas", PASS, &key, renamed).unwrap();
    let now = varsto_core::util::now_utc();
    assert!(b.auto_verify_due(now), "a first run is due at once");
    // A budget of one pack per run: one is verified, the other waits.
    b.set_verify_schedule(VerifySchedule {
        max_blocks: 1,
        ..Default::default()
    })
    .unwrap();
    let r = b.auto_verify().unwrap();
    assert_eq!(
        (r.due, r.blocks_verified, r.left_for_next_run),
        (packs, 1, 1)
    );
    assert!(r.bytes_downloaded >= 256 << 10, "a whole pack: {r:?}");
    a.sync(None).unwrap();
    let some = verified_elsewhere(&a);
    assert!(some > 0 && some < chunks, "{some} of {chunks}");

    b.set_verify_schedule(VerifySchedule::default()).unwrap();
    let r = b.auto_verify().unwrap();
    assert_eq!((r.blocks_verified, r.left_for_next_run), (1, 0), "{r:?}");
    assert!(r.corrupt.is_empty() && r.missing.is_empty());
    assert_eq!(b.verify_status().total_verified, packs);
    a.sync(None).unwrap();
    assert_eq!(verified_elsewhere(&a), chunks);
    // Nothing is due again until the copies are 30 days old.
    assert_eq!(b.auto_verify().unwrap().due, 0);
    assert_eq!(b.auto_verify_at(now + 31 * DAY).unwrap().due, packs);
}

#[test]
fn another_device_verifies_automatically_and_the_policy_becomes_ok() {
    let lab = lab();
    let (mut a, key) = writer(&lab);
    // A second push: a second pack.
    fs::write(lab.root.join("a-docs/more.bin"), pseudo_random(90_000, 8)).unwrap();
    a.push("docs").unwrap();
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 1,
            verified_within_days: Some(30),
            ..Default::default()
        }),
    )
    .unwrap();
    let packs = common::pack_files(&lab.root.join("storage")).len() as u64;
    assert_eq!(packs, 2);
    let chunks = chunks_of(&a);
    assert!(chunks > 2, "several chunks: {chunks}");
    // Just stored: verification pending (the grace for new data), no alert;
    // after the window with nobody verifying it is a violation.
    let r = a.policy_check().unwrap();
    assert_eq!(r[0].state, PolicyState::Ok);
    assert_eq!(r[0].chunks_verification_pending, chunks);
    let late = varsto_core::util::now_utc() + 31 * 86_400;
    assert_eq!(
        a.policy_check_at(late).unwrap()[0].state,
        PolicyState::Violated
    );
    // The writer's own run has nothing to do: its own copies do not count.
    let r = a.auto_verify().unwrap();
    assert_eq!((r.due, r.blocks_verified), (0, 0));

    // Device B joins without attaching the folder: it only verifies. It calls
    // the storage "primary"; the writer published that its "box" is the same
    // storage (by the identity object on it).
    let renamed = dir_storage("primary", &lab.root.join("storage"), false);
    let mut b = Engine::join(&lab.root.join("b-home"), "nas", PASS, &key, renamed).unwrap();
    let now = varsto_core::util::now_utc();
    assert!(b.auto_verify_due(now), "a first run is due at once");
    // A budget of one pack per run: one is verified, the other waits, and
    // the blocks of the pack verified count for the policy.
    b.set_verify_schedule(VerifySchedule {
        max_blocks: 1,
        ..Default::default()
    })
    .unwrap();
    let r = b.auto_verify().unwrap();
    assert_eq!(
        (r.due, r.blocks_verified, r.left_for_next_run),
        (packs, 1, 1)
    );
    a.sync(None).unwrap();
    let r = a.policy_check().unwrap();
    let pending = r[0].chunks_verification_pending;
    assert!(pending > 0 && pending < chunks, "{pending} of {chunks}");
    assert_eq!(
        a.policy_check_at(late).unwrap()[0].state,
        PolicyState::Violated
    );

    // Default budget: the rest is verified, and the policy holds.
    b.set_verify_schedule(VerifySchedule::default()).unwrap();
    let r = b.auto_verify().unwrap();
    assert_eq!((r.blocks_verified, r.left_for_next_run), (1, 0), "{r:?}");
    assert!(r.corrupt.is_empty() && r.missing.is_empty());
    assert_eq!(b.verify_status().total_verified, packs);
    a.sync(None).unwrap();
    let rep = a.policy_check().unwrap();
    assert_eq!(
        rep[0].state,
        PolicyState::Ok,
        "{:?} {:?}",
        rep[0].reasons,
        rep[0].warnings
    );
    assert_eq!(rep[0].chunks_verification_pending, 0);
    assert_eq!(
        a.status().unwrap().folders[0].chunks_verified_elsewhere,
        chunks
    );
}

#[test]
fn automatic_verification_skips_cold_storage_and_reports_corruption() {
    let lab = lab();
    let (mut a, key) = writer(&lab);
    let cold = dir_storage("archive", &lab.root.join("archive"), true);
    a.add_storage(cold.clone()).unwrap();
    // Cold storages are written, never read; a second push, a second pack.
    fs::write(lab.root.join("a-docs/more.bin"), pseudo_random(90_000, 8)).unwrap();
    a.push("docs").unwrap();
    let packs = common::pack_files(&lab.root.join("storage")).len() as u64;
    let mut b = Engine::join(
        &lab.root.join("b-home"),
        "nas",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    b.add_storage(cold).unwrap();
    // Damage one object on the hot storage.
    let hot = lab.root.join("storage");
    let victim = common::object_names(&hot).into_iter().next().unwrap();
    common::corrupt_object(&hot, &victim);
    let r = b.auto_verify().unwrap();
    assert_eq!(r.storages_skipped, vec!["archive".to_string()]);
    assert_eq!(r.due, packs, "only the hot copies are candidates");
    assert_eq!(r.corrupt.len(), 1, "{r:?}");
    assert_eq!(r.blocks_verified, packs - 1);
    assert_eq!(r.queued_for_repair, 1);
    // Automatic verification can be turned off; a run on request still works.
    b.set_verify_schedule(VerifySchedule {
        enabled: false,
        ..Default::default()
    })
    .unwrap();
    assert!(!b.auto_verify_due(varsto_core::util::now_utc() + 100 * DAY));
    assert!(b.verify_status().next_run_utc.is_none());
    assert!(b
        .set_verify_schedule(VerifySchedule {
            interval_hours: 0,
            ..Default::default()
        })
        .is_err());
}

#[test]
fn storage_prices_feed_the_estimates() {
    let lab = lab();
    let (mut a, _) = writer(&lab);
    assert!(
        a.storage_price("box").is_none(),
        "a directory has no built-in price"
    );
    a.set_storage_price(
        "box",
        Some(StoragePrice {
            storage_per_gb_month: Some(2.0),
            egress_per_gb: Some(1.0),
            currency: "eur".into(),
            ..Default::default()
        }),
    )
    .unwrap();
    let p = a.storage_price("box").unwrap();
    assert_eq!(p.currency, "EUR");
    assert_eq!(p.source, "set by you");
    assert!(a.set_storage_price("nope", None).is_err());
    assert!(a
        .set_storage_price(
            "box",
            Some(StoragePrice {
                storage_per_gb_month: Some(-1.0),
                ..Default::default()
            })
        )
        .is_err());
    let est = a.storage_estimates().unwrap();
    assert_eq!(est.len(), 1);
    assert!(est[0].bytes > 150_000);
    let expected = est[0].bytes as f64 / 1_073_741_824.0 * 2.0;
    assert!((est[0].monthly_cost.unwrap() - expected).abs() < 1e-12);
    // The price survives a restart (config.json) and per-folder costs follow it.
    drop(a);
    let a = Engine::open(&lab.root.join("a-home"), PASS).unwrap();
    let adv = a.placement_advice(0, varsto_core::util::now_utc()).unwrap();
    assert_eq!(adv.folders.len(), 1);
    assert!(adv.folders[0].monthly["EUR"] > 0.0);
    assert!(adv.folders[0].unpriced_storages.is_empty());
    assert!(adv.storages[0].idle_monthly_cost.is_some());
    // Clearing the user's figures leaves no price.
    let mut a = a;
    a.set_storage_price("box", None).unwrap();
    assert!(a.storage_price("box").is_none());
}

#[test]
fn applying_a_placement_suggestion_frees_idle_files_safely() {
    let lab = lab();
    let (mut a, _) = writer(&lab);
    let now = varsto_core::util::now_utc();
    // Nothing is idle for 90 days yet.
    assert!(a.placement_advice(90, now).unwrap().suggestions.is_empty());
    let adv = a.placement_advice(0, now).unwrap();
    assert_eq!(adv.suggestions.len(), 1);
    let s = &adv.suggestions[0];
    assert_eq!(s.id, "free-idle:docs");
    assert_eq!(s.files, 2);
    assert_eq!(s.keep_on, vec!["box".to_string()]);
    assert!(s.verify_first_bytes > 0, "nobody verified the copies yet");
    assert!(s.summary.contains("Free 2 idle files"), "{}", s.summary);

    // A policy that asks for two copies is not met with one storage: nothing goes.
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 2,
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(a.placement_advice(0, now).unwrap().suggestions.is_empty());
    let r = a.apply_suggestion("free-idle:docs", 0).unwrap();
    assert_eq!(r.files_freed, 0);
    assert_eq!(r.skipped.len(), 2);
    assert!(r.skipped[0].1.contains("policy"), "{:?}", r.skipped);
    assert!(lab.root.join("a-docs/big.bin").exists());

    // With one copy required, the files are verified first and then freed.
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 1,
            ..Default::default()
        }),
    )
    .unwrap();
    let r = a.apply_suggestion("free-idle:docs", 0).unwrap();
    assert_eq!(r.files_freed, 2, "{:?}", r.skipped);
    assert!(r.blocks_verified > 0);
    assert!(r.bytes_freed > 150_000);
    assert!(!lab.root.join("a-docs/big.bin").exists());
    assert!(lab.root.join("a-docs/big.bin.varsto-placeholder").exists());
    // A sync does not take the freed files for deletions; they come back on demand.
    a.sync(None).unwrap();
    assert_eq!(a.list_files("docs").unwrap().len(), 2);
    a.fetch_file("docs", "big.bin").unwrap();
    assert_eq!(
        fs::read(lab.root.join("a-docs/big.bin")).unwrap(),
        pseudo_random(150_000, 7)
    );
    // The fetched file was just used: not idle for 30 days.
    let adv = a
        .placement_advice(30, varsto_core::util::now_utc())
        .unwrap();
    assert!(adv.suggestions.is_empty());
}

#[test]
fn a_file_only_on_cold_storage_is_never_freed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    // The folder's records live on a hot storage; its blocks go only to
    // the archive.
    a.add_storage(dir_storage("records", &root.join("records"), false))
        .unwrap();
    a.add_storage(dir_storage("archive", &root.join("archive"), true))
        .unwrap();
    let dir = root.join("docs");
    fs::create_dir_all(&dir).unwrap();
    a.add_folder("docs", &dir).unwrap();
    a.set_placement(
        "docs",
        Some(varsto_core::placement::Placement {
            storages: vec!["archive".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    fs::write(dir.join("only.txt"), b"one copy in the archive").unwrap();
    a.push("docs").unwrap();
    let adv = a.placement_advice(0, varsto_core::util::now_utc()).unwrap();
    assert!(adv.suggestions.is_empty());
    let r = a.apply_suggestion("docs", 0).unwrap();
    assert_eq!(r.files_freed, 0);
    assert!(r.skipped[0].1.contains("cold"), "{:?}", r.skipped);
    assert!(dir.join("only.txt").exists());
}
