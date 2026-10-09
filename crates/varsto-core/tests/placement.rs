// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Data placement: the drop event, per-folder placement, moving blocks
//! between storages (policy kept, never the last copy, resumable) and disk
//! group rules.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto::{SecretKey, SigningKey};
use varsto_core::ids::{ChunkId, FolderId, ObjectName};
use varsto_core::ledger::{self, Batch, Event, LedgerStore, ViewCache, KEY_LEDGER};
use varsto_core::placement::{MoveRequest, Placement};
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::pool::{self, DiskSpace};
use varsto_core::price::StoragePrice;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const GIB: u64 = 1 << 30;

fn dir(name: &str, path: &Path, cold: bool, place: &str) -> StorageSpec {
    fs::create_dir_all(path).unwrap();
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold,
        carrier: false,
        place: place.into(),
    }
}

fn objects(path: &Path) -> usize {
    walkdir::WalkDir::new(path.join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

/// Blocks of a folder the ledger shows on a storage.
fn on_storage(e: &Engine, storage: &str) -> usize {
    e.view()
        .unwrap()
        .chunks
        .values()
        .filter(|c| c.storages.contains_key(storage))
        .count()
}

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

/// Write a file whose access and modification times are `days` ahead: it
/// is in use for that long, whatever reads it meanwhile. (Varsto's own
/// reads when it uploads a file make it look used now, so "idle" in these
/// tests means "idle for 0 days".)
fn write_in_use(path: &Path, bytes: &[u8], days: u64) {
    fs::write(path, bytes).unwrap();
    let t = SystemTime::now() + Duration::from_secs(days * 86_400);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(t).set_modified(t))
        .unwrap();
}

fn engine(home: &Path, name: &str) -> (Engine, String) {
    let (mut e, key) = Engine::init(home, name, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    (e, key)
}

fn price(gb_month: f64) -> Option<StoragePrice> {
    Some(StoragePrice {
        storage_per_gb_month: Some(gb_month),
        egress_per_gb: Some(0.01),
        retrieval_per_gb: None,
        minimum_storage_days: None,
        currency: "EUR".into(),
        source: String::new(),
    })
}

// ----- the drop event ------------------------------------------------------

#[test]
fn a_drop_removes_earlier_claims_and_later_claims_count_again() {
    let t = tempfile::tempdir().unwrap();
    let key = SecretKey::random();
    let a = SigningKey::from_bytes(&[3; 32]).unwrap();
    let b = SigningKey::from_bytes(&[4; 32]).unwrap();
    let (da, db) = (
        ledger::device_id_for(&a.public()),
        ledger::device_id_for(&b.public()),
    );
    let folder = FolderId::from_bytes(&[1]);
    let chunk = ChunkId::from_bytes(&[2]);
    let object = ObjectName::from_bytes(&[5]);
    let stored = |storage: &str| Event::ChunkStored {
        folder: folder.clone(),
        chunk: chunk.clone(),
        object: object.clone(),
        storage: storage.into(),
        size: 10,
    };
    let dropped = |storage: &str| Event::ChunkDropped {
        folder: folder.clone(),
        chunk: chunk.clone(),
        object: object.clone(),
        storage: storage.into(),
    };
    let mut own_a = LedgerStore::open(&t.path().join("a")).unwrap();
    let mut own_b = LedgerStore::open(&t.path().join("b")).unwrap();
    let mut batches = vec![
        (
            0,
            own_a
                .append_own(&da, vec![stored("hot"), stored("cold")], 1, &key, &a)
                .unwrap(),
        ),
        // b verifies the hot copy before it is dropped (Lamport 2) ...
        (
            1,
            own_b
                .append_own(
                    &db,
                    vec![Event::ChunkVerified {
                        folder: folder.clone(),
                        chunk: chunk.clone(),
                        object: object.clone(),
                        storage: "hot".into(),
                    }],
                    5,
                    &key,
                    &b,
                )
                .unwrap(),
        ),
        // ... a drops it at Lamport 3 (b's verification at 5 does not bring it back).
        (
            0,
            own_a
                .append_own(&da, vec![dropped("hot")], 3, &key, &a)
                .unwrap(),
        ),
    ];
    let mut reader = LedgerStore::open(&t.path().join("reader")).unwrap();
    let key_for = |id: &str| (id == KEY_LEDGER).then(|| key.clone());
    let pk = [a.public(), b.public()];
    // Arrival order does not matter: apply the drop first.
    batches.reverse();
    for (who, batch) in &batches {
        reader.ingest(batch.clone(), &pk[*who], &key).unwrap();
    }
    let view = reader.view(&key).unwrap();
    let rec = view.locate(&folder, &chunk).unwrap();
    assert!(!rec.storages.contains_key("hot"));
    assert!(rec.storages.contains_key("cold"));
    assert!(rec.dropped_from("hot"));
    assert!(!rec.dropped_from("cold"));

    // A later claim (Lamport 7) stores it there again.
    let again = own_a
        .append_own(&da, vec![stored("hot")], 7, &key, &a)
        .unwrap();
    reader.ingest(again, &pk[0], &key).unwrap();
    let view = reader.view(&key).unwrap();
    let rec = view.locate(&folder, &chunk).unwrap();
    assert!(rec.storages.contains_key("hot"));
    assert!(!rec.dropped_from("hot"));

    // The cached view, brought up to date step by step, equals the replay;
    // so does a reader that starts from a checkpoint holding the drop.
    let mut cache = ViewCache::new("ctx".into());
    reader
        .update_view(&mut cache, key_for, |_, _| true)
        .unwrap();
    assert_eq!(reader.finish(&cache.raw), view);
    let cp = own_a
        .make_checkpoint(&da, 2, key_for, &key, KEY_LEDGER, &a)
        .unwrap();
    let mut fresh = LedgerStore::open(&t.path().join("fresh")).unwrap();
    cp.verify(&pk[0]).unwrap();
    fresh.ingest_checkpoint(cp).unwrap();
    for (who, batch) in &batches {
        if batch.device == db {
            fresh.ingest(batch.clone(), &pk[*who], &key).unwrap();
        }
    }
    let cp_view = fresh.view(&key).unwrap();
    let rec = cp_view.locate(&folder, &chunk).unwrap();
    assert!(rec.dropped_from("hot"), "the checkpoint carries the drop");
    let mut cache = ViewCache::new("ctx".into());
    fresh.update_view(&mut cache, key_for, |_, _| true).unwrap();
    assert_eq!(fresh.finish(&cache.raw), cp_view);
}

#[test]
fn unknown_event_types_are_read_and_ignored() {
    let ev: Event = serde_json::from_str(r#"{"type":"something_newer","x":1}"#).unwrap();
    assert_eq!(ev, Event::Unknown);
    let raw = r#"{"device":"00000000000000000000000000000001","seq":1,"prev":null,"lamport":1,"created_utc":0,
        "events":[{"type":"folder_added","folder":"01"},{"type":"later_kind","a":[1,2]}]}"#;
    let b: Batch = serde_json::from_str(raw).unwrap();
    assert_eq!(b.events.len(), 2);
    assert_eq!(b.events[1], Event::Unknown);
    let dropped = serde_json::to_value(Event::ChunkDropped {
        folder: FolderId::from_bytes(&[1]),
        chunk: ChunkId::from_bytes(&[2]),
        object: ObjectName::from_bytes(&[3]),
        storage: "s".into(),
    })
    .unwrap();
    assert_eq!(dropped["type"], "chunk_dropped");
}

// ----- per-folder placement ---------------------------------------------------

#[test]
fn placement_writes_only_to_the_chosen_storages_on_every_device() {
    let t = tempfile::tempdir().unwrap();
    let p = |n: &str| t.path().join(n);
    let (mut a, key) = engine(&p("a"), "laptop");
    a.add_storage(dir("one", &p("s1"), false, "home")).unwrap();
    a.add_storage(dir("two", &p("s2"), false, "cloud")).unwrap();
    a.add_storage(dir("three", &p("s3"), false, "offsite"))
        .unwrap();
    fs::create_dir_all(p("docs-a")).unwrap();
    a.add_folder("docs", &p("docs-a")).unwrap();
    // Storages a placement names must exist here.
    assert!(a
        .set_placement(
            "docs",
            Some(Placement {
                storages: vec!["nowhere".into()],
                ..Default::default()
            })
        )
        .is_err());
    let info = a
        .set_placement(
            "docs",
            Some(Placement {
                storages: vec!["one".into(), "three".into()],
                ..Default::default()
            }),
        )
        .unwrap();
    assert_eq!(info.targets, vec!["one".to_string(), "three".to_string()]);
    fs::write(p("docs-a").join("a.bin"), pseudo_random(60_000, 1)).unwrap();
    a.sync(None).unwrap();
    assert!(objects(&p("s1")) > 0);
    assert_eq!(objects(&p("s2")), 0, "not in the placement");
    assert_eq!(objects(&p("s1")), objects(&p("s3")));
    // Policies still count every copy the ledger records.
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 2,
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);

    // A second device names the storages differently; the placement record
    // (with storage identities) makes it write the same way.
    let mut b = Engine::join(
        &p("b"),
        "desk",
        PASS,
        &key,
        dir("one", &p("s1"), false, "home"),
    )
    .unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.add_storage(dir("second", &p("s2"), false, "cloud"))
        .unwrap();
    b.add_storage(dir("third", &p("s3"), false, "far")).unwrap();
    fs::create_dir_all(p("docs-b")).unwrap();
    b.sync(None).unwrap();
    b.attach_folder("docs", &p("docs-b"), false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        b.placement("docs").unwrap().targets,
        vec!["one".to_string(), "third".to_string()]
    );
    let before = objects(&p("s3"));
    fs::write(p("docs-b").join("b.bin"), pseudo_random(60_000, 2)).unwrap();
    b.sync(None).unwrap();
    assert_eq!(objects(&p("s2")), 0);
    assert!(objects(&p("s3")) > before);
    assert_eq!(objects(&p("s1")), objects(&p("s3")));

    // By place: only the offsite storage takes new blocks (on device a).
    a.set_placement(
        "docs",
        Some(Placement {
            places: vec!["offsite".into()],
            ..Default::default()
        }),
    )
    .unwrap();
    let (s1, s3) = (objects(&p("s1")), objects(&p("s3")));
    fs::write(p("docs-a").join("c.bin"), pseudo_random(60_000, 3)).unwrap();
    a.sync(None).unwrap();
    assert_eq!(objects(&p("s1")), s1);
    assert!(objects(&p("s3")) > s3);
    // Back to every storage: the next push fills the others.
    a.set_placement("docs", None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(objects(&p("s2")), objects(&p("s3")));
    assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
}

// ----- moving data ----------------------------------------------------------------

struct MoveLab {
    _t: tempfile::TempDir,
    root: PathBuf,
    a: Engine,
    key: String,
}

impl MoveLab {
    fn p(&self, n: &str) -> PathBuf {
        self.root.join(n)
    }
}

/// Device a with storages hot1, hot2 (cloud) and cold (cloud, cold), folder
/// docs with a few files synced everywhere.
fn move_lab() -> MoveLab {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    let (mut a, key) = engine(&root.join("a"), "laptop");
    a.add_storage(dir("hot1", &root.join("h1"), false, "cloud"))
        .unwrap();
    a.add_storage(dir("hot2", &root.join("h2"), false, "cloud"))
        .unwrap();
    a.add_storage(dir("cold", &root.join("c"), true, "cloud"))
        .unwrap();
    let docs = root.join("docs-a");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("old.bin"), pseudo_random(80_000, 7)).unwrap();
    write_in_use(&docs.join("new.bin"), &pseudo_random(40_000, 8), 30);
    a.add_folder("docs", &docs).unwrap();
    a.sync(None).unwrap();
    MoveLab {
        _t: t,
        root,
        a,
        key,
    }
}

#[test]
fn moving_keeps_the_policy_and_lowers_the_bill() {
    let mut lab = move_lab();
    let blocks = on_storage(&lab.a, "hot1");
    assert!(blocks > 2);
    assert_eq!(objects(&lab.p("c")), blocks);
    lab.a.set_storage_price("hot1", price(0.02)).unwrap();
    lab.a.set_storage_price("hot2", price(0.02)).unwrap();
    lab.a.set_storage_price("cold", price(0.002)).unwrap();
    lab.a
        .set_policy(
            "docs",
            Some(Policy {
                min_copies: 2,
                ..Default::default()
            }),
        )
        .unwrap();

    // Idle files only (old.bin): a dry run changes nothing.
    let req = MoveRequest {
        folder: "docs".into(),
        from: "hot1".into(),
        to: "cold".into(),
        idle_days: Some(0),
        dry_run: true,
        confirm_cold_read: false,
    };
    let plan = lab.a.move_data(&req).unwrap();
    assert_eq!(plan.files, 1);
    assert!(plan.blocks > 0 && (plan.blocks as usize) < blocks);
    // Every block is on cold already: nothing new is stored, hot1 is saved.
    assert!(plan.monthly_cost_to.values().all(|v| *v == 0.0));
    assert!(plan.monthly_saving["EUR"] > 0.0);
    assert!(plan.cold_notes.iter().any(|n| n.contains("cold storage")));
    assert_eq!(plan.min_copies_after, 2);
    assert_eq!(objects(&lab.p("h1")), blocks);

    let r = lab
        .a
        .move_data(&MoveRequest {
            dry_run: false,
            ..req.clone()
        })
        .unwrap();
    assert_eq!(r.blocks_dropped, plan.blocks);
    assert_eq!(r.blocks_kept, 0);
    assert!(
        r.placement_changed.is_none(),
        "idle moves keep the placement"
    );
    assert_eq!(objects(&lab.p("h1")), blocks - plan.blocks as usize);
    assert_eq!(on_storage(&lab.a, "hot1"), blocks - plan.blocks as usize);
    // Met, with no margin: one of the two copies is on cold storage.
    assert_eq!(lab.a.policy_check().unwrap()[0].state, PolicyState::AtRisk);
    // The next push does not put the moved blocks back.
    lab.a.sync(None).unwrap();
    assert_eq!(objects(&lab.p("h1")), blocks - plan.blocks as usize);
    // Running it again finds nothing left to move.
    let again = lab.a.move_data(&req).unwrap();
    assert_eq!(again.blocks, 0);
    assert_eq!(again.already_moved, plan.blocks);

    // hot2 -> cold would leave one copy of the idle blocks: the policy
    // needs two, so they stay.
    let r = lab
        .a
        .move_data(&MoveRequest {
            from: "hot2".into(),
            dry_run: false,
            ..req.clone()
        })
        .unwrap();
    assert_eq!(r.blocks_dropped, 0);
    assert_eq!(r.blocks_kept, plan.blocks);
    assert!(r.kept[0].1.contains("policy"));
    assert_eq!(objects(&lab.p("h2")), blocks);

    // The suggestion: hot2 still holds the idle blocks and cold is cheaper,
    // but the policy keeps them; without the policy the move is suggested.
    lab.a.set_policy("docs", None).unwrap();
    let advice = lab
        .a
        .placement_advice(0, varsto_core::util::now_utc())
        .unwrap();
    let s = advice
        .suggestions
        .iter()
        .find(|s| s.kind == "cold-idle")
        .expect("a cold storage suggestion");
    assert_eq!(s.move_from.as_deref(), Some("hot2"));
    assert_eq!(s.move_to.as_deref(), Some("cold"));
    assert!(s.monthly_saving["EUR"] > 0.0);
    assert!(s.summary.contains("at least 1 copy"));
    let applied = lab.a.apply_suggestion(&s.id, 0).unwrap();
    assert_eq!(applied.moved.unwrap().blocks_dropped, plan.blocks);
    assert_eq!(objects(&lab.p("h2")), blocks - plan.blocks as usize);

    // A second device sees the moves, keeps reading the active file from a
    // hot storage, and does not upload the moved blocks again.
    let mut b = Engine::join(
        &lab.p("b"),
        "desk",
        PASS,
        &lab.key,
        dir("hot1", &lab.p("h1"), false, "cloud"),
    )
    .unwrap();
    b.add_storage(dir("hot2", &lab.p("h2"), false, "cloud"))
        .unwrap();
    b.add_storage(dir("cold", &lab.p("c"), true, "cloud"))
        .unwrap();
    fs::create_dir_all(lab.p("docs-b")).unwrap();
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.p("docs-b"), false).unwrap();
    b.sync(None).unwrap();
    assert!(lab.p("docs-b").join("new.bin").exists());
    assert_eq!(objects(&lab.p("h1")), blocks - plan.blocks as usize);
    assert_eq!(b.view().unwrap(), b.view_replayed().unwrap());
    assert_eq!(on_storage(&b, "hot1"), blocks - plan.blocks as usize);
}

#[test]
fn moving_a_whole_folder_changes_its_placement_and_never_drops_the_last_copy() {
    let mut lab = move_lab();
    let blocks = on_storage(&lab.a, "hot1");
    // A pool without disks takes nothing: every block stays where it is.
    let pool_spec = StorageSpec::Pool {
        name: "shelf".into(),
        place: "home".into(),
        reserve_percent: 5,
        min_reserve_bytes: GIB,
        disks: vec![],
        scan_roots: vec![lab.p("mounts")],
        copies: 1,
    };
    lab.a.add_storage(pool_spec).unwrap();
    let r = lab
        .a
        .move_data(&MoveRequest {
            folder: "docs".into(),
            from: "hot1".into(),
            to: "shelf".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert_eq!(r.blocks_dropped, 0);
    assert_eq!(r.blocks_kept as usize, blocks);
    assert_eq!(objects(&lab.p("h1")), blocks);
    assert_eq!(on_storage(&lab.a, "hot1"), blocks);

    // Whole folder hot1 -> hot2 when hot2 holds everything already: hot1 is
    // emptied and the placement leaves it out from now on.
    let r = lab
        .a
        .move_data(&MoveRequest {
            folder: "docs".into(),
            from: "hot1".into(),
            to: "hot2".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert_eq!(r.blocks_dropped as usize, blocks);
    assert_eq!(r.blocks_copied, 0);
    assert!(r.placement_changed.is_some());
    assert_eq!(objects(&lab.p("h1")), 0);
    let info = lab.a.placement("docs").unwrap();
    assert!(!info.targets.contains(&"hot1".to_string()));
    fs::write(lab.p("docs-a").join("more.bin"), pseudo_random(30_000, 9)).unwrap();
    lab.a.sync(None).unwrap();
    assert_eq!(objects(&lab.p("h1")), 0);

    // Moving from cold storage needs a confirmed cold read when no other
    // copy can be read: hot1 is gone, so first empty hot2 into cold ...
    let to_cold = lab
        .a
        .move_data(&MoveRequest {
            folder: "docs".into(),
            from: "hot2".into(),
            to: "cold".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert!(to_cold.blocks_dropped > 0);
    assert_eq!(objects(&lab.p("h2")), 0);
    // ... the folder now lives on cold storage only, and the files are still
    // on this device: re-encrypting them is enough, no cold read needed.
    let back = lab
        .a
        .move_data(&MoveRequest {
            folder: "docs".into(),
            from: "cold".into(),
            to: "hot1".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert_eq!(back.blocks_kept, 0, "{:?}", back.kept);
    assert!(objects(&lab.p("h1")) > 0);
    assert_eq!(objects(&lab.p("c")), 0);
    assert_eq!(lab.a.view().unwrap(), lab.a.view_replayed().unwrap());
}

#[cfg(unix)]
#[test]
fn an_interrupted_move_is_carried_on_by_running_it_again() {
    use std::os::unix::fs::PermissionsExt;
    let mut lab = move_lab();
    let blocks = on_storage(&lab.a, "hot1");
    // Some blocks are on hot2's replacement already (an earlier run copied
    // them before it stopped): "spare" holds a copy of a few objects without
    // any ledger record.
    let spare = lab.p("spare");
    lab.a
        .add_storage(dir("spare", &spare, false, "cloud"))
        .unwrap();
    let mut copied = 0;
    for entry in walkdir::WalkDir::new(lab.p("h1").join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .take(2)
    {
        let rel = entry.path().strip_prefix(lab.p("h1")).unwrap();
        fs::create_dir_all(spare.join(rel).parent().unwrap()).unwrap();
        fs::copy(entry.path(), spare.join(rel)).unwrap();
        copied += 1;
    }
    // Deleting from hot1 fails: the drops are recorded, the objects stay.
    let chunk_dirs: Vec<PathBuf> = fs::read_dir(lab.p("h1").join("chunks"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    for d in &chunk_dirs {
        fs::set_permissions(d, fs::Permissions::from_mode(0o555)).unwrap();
    }
    let req = MoveRequest {
        folder: "docs".into(),
        from: "hot1".into(),
        to: "spare".into(),
        idle_days: None,
        dry_run: false,
        confirm_cold_read: false,
    };
    let first = lab.a.move_data(&req);
    for d in &chunk_dirs {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let first = first.unwrap();
    if first.blocks_dropped as usize == blocks {
        // Running as a user that ignores permissions: nothing to resume.
        return;
    }
    assert_eq!(first.blocks_copied as usize, blocks - copied);
    assert_eq!(first.blocks_dropped, 0);
    assert_eq!(objects(&lab.p("h1")), blocks, "deletes failed");
    assert_eq!(on_storage(&lab.a, "hot1"), 0, "but the drops are recorded");
    // Run again: the leftovers go, nothing is copied twice.
    let second = lab.a.move_data(&req).unwrap();
    assert_eq!(second.blocks, 0);
    assert_eq!(second.blocks_copied, 0);
    assert_eq!(second.leftovers_removed as usize, blocks);
    assert_eq!(objects(&lab.p("h1")), 0);
    assert_eq!(objects(&spare), blocks);
    assert_eq!(on_storage(&lab.a, "spare"), blocks);
}

// ----- disk groups -------------------------------------------------------------------

#[test]
fn disk_groups_keep_copies_in_different_places() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    let mounts = root.join("mounts");
    fs::create_dir_all(&mounts).unwrap();
    let mount = |name: &str| {
        let m = mounts.join(name);
        fs::create_dir_all(&m).unwrap();
        pool::set_fake_space(
            &m,
            Some(DiskSpace {
                free: 50 * GIB,
                total: 100 * GIB,
            }),
        );
        m
    };
    let (mut a, _) = engine(&root.join("a"), "laptop");
    a.add_storage(dir("box", &root.join("box"), false, "cloud"))
        .unwrap();
    a.add_storage(StorageSpec::Pool {
        name: "shelf".into(),
        place: "home".into(),
        reserve_percent: 5,
        min_reserve_bytes: GIB,
        disks: vec![],
        scan_roots: vec![mounts.clone()],
        copies: 2,
    })
    .unwrap();
    let d1 = mount("d1");
    a.disk_add_at(&d1, "shelf", "home-01", "").unwrap();
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("a.bin"), pseudo_random(90_000, 11)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 1,
            ..Default::default()
        }),
    )
    .unwrap();
    a.sync(None).unwrap();
    let blocks = on_storage(&a, "shelf");
    assert!(blocks > 1);
    // One place only: the rule is not met and the policy says so.
    let g = a.disk_groups().unwrap();
    assert_eq!(g[0].copies, 2);
    assert_eq!(g[0].objects_short as usize, blocks);
    assert!(!g[0].warnings.is_empty());
    let report = &a.policy_check().unwrap()[0];
    assert_eq!(report.state, PolicyState::Violated);
    assert!(report.reasons.iter().any(|r| r.contains("pool shelf")));

    // A second disk at home does not help; one kept offsite gets a copy of
    // everything when it is added.
    let d2 = mount("d2");
    let added = a.disk_add_at(&d2, "shelf", "home-02", "").unwrap();
    assert_eq!(added.objects_added, 0);
    let d3 = mount("d3");
    let added = a.disk_add_at(&d3, "shelf", "away-01", "offsite").unwrap();
    assert_eq!(added.objects_added as usize, blocks);
    assert_eq!(a.disk_groups().unwrap()[0].objects_short, 0);
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);
    // Policies count each disk copy at its disk's place.
    a.set_policy(
        "docs",
        Some(Policy {
            min_per_place: [("home".to_string(), 1), ("offsite".to_string(), 1)]
                .into_iter()
                .collect(),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);

    // With disks of both places attached, a push writes both copies.
    fs::write(docs.join("b.bin"), pseudo_random(40_000, 12)).unwrap();
    a.sync(None).unwrap();
    assert_eq!(a.disk_groups().unwrap()[0].objects_short, 0);

    // The offsite disk goes away; a new block has one place only until a
    // check of the offsite disk fills it.
    let away = root.join("away");
    fs::rename(&d3, &away).unwrap();
    fs::write(docs.join("c.bin"), pseudo_random(40_000, 13)).unwrap();
    a.sync(None).unwrap();
    assert!(a.disk_groups().unwrap()[0].objects_short > 0);
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Violated);
    fs::rename(&away, &d3).unwrap();
    let check = a.disk_check("away-01", false).unwrap();
    assert!(check.objects_added > 0);
    assert_eq!(check.group_copies, 2);
    assert_eq!(check.group_short, 0);
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);

    // Turning the rule off.
    a.set_pool_copies("shelf", 1).unwrap();
    assert_eq!(a.disk_groups().unwrap()[0].objects_short, 0);
    a.set_disk_place("home-02", "offsite").unwrap();
    assert!(a
        .disks()
        .unwrap()
        .iter()
        .any(|d| d.label == "home-02" && d.place == "offsite"));
}
