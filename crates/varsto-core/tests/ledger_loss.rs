// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Losing ledger copies and getting them back (`docs/spec/alpha-0-format.md`
//! section 38): a storage that lost its ledger objects (S1), a device whose
//! local `ledger/` directory was deleted or damaged (S2), a device restored
//! from an old backup and two copies of one identity (S3), the ledger lost
//! everywhere (S4) and a damaged cached view (S5).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::LedgerRebuildOptions;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
    key: String,
}

impl Lab {
    fn storage_dir(&self) -> PathBuf {
        self.root.join("storage")
    }
    fn a_home(&self) -> PathBuf {
        self.root.join("a")
    }
    fn b_home(&self) -> PathBuf {
        self.root.join("b")
    }
    fn a_docs(&self) -> PathBuf {
        self.root.join("a-docs")
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

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

/// A with a folder of three files synced to the storage, B joined and synced.
fn two_devices() -> (Lab, Engine, Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let (mut a, key) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &root.join("a-docs")).unwrap();
    fs::write(root.join("a-docs/one.txt"), b"first file").unwrap();
    fs::write(root.join("a-docs/two.bin"), pseudo_random(60_000, 2)).unwrap();
    // Two pushes: two packs.
    a.sync(None).unwrap();
    fs::create_dir_all(root.join("a-docs/sub")).unwrap();
    fs::write(root.join("a-docs/sub/three.bin"), pseudo_random(90_000, 3)).unwrap();
    a.sync(None).unwrap();
    let mut b = common::join_approved(&root.join("b"), "phone", PASS, &key, storage.clone(), &mut a);
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &root.join("b-docs"), false)
        .unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let lab = Lab {
        _tmp: tmp,
        root,
        storage,
        key,
    };
    (lab, a, b)
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for e in walkdir::WalkDir::new(from)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = e.path().strip_prefix(from).unwrap();
        let dst = to.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&dst).unwrap();
        } else {
            fs::copy(e.path(), &dst).unwrap();
        }
    }
}

fn own_head(e: &Engine) -> u64 {
    e.ledger_health().own_head
}

/// Batches of `device` held by `e`.
fn heads_of(e: &Engine, device: &str) -> BTreeSet<u64> {
    e.ledger_entries()
        .unwrap()
        .into_iter()
        .filter(|x| x.device == device)
        .map(|x| x.seq)
        .collect()
}

/// Every pack copy the ledger view claims: `<pack>@<storage>`.
fn claims(e: &Engine) -> BTreeSet<String> {
    let view = e.ledger_view3().unwrap();
    view.packs
        .keys()
        .flat_map(|id| {
            view.copies(id)
                .into_iter()
                .filter(|c| !c.claimed_by.is_empty())
                .map(move |c| format!("{}@{}", &hex::encode(id)[..12], c.storage))
        })
        .collect()
}

/// A batch file of `device` in a ledger directory (storage or local).
fn batch_file(dir: &Path, device: &str, seq: u64) -> PathBuf {
    dir.join(device).join(format!("{seq:016}-0000.rec"))
}

/// S1: a storage that lost the ledger objects is filled again by the next
/// push of every device, and a device joining afterwards sees everything.
#[test]
fn s1_storage_that_lost_its_ledger_is_filled_again() {
    let (lab, mut a, mut b) = two_devices();
    let before = claims(&a);
    fs::remove_dir_all(lab.storage_dir().join("ledger")).unwrap();
    fs::write(lab.a_docs().join("four.txt"), b"fourth").unwrap();
    a.sync(None).unwrap();
    fs::write(lab.root.join("b-docs/five.txt"), b"fifth").unwrap();
    b.sync(None).unwrap();
    for e in [&a, &b] {
        let dir = lab
            .storage_dir()
            .join("ledger")
            .join(e.device_id().as_str());
        let n = fs::read_dir(&dir).unwrap().count() as u64;
        assert_eq!(n, own_head(e), "every batch is back on the storage");
        assert!(e.ledger_health().is_ok());
    }
    // A device joining with the vault words alone sees every claim.
    let mut c = Engine::join(
        &lab.root.join("c"),
        "tablet",
        PASS,
        &lab.key,
        lab.storage.clone(),
    )
    .unwrap();
    c.sync(None).unwrap();
    assert!(claims(&c).is_superset(&before));
    assert!(c.status().unwrap().forked_devices.is_empty());
}

/// S2: the local `ledger/` directory is deleted. The device signs nothing
/// (the command line says to rebuild), the rebuild takes its own batches
/// back from the storage and the other devices' as well, the view comes
/// back, and the next batch continues the numbering: the other device
/// accepts it without seeing a fork.
#[test]
fn s2_deleted_local_ledger_is_restored_and_numbering_continues() {
    let (lab, a, b) = two_devices();
    let home = lab.a_home();
    let a_id = a.device_id().to_string();
    let head = own_head(&a);
    let view = a.ledger_view3().unwrap().canonical();
    drop((a, b));
    fs::remove_dir_all(home.join("ledger")).unwrap();

    let mut a = open(&home);
    let h = a.ledger_health();
    assert_eq!(h.state, "rebuild_needed", "{h:?}");
    assert!(h.automatic);
    assert_eq!(h.suggestion.as_deref(), Some("varsto ledger rebuild"));
    assert!(h.problems.iter().any(|p| p.code == "local_ledger_missing"));
    // Reading still works and says so; signing stops with the suggestion.
    assert_eq!(a.status().unwrap().ledger_health.state, "rebuild_needed");
    let err = format!(
        "{:#}",
        a.add_folder("more", &lab.root.join("a-more")).unwrap_err()
    );
    assert!(err.contains("varsto ledger rebuild"), "{err}");
    let err = format!("{:#}", a.sync(None).unwrap_err());
    assert!(err.contains("varsto ledger rebuild"), "{err}");

    // The rebuild continues after the old head: the folder created while
    // the ledger was missing is recorded in the one batch it signs.
    let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert!(r.own_found_on_storages);
    assert_eq!(r.own_head_after, head + 1, "{r:?}");
    assert!(r.batches_pulled > 0, "B's batches came back too: {r:?}");
    assert!(!r.reenrolled);
    assert!(r.health.is_ok(), "{:?}", r.health);
    let after = a.ledger_view3().unwrap().canonical();
    assert_eq!(after.packs, view.packs);
    assert_eq!(after.devices, view.devices);
    assert_eq!(after.folders.len(), 2, "the new folder is recorded");

    // The next batch continues after that.
    fs::write(lab.a_docs().join("four.txt"), b"fourth").unwrap();
    a.sync(None).unwrap();
    assert_eq!(own_head(&a), head + 2);
    let mut b = open(&lab.b_home());
    b.sync(None).unwrap();
    assert!(b.status().unwrap().forked_devices.is_empty());
    assert!(heads_of(&b, &a_id).contains(&(head + 2)));
    assert_eq!(
        fs::read(lab.root.join("b-docs/four.txt")).unwrap(),
        b"fourth"
    );
    assert!(b.ledger_health().is_ok());
}

/// S2 with checkpoints: after pruning, the storage holds the device's
/// checkpoint and only the last batches; the rebuild takes the checkpoint
/// back, so the view still has the claims of the pruned batches.
#[test]
fn s2_restores_own_checkpoint_after_pruning() {
    let (lab, mut a, mut b) = two_devices();
    a.set_ledger_policy(3, 1);
    b.set_ledger_policy(3, 1);
    for i in 0..5 {
        fs::write(lab.a_docs().join(format!("n{i}.txt")), format!("note {i}")).unwrap();
        a.sync(None).unwrap();
        b.sync(None).unwrap();
    }
    a.sync(None).unwrap();
    let a_id = a.device_id().to_string();
    let st = a.ledger_status(true).unwrap();
    let mine = st.devices.iter().find(|d| d.this_device).unwrap();
    let cp = mine.checkpoint.expect("a checkpoint was written");
    let on_box = mine.held.iter().find(|h| h.place == "box").unwrap();
    assert!(
        on_box.first.unwrap() > 1,
        "old batches were pruned: {on_box:?}"
    );
    let head = own_head(&a);
    let view = a.ledger_view3().unwrap().canonical();
    let home = lab.a_home();
    drop(a);
    fs::remove_dir_all(home.join("ledger")).unwrap();

    let mut a = open(&home);
    let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert_eq!(r.adopted_checkpoint, Some(cp));
    assert_eq!(own_head(&a), head);
    assert_eq!(a.ledger_view3().unwrap().canonical().packs, view.packs);
    fs::write(lab.a_docs().join("after.txt"), b"after").unwrap();
    a.sync(None).unwrap();
    assert_eq!(own_head(&a), head + 1);
    b.sync(None).unwrap();
    assert!(b.status().unwrap().forked_devices.is_empty());
    assert!(heads_of(&b, &a_id).contains(&(head + 1)));
}

/// S2, damaged files: an unreadable heads file no longer stops the device
/// from opening; the rebuild reads the heads back from the batch files.
/// Unreadable `pushed.json` and `pending.json` are set aside and noted.
/// A missing newest own batch is fetched again.
#[test]
fn s2_damaged_local_files_are_set_aside_and_rebuilt() {
    let (lab, a, b) = two_devices();
    let home = lab.a_home();
    let a_id = a.device_id().to_string();
    let head = own_head(&a);
    drop((a, b));
    fs::write(home.join("ledger/heads.json"), b"{ not json").unwrap();
    fs::write(home.join("ledger/pushed.json"), b"[[[").unwrap();
    fs::write(home.join("ledger/pending.json"), b"nope").unwrap();
    let mut a = open(&home);
    let h = a.ledger_health();
    assert_eq!(h.state, "rebuild_needed");
    assert!(h.problems.iter().any(|p| p.code == "local_files_damaged"));
    assert_eq!(h.notes.len(), 2, "{h:?}");
    let damaged = fs::read_dir(home.join("ledger"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".damaged-")
        })
        .count();
    assert_eq!(damaged, 3, "kept aside, not deleted");
    let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert!(r.local.batches > 0);
    assert_eq!(own_head(&a), head);
    assert!(r.health.is_ok());
    a.sync(None).unwrap();

    // The newest own batch file goes missing.
    let head = own_head(&a);
    drop(a);
    fs::remove_file(batch_file(&home.join("ledger"), &a_id, head)).unwrap();
    let mut a = open(&home);
    assert_eq!(a.ledger_health().state, "rebuild_needed");
    a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert_eq!(own_head(&a), head);
    fs::write(lab.a_docs().join("x.txt"), b"x").unwrap();
    a.sync(None).unwrap();
    assert_eq!(own_head(&a), head + 1);
}

/// S3: a device restored from an old backup is fenced; the rebuild adopts
/// its own later batches from the storage (they are signed with its key
/// and continue its history), and it goes on after them.
#[test]
fn s3_restored_device_adopts_its_later_history() {
    let (lab, mut a, mut b) = two_devices();
    let home = lab.a_home();
    let a_id = a.device_id().to_string();
    let backup = lab.root.join("a-backup");
    copy_tree(&home, &backup);
    fs::write(lab.a_docs().join("four.txt"), b"fourth").unwrap();
    a.sync(None).unwrap();
    fs::write(lab.a_docs().join("five.txt"), b"fifth").unwrap();
    a.sync(None).unwrap();
    let head = own_head(&a);
    b.sync(None).unwrap();
    drop((a, b));
    fs::remove_dir_all(&home).unwrap();
    copy_tree(&backup, &home);

    let mut a = open(&home);
    assert!(own_head(&a) < head);
    // Nothing is known to be wrong before a storage is read.
    assert!(a.ledger_health().is_ok());
    let h = a.ledger_check_storages().unwrap();
    assert_eq!(h.state, "fenced", "{h:?}");
    assert_eq!(h.storage_ahead, Some(head));
    assert!(!h.automatic, "adopting is offered, not done by itself");
    let err = format!("{:#}", a.sync(None).unwrap_err());
    assert!(err.contains("varsto ledger rebuild"), "{err}");

    let r = a.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert!(r.adopted_batches >= 2, "{r:?}");
    assert!(r.discarded_unpublished.is_empty());
    assert_eq!(own_head(&a), head, "{r:?}");
    assert!(r.health.is_ok());
    fs::write(lab.a_docs().join("six.txt"), b"sixth").unwrap();
    a.sync(None).unwrap();
    assert_eq!(own_head(&a), head + 1);
    let mut b = open(&lab.b_home());
    b.sync(None).unwrap();
    assert!(b.status().unwrap().forked_devices.is_empty());
    assert!(heads_of(&b, &a_id).contains(&(head + 1)));
    assert_eq!(fs::read(lab.root.join("b-docs/six.txt")).unwrap(), b"sixth");
}

/// Point the storage named `name` in a device's config at `path`, and
/// add the other storages given before it (so they are read first).
fn set_storages(home: &Path, name: &str, path: &Path, extra: &[(&str, &Path)]) {
    let p = home.join("config.json");
    let mut cfg: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    let list = cfg["storages"].as_array_mut().unwrap();
    let mut template = None;
    for s in list.iter_mut() {
        if s["name"] == name {
            s["path"] = serde_json::json!(path);
            template = Some(s.clone());
        }
    }
    for (n, p) in extra {
        let mut s = template.clone().unwrap();
        s["name"] = serde_json::json!(n);
        s["path"] = serde_json::json!(p);
        list.insert(0, s);
    }
    fs::write(&p, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
}

/// S3, a real fork: two copies of one device both published a batch with
/// the same number. The rebuild refuses, says to pair the device again,
/// and the device stays fenced across restarts.
#[test]
fn s3_two_copies_of_one_identity_are_refused() {
    let (lab, mut a, b) = two_devices();
    let home = lab.a_home();
    let twin = lab.root.join("a-twin");
    let alt = lab.root.join("storage-alt");
    copy_tree(&home, &twin);
    copy_tree(&lab.storage_dir(), &alt);
    drop(b);
    // The original goes on with the shared storage.
    a.add_folder("photos", &lab.root.join("a-photos")).unwrap();
    // The twin, seeing only a copy of the storage, signs the same number.
    set_storages(&twin, "box", &alt, &[]);
    let mut t = open(&twin);
    t.add_folder("music", &lab.root.join("t-music")).unwrap();
    assert_eq!(own_head(&t), own_head(&a));
    drop(t);
    // Now it sees both storages.
    set_storages(&twin, "box", &lab.storage_dir(), &[("alt", &alt)]);
    let mut t = open(&twin);
    let err = format!(
        "{:#}",
        t.ledger_rebuild(&LedgerRebuildOptions::default())
            .unwrap_err()
    );
    assert!(err.contains("pair this computer again"), "{err}");
    let h = t.ledger_health();
    assert_eq!(h.state, "forked");
    assert!(!h.automatic);
    drop(t);
    let mut t = open(&twin);
    assert_eq!(t.ledger_health().state, "forked", "remembered");
    assert!(t.sync(None).is_err());
    // The original is not disturbed.
    a.sync(None).unwrap();
    assert!(a.ledger_health().is_ok());
}

/// S4: the ledger is gone from the storage and from both devices. The
/// first device restores what it can (no batch), enrols again and, as no
/// ledger is left anywhere while its folder names blocks, rebuilds the
/// claims: every pack its block maps name is read and hashed, then
/// claimed, and its map and manifest records are announced again. A device
/// joining afterwards pulls identical files and fsck with verification is
/// clean; the second device restores itself and syncs without a fork.
#[test]
fn s4_ledger_lost_everywhere_is_rebuilt_from_storage() {
    let (lab, a, b) = two_devices();
    let before = claims(&a);
    assert!(!before.is_empty());
    drop((a, b));
    fs::remove_dir_all(lab.storage_dir().join("ledger")).unwrap();
    fs::remove_dir_all(lab.a_home().join("ledger")).unwrap();
    fs::remove_dir_all(lab.b_home().join("ledger")).unwrap();

    let mut a = open(&lab.a_home());
    assert_eq!(a.ledger_health().state, "rebuild_needed");
    let r = a
        .ledger_rebuild(&LedgerRebuildOptions {
            from_storage: true,
            ..Default::default()
        })
        .unwrap();
    assert!(!r.own_found_on_storages);
    assert!(r.reenrolled);
    let s = r.from_storage.expect("claims rebuilt");
    assert!(s.claims_written > 0, "{s:?}");
    assert_eq!(s.objects_corrupt, 0);
    assert_eq!(s.objects_unverified, 0, "a small vault is verified in full");
    assert!(s.objects_verified > 0);
    assert!(s.manifests_announced > 0);
    assert!(!r.no_ledger_anywhere);
    assert!(r.health.is_ok(), "{:?}", r.health);
    assert!(claims(&a).is_superset(&before));
    let st = a.status().unwrap();
    assert_eq!(st.folders[0].chunks_without_storage_copy, 0);
    // Running it again adds nothing.
    let again = a
        .ledger_rebuild(&LedgerRebuildOptions {
            from_storage: true,
            ..Default::default()
        })
        .unwrap()
        .from_storage
        .unwrap();
    assert_eq!(again.claims_written, 0);

    // A new device pulls byte-identical files; fsck with verification is clean.
    let mut c = common::join_approved(
        &lab.root.join("c"),
        "tablet",
        PASS,
        &lab.key,
        lab.storage.clone(),
        &mut a,
    );
    c.chunker = ChunkerParams::SMALL;
    c.attach_folder("docs", &lab.root.join("c-docs"), false)
        .unwrap();
    c.sync(None).unwrap();
    assert_eq!(tree(&lab.a_docs()), tree(&lab.root.join("c-docs")));
    let f = c.fsck(true).unwrap();
    assert!(f.chunks_missing.is_empty(), "{f:?}");
    assert!(f.objects_corrupt.is_empty(), "{f:?}");
    assert_eq!(f.claims_without_object, 0);
    assert!(f.forked_devices.is_empty());
    assert_eq!(f.chunks_referenced, f.chunks_with_storage_copy);
    assert!(f.ledger_health.is_ok(), "{:?}", f.ledger_health);

    // B comes back: its own ledger is gone too; it enrols again and syncs.
    let mut b = open(&lab.b_home());
    assert_eq!(b.ledger_health().state, "rebuild_needed");
    let r = b.ledger_rebuild(&LedgerRebuildOptions::default()).unwrap();
    assert!(r.reenrolled);
    assert!(!r.no_ledger_anywhere, "A rebuilt the claims already");
    b.sync(None).unwrap();
    assert!(b.status().unwrap().forked_devices.is_empty());
    assert!(a.sync(None).is_ok());
    assert!(a.status().unwrap().forked_devices.is_empty());
}

/// S4 in the service: one automatic rebuild restores what it can and, as
/// no ledger is left anywhere, rebuilds the claims as well; a damaged
/// object is not claimed but queued for repair.
#[test]
fn s4_service_rebuilds_by_itself_and_skips_damaged_objects() {
    let (lab, a, b) = two_devices();
    let objects: Vec<String> = common::object_names(&lab.storage_dir())
        .into_iter()
        .collect();
    drop((a, b));
    fs::remove_dir_all(lab.storage_dir().join("ledger")).unwrap();
    fs::remove_dir_all(lab.a_home().join("ledger")).unwrap();
    fs::remove_dir_all(lab.b_home().join("ledger")).unwrap();
    // Damage one object as it is read (an object kept both alone and in a
    // pack is read from the pack).
    let _damaged = objects
        .iter()
        .find(|o| {
            common::corrupt_object(&lab.storage_dir(), o);
            !common::intact(&lab.storage_dir(), o)
        })
        .expect("an object to damage");
    let mut a = open(&lab.a_home());
    let h = a.ledger_health();
    assert!(h.automatic);
    let r = a.ledger_rebuild(&LedgerRebuildOptions::service()).unwrap();
    let s = r.from_storage.expect("rebuilt by itself");
    assert_eq!(s.objects_corrupt, 1);
    assert!(s.claims_written > 0);
    assert!(r.health.is_ok());
    assert!(
        a.repair_status().queued >= 1,
        "the damaged copy waits for repair"
    );
}

/// S5: a damaged cached view is rebuilt from the batches.
#[test]
fn s5_damaged_view_cache_is_rebuilt() {
    let (lab, a, b) = two_devices();
    let home = lab.a_home();
    let before = a.ledger_view3().unwrap().canonical();
    drop((a, b));
    fs::write(home.join("ledger/view.rec"), b"garbage").unwrap();
    let a = open(&home);
    assert_eq!(a.ledger_view3().unwrap().canonical(), before);
    assert!(a.ledger_health().is_ok());
}

/// `ledger status`: heads per device and where their batches are held.
#[test]
fn ledger_status_lists_heads_and_holdings() {
    let (_lab, mut a, b) = two_devices();
    let st = a.ledger_status(true).unwrap();
    assert!(st.health.is_ok());
    assert_eq!(st.devices.len(), 2);
    for d in &st.devices {
        assert!(d.head > 0);
        let here = d.held.iter().find(|h| h.place == "this device").unwrap();
        let on_box = d.held.iter().find(|h| h.place == "box").unwrap();
        assert_eq!(here.last, Some(d.head));
        assert_eq!(on_box.last, Some(d.head), "{d:?}");
    }
    assert!(st
        .devices
        .iter()
        .any(|d| d.this_device && d.name == "laptop"));
    drop(b);
}
