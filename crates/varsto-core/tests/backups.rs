// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backups (`docs/spec/alpha-0-format.md` section 31): snapshots restore
//! byte for byte, the contents never reach the vault's devices or its
//! transferrers, snapshots cannot be altered unnoticed, and expiry deletes
//! exactly the blocks no live snapshot uses (packed ones included), leaves
//! other folders alone and removes a stopped backup with its last snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::engine::{BackupOptions, SnapshotPick};
use varsto_core::ids::FolderId;
use varsto_core::storage::StorageSpec;
use varsto_core::vault::BackupSchedule;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const DAY: i64 = 86_400;

fn dir(name: &str, path: &Path, carrier: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier,
        place: String::new(),
        min_free: None,
    }
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    key: String,
}

impl Lab {
    fn p(&self, n: &str) -> PathBuf {
        self.root.join(n)
    }
}

/// Device "laptop" with storages "one" and "two" and transferrer "usb", and
/// a directory "src" with small and large files.
fn lab() -> (Lab, Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    for d in ["one", "two", "usb", "src/docs", "src/media"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let (mut a, key) = Engine::init(&root.join("laptop"), "laptop", PASS).unwrap();
    a.add_storage(dir("one", &root.join("one"), false)).unwrap();
    a.add_storage(dir("two", &root.join("two"), false)).unwrap();
    a.add_storage(dir("usb", &root.join("usb"), true)).unwrap();
    fs::write(root.join("src/docs/a.txt"), b"alpha").unwrap();
    fs::write(
        root.join("src/docs/b.txt"),
        b"bravo, only in the first snapshot",
    )
    .unwrap();
    fs::write(root.join("src/top.txt"), b"top level").unwrap();
    fs::write(root.join("src/media/big.bin"), pattern(3_000_000, 1)).unwrap();
    fs::write(root.join("src/empty"), b"").unwrap();
    (
        Lab {
            _tmp: tmp,
            root,
            key,
        },
        a,
    )
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Every file under `root` by relative path.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(root).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

fn objects(path: &Path) -> usize {
    walkdir::WalkDir::new(path.join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

fn chunk_key(object: &str) -> String {
    format!("chunks/{}/{object}", &object[..2])
}

/// Objects of a folder's blocks that the storage still holds (packed or not).
fn stored(e: &Engine, storage: &str, folder: &FolderId) -> BTreeSet<String> {
    let backend = e.open_storage(storage).unwrap();
    e.view()
        .unwrap()
        .chunks
        .iter()
        .filter(|((f, _), _)| f == folder)
        .map(|(_, r)| r.object.to_string())
        .filter(|o| backend.exists(&chunk_key(o)).unwrap())
        .collect()
}

/// Object names listed in the pack indexes of a storage directory.
fn packed(path: &Path) -> BTreeSet<String> {
    walkdir::WalkDir::new(path.join("packs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "idx"))
        .flat_map(|e| {
            let idx: varsto_core::packs::PackIndex =
                serde_json::from_slice(&fs::read(e.path()).unwrap()).unwrap();
            idx.members.into_iter().map(|m| m.object)
        })
        .collect()
}

fn snapshot_files(path: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(path.join("snapshots"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

#[test]
fn snapshots_restore_byte_for_byte() {
    let (lab, mut a) = lab();
    let id = a
        .add_backup("photos-backup", &lab.p("src"), BackupOptions::default())
        .unwrap();
    // A backup is no folder: not listed, never synced, never attached.
    assert!(a.folders().iter().all(|(r, _)| r.folder_id != id));
    let first_tree = tree(&lab.p("src"));
    let s1 = a.take_snapshot("photos-backup").unwrap();
    assert_eq!(s1.seq, 1);
    assert_eq!(s1.files, 5);
    assert!(s1.skipped.is_empty());
    // A snapshot is written also when nothing changed.
    assert_eq!(a.take_snapshot("photos-backup").unwrap().seq, 2);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(lab.p("src/docs/a.txt"), b"alpha, second version").unwrap();
    fs::remove_file(lab.p("src/docs/b.txt")).unwrap();
    fs::write(lab.p("src/docs/c.txt"), b"charlie").unwrap();
    let second_tree = tree(&lab.p("src"));
    let s3 = a.take_snapshot("photos-backup").unwrap();
    assert_eq!(s3.seq, 3);
    assert_eq!(a.backup_snapshots("photos-backup").unwrap().len(), 3);
    // The source directory was only read.
    assert_eq!(tree(&lab.p("src")), second_tree);

    let out = lab.p("restore-latest");
    let r = a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::Latest,
            &out,
            &[],
            false,
            false,
        )
        .unwrap();
    assert_eq!(r.seq, 3);
    assert!(r.unavailable.is_empty(), "{:?}", r.unavailable);
    assert_eq!(tree(&out), second_tree);

    let out = lab.p("restore-1");
    a.restore_snapshot(
        "photos-backup",
        SnapshotPick::Seq(1),
        &out,
        &[],
        false,
        false,
    )
    .unwrap();
    assert_eq!(tree(&out), first_tree);

    // By date: the newest snapshot taken by then.
    let out = lab.p("restore-date");
    let r = a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::OnOrBefore(s1.taken_utc),
            &out,
            &[],
            false,
            false,
        )
        .unwrap();
    assert!(r.seq <= 2);
    assert_eq!(tree(&out), first_tree);
    assert!(a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::OnOrBefore(s1.taken_utc - 1),
            &lab.p("too-early"),
            &[],
            false,
            false
        )
        .is_err());

    // Only some paths.
    let out = lab.p("restore-docs");
    let r = a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::Seq(1),
            &out,
            &["docs".to_string()],
            false,
            false,
        )
        .unwrap();
    assert_eq!(r.files_restored, 2);
    let docs: BTreeMap<String, Vec<u8>> = first_tree
        .iter()
        .filter(|(k, _)| k.starts_with("docs/"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(tree(&out), docs);
    assert!(a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::Seq(1),
            &lab.p("nothing"),
            &["nope".to_string()],
            false,
            false
        )
        .is_err());

    // A directory with something in it is refused unless overwriting.
    let busy = lab.p("busy");
    fs::create_dir_all(&busy).unwrap();
    fs::write(busy.join("keep.txt"), b"mine").unwrap();
    let err = a
        .restore_snapshot(
            "photos-backup",
            SnapshotPick::Latest,
            &busy,
            &[],
            false,
            false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("not empty"), "{err}");
    assert_eq!(tree(&busy).len(), 1);
    a.restore_snapshot(
        "photos-backup",
        SnapshotPick::Latest,
        &busy,
        &[],
        true,
        false,
    )
    .unwrap();
    let mut expected = second_tree.clone();
    expected.insert("keep.txt".into(), b"mine".to_vec());
    assert_eq!(tree(&busy), expected);

    // Another device of the vault restores it as well, from the storages.
    let mut b = Engine::join(
        &lab.p("desktop"),
        "desktop",
        PASS,
        &lab.key,
        dir("one", &lab.p("one"), false),
    )
    .unwrap();
    b.sync(None).unwrap();
    let list = b.backups().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].snapshots, 3);
    assert!(!list[0].this_device);
    // Only the source takes snapshots.
    assert!(b.take_snapshot("photos-backup").is_err());
    let out = lab.p("restore-elsewhere");
    b.restore_snapshot(
        "photos-backup",
        SnapshotPick::Seq(1),
        &out,
        &[],
        false,
        false,
    )
    .unwrap();
    assert_eq!(tree(&out), first_tree);
}

#[test]
fn devices_and_transferrers_never_receive_backup_contents() {
    let (lab, mut a) = lab();
    let id = a
        .add_backup("bk", &lab.p("src"), BackupOptions::default())
        .unwrap();
    a.take_snapshot("bk").unwrap();
    // Kept on both storages, never on the transferrer.
    assert!(objects(&lab.p("one")) > 0 || !packed(&lab.p("one")).is_empty());
    assert_eq!(objects(&lab.p("usb")), 0);
    assert!(!lab.p("usb/packs").exists());
    assert!(snapshot_files(&lab.p("usb")).is_empty());
    assert_eq!(snapshot_files(&lab.p("one")).len(), 1);
    assert_eq!(snapshot_files(&lab.p("two")).len(), 1);
    // No device claims to hold its blocks.
    let view = a.view().unwrap();
    let mine: Vec<_> = view.chunks.iter().filter(|((f, _), _)| f == &id).collect();
    assert!(!mine.is_empty());
    assert!(mine.iter().all(|(_, r)| r.devices.is_empty()));
    assert!(mine.iter().all(|(_, r)| !r.storages.contains_key("usb")));

    let mut b = Engine::join(
        &lab.p("desktop"),
        "desktop",
        PASS,
        &lab.key,
        dir("one", &lab.p("one"), false),
    )
    .unwrap();
    b.sync(None).unwrap();
    assert!(b.folders().iter().all(|(r, _)| r.folder_id != id));
    let err = b.attach_folder("bk", &lab.p("b-bk"), false).unwrap_err();
    assert!(err.to_string().contains("backup"), "{err}");
    assert!(!lab.p("b-bk").exists());
    assert!(b.status().unwrap().folders.is_empty());
    // A restore on b fetches from the storages and still records nothing
    // held on a device.
    b.restore_snapshot("bk", SnapshotPick::Latest, &lab.p("out"), &[], false, false)
        .unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let view = a.view().unwrap();
    assert!(view
        .chunks
        .iter()
        .filter(|((f, _), _)| f == &id)
        .all(|(_, r)| r.devices.is_empty()));
    assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
}

#[test]
fn an_altered_snapshot_is_refused() {
    let (lab, mut a) = lab();
    a.add_backup("bk", &lab.p("src"), BackupOptions::default())
        .unwrap();
    a.take_snapshot("bk").unwrap();
    // One storage's copy altered: the other one's is used.
    let one = snapshot_files(&lab.p("one"));
    let mut blob = fs::read(&one[0]).unwrap();
    let n = blob.len();
    blob[n / 2] ^= 1;
    fs::write(&one[0], &blob).unwrap();
    let out = lab.p("out");
    a.restore_snapshot("bk", SnapshotPick::Latest, &out, &[], false, false)
        .unwrap();
    assert_eq!(tree(&out), tree(&lab.p("src")));
    // Both altered: nothing is restored. Even a validly sealed replacement
    // (an older snapshot copied over) does not match the ledger.
    let two = snapshot_files(&lab.p("two"));
    fs::write(&two[0], &blob).unwrap();
    let err = a
        .restore_snapshot(
            "bk",
            SnapshotPick::Latest,
            &lab.p("out2"),
            &[],
            false,
            false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("altered"), "{err}");
    fs::write(lab.p("src/docs/a.txt"), b"changed").unwrap();
    a.take_snapshot("bk").unwrap();
    let newer: Vec<PathBuf> = snapshot_files(&lab.p("one"))
        .into_iter()
        .filter(|p| p != &one[0])
        .collect();
    fs::copy(&newer[0], &one[0]).unwrap();
    fs::copy(&newer[0], &two[0]).unwrap();
    assert!(a
        .restore_snapshot(
            "bk",
            SnapshotPick::Seq(1),
            &lab.p("out3"),
            &[],
            false,
            false
        )
        .is_err());
}

#[test]
fn expiry_deletes_only_what_no_live_snapshot_uses() {
    let (lab, mut a) = lab();
    // An ordinary folder beside the backup.
    fs::create_dir_all(lab.p("docs")).unwrap();
    fs::write(lab.p("docs/note.txt"), b"a note").unwrap();
    fs::write(lab.p("docs/large.bin"), pattern(500_000, 9)).unwrap();
    let docs = a.add_folder("docs", &lab.p("docs")).unwrap();
    a.sync(None).unwrap();

    let id = a
        .add_backup(
            "bk",
            &lab.p("src"),
            BackupOptions {
                retention_days: 1,
                schedule: BackupSchedule::Manual,
                placement: None,
            },
        )
        .unwrap();
    let s1 = a.take_snapshot("bk").unwrap();
    let after_first = stored(&a, "one", &id);
    // The second snapshot is kept longer and lacks b.txt and big.bin.
    a.set_backup("bk", Some(90), None).unwrap();
    fs::remove_file(lab.p("src/docs/b.txt")).unwrap();
    fs::remove_file(lab.p("src/media/big.bin")).unwrap();
    fs::write(lab.p("src/docs/d.txt"), b"delta").unwrap();
    let s2 = a.take_snapshot("bk").unwrap();
    assert!(s2.expires_utc - s1.expires_utc >= 89 * DAY);
    let second_tree = tree(&lab.p("src"));
    let before = stored(&a, "one", &id);
    let docs_before = (stored(&a, "one", &docs), stored(&a, "two", &docs));
    let packed_before = packed(&lab.p("one"));
    assert!(!docs_before.0.is_empty());

    // Within the grace period nothing goes.
    let r = a.expire_backups_at(s1.expires_utc + DAY / 2).unwrap();
    assert_eq!(r.snapshots_expired, 0);
    assert_eq!(stored(&a, "one", &id), before);

    let r = a.expire_backups_at(s1.expires_utc + DAY + 60).unwrap();
    assert_eq!(r.snapshots_expired, 1);
    assert!(r.waiting.is_empty());
    let after = stored(&a, "one", &id);
    let gone: BTreeSet<String> = before.difference(&after).cloned().collect();
    assert!(!gone.is_empty());
    assert!(gone.is_subset(&after_first));
    // Small blocks were in packs: those went as well.
    assert!(gone.iter().any(|o| packed_before.contains(o)));
    assert_eq!(stored(&a, "two", &id), after);
    // The live snapshot is whole, its snapshot object stays, the expired one
    // is gone, and the folder beside it is untouched.
    assert_eq!(
        a.backup_snapshots("bk")
            .unwrap()
            .iter()
            .map(|s| s.seq)
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(snapshot_files(&lab.p("one")).len(), 1);
    let out = lab.p("out");
    let r = a
        .restore_snapshot("bk", SnapshotPick::Latest, &out, &[], false, false)
        .unwrap();
    assert!(r.unavailable.is_empty(), "{:?}", r.unavailable);
    assert_eq!(tree(&out), second_tree);
    assert!(a
        .restore_snapshot("bk", SnapshotPick::Seq(1), &lab.p("x"), &[], false, false)
        .is_err());
    assert_eq!(
        (stored(&a, "one", &docs), stored(&a, "two", &docs)),
        docs_before
    );
    // Running it again changes nothing.
    let r = a.expire_backups_at(s1.expires_utc + DAY + 120).unwrap();
    assert_eq!((r.snapshots_expired, r.objects_deleted), (0, 0));
    assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
    let fsck = a.fsck(false).unwrap();
    assert!(fsck.chunks_missing.is_empty(), "{:?}", fsck.chunks_missing);
}

#[test]
fn other_devices_wait_for_the_source() {
    let (lab, mut a) = lab();
    a.add_backup(
        "bk",
        &lab.p("src"),
        BackupOptions {
            retention_days: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let s1 = a.take_snapshot("bk").unwrap();
    let mut b = Engine::join(
        &lab.p("desktop"),
        "desktop",
        PASS,
        &lab.key,
        dir("one", &lab.p("one"), false),
    )
    .unwrap();
    b.add_storage(dir("two", &lab.p("two"), false)).unwrap();
    b.sync(None).unwrap();
    // The source is in the vault: b leaves the expiry to it at first ...
    let r = b.expire_backups_at(s1.expires_utc + DAY + 60).unwrap();
    assert_eq!(r.snapshots_expired, 0);
    // ... and steps in once two days have passed.
    let r = b.expire_backups_at(s1.expires_utc + 2 * DAY + 60).unwrap();
    assert_eq!(r.snapshots_expired, 1);
    assert!(r.objects_deleted > 0);
    a.sync(None).unwrap();
    assert!(a.backup_snapshots("bk").unwrap().is_empty());
}

#[test]
fn a_stopped_backup_goes_with_its_last_snapshot() {
    let (lab, mut a) = lab();
    let id = a
        .add_backup("bk", &lab.p("src"), BackupOptions::default())
        .unwrap();
    // Names are unique across folders and backups.
    assert!(a.add_folder("bk", &lab.p("other")).is_err());
    let s1 = a.take_snapshot("bk").unwrap();
    a.stop_backup("bk").unwrap();
    assert!(a.take_snapshot("bk").is_err());
    assert!(a.backups().unwrap()[0].stopped);
    assert!(a.backups_due(s1.taken_utc + 10 * DAY).is_empty());
    // Stopping deletes nothing early.
    let r = a.expire_backups_at(s1.taken_utc + 30 * DAY).unwrap();
    assert_eq!(r.snapshots_expired, 0);
    assert_eq!(a.backup_snapshots("bk").unwrap().len(), 1);

    let r = a.expire_backups_at(s1.expires_utc + DAY + 60).unwrap();
    assert_eq!(r.snapshots_expired, 1);
    assert_eq!(r.backups_removed, vec!["bk".to_string()]);
    assert!(a.backups().unwrap().is_empty());
    for s in ["one", "two"] {
        assert!(stored(&a, s, &id).is_empty());
        assert!(snapshot_files(&lab.p(s)).is_empty());
    }
    // The source directory is untouched.
    assert_eq!(tree(&lab.p("src")).len(), 5);
}

#[test]
fn schedules_and_settings() {
    let (lab, mut a) = lab();
    a.add_backup(
        "bk",
        &lab.p("src"),
        BackupOptions {
            schedule: BackupSchedule::EveryHours(24),
            ..Default::default()
        },
    )
    .unwrap();
    let now = varsto_core::util::now_utc();
    assert_eq!(a.backups_due(now), vec!["bk".to_string()]);
    let s = a.take_snapshot("bk").unwrap();
    assert!(a.backups_due(s.taken_utc + 3600).is_empty());
    assert_eq!(a.backups_due(s.taken_utc + DAY), vec!["bk".to_string()]);
    a.set_backup("bk", None, Some(BackupSchedule::Manual))
        .unwrap();
    assert!(a.backups_due(s.taken_utc + 10 * DAY).is_empty());
    // A requested snapshot is due whatever the schedule, shows as requested,
    // and taking it clears the request.
    a.request_snapshot("bk").unwrap();
    assert_eq!(a.backups_due(s.taken_utc + 3600), vec!["bk".to_string()]);
    assert!(a.backups().unwrap()[0].snapshot_requested);
    a.take_snapshot("bk").unwrap();
    assert!(a.backups_due(s.taken_utc + 10 * DAY).is_empty());
    assert!(!a.backups().unwrap()[0].snapshot_requested);
    assert!(a.set_backup("bk", Some(0), None).is_err());
    // A backup needs a storage that is not a transferrer.
    let (mut lone, _) = Engine::init(&lab.p("lone"), "lone", PASS).unwrap();
    fs::create_dir_all(lab.p("usb2")).unwrap();
    lone.add_storage(dir("usb", &lab.p("usb2"), true)).unwrap();
    assert!(lone
        .add_backup("x", &lab.p("src"), BackupOptions::default())
        .is_err());
}
