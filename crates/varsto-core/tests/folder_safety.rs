// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder safety (spec section 47): the folder marker that keeps an
//! unmounted disk from reading as "every file deleted", the mass-deletion
//! guard, send-only and receive-only folders, and downloads newest first.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{PauseKind, FOLDER_MARKER};
use varsto_core::storage::StorageSpec;
use varsto_core::vault::{DeletionGuard, FolderMode};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

/// The folder's files (the marker and Varsto's own files left out).
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if !root.exists() {
        return out;
    }
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
            if rel.split('/').any(|c| c.starts_with(".varsto")) {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

fn trash_files(home: &Path) -> Vec<(String, Vec<u8>)> {
    let root = home.join("trash");
    if !root.exists() {
        return Vec::new();
    }
    walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Lab {
            storage: StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("storage"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            },
            a_dir: root.join("a-docs"),
            b_dir: root.join("b-docs"),
            root,
            _tmp: tmp,
        }
    }

    /// Device A with folder "docs" holding `files` small files, pushed.
    fn device_a(&self, files: usize) -> (Engine, String) {
        let (mut a, key) = Engine::init(&self.root.join("a-home"), "laptop", PASS).unwrap();
        a.chunker = ChunkerParams::SMALL;
        a.add_storage(self.storage.clone()).unwrap();
        a.add_folder("docs", &self.a_dir).unwrap();
        for i in 0..files {
            fs::write(self.a_dir.join(format!("f{i:04}.txt")), format!("file {i}")).unwrap();
        }
        a.sync(None).unwrap();
        (a, key)
    }

    /// Device B attached to "docs" and pulled.
    fn device_b(&self, a: &mut Engine, key: &str) -> Engine {
        let mut b = Engine::join(
            &self.root.join("b-home"),
            "phone",
            PASS,
            key,
            self.storage.clone(),
        )
        .unwrap();
        Engine::grant_all_for_tests(a, &mut b).unwrap();
        b.chunker = ChunkerParams::SMALL;
        b.attach_folder("docs", &self.b_dir, false).unwrap();
        b.sync(None).unwrap();
        b
    }
}

fn paused_kind(e: &mut Engine) -> Option<PauseKind> {
    let reports = e.sync(Some("docs")).unwrap();
    reports[0].0.paused.as_ref().map(|p| p.kind)
}

fn status_of(e: &Engine) -> varsto_core::engine::FolderStatus {
    e.status()
        .unwrap()
        .folders
        .into_iter()
        .find(|f| f.name == "docs")
        .unwrap()
}

#[test]
fn adding_and_attaching_write_the_marker() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(2);
    let id = a.folders()[0].0.folder_id.to_string();
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(lab.a_dir.join(FOLDER_MARKER)).unwrap()).unwrap();
    assert_eq!(marker["folder_id"], id.as_str());
    assert_eq!(marker["name"], "docs");
    let _b = lab.device_b(&mut a, &key);
    assert!(lab.b_dir.join(FOLDER_MARKER).is_file());
    // The marker is not a file of the folder.
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert!(!tree(&lab.b_dir).contains_key(FOLDER_MARKER));
}

#[test]
fn empty_root_without_marker_pauses_and_nothing_is_deleted() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(5);
    let mut b = lab.device_b(&mut a, &key);
    let before = tree(&lab.a_dir);
    assert_eq!(before.len(), 5);

    // The disk is unmounted: the mount point is there, empty.
    let away = lab.root.join("a-docs-away");
    fs::rename(&lab.a_dir, &away).unwrap();
    fs::create_dir(&lab.a_dir).unwrap();
    assert_eq!(paused_kind(&mut a), Some(PauseKind::MarkerMissing));
    let st = status_of(&a);
    let p = st.paused.expect("paused in status");
    assert!(p.message.contains("is the disk mounted?"), "{}", p.message);
    assert!(p.message.contains("varsto folder repair-marker docs"));
    assert_eq!(st.files, 5, "no file was read as deleted");
    // Explicit pull and push refuse with the same pause.
    let err = a.push("docs").unwrap_err();
    assert_eq!(
        varsto_core::engine::paused_error(&err).unwrap().kind,
        PauseKind::MarkerMissing
    );
    assert!(a.pull("docs").is_err());
    // Other folders are not held up: a sync of everything still succeeds.
    assert!(a.sync(None).is_ok());

    // B sees no deletion.
    let pb = b.sync(None).unwrap();
    assert_eq!(pb[0].0.files_deleted, 0);
    assert_eq!(tree(&lab.b_dir), before);

    // The disk is back: the folder resumes with nothing lost.
    fs::remove_dir(&lab.a_dir).unwrap();
    fs::rename(&away, &lab.a_dir).unwrap();
    assert_eq!(paused_kind(&mut a), None);
    assert!(status_of(&a).paused.is_none());
    fs::write(lab.a_dir.join("new.txt"), b"after the disk came back").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(tree(&lab.b_dir).len(), 6);
}

#[test]
fn a_missing_root_pauses_too() {
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(3);
    let away = lab.root.join("gone");
    fs::rename(&lab.a_dir, &away).unwrap();
    assert_eq!(paused_kind(&mut a), Some(PauseKind::MarkerMissing));
    // Repairing needs the directory.
    assert!(a.repair_marker("docs").is_err());
    fs::rename(&away, &lab.a_dir).unwrap();
    assert_eq!(paused_kind(&mut a), None);
}

#[test]
fn another_folders_marker_pauses_until_repaired() {
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(3);
    let pics = lab.root.join("a-pics");
    a.add_folder("pics", &pics).unwrap();
    fs::write(pics.join("p.jpg"), b"picture").unwrap();
    a.sync(None).unwrap();
    // The wrong disk is mounted at docs: it carries pics' marker.
    fs::copy(pics.join(FOLDER_MARKER), lab.a_dir.join(FOLDER_MARKER)).unwrap();
    assert_eq!(paused_kind(&mut a), Some(PauseKind::MarkerOther));
    let msg = status_of(&a).paused.unwrap().message;
    assert!(msg.contains("belongs to another folder"), "{msg}");
    // pics is unaffected.
    let r = a.sync(Some("pics")).unwrap();
    assert!(r[0].0.paused.is_none());
    // The user says the directory is right.
    a.repair_marker("docs").unwrap();
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 3);
}

#[test]
fn pull_does_not_fill_an_unmarked_root() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(3);
    let mut b = lab.device_b(&mut a, &key);
    // B's disk is unmounted; A adds files meanwhile.
    let away = lab.root.join("b-docs-away");
    fs::rename(&lab.b_dir, &away).unwrap();
    fs::create_dir(&lab.b_dir).unwrap();
    fs::write(lab.a_dir.join("later.txt"), b"later").unwrap();
    a.sync(None).unwrap();
    let err = b.pull("docs").unwrap_err();
    assert_eq!(
        varsto_core::engine::paused_error(&err).unwrap().kind,
        PauseKind::MarkerMissing
    );
    assert_eq!(paused_kind(&mut b), Some(PauseKind::MarkerMissing));
    assert!(b.fetch_file("docs", "later.txt").is_err());
    assert_eq!(
        fs::read_dir(&lab.b_dir).unwrap().count(),
        0,
        "nothing was written into the empty mount point"
    );
    // Back: the new file arrives.
    fs::remove_dir(&lab.b_dir).unwrap();
    fs::rename(&away, &lab.b_dir).unwrap();
    b.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
}

#[test]
fn older_mounts_get_a_marker_only_when_their_files_are_there() {
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(4);
    let home = lab.root.join("a-home");
    let id = a.folders()[0].0.folder_id.to_string();
    // As before markers existed: no marker, no record of one.
    let forget = || {
        fs::remove_file(lab.a_dir.join(FOLDER_MARKER)).unwrap();
        fs::remove_file(home.join("state").join(format!("{id}.marked"))).unwrap();
    };
    forget();
    assert_eq!(paused_kind(&mut a), None, "files are there: adopted");
    assert!(lab.a_dir.join(FOLDER_MARKER).is_file());
    // An older mount whose disk is not mounted at the upgrade: paused.
    forget();
    let away = lab.root.join("away");
    fs::rename(&lab.a_dir, &away).unwrap();
    fs::create_dir(&lab.a_dir).unwrap();
    assert_eq!(paused_kind(&mut a), Some(PauseKind::MarkerMissing));
    assert!(!lab.a_dir.join(FOLDER_MARKER).exists());
    assert_eq!(status_of(&a).files, 4);
}

#[test]
fn mass_deletion_is_held_and_discard_restores() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(150);
    let mut b = lab.device_b(&mut a, &key);
    let before = tree(&lab.a_dir);
    for i in 0..120 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), Some(PauseKind::DeletionsHeld));
    let st = status_of(&a);
    let held = st.held_deletions.expect("held deletions in status");
    assert_eq!(
        (held.origin.as_str(), held.files, held.of_files),
        ("local", 120, 150)
    );
    assert!(st
        .paused
        .unwrap()
        .message
        .contains("varsto folder confirm-deletions docs"));
    // Nothing was published.
    let pb = b.sync(None).unwrap();
    assert_eq!(pb[0].0.files_deleted, 0);
    assert_eq!(tree(&lab.b_dir).len(), 150);
    // Restore them instead.
    let r = a.discard_deletions("docs").unwrap();
    assert_eq!(r.restored, 120);
    assert!(r.unavailable.is_empty());
    assert_eq!(tree(&lab.a_dir), before);
    assert_eq!(paused_kind(&mut a), None);
    b.sync(None).unwrap();
    assert_eq!(tree(&lab.b_dir), before);
}

#[test]
fn files_coming_back_release_a_hold() {
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(150);
    let away = lab.root.join("moved");
    fs::create_dir(&away).unwrap();
    for i in 0..120 {
        let n = format!("f{i:04}.txt");
        fs::rename(lab.a_dir.join(&n), away.join(&n)).unwrap();
    }
    assert_eq!(paused_kind(&mut a), Some(PauseKind::DeletionsHeld));
    for i in 0..120 {
        let n = format!("f{i:04}.txt");
        fs::rename(away.join(&n), lab.a_dir.join(&n)).unwrap();
    }
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 150);
}

#[test]
fn confirmed_mass_deletion_is_held_again_on_the_other_device() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(150);
    let mut b = lab.device_b(&mut a, &key);
    for i in 0..120 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), Some(PauseKind::DeletionsHeld));
    assert!(a.discard_deletions("pics").is_err());
    assert_eq!(a.confirm_deletions("docs").unwrap(), 120);
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 30);

    // B: another device's file list would delete 120 of 150 files here.
    assert_eq!(paused_kind(&mut b), Some(PauseKind::DeletionsHeld));
    let held = status_of(&b).held_deletions.unwrap();
    assert_eq!(held.origin, "remote");
    assert_eq!(held.device.as_deref(), Some("laptop"));
    assert_eq!(held.files, 120);
    assert_eq!(
        tree(&lab.b_dir).len(),
        150,
        "nothing deleted before confirmation"
    );
    let n = b.confirm_deletions("docs").unwrap();
    assert_eq!(n, 120);
    assert_eq!(tree(&lab.b_dir).len(), 30);
    assert_eq!(trash_files(&lab.root.join("b-home")).len(), 120);
    assert_eq!(paused_kind(&mut b), None);
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // A file A adds later arrives as usual.
    fs::write(lab.a_dir.join("next.txt"), b"next").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
}

#[test]
fn remote_mass_deletion_discarded_restores_on_every_device() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(150);
    let mut b = lab.device_b(&mut a, &key);
    let before = tree(&lab.a_dir);
    for i in 0..120 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    paused_kind(&mut a);
    a.confirm_deletions("docs").unwrap();
    a.sync(None).unwrap();
    assert_eq!(paused_kind(&mut b), Some(PauseKind::DeletionsHeld));
    let r = b.discard_deletions("docs").unwrap();
    assert_eq!(r.restored, 120);
    assert_eq!(paused_kind(&mut b), None);
    assert_eq!(tree(&lab.b_dir), before);
    // A gets them back: B's versions are newer than the deletions.
    let pa = a.sync(None).unwrap();
    assert_eq!(pa[0].0.files_updated, 120);
    assert_eq!(tree(&lab.a_dir), before);
}

#[test]
fn deletions_below_the_threshold_sync_normally() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(150);
    let mut b = lab.device_b(&mut a, &key);
    // 40 of 150: under half.
    for i in 0..40 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), None);
    let pb = b.sync(None).unwrap();
    assert!(pb[0].0.paused.is_none());
    assert_eq!(pb[0].0.files_deleted, 40);
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // Most of a small folder: under the 100 files.
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(10);
    for i in 0..9 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 1);
}

#[test]
fn the_guard_is_set_per_folder() {
    let lab = Lab::new();
    let (mut a, _) = lab.device_a(30);
    a.set_deletion_guard(
        "docs",
        Some(DeletionGuard {
            enabled: true,
            percent: 100,
            min_files: 0,
            max_files: 10,
        }),
    )
    .unwrap();
    assert_eq!(status_of(&a).deletion_guard, "more than 10 files");
    for i in 0..20 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), Some(PauseKind::DeletionsHeld));
    a.confirm_deletions("docs").unwrap();
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 10);
    // Off: nothing is held.
    a.set_deletion_guard(
        "docs",
        Some(DeletionGuard {
            enabled: false,
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(status_of(&a).deletion_guard, "off");
    for i in 20..30 {
        fs::remove_file(lab.a_dir.join(format!("f{i:04}.txt"))).unwrap();
    }
    assert_eq!(paused_kind(&mut a), None);
    assert_eq!(status_of(&a).files, 0);
    // Back to the default.
    a.set_deletion_guard("docs", None).unwrap();
    assert_eq!(
        status_of(&a).deletion_guard,
        "more than 50 % and more than 100 files, or more than 1000 files"
    );
}

#[test]
fn send_only_ignores_remote_changes_until_override() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(4);
    let mut b = lab.device_b(&mut a, &key);
    b.set_folder_mode("docs", FolderMode::SendOnly).unwrap();
    assert_eq!(status_of(&b).mode, FolderMode::SendOnly);
    let b_before = tree(&lab.b_dir);

    // A edits, adds and deletes.
    fs::write(lab.a_dir.join("f0000.txt"), b"edited on A").unwrap();
    fs::write(lab.a_dir.join("added.txt"), b"added on A").unwrap();
    fs::remove_file(lab.a_dir.join("f0001.txt")).unwrap();
    a.sync(None).unwrap();
    let pb = b.sync(None).unwrap();
    assert_eq!(pb[0].0.files_updated + pb[0].0.files_deleted, 0);
    assert_eq!(
        tree(&lab.b_dir),
        b_before,
        "nothing applied on the send-only device"
    );
    assert_eq!(status_of(&b).remote_not_applied, 3);
    let ch = b.folder_changes("docs").unwrap();
    let kinds: BTreeMap<String, String> = ch
        .remote_not_applied
        .iter()
        .map(|c| (c.path.clone(), format!("{:?}", c.kind)))
        .collect();
    assert_eq!(kinds["f0000.txt"], "Modified");
    assert_eq!(kinds["added.txt"], "Added");
    assert_eq!(kinds["f0001.txt"], "Deleted");

    // B's own changes are still published.
    fs::write(lab.b_dir.join("from-b.txt"), b"camera").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(fs::read(lab.a_dir.join("from-b.txt")).unwrap(), b"camera");

    // Override: everyone matches B.
    assert_eq!(b.override_remote("docs").unwrap(), 3);
    b.sync(None).unwrap();
    assert_eq!(status_of(&b).remote_not_applied, 0);
    a.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(fs::read(lab.a_dir.join("f0000.txt")).unwrap(), b"file 0");
    assert!(lab.a_dir.join("f0001.txt").exists());
    assert!(!lab.a_dir.join("added.txt").exists());
}

#[test]
fn send_only_back_to_normal_applies_what_waited() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(2);
    let mut b = lab.device_b(&mut a, &key);
    b.set_folder_mode("docs", FolderMode::SendOnly).unwrap();
    fs::write(lab.a_dir.join("f0000.txt"), b"edited on A").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(fs::read(lab.b_dir.join("f0000.txt")).unwrap(), b"file 0");
    b.set_folder_mode("docs", FolderMode::Normal).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("f0000.txt")).unwrap(),
        b"edited on A"
    );
    assert_eq!(status_of(&b).remote_not_applied, 0);
}

#[test]
fn receive_only_keeps_local_edits_private_and_revert_restores() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(4);
    let mut b = lab.device_b(&mut a, &key);
    b.set_folder_mode("docs", FolderMode::ReceiveOnly).unwrap();
    let vault = tree(&lab.a_dir);

    fs::write(lab.b_dir.join("f0000.txt"), b"edited on B").unwrap();
    fs::write(lab.b_dir.join("local.txt"), b"only on B").unwrap();
    fs::remove_file(lab.b_dir.join("f0001.txt")).unwrap();
    b.sync(None).unwrap();
    b.sync(None).unwrap();
    let pa = a.sync(None).unwrap();
    assert_eq!(pa[0].0.files_updated + pa[0].0.files_deleted, 0);
    assert_eq!(
        tree(&lab.a_dir),
        vault,
        "B's local changes are not published"
    );
    assert_eq!(status_of(&b).local_changes, 3);
    let ch = b.folder_changes("docs").unwrap();
    assert_eq!(ch.local_changes.len(), 3);

    // A's changes still arrive.
    fs::write(lab.a_dir.join("f0002.txt"), b"edited on A").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("f0002.txt")).unwrap(),
        b"edited on A"
    );

    // Revert: the vault's versions come back, the local copies go to the trash.
    let r = b.revert_local("docs").unwrap();
    assert_eq!(r.reverted, 3);
    assert_eq!(r.moved_to_trash, 2);
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(status_of(&b).local_changes, 0);
    let trash: Vec<Vec<u8>> = trash_files(&lab.root.join("b-home"))
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    assert!(trash.contains(&b"edited on B".to_vec()));
    assert!(trash.contains(&b"only on B".to_vec()));
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
}

#[test]
fn receive_only_remote_update_keeps_the_local_edit_in_the_trash() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(2);
    let mut b = lab.device_b(&mut a, &key);
    b.set_folder_mode("docs", FolderMode::ReceiveOnly).unwrap();
    fs::write(lab.b_dir.join("f0000.txt"), b"edited on B").unwrap();
    b.sync(None).unwrap();
    fs::write(lab.a_dir.join("f0000.txt"), b"edited on A").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("f0000.txt")).unwrap(),
        b"edited on A"
    );
    assert!(trash_files(&lab.root.join("b-home"))
        .iter()
        .any(|(_, b)| b == b"edited on B"));
    assert_eq!(status_of(&b).local_changes, 0);
}

#[test]
fn receive_only_back_to_normal_publishes_the_changes() {
    let lab = Lab::new();
    let (mut a, key) = lab.device_a(2);
    let mut b = lab.device_b(&mut a, &key);
    b.set_folder_mode("docs", FolderMode::ReceiveOnly).unwrap();
    fs::write(lab.b_dir.join("f0000.txt"), b"edited on B").unwrap();
    b.sync(None).unwrap();
    b.set_folder_mode("docs", FolderMode::Normal).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.a_dir.join("f0000.txt")).unwrap(),
        b"edited on B"
    );
}

#[test]
fn downloads_go_newest_first() {
    let lab = Lab::new();
    let (mut a, key) = Engine::init(&lab.root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    // Modification times out of name order; one file large enough for
    // several blocks.
    let times = [
        ("a.txt", 1_000_000),
        ("b.txt", 5_000_000),
        ("c.bin", 3_000_000),
        ("d.txt", 4_000_000),
        ("e.txt", 2_000_000),
    ];
    for (name, t) in times {
        let body = if name == "c.bin" {
            (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect()
        } else {
            name.as_bytes().to_vec()
        };
        let p = lab.a_dir.join(name);
        fs::write(&p, body).unwrap();
        let f = fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(UNIX_EPOCH + Duration::from_secs(t)).unwrap();
    }
    a.sync(None).unwrap();
    let mut b = Engine::join(
        &lab.root.join("b-home"),
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let log = Arc::new(Mutex::new(Vec::new()));
    b.record_downloads(log.clone());
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec!["b.txt", "d.txt", "c.bin", "e.txt", "a.txt"]
    );
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));

    // Turning selective sync off fills the placeholders newest first too.
    let lab2 = Lab::new();
    let mut c = Engine::join(
        &lab2.root.join("c-home"),
        "tablet",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    Engine::grant_all_for_tests(&mut a, &mut c).unwrap();
    c.chunker = ChunkerParams::SMALL;
    c.attach_folder("docs", &lab2.b_dir, true).unwrap();
    c.sync(None).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    c.record_downloads(log.clone());
    c.set_selective("docs", false).unwrap();
    c.sync(None).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec!["b.txt", "d.txt", "c.bin", "e.txt", "a.txt"]
    );
}

#[test]
fn guard_rules() {
    let g = DeletionGuard::default();
    assert!(!g.trips(100, 150), "100 files is not more than 100");
    assert!(g.trips(101, 150));
    assert!(!g.trips(101, 300), "a third");
    assert!(g.trips(1001, 100_000));
    assert!(!g.trips(1000, 100_000));
    assert!(!g.trips(0, 0));
}
