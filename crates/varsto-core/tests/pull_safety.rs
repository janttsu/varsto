// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A pull must not destroy a local edit that landed after the scan, and one
//! bad file must not stop the rest of the folder (ENGINE-1, ENGINE-2, ENGINE-3).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    storage_path: PathBuf,
    storage: StorageSpec,
    a_home: PathBuf,
    b_home: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    fs::create_dir_all(root.join("a-docs")).unwrap();
    fs::create_dir_all(root.join("b-docs")).unwrap();
    let storage_path = root.join("storage");
    Lab {
        storage_path: storage_path.clone(),
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: storage_path,
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        },
        a_home: root.join("a-home"),
        b_home: root.join("b-home"),
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        _tmp: tmp,
    }
}

/// Device A with `docs` pushed, device B attached to the same folder.
fn pair(lab: &Lab) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    let mut b = common::join_approved(
        &lab.b_home,
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    (a, b)
}

fn contents(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with(".varsto") {
            continue;
        }
        out.push((rel, fs::read(e.path()).unwrap()));
    }
    out.sort();
    out
}

fn has_bytes(root: &Path, bytes: &[u8]) -> bool {
    contents(root).iter().any(|(_, c)| c == bytes)
}

/// Edit `name` on B while A's version is being downloaded.
fn hook_write(dir: &Path, name: &str, bytes: &'static [u8]) -> Arc<dyn Fn(&Path) + Send + Sync> {
    let dir = dir.to_path_buf();
    let name = name.to_string();
    let once = Arc::new(AtomicBool::new(false));
    Arc::new(move |disk: &Path| {
        if disk.ends_with(&name) && !once.swap(true, Ordering::SeqCst) {
            fs::write(dir.join(&name), bytes).unwrap();
        }
    })
}

#[test]
fn a_pull_does_not_overwrite_an_edit_made_during_the_download() {
    let lab = lab();
    fs::write(lab.a_dir.join("note.txt"), b"v1").unwrap();
    let (mut a, mut b) = pair(&lab);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    assert_eq!(fs::read(lab.b_dir.join("note.txt")).unwrap(), b"v1");

    fs::write(lab.a_dir.join("note.txt"), b"from-a-v2").unwrap();
    a.push("docs").unwrap();
    drop(a);

    b.set_replace_hook(Some(hook_write(
        &lab.b_dir,
        "note.txt",
        b"local-during-pull",
    )));
    let pull = b.pull("docs").unwrap();
    b.set_replace_hook(None);
    assert_eq!(
        fs::read(lab.b_dir.join("note.txt")).unwrap(),
        b"local-during-pull"
    );
    assert!(
        pull.files_unavailable
            .iter()
            .any(|s| s.contains("note.txt") && s.contains("nothing was overwritten")),
        "{:?}",
        pull.files_unavailable
    );
    assert_eq!(pull.files_updated, 0, "{pull:?}");

    // The next sync merges the edit with the remote version; both survive.
    let synced = b.sync(Some("docs")).unwrap();
    assert!(synced[0].0.error.is_none(), "{synced:?}");
    assert!(
        has_bytes(&lab.b_dir, b"local-during-pull"),
        "{:?}",
        contents(&lab.b_dir)
    );
    assert!(
        has_bytes(&lab.b_dir, b"from-a-v2"),
        "{:?}",
        contents(&lab.b_dir)
    );
}

#[test]
fn a_pull_does_not_delete_a_file_edited_during_the_pull() {
    let lab = lab();
    fs::write(lab.a_dir.join("gone.txt"), b"keep").unwrap();
    let (mut a, mut b) = pair(&lab);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();

    fs::remove_file(lab.a_dir.join("gone.txt")).unwrap();
    a.push("docs").unwrap();
    drop(a);

    b.set_replace_hook(Some(hook_write(&lab.b_dir, "gone.txt", b"revived")));
    let pull = b.pull("docs").unwrap();
    b.set_replace_hook(None);
    assert_eq!(fs::read(lab.b_dir.join("gone.txt")).unwrap(), b"revived");
    assert_eq!(pull.files_deleted, 0, "{pull:?}");
    assert!(
        pull.files_unavailable
            .iter()
            .any(|s| s.contains("gone.txt") && s.contains("nothing was overwritten")),
        "{:?}",
        pull.files_unavailable
    );

    b.sync(Some("docs")).unwrap();
    assert!(
        has_bytes(&lab.b_dir, b"revived"),
        "{:?}",
        contents(&lab.b_dir)
    );
}

#[test]
fn a_file_that_appears_during_the_download_is_not_overwritten() {
    let lab = lab();
    let (mut a, mut b) = pair(&lab);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();

    fs::write(lab.a_dir.join("newfile.txt"), b"from-a").unwrap();
    a.push("docs").unwrap();
    drop(a);

    b.set_replace_hook(Some(hook_write(&lab.b_dir, "newfile.txt", b"mine")));
    let pull = b.pull("docs").unwrap();
    b.set_replace_hook(None);
    assert_eq!(fs::read(lab.b_dir.join("newfile.txt")).unwrap(), b"mine");
    assert!(
        pull.files_unavailable
            .iter()
            .any(|s| s.contains("newfile.txt") && s.contains("nothing was overwritten")),
        "{:?}",
        pull.files_unavailable
    );
}

#[test]
fn one_unavailable_file_does_not_stop_the_pull_or_the_push() {
    let lab = lab();
    fs::write(lab.a_dir.join("a.txt"), b"v1").unwrap();
    fs::write(lab.a_dir.join("c.txt"), b"v1").unwrap();
    let (mut a, mut b) = pair(&lab);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();

    // d.txt is stored on its own, then a.txt changes. Only the new a.txt
    // blocks are removed, so the other file can still be fetched.
    fs::write(lab.a_dir.join("d.txt"), b"DDD").unwrap();
    a.push("docs").unwrap();
    let before = common::object_names(&lab.storage_path);
    fs::write(lab.a_dir.join("a.txt"), b"AAA").unwrap();
    a.push("docs").unwrap();
    let added: Vec<String> = common::object_names(&lab.storage_path)
        .difference(&before)
        .cloned()
        .collect();
    assert!(!added.is_empty(), "the new version of a.txt stored nothing");
    for object in &added {
        common::lose_object(&lab.storage_path, object);
    }
    drop(a);

    // B's clock is ahead, so B's edit of a.txt wins and A's version is the
    // conflict copy that can no longer be downloaded.
    for _ in 0..50 {
        b.tick_clock().unwrap();
    }
    fs::write(lab.b_dir.join("a.txt"), b"BBB").unwrap();
    fs::write(lab.b_dir.join("c.txt"), b"CCC").unwrap();
    let synced = b.sync(Some("docs")).unwrap();
    let (pull, push) = &synced[0];
    assert!(pull.error.is_none(), "{pull:?}");
    assert!(pull.conflicts >= 1, "{pull:?}");
    assert!(
        !pull.files_unavailable.is_empty(),
        "the missing conflict copy should be reported, not abort the pull: {pull:?}"
    );
    assert_eq!(fs::read(lab.b_dir.join("a.txt")).unwrap(), b"BBB");
    assert_eq!(fs::read(lab.b_dir.join("d.txt")).unwrap(), b"DDD");
    assert!(
        push.files_changed >= 1,
        "local changes were not pushed: {push:?}"
    );

    let mut a = Engine::open(&lab.a_home, PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    let pulled = a.pull("docs").unwrap();
    assert!(pulled.error.is_none());
    assert_eq!(fs::read(lab.a_dir.join("c.txt")).unwrap(), b"CCC");
    assert_eq!(fs::read(lab.a_dir.join("a.txt")).unwrap(), b"BBB");
    assert_eq!(fs::read(lab.a_dir.join("d.txt")).unwrap(), b"DDD");
}

#[test]
fn a_failed_pull_still_pushes_local_changes() {
    let lab = lab();
    fs::write(lab.a_dir.join("base.txt"), b"base").unwrap();
    let (mut a, mut b) = pair(&lab);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    drop(a);

    fs::write(lab.b_dir.join("local-only.txt"), b"from-b").unwrap();
    b.fail_next_pull_for_tests("storage exploded");
    let synced = b.sync(Some("docs")).unwrap();
    let (pull, push) = &synced[0];
    assert!(
        pull.error
            .as_deref()
            .is_some_and(|e| e.contains("storage exploded")),
        "{pull:?}"
    );
    assert!(
        push.files_changed >= 1,
        "push was skipped after the pull failed: {push:?}"
    );
    assert!(push.upload_pending.is_none(), "{push:?}");

    let mut a = Engine::open(&lab.a_home, PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.pull("docs").unwrap();
    assert_eq!(
        fs::read(lab.a_dir.join("local-only.txt")).unwrap(),
        b"from-b"
    );
}
