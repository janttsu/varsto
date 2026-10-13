// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Minimum free disk space (`freespace`): downloads into a folder whose
//! disk would drop below its limit wait and resume once there is room;
//! a local-directory storage on a full disk is left out of a push while the
//! other storages still get the blocks. Disk space comes from the fake
//! provider (`pool::set_fake_space`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::freespace::{self, MinFree};
use varsto_core::pool::{set_fake_space, DiskSpace};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const GB: u64 = 1_000_000_000;

fn local(name: &str, path: PathBuf) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path,
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn space(path: &Path, free_gb: u64) {
    set_fake_space(
        path,
        Some(DiskSpace {
            free: free_gb * GB,
            total: 100 * GB,
        }),
    );
}

fn files(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && !e.file_name().to_string_lossy().starts_with('.'))
        .count()
}

#[test]
fn downloads_wait_below_the_limit_and_resume_when_space_is_back() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = local("box", root.join("storage"));
    let (mut a, key) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("space-docs", &a_dir).unwrap();
    for i in 0..3 {
        fs::write(a_dir.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    a.push("space-docs").unwrap();

    let mut b = Engine::join(&root.join("b"), "desk", PASS, &key, storage).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let b_dir = root.join("b-docs");
    fs::create_dir_all(&b_dir).unwrap();
    b.attach_folder("space-docs", &b_dir, false).unwrap();
    // 3 % free: below the default 5 %.
    space(&b_dir, 3);
    let pull = b.pull("space-docs").unwrap();
    assert_eq!(pull.files_updated, 0);
    assert_eq!(pull.files_waiting_for_space, 3);
    assert!(
        pull.files_unavailable.is_empty(),
        "{:?}",
        pull.files_unavailable
    );
    assert_eq!(
        pull.low_space,
        vec!["disk of folder space-docs has 3 % free, below the 5 % limit; downloads paused"]
    );
    assert_eq!(files(&b_dir), 0);
    assert!(freespace::short_places()
        .iter()
        .any(|l| l.place.key == "folder:space-docs"));

    // Space is back: the next sync fetches what waited.
    space(&b_dir, 40);
    assert!(freespace::recheck()
        .iter()
        .any(|l| l.place.key == "folder:space-docs"));
    let pull = b.pull("space-docs").unwrap();
    assert_eq!(pull.files_updated, 3);
    assert_eq!(pull.files_waiting_for_space, 0);
    assert_eq!(files(&b_dir), 3);
    assert_eq!(fs::read(b_dir.join("f1.txt")).unwrap(), b"file 1");

    // The folder's own limit: 50 % here, so 40 % free is too little.
    b.set_folder_min_free("space-docs", Some(MinFree::parse("50%").unwrap()))
        .unwrap();
    let st = b.status().unwrap();
    let f = st.folders.iter().find(|f| f.name == "space-docs").unwrap();
    assert_eq!(f.min_free.as_deref(), Some("50%"));
    assert_eq!(f.min_free_text, "50 %");
    fs::write(a_dir.join("new.txt"), b"new").unwrap();
    a.push("space-docs").unwrap();
    let pull = b.pull("space-docs").unwrap();
    assert_eq!(pull.files_waiting_for_space, 1);
    assert!(
        pull.low_space[0].contains("below the 50 % limit"),
        "{:?}",
        pull.low_space
    );
    assert!(!b_dir.join("new.txt").exists());
    // Back to the default: it arrives.
    b.set_folder_min_free("space-docs", None).unwrap();
    let pull = b.pull("space-docs").unwrap();
    assert_eq!(pull.files_updated, 1);
    assert!(b_dir.join("new.txt").exists());

    // A fetch of a placeholder is refused with the reason, as a restore is.
    b.set_selective("space-docs", true).unwrap();
    fs::write(a_dir.join("later.txt"), b"later").unwrap();
    a.push("space-docs").unwrap();
    b.pull("space-docs").unwrap();
    space(&b_dir, 1);
    let err = b.fetch_file("space-docs", "later.txt").unwrap_err();
    assert!(freespace::low_space(&err).is_some(), "{err:#}");
    assert!(format!("{err:#}").contains("1 % free, below the 5 % limit"));
    space(&b_dir, 40);
    b.fetch_file("space-docs", "later.txt").unwrap();
    assert_eq!(fs::read(b_dir.join("later.txt")).unwrap(), b"later");
    set_fake_space(&b_dir, None);
}

#[test]
fn a_full_directory_storage_is_left_out_while_the_others_get_the_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(local("space-cloud", root.join("cloud")))
        .unwrap();
    a.add_storage(local("space-usb", root.join("usb"))).unwrap();
    space(&root.join("usb"), 2);
    let dir = root.join("docs");
    a.add_folder("space-up", &dir).unwrap();
    fs::write(dir.join("a.bin"), vec![7u8; 50_000]).unwrap();
    let push = a.push("space-up").unwrap();
    assert!(push.chunks_uploaded > 0);
    assert_eq!(push.storages_unavailable, vec!["space-usb".to_string()]);
    assert!(common::object_count(&root.join("cloud")) > 0);
    assert_eq!(common::object_count(&root.join("usb")), 0);
    let short = freespace::short_places();
    let usb = short
        .iter()
        .find(|l| l.place.key == "storage:space-usb")
        .unwrap();
    assert!(
        usb.text
            .starts_with("disk of storage space-usb has 2 % free"),
        "{}",
        usb.text
    );
    assert!(usb.text.ends_with("uploads paused"));

    // A smaller limit for that disk: the next push fills it in.
    a.set_storage_min_free("space-usb", Some(MinFree::parse("1GB").unwrap()))
        .unwrap();
    let push = a.push("space-up").unwrap();
    assert!(push.storages_unavailable.is_empty());
    assert_eq!(
        common::object_count(&root.join("usb")),
        common::object_count(&root.join("cloud"))
    );
    assert!(freespace::short_places()
        .iter()
        .all(|l| l.place.key != "storage:space-usb"));
    // Pools keep their own reserve; remote storages have no disk here.
    assert!(a
        .set_storage_min_free("nope", Some(MinFree::Basis(500)))
        .is_err());
    set_fake_space(&root.join("usb"), None);
}

#[test]
fn a_folder_kept_encrypted_here_waits_for_space_in_the_device_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = local("box", root.join("storage"));
    let (mut a, key) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-pics");
    a.add_folder("space-pics", &a_dir).unwrap();
    fs::write(a_dir.join("p.jpg"), vec![1u8; 20_000]).unwrap();
    a.push("space-pics").unwrap();

    let b_home = root.join("b");
    let mut b = Engine::join(&b_home, "phone", PASS, &key, storage).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("space-pics", &root.join("b-pics"), false)
        .unwrap();
    b.set_encrypted_here("space-pics", true).unwrap();
    space(&b_home, 4);
    let pull = b.pull("space-pics").unwrap();
    assert_eq!(pull.files_waiting_for_space, 1, "{pull:?}");
    assert!(pull.low_space[0].starts_with("disk of folder space-pics has 4 % free"));
    space(&b_home, 30);
    let pull = b.pull("space-pics").unwrap();
    assert_eq!(pull.files_waiting_for_space, 0);
    assert_eq!(pull.files_updated, 1);
    set_fake_space(&b_home, None);
}
