// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The folder safety indicator (`Engine::protection`, `FolderStatus::protection`):
//! computed from the ledger view per folder and storage class. Cloud means an
//! S3 or rclone target, disks mean directories and disk pools, devices mean
//! files held by devices. Verified (by another device) is told from claimed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use varsto_core::chunking::ChunkerParams;
use varsto_core::pool::{self, DiskSpace};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const GIB: u64 = 1 << 30;

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

fn have_rclone() -> bool {
    Command::new("rclone")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn dir(root: &Path, name: &str, carrier: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold: false,
        carrier,
        place: String::new(),
        min_free: None,
    }
}

fn cloud(root: &Path) -> StorageSpec {
    StorageSpec::Rclone {
        name: "cloud".into(),
        remote: format!(":local:{}", root.join("cloud-data").display()),
        cold: false,
        place: String::new(),
    }
}

fn pool_spec(mounts: &Path) -> StorageSpec {
    StorageSpec::Pool {
        name: "shelf".into(),
        place: "shelf".into(),
        reserve_percent: 5,
        min_reserve_bytes: 2 * GIB,
        disks: vec![],
        scan_roots: vec![mounts.to_path_buf()],
        copies: 1,
        verify_after_days: pool::DEFAULT_VERIFY_AFTER_DAYS,
    }
}

fn protection(e: &Engine, folder: &str) -> varsto_core::engine::Protection {
    let id = e
        .status()
        .unwrap()
        .folders
        .iter()
        .find(|f| f.name == folder)
        .unwrap()
        .folder_id
        .clone();
    e.protection().unwrap().remove(&id).unwrap()
}

fn make(root: &Path, home: &str) -> (Engine, String) {
    let (mut e, key) = Engine::init(&root.join(home), "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    (e, key)
}

fn write(root: &Path, folder: &str, file: &str, len: usize, seed: u64) -> PathBuf {
    let d = root.join(folder);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join(file), pseudo_random(len, seed)).unwrap();
    d
}

#[test]
fn a_folder_only_on_this_device_is_red_then_disks_then_cloud() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _) = make(root, "a-home");
    let docs = write(root, "docs", "one.bin", 120_000, 1);
    a.add_folder("docs", &docs).unwrap();

    // Nothing is in the ledger yet: nothing to be protected.
    assert_eq!(protection(&a, "docs").state, "empty");
    a.push("docs").unwrap();
    // Published, but on no storage: the files exist on this device only.
    let p = protection(&a, "docs");
    assert_eq!(p.state, "device");
    assert_eq!(p.cloud.pct, 0.0);
    assert_eq!(p.disks.pct, 0.0);
    assert!(p.total_bytes > 0 && p.unprotected_bytes == p.total_bytes);

    // An empty folder says so.
    let empty = root.join("empty");
    fs::create_dir_all(&empty).unwrap();
    a.add_folder("empty", &empty).unwrap();
    assert_eq!(protection(&a, "empty").state, "empty");

    // A directory is one of the user's own disks: 100 %, but no cloud copy.
    a.add_storage(dir(root, "usb", false)).unwrap();
    a.push("docs").unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.state, "disks");
    assert_eq!(p.disks.pct, 100.0);
    assert_eq!(p.cloud.pct, 0.0);
    assert_eq!(p.pct, 100.0);
    assert_eq!(p.disks.bytes, p.total_bytes);

    // A transferrer keeps no copy and does not count.
    let (mut b, _) = make(root, "b-home");
    b.add_storage(dir(root, "stick", true)).unwrap();
    let pics = write(root, "pics", "p.bin", 60_000, 2);
    b.add_folder("pics", &pics).unwrap();
    b.push("pics").unwrap();
    assert_eq!(protection(&b, "pics").state, "device");

    // The status carries the same numbers per folder.
    let st = a.status().unwrap();
    let f = st.folders.iter().find(|f| f.name == "docs").unwrap();
    assert_eq!(f.protection.state, "disks");
    assert_eq!(
        serde_json::to_value(&f.protection).unwrap()["disks"]["pct"],
        100.0
    );
    assert_eq!(f.protection.policy_state.as_deref(), Some("violated"));

    if !have_rclone() {
        eprintln!("rclone not installed: cloud part skipped");
        return;
    }
    // A cloud target is added: nothing is there yet.
    a.add_storage(cloud(root)).unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.state, "disks");
    assert_eq!(p.cloud.pct, 0.0);
    // The push brings the older blocks along: now everything is in the cloud.
    write(root, "docs", "two.bin", 50_000, 3);
    a.push("docs").unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.state, "cloud");
    assert_eq!(p.cloud.pct, 100.0);
    // A new folder written after both storages exist is wholly in the cloud.
    let docs2 = write(root, "work", "w.bin", 80_000, 4);
    a.add_folder("work", &docs2).unwrap();
    a.push("work").unwrap();
    let p = protection(&a, "work");
    assert_eq!(p.state, "cloud");
    assert_eq!(p.cloud.pct, 100.0);
    assert_eq!(p.disks.pct, 100.0);
}

#[test]
fn a_disk_pool_counts_as_own_disks() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mounts = root.join("mounts");
    let d1 = mounts.join("d1");
    fs::create_dir_all(&d1).unwrap();
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
    let (mut a, _) = make(root, "a-home");
    a.add_storage(dir(root, "box", false)).unwrap();
    a.add_storage(pool_spec(&mounts)).unwrap();
    a.disk_add(&d1, "shelf", "data-01").unwrap();
    let docs = write(root, "docs", "one.bin", 150_000, 7);
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.state, "disks");
    assert_eq!(p.disks.pct, 100.0);
    assert_eq!(p.devices.pct, 100.0, "this device still holds the files");
}

#[test]
fn verified_is_told_from_claimed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let shelf = dir(root, "shelf", false);
    let (mut a, key) = make(root, "a-home");
    a.add_storage(shelf.clone()).unwrap();
    let docs = write(root, "a-docs", "one.bin", 100_000, 9);
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();

    // The writer's own checks are not independent verification.
    a.fsck(true).unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.disks.pct, 100.0);
    assert_eq!(
        p.disks.verified_pct, 0.0,
        "claimed, not yet verified by another device"
    );

    // Another device reads the objects back and says so.
    let mut b = Engine::join(&root.join("b-home"), "phone", PASS, &key, shelf).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &root.join("b-docs"), false)
        .unwrap();
    b.sync(Some("docs")).unwrap();
    b.fsck(true).unwrap();
    a.sync(None).unwrap();
    let p = protection(&a, "docs");
    assert_eq!(p.disks.pct, 100.0);
    assert_eq!(p.disks.verified_pct, 100.0);
    assert_eq!(p.disks.verified_bytes, p.disks.bytes);
    assert_eq!(p.state, "disks");
}
