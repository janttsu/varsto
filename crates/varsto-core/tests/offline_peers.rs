// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peers without a storage (`alpha-0-format.md` section 77.8, "Offline"): the
//! directory of accepted peer records is saved on the device, checked
//! again when it is loaded, and used when the vault opens, so LAN
//! peer-to-peer works while no storage answers; a listing that answers
//! nothing does not empty it; a publish that one storage refuses still
//! reaches the others and is reported for a retry.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::p2p::v3::SavedDirectory;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const SAVED: &str = "peer-records.json";

fn spec(name: &str, path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

/// A laptop and a desk of one vault on one storage, both synced.
fn two(root: &Path) -> (Engine, Engine) {
    let storage = root.join("storage");
    let (mut a, key) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.add_storage(spec("box", &storage)).unwrap();
    let mut b = Engine::join(&root.join("b"), "desk", PASS, &key, spec("box", &storage)).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    (a, b)
}

fn id16(e: &Engine) -> [u8; 16] {
    varsto_core::record::id16(e.device_id()).unwrap()
}

/// Every file under `dir`.
fn files(dir: &Path) -> Vec<PathBuf> {
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

#[test]
fn peers_are_reached_from_the_saved_directory_with_the_storage_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, mut b) = two(root);
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    let saved = b.home().join(SAVED);
    assert!(saved.exists(), "the directory read is saved on the device");
    let home_b = b.home().to_path_buf();
    drop(b);

    // The storage goes away: the next open recreates an empty directory,
    // which lists nothing, as an outage of some storages does.
    fs::rename(root.join("storage"), root.join("gone")).unwrap();
    let b = Engine::open(&home_b, PASS).unwrap();
    assert!(
        b.local_peer_directory().get(&id16(&a)).is_some(),
        "opening reads the saved directory"
    );
    let (dir, read) = b.peer_directory_read();
    assert!(read.storages >= 1, "{read:?}");
    assert!(
        dir.get(&id16(&a)).is_some(),
        "an empty listing does not empty the directory"
    );
    // The laptop is reached over TLS with the pin from the saved record.
    let peers = b.p2p_peers_tcp().expect("peers from the saved directory");
    let status = peers.probe();
    assert!(
        status.iter().any(|s| &s.device == a.device_id() && s.ok),
        "{status:?}"
    );
    drop(serving);
}

#[test]
fn a_saved_record_that_was_changed_is_refused_on_load() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, mut b) = two(root);
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    let path = b.home().join(SAVED);
    let mut saved: SavedDirectory = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(!saved.records.is_empty());
    for rec in &mut saved.records {
        for (_, hexed) in &mut rec.parts {
            // One changed byte near the end of every part (the sealed body
            // and its signature).
            let at = hexed.len() - 8;
            let flip = if &hexed[at..at + 1] == "0" { "1" } else { "0" };
            hexed.replace_range(at..at + 1, flip);
        }
    }
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    assert!(
        b.local_peer_directory().get(&id16(&a)).is_none(),
        "the file is no source of trust"
    );
    // The storage still has the real record: reading it heals the file.
    let dir = b.peer_directory().unwrap();
    assert!(dir.get(&id16(&a)).is_some());
    assert!(b.local_peer_directory().get(&id16(&a)).is_some());
}

#[cfg(unix)]
#[test]
fn a_publish_one_storage_refuses_reaches_the_others_and_reports_the_miss() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _b) = two(root);
    let second = root.join("storage2");
    a.add_storage(spec("box2", &second)).unwrap();
    a.p2p_identity().unwrap();
    let set_mode = |mode: u32| {
        for e in walkdir::WalkDir::new(&second)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir())
        {
            let _ = fs::set_permissions(e.path(), fs::Permissions::from_mode(mode));
        }
    };
    set_mode(0o555);
    // Running as root, permissions refuse nothing: no way to fail here.
    let probe = second.join("probe");
    if fs::write(&probe, b"x").is_ok() {
        let _ = fs::remove_file(&probe);
        set_mode(0o755);
        return;
    }
    let mut body = a.peer_body(9);
    let err = a.publish_peer_body(&mut body).unwrap_err();
    set_mode(0o755);
    assert!(format!("{err:#}").contains("1 of 2"), "{err:#}");
    assert!(
        !files(&root.join("storage").join("vault").join("peers")).is_empty(),
        "the first storage has the record"
    );
}
