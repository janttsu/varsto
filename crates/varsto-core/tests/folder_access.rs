// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Documents how a second device gets a folder in the current format: any
//! device that holds the vault key learns every folder record (and so every
//! folder key) from the storage and can attach the folder with no
//! confirmation from a device that holds it. Per-device folder keys with
//! manual approval (PR #35, format2-records) are meant to change this; when
//! they land this test is expected to fail and must be rewritten to assert
//! that the attach is refused until a holder approves.

use std::fs;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn today_a_device_with_the_vault_key_attaches_any_folder_without_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    // "Android" creates a folder with a photo and goes offline: nobody
    // holding the folder is online to approve anything.
    let (mut phone, vault_key) = Engine::init(&root.join("phone"), "phone", PASS).unwrap();
    phone.chunker = ChunkerParams::SMALL;
    phone.add_storage(storage.clone()).unwrap();
    let dir = root.join("camera");
    phone.add_folder("Camera", &dir).unwrap();
    fs::write(dir.join("photo.jpg"), b"a private photo").unwrap();
    phone.push("Camera").unwrap();
    drop(phone);

    // "macOS" has only the vault key and the storage.
    let mut mac = Engine::join(&root.join("mac"), "mac", PASS, &vault_key, storage).unwrap();
    mac.chunker = ChunkerParams::SMALL;
    // The folder record, with the folder key, arrived by itself ...
    assert!(mac.folders().iter().any(|(r, _)| r.name == "Camera"));
    // ... and attaching and reading the files needs no approval.
    mac.attach_folder("Camera", &root.join("mac-camera"), false)
        .unwrap();
    mac.pull("Camera").unwrap();
    assert_eq!(
        fs::read(root.join("mac-camera/photo.jpg")).unwrap(),
        b"a private photo"
    );
}
