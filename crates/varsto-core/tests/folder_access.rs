// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! How a second device gets a folder in storage format 3: a device that
//! holds the vault key learns the folder record (its name, who takes part)
//! from the storage but no folder key. It asks for the folder, a device that
//! holds it compares the six words of the request and approves, and only
//! then does the folder open on the new device.

use std::fs;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_device_with_the_vault_key_opens_a_folder_only_after_a_holder_approves() {
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
    let (mut phone, vault_key) = Engine::init(&root.join("phone"), "phone", PASS).unwrap();
    phone.chunker = ChunkerParams::SMALL;
    phone.add_storage(storage.clone()).unwrap();
    let dir = root.join("camera");
    phone.add_folder("Camera", &dir).unwrap();
    fs::write(dir.join("photo.jpg"), b"a private photo").unwrap();
    phone.push("Camera").unwrap();

    // "macOS" has only the vault key and the storage.
    let mut mac = Engine::join(&root.join("mac"), "mac", PASS, &vault_key, storage).unwrap();
    mac.chunker = ChunkerParams::SMALL;
    // The folder record arrived by itself, without a key ...
    assert!(mac.folders().iter().any(|(r, _)| r.name == "Camera"));
    // ... so attaching is refused until a holder approves.
    let err = mac
        .attach_folder("Camera", &root.join("mac-camera"), false)
        .unwrap_err();
    assert!(err.to_string().contains("holds no key"), "{err}");
    assert!(!root.join("mac-camera/photo.jpg").exists());

    let req = mac.f3_folder_request("Camera", "editor").unwrap();
    phone
        .f3_approve("Camera", "mac", None, Some(&req.fingerprint))
        .unwrap();
    mac.refresh_devices().unwrap();
    mac.attach_folder("Camera", &root.join("mac-camera"), false)
        .unwrap();
    mac.pull("Camera").unwrap();
    assert_eq!(
        fs::read(root.join("mac-camera/photo.jpg")).unwrap(),
        b"a private photo"
    );
}
