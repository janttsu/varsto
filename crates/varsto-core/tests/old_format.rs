// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A vault written by an older storage format (0.0.1-alpha.14 wrote format 1)
//! is refused with a message that says to recreate it, on this device and
//! when joining through a storage; a vault of a newer format asks for an
//! update.

use std::fs;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn local(path: std::path::PathBuf) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path,
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn set_version(path: &std::path::Path, version: u16) {
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    v["format_version"] = version.into();
    fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

#[test]
#[ignore = "f3-switch: port in part B (format checks)"]
fn an_older_or_newer_vault_is_refused_with_a_clear_message() {
    assert_eq!(varsto_core::FORMAT_VERSION, 2);
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let (mut e, key) = Engine::init(&home, "laptop", PASS).unwrap();
    let storage = local(tmp.path().join("storage"));
    e.add_storage(storage.clone()).unwrap();
    drop(e);

    // On this device.
    set_version(&home.join("vault.json"), 1);
    let err = format!(
        "{:#}",
        Engine::open(&home, PASS)
            .err()
            .expect("format 1 must be refused")
    );
    assert!(
        err.contains("Recreate the vault") && err.contains("alpha.14"),
        "{err}"
    );
    set_version(&home.join("vault.json"), 3);
    let err = format!(
        "{:#}",
        Engine::open(&home, PASS)
            .err()
            .expect("format 3 must be refused")
    );
    assert!(err.contains("Update Varsto"), "{err}");
    set_version(&home.join("vault.json"), 2);
    Engine::open(&home, PASS).unwrap();

    // Joining through a storage that holds an alpha.14 vault.
    let meta = tmp.path().join("storage/vault/meta.json");
    set_version(&meta, 1);
    let other = tmp.path().join("other");
    let err = format!(
        "{:#}",
        Engine::join(&other, "desktop", PASS, &key, storage.clone())
            .err()
            .expect("a format 1 vault must not be joined")
    );
    assert!(err.contains("Recreate the vault"), "{err}");
    set_version(&meta, 2);
    Engine::join(&other, "desktop", PASS, &key, storage).unwrap();
}

#[test]
#[ignore = "f3-switch: port in part B (format checks)"]
fn the_messages_tell_what_to_do() {
    let old = varsto_core::format_mismatch(1);
    assert!(
        old.contains("Recreate the vault") && old.contains("alpha.14"),
        "{old}"
    );
    let new = varsto_core::format_mismatch(varsto_core::FORMAT_VERSION + 1);
    assert!(new.contains("Update Varsto"), "{new}");
}
