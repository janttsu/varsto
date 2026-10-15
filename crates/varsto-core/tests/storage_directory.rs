// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Every device lists the storages of the whole vault (configured here or
//! "known, not configured here"), in both directions, and the same bucket,
//! remote or directory cannot be added twice (spec section 20).

use std::fs;
use std::path::Path;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path) -> StorageSpec {
    fs::create_dir_all(path).unwrap();
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn s3(endpoint: &str, bucket: &str, prefix: &str) -> StorageSpec {
    StorageSpec::S3 {
        name: "x".into(),
        endpoint: endpoint.into(),
        region: "eu-north-1".into(),
        bucket: bucket.into(),
        prefix: prefix.into(),
        access_key_id: "AK".into(),
        secret_ref: String::new(),
        path_style: true,
        storage_class: None,
        cold: false,
        place: String::new(),
        allow_insecure_http: false,
    }
}

fn rclone(remote: &str) -> StorageSpec {
    StorageSpec::Rclone {
        name: "x".into(),
        remote: remote.into(),
        cold: false,
        place: String::new(),
    }
}

/// A (laptop) and B (phone) share the vault through "mac-a"; each adds a
/// storage of its own afterwards.
fn two_devices(t: &Path) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&t.join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("mac-a", &t.join("store-a"))).unwrap();
    let mut b = Engine::join(
        &t.join("b"),
        "phone",
        PASS,
        &key,
        dir("mac-a", &t.join("store-a")),
    )
    .unwrap();
    b.add_storage(dir("phone-b", &t.join("store-b"))).unwrap();
    a.add_storage(dir("mac-c", &t.join("store-c"))).unwrap();
    (a, b)
}

#[test]
fn a_storage_added_on_one_device_is_listed_on_the_other_both_ways() {
    let t = tempfile::tempdir().unwrap();
    let (mut a, mut b) = two_devices(t.path());
    // Each has learned the other's name from the vault.
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let on_a = a.storage_directory().unwrap();
    let theirs = on_a.iter().find(|k| k.name == "phone-b").unwrap();
    assert!(!theirs.configured, "{theirs:?}");
    assert!(theirs.state.contains("not configured here"));
    assert_eq!(theirs.devices, vec!["phone".to_string()]);
    assert!(on_a.iter().filter(|k| k.configured).count() == 2);
    let on_b = b.storage_directory().unwrap();
    let theirs = on_b.iter().find(|k| k.name == "mac-c").unwrap();
    assert!(!theirs.configured, "{theirs:?}");
    assert_eq!(theirs.devices, vec!["laptop".to_string()]);
    // The shared one is configured on both and known to be on the other.
    let shared = on_b.iter().find(|k| k.name == "mac-a").unwrap();
    assert!(shared.configured && shared.devices == vec!["laptop".to_string()]);
}

#[test]
fn the_same_directory_cannot_be_added_twice_on_a_device() {
    let t = tempfile::tempdir().unwrap();
    let (mut a, _) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(dir("box", &t.path().join("store"))).unwrap();
    // Trailing slash: same place.
    let again = dir("box2", &t.path().join("store/"));
    let err = a.add_storage(again).unwrap_err().to_string();
    assert!(err.contains("same") && err.contains("'box'"), "{err}");
    // Another route to the same directory is found by the storage identity.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(t.path().join("store"), t.path().join("link")).unwrap();
        let err = a
            .add_storage(dir("box3", &t.path().join("link")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("same") && err.contains("'box'"), "{err}");
    }
    assert_eq!(a.storages().len(), 1);
    a.add_storage(dir("other", &t.path().join("elsewhere")))
        .unwrap();
}

#[cfg(unix)]
#[test]
fn a_storage_another_device_has_is_refused_under_a_new_name_and_allowed_under_its_own() {
    let t = tempfile::tempdir().unwrap();
    let (mut a, _) = two_devices(t.path());
    std::os::unix::fs::symlink(t.path().join("store-b"), t.path().join("link-b")).unwrap();
    let err = a
        .add_storage(dir("my-name", &t.path().join("link-b")))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("'phone-b'") && err.contains("same name"),
        "{err}"
    );
    // The credentials of the same storage, under the same name: attaches it.
    a.add_storage(dir("phone-b", &t.path().join("link-b")))
        .unwrap();
    let list = a.storage_directory().unwrap();
    let k = list.iter().find(|k| k.name == "phone-b").unwrap();
    assert!(k.configured);
}

#[test]
fn s3_locations_compare_by_endpoint_bucket_and_prefix() {
    let base = s3("https://s3.eu-north-1.amazonaws.com", "bucket", "vault").location_key();
    for same in [
        s3("https://S3.eu-north-1.amazonaws.com/", "bucket", "vault"),
        s3(
            "https://s3.eu-north-1.amazonaws.com:443",
            "bucket",
            "/vault/",
        ),
        s3("s3.eu-north-1.amazonaws.com", "Bucket", "vault//"),
    ] {
        assert_eq!(same.location_key(), base);
    }
    for other in [
        s3("https://s3.eu-north-1.amazonaws.com", "bucket", "other"),
        s3("https://s3.eu-north-1.amazonaws.com", "bucket", ""),
        s3("https://s3.eu-north-1.amazonaws.com", "bucket2", "vault"),
        s3("https://s3.eu-west-1.amazonaws.com", "bucket", "vault"),
    ] {
        assert_ne!(other.location_key(), base);
    }
}

#[test]
fn rclone_locations_compare_by_remote_and_path() {
    let base = rclone("b2:bucket/vault").location_key();
    assert_eq!(rclone("b2:bucket/vault/").location_key(), base);
    assert_eq!(rclone("b2:/bucket//vault").location_key(), base);
    assert_ne!(rclone("b2:bucket/other").location_key(), base);
    assert_ne!(rclone("drive:bucket/vault").location_key(), base);
}
