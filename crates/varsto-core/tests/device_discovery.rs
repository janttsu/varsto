// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A device that has just joined shows in the other devices' device list
//! after one cheap look at the storage, not only after their next sync
//! (spec section 73).

use std::time::{Duration, Instant};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_joined_device_shows_after_one_look_without_a_sync() {
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
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(storage.clone()).unwrap();
    assert_eq!(a.devices_list().len(), 1);
    // Nothing changed yet: nothing found.
    assert!(!a.refresh_devices().unwrap());

    // A second device joins with the vault key (the case without a pairing
    // host that could tell the first one).
    let b = Engine::join(&root.join("b-home"), "phone", PASS, &key, storage.clone()).unwrap();
    assert_eq!(b.devices_list().len(), 2);
    assert!(
        a.devices_list().iter().all(|d| d.name != "phone"),
        "the first device cannot know yet"
    );

    let t = Instant::now();
    assert!(a.refresh_devices().unwrap(), "the new device is found");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(a.devices_list().iter().any(|d| d.name == "phone"));
    // Found once; the next look finds nothing new.
    assert!(!a.refresh_devices().unwrap());

    // A third one: the second one learns of it the same way, and the first
    // finds both.
    let c = Engine::join(&root.join("c-home"), "tablet", PASS, &key, storage).unwrap();
    let mut b = b;
    assert!(b.refresh_devices().unwrap());
    assert!(a.refresh_devices().unwrap());
    for e in [&a, &b, &c] {
        assert_eq!(e.devices_list().len(), 3);
    }
}
