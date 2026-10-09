// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! "Where your data is": two devices, two storages (one at home, one in the
//! cloud place), two folders of which only one is on both devices. The bytes
//! per storage, device and folder and the copy counts must add up.

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

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

fn dir(root: &std::path::Path, name: &str, place: &str, carrier: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold: false,
        carrier,
        place: place.into(),
    }
}

#[test]
fn data_locations_add_up_across_storages_and_devices() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().to_path_buf();
    let shelf = dir(&root, "shelf", "", false);
    let cloud = dir(&root, "cloud", "cloud", false);

    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(shelf.clone()).unwrap();
    a.add_storage(cloud.clone()).unwrap();
    a.add_storage(dir(&root, "stick", "", true)).unwrap();
    a.add_folder("docs", &root.join("a-docs")).unwrap();
    a.add_folder("music", &root.join("a-music")).unwrap();
    fs::write(root.join("a-docs/one.bin"), pseudo_random(90_000, 1)).unwrap();
    fs::write(root.join("a-docs/two.bin"), pseudo_random(40_000, 2)).unwrap();
    // The same content twice: its blocks count once.
    fs::write(root.join("a-docs/two-again.bin"), pseudo_random(40_000, 2)).unwrap();
    fs::write(root.join("a-music/song.bin"), pseudo_random(250_000, 3)).unwrap();
    a.push("docs").unwrap();
    a.push("music").unwrap();

    // The phone shares only the home storage and only the docs folder.
    let mut b = Engine::join(&root.join("b-home"), "phone", PASS, &key, shelf.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &root.join("b-docs"), false)
        .unwrap();
    b.sync(Some("docs")).unwrap();
    a.sync(None).unwrap();

    let loc = a.data_locations().unwrap();
    let plain = 90_000 + 40_000 + 250_000u64;
    assert!(
        loc.total_bytes > plain && loc.total_bytes < plain + plain / 10,
        "ciphertext of the unique blocks, got {}",
        loc.total_bytes
    );
    let folder = |n: &str| loc.folders.iter().find(|f| f.name == n).unwrap();
    let docs = folder("docs");
    let music = folder("music");
    assert_eq!(loc.folders[0].name, "music", "largest folder first");
    assert_eq!(docs.bytes + music.bytes, loc.total_bytes);
    assert_eq!(docs.blocks + music.blocks, loc.total_blocks);
    assert!(docs.bytes < 140_000, "duplicate file counted once");

    let storage = |n: &str| loc.storages.iter().find(|s| s.name == n).unwrap();
    for name in ["shelf", "cloud"] {
        let s = storage(name);
        assert!(s.configured);
        assert_eq!(s.kind, "directory");
        assert_eq!(s.bytes, loc.total_bytes, "{name} holds everything");
        assert_eq!(s.blocks, loc.total_blocks);
        assert!((s.share - 1.0).abs() < 1e-9);
        assert_eq!(docs.storages[name] + music.storages[name], s.bytes);
    }
    assert_eq!(storage("shelf").place, "home");
    assert_eq!(storage("cloud").place, "cloud");
    // The phone fetched the docs blocks from the shelf and checked them.
    assert_eq!(storage("shelf").verified_bytes, docs.bytes);
    assert_eq!(storage("cloud").verified_bytes, 0);
    let stick = storage("stick");
    assert!(stick.carrier && stick.kind == "transferrer");

    let device = |n: &str| loc.devices.iter().find(|d| d.name == n).unwrap();
    let laptop = device("laptop");
    let phone = device("phone");
    assert!(laptop.this_device && !phone.this_device);
    assert_eq!(laptop.bytes, loc.total_bytes);
    assert_eq!(phone.bytes, docs.bytes);
    assert_eq!(phone.blocks, docs.blocks);
    assert!((phone.share - docs.bytes as f64 / loc.total_bytes as f64).abs() < 1e-9);
    assert_eq!(docs.devices[&phone.device_id], docs.bytes);
    assert!(!music.devices.contains_key(&phone.device_id));

    // Shelf and cloud keep every block; the transferrer does not count.
    assert_eq!(loc.copies.two, loc.total_blocks);
    assert_eq!(loc.copies.none + loc.copies.one + loc.copies.three_plus, 0);
    assert_eq!(loc.copies.bytes[2], loc.total_bytes);
    assert!((loc.copies.average - 2.0).abs() < 1e-9);

    // On the phone, the cloud storage is only known from the laptop's claims,
    // and only the folder it has files of counts.
    let seen = b.data_locations().unwrap();
    assert_eq!(seen.total_bytes, docs.bytes);
    let music_there = seen.folders.iter().find(|f| f.name == "music").unwrap();
    assert!(!music_there.attached && music_there.bytes == 0);
    let cloud_there = seen.storages.iter().find(|s| s.name == "cloud").unwrap();
    assert_eq!(cloud_there.bytes, docs.bytes);
    let phone_self = seen.devices.iter().find(|d| d.this_device).unwrap();
    assert_eq!(phone_self.bytes, docs.bytes);
}
