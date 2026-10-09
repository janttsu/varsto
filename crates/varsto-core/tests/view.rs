// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The in-app viewer reads a file of a folder kept encrypted on a phone
//! without writing its plaintext anywhere on that device.

use std::fs;
use std::path::Path;
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

/// Every file under `root` with its contents.
fn files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files(&p));
        } else {
            out.push((p.display().to_string(), fs::read(&p).unwrap_or_default()));
        }
    }
    out.sort();
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn view_decrypts_ranges_in_memory_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
    };
    let (a_dir, b_home, b_dir) = (
        root.join("a-docs"),
        root.join("b-home"),
        root.join("b-docs"),
    );
    let content = pseudo_random(100_000, 7);
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("photos", &a_dir).unwrap();
    fs::write(a_dir.join("clip.mp4"), &content).unwrap();
    a.push("photos").unwrap();

    // The phone keeps the folder encrypted: only a placeholder is on disk.
    let mut b = Engine::join(&b_home, "phone", PASS, &key, storage).unwrap();
    b.attach_folder("photos", &b_dir, true).unwrap();
    b.set_encrypted_here("photos", true).unwrap();
    b.pull("photos").unwrap();
    assert!(!b_dir.join("clip.mp4").exists());
    let before = (files(&b_home), files(&b_dir));

    assert_eq!(b.view_size("photos", "clip.mp4").unwrap(), 100_000);
    // Whole file, a range across chunk borders, the tail, and past the end.
    assert_eq!(
        b.view_range("photos", "clip.mp4", 0, 100_000).unwrap(),
        content
    );
    assert_eq!(
        b.view_range("photos", "clip.mp4", 12_345, 54_321).unwrap(),
        content[12_345..54_321]
    );
    assert_eq!(
        b.view_range("photos", "clip.mp4", 99_990, 200_000).unwrap(),
        content[99_990..]
    );
    assert!(b
        .view_range("photos", "clip.mp4", 100_000, 100_010)
        .unwrap()
        .is_empty());
    assert!(b.view_range("photos", "../x", 0, 10).is_err());
    assert!(b.view_range("photos", "missing.mp4", 0, 10).is_err());

    // Nothing was written: the device directory and the folder are unchanged,
    // and no file on the device holds any of the plaintext.
    let after = (files(&b_home), files(&b_dir));
    assert_eq!(before, after, "viewing must not write to the device");
    let probe = &content[40_000..40_064];
    for (path, bytes) in after.0.iter().chain(after.1.iter()) {
        assert!(!contains(bytes, probe), "plaintext found in {path}");
    }

    // With the plaintext on the device (fetched), the local copy is read.
    b.fetch_file("photos", "clip.mp4").unwrap();
    assert_eq!(
        b.view_range("photos", "clip.mp4", 5, 10).unwrap(),
        content[5..10]
    );
}
