// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Engine bugs the lab scenarios found (scripts/test/lab/scenarios.py), each
//! reproduced here on local storages.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn data(len: usize, seed: u64) -> Vec<u8> {
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

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

fn files_under(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            e.path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|p| !p.starts_with(".varsto"))
        .collect();
    out.sort();
    out
}

/// A folder of `n` small files and one larger one.
fn fill(dir: &Path, n: usize) {
    for i in 0..n {
        let d = dir.join(format!("dir{}", i % 7));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(format!("note-{i}.txt")), format!("note {i} ").repeat(1 + i % 40)).unwrap();
    }
    fs::write(dir.join("big.bin"), data(200_000, 9)).unwrap();
}

/// `folder detach` and `folder attach` of the same folder at another path on
/// the same device: the new path gets every file (or placeholder) the
/// folder has, not only what changed since the detach.
#[test]
fn attach_after_detach_gets_every_file_again() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = local("box", root.join("storage"));
    let (mut a, words) = Engine::init(&root.join("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    let a_dir = root.join("a-docs");
    a.add_folder("docs", &a_dir).unwrap();
    fill(&a_dir, 160);
    a.sync(None).unwrap();
    let expect = files_under(&a_dir);
    assert_eq!(expect.len(), 161);

    let mut b = common::join_approved(&root.join("b"), "pub", PASS, &words, storage, &mut a);
    b.chunker = ChunkerParams::SMALL;
    let first = root.join("b-docs");
    b.attach_folder("docs", &first, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(files_under(&first), expect);

    // Elsewhere, selective: a placeholder for every file.
    b.detach_folder("docs").unwrap();
    let sel = root.join("sel");
    b.attach_folder("docs", &sel, true).unwrap();
    b.sync(None).unwrap();
    let got = files_under(&sel);
    let placeholders: Vec<&String> = got
        .iter()
        .filter(|p| p.ends_with(".varsto-placeholder"))
        .collect();
    assert_eq!(
        placeholders.len(),
        expect.len(),
        "placeholders after attaching again: {got:?}"
    );
    assert_eq!(placeholders.len(), got.len(), "real files in a selective folder");

    // And once more in full, after a restart of the engine.
    b.detach_folder("docs").unwrap();
    drop(b);
    let mut b = open(&root.join("b"));
    let again = root.join("again");
    b.attach_folder("docs", &again, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(files_under(&again), expect);
    for p in &expect {
        assert_eq!(
            fs::read(again.join(p)).unwrap(),
            fs::read(a_dir.join(p)).unwrap(),
            "{p}"
        );
    }
}
