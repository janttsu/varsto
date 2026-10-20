// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Local actions with a storage that cannot be reached (spec section 79.4):
//! the local import, the trash list, the thumbnail lookup and the file
//! writes finish with what is on this device; the upload follows later.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ImportOptions;
use varsto_core::import::dir::DirSource;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn storage(path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    a: Engine,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let (mut a, _) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
        a.chunker = ChunkerParams::SMALL;
        a.add_storage(storage(&root.join("storage"))).unwrap();
        Lab { _tmp: tmp, root, a }
    }
    fn down(&self) {
        fs::rename(self.root.join("storage"), self.root.join("storage-away")).unwrap();
    }
    fn up(&self) {
        fs::rename(self.root.join("storage-away"), self.root.join("storage")).unwrap();
    }
}

#[test]
fn writes_finish_locally_when_the_storage_is_down() {
    let mut lab = Lab::new();
    let docs = lab.root.join("docs");
    lab.a.add_folder("docs", &docs).unwrap();
    lab.a.sync(None).unwrap();
    lab.down();

    lab.a
        .write_file("docs", "a.txt", b"written offline")
        .unwrap();
    assert_eq!(fs::read(docs.join("a.txt")).unwrap(), b"written offline");
    lab.a
        .create_file("docs", "b.txt", b"created offline")
        .unwrap();
    assert_eq!(fs::read(docs.join("b.txt")).unwrap(), b"created offline");
    lab.a.move_file("docs", "b.txt", "c.txt").unwrap();
    assert!(!docs.join("b.txt").exists());
    assert_eq!(fs::read(docs.join("c.txt")).unwrap(), b"created offline");

    // The storage is back: the next push uploads everything.
    lab.up();
    let r = lab.a.push("docs").unwrap();
    assert!(r.upload_pending.is_none());
    lab.a.sync(None).unwrap();
    assert_eq!(
        lab.a.read_file("docs", "a.txt").unwrap(),
        b"written offline"
    );
}

#[test]
fn a_local_import_goes_on_when_the_storage_is_down() {
    let mut lab = Lab::new();
    let src = lab.root.join("old-drive");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("one.txt"), b"one").unwrap();
    let opts = ImportOptions {
        folder: Some("archive".into()),
        dest: Some(lab.root.join("archive")),
        ..Default::default()
    };
    let mut s = DirSource::open(&src).unwrap();
    lab.a.import_run(&mut s, &opts).unwrap();
    lab.down();

    fs::write(src.join("two.txt"), b"two").unwrap();
    let mut s = DirSource::open(&src).unwrap();
    lab.a.import_run(&mut s, &opts).unwrap();
    assert_eq!(fs::read(lab.root.join("archive/two.txt")).unwrap(), b"two");
}

#[test]
fn the_trash_list_falls_back_to_the_cache_when_the_storage_is_down() {
    let mut lab = Lab::new();
    let docs = lab.root.join("docs");
    lab.a.add_folder("docs", &docs).unwrap();
    fs::write(docs.join("gone.txt"), b"to be deleted").unwrap();
    lab.a.sync(None).unwrap();
    fs::remove_file(docs.join("gone.txt")).unwrap();
    lab.a.sync(None).unwrap();
    let before = lab.a.trash_list(None).unwrap();
    assert_eq!(before.len(), 1);

    lab.down();
    let (list, _stale) = lab.a.trash_list_checked(None).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].path, "gone.txt");
}

#[test]
fn a_missing_thumbnail_is_not_an_error_when_the_storage_is_down() {
    let mut lab = Lab::new();
    let pics = lab.root.join("pics");
    lab.a.add_folder("pics", &pics).unwrap();
    fs::write(pics.join("p.txt"), b"not a picture").unwrap();
    lab.a.sync(None).unwrap();
    lab.down();
    // No thumbnail exists; asking twice neither fails nor needs the storage.
    assert!(lab.a.thumbnail("pics", "p.txt").unwrap().is_none());
    assert!(lab.a.thumbnail("pics", "p.txt").unwrap().is_none());
}
