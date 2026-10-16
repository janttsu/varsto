// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A storage added after the thumbnails were made gets them too: a device that
//! reaches only that storage (a phone with a bucket) must still show previews.

use std::fs;
use std::path::Path;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn local(root: &Path, name: &str) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn thumb_files(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().to_string_lossy().contains("thumbs") && e.file_type().is_file())
        .count()
}

#[test]
fn thumbnails_made_before_a_storage_was_added_reach_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(local(root, "first")).unwrap();
    let dir = root.join("pics");
    a.add_folder("pics", &dir).unwrap();
    fs::create_dir_all(&dir).unwrap();
    image::RgbImage::from_fn(300, 200, |x, y| image::Rgb([x as u8, y as u8, 3]))
        .save(dir.join("a.png"))
        .unwrap();
    a.push("pics").unwrap();
    assert_eq!(thumb_files(&root.join("first")), 1);
    assert_eq!(thumb_files(&root.join("second")), 0);

    a.add_storage(local(root, "second")).unwrap();
    a.push("pics").unwrap();
    assert_eq!(thumb_files(&root.join("second")), 1);
}
