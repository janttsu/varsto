// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The thumbnails a sync stores are real pictures: decodable JPEGs of the
//! expected size with picture content, not empty or blank images.

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

fn picture(dir: &Path, name: &str, w: u32, h: u32, seed: u8) {
    image::RgbImage::from_fn(w, h, |x, y| {
        image::Rgb([(x * 3) as u8, (y * 5) as u8, seed])
    })
    .save(dir.join(name))
    .unwrap();
}

/// The stored thumbnail is a decodable JPEG at the expected size with
/// picture content.
fn assert_real_thumbnail(a: &Engine, folder: &str, path: &str, w: u32, h: u32) {
    let t = a
        .thumbnail(folder, path)
        .unwrap()
        .unwrap_or_else(|| panic!("no thumbnail for {path}"));
    assert!(t.len() > 200, "{path}: thumbnail of {} bytes", t.len());
    assert_eq!(&t[..2], &[0xff, 0xd8], "{path}: JPEG magic");
    let img = image::load_from_memory(&t)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .to_rgb8();
    // The longest side is 256 (small pictures are scaled up to it).
    let scale = 256.0 / w.max(h) as f64;
    let (ew, eh) = (
        (w as f64 * scale).round() as i64,
        (h as f64 * scale).round() as i64,
    );
    assert!(
        (img.width() as i64 - ew).abs() <= 1 && (img.height() as i64 - eh).abs() <= 1,
        "{path}: {}x{} expected {ew}x{eh}",
        img.width(),
        img.height()
    );
    let distinct: std::collections::BTreeSet<_> = img.pixels().map(|p| p.0).collect();
    assert!(
        distinct.len() > 20,
        "{path}: blank thumbnail ({} colours)",
        distinct.len()
    );
}

#[test]
fn thumbnails_are_real_pictures_after_sync_and_after_adding_a_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(local(root, "first")).unwrap();
    let dir = root.join("pics");
    fs::create_dir_all(&dir).unwrap();
    a.add_folder("pics", &dir).unwrap();
    picture(&dir, "big.png", 800, 600, 1);
    picture(&dir, "small.png", 100, 60, 2);
    image::RgbImage::from_fn(640, 480, |x, y| image::Rgb([x as u8, y as u8, 7]))
        .save(dir.join("p.jpg"))
        .unwrap();
    a.push("pics").unwrap();
    assert_real_thumbnail(&a, "pics", "big.png", 800, 600);
    assert_real_thumbnail(&a, "pics", "small.png", 100, 60);
    assert_real_thumbnail(&a, "pics", "p.jpg", 640, 480);

    a.add_storage(local(root, "second")).unwrap();
    a.push("pics").unwrap();
    assert_real_thumbnail(&a, "pics", "big.png", 800, 600);
}

#[test]
fn thumbnails_are_real_pictures_for_an_attached_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(local(root, "first")).unwrap();
    let dir = root.join("pics");
    fs::create_dir_all(dir.join("sub")).unwrap();
    picture(&dir, "x.png", 300, 200, 3);
    picture(&dir.join("sub"), "y.png", 200, 300, 4);
    a.add_folder("pics", &dir).unwrap();
    a.push("pics").unwrap();
    assert_real_thumbnail(&a, "pics", "x.png", 300, 200);
    assert_real_thumbnail(&a, "pics", "sub/y.png", 200, 300);
}
