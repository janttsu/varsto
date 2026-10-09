// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folders kept "encrypted on this device" (phones): the device keeps the
//! folder's encrypted blocks in its block cache and never a plain file;
//! selective sync works as in any folder.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::ids::ObjectName;
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
fn files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files(&p));
        } else {
            out.push((p.clone(), fs::read(&p).unwrap_or_default()));
        }
    }
    out.sort();
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// No file under any of `roots` holds a 48-byte piece of any of `contents`.
fn assert_no_plaintext(roots: &[&Path], contents: &[&[u8]]) {
    for root in roots {
        for (path, bytes) in files(root) {
            for c in contents {
                for at in [0, c.len() / 3, c.len() / 2, c.len() - 48] {
                    assert!(
                        !contains(&bytes, &c[at..at + 48]),
                        "plaintext found in {}",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Object names in a directory with the storage layout (`chunks/xx/<name>`).
fn objects(root: &Path) -> BTreeSet<String> {
    files(&root.join("chunks"))
        .into_iter()
        .map(|(p, _)| p.file_name().unwrap().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.'))
        .collect()
}

fn state_of(e: &Engine, folder: &str, path: &str) -> String {
    e.list_files(folder)
        .unwrap()
        .into_iter()
        .find(|f| f.path == path)
        .map(|f| f.state)
        .unwrap_or_else(|| "absent".into())
}

struct Setup {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
    a: Engine,
    a_dir: PathBuf,
    key: String,
    photo: Vec<u8>,
    notes: Vec<u8>,
}

/// A laptop with a plain folder "docs" holding two files, pushed to a
/// local-directory storage.
fn setup() -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
    };
    let a_dir = root.join("a-docs");
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    let photo = pseudo_random(150_000, 11);
    let notes = pseudo_random(40_000, 12);
    fs::create_dir_all(a_dir.join("trip")).unwrap();
    fs::write(a_dir.join("trip/photo.bin"), &photo).unwrap();
    fs::write(a_dir.join("notes.bin"), &notes).unwrap();
    a.push("docs").unwrap();
    Setup {
        _tmp: tmp,
        root,
        storage,
        a,
        a_dir,
        key,
        photo,
        notes,
    }
}

/// The phone: joined, "docs" attached and kept encrypted here.
fn phone(s: &Setup, selective: bool) -> (Engine, PathBuf, PathBuf) {
    let (home, dir) = (s.root.join("b-home"), s.root.join("b-docs"));
    let mut b = Engine::join(&home, "phone", PASS, &s.key, s.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &dir, selective).unwrap();
    b.set_encrypted_here("docs", true).unwrap();
    (b, home, dir)
}

#[test]
fn not_selective_caches_every_block_and_no_plaintext() {
    let s = setup();
    let (mut b, home, dir) = phone(&s, false);
    b.sync(None).unwrap();
    // Every object of the folder is in the block cache, as stored.
    let stored = objects(&s.root.join("storage"));
    let cached = objects(&home.join("block-cache"));
    assert!(!stored.is_empty());
    assert_eq!(stored, cached);
    for (p, bytes) in files(&home.join("block-cache").join("chunks")) {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(
            fs::read(s.root.join("storage/chunks").join(&name[..2]).join(&name)).unwrap(),
            bytes
        );
    }
    assert_eq!(state_of(&b, "docs", "trip/photo.bin"), "local");
    assert_eq!(state_of(&b, "docs", "notes.bin"), "local");
    // Peers are served the cached objects as they are.
    let snap = b.peer_snapshot().unwrap();
    for name in &cached {
        let obj = snap.object(&ObjectName::from_hex(name).unwrap()).unwrap();
        let p = home.join("block-cache/chunks").join(&name[..2]).join(name);
        assert_eq!(obj, Some(fs::read(p).unwrap()));
    }
    // The folder directory holds nothing; no file anywhere holds plaintext.
    assert!(files(&dir).is_empty());
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes]);
    let st = b.status().unwrap();
    let f = st.folders.iter().find(|f| f.name == "docs").unwrap();
    assert!(!f.plain && !f.selective);
    assert_eq!(f.placeholders, 0);
    assert_eq!(f.blocks.stored_away + f.blocks.verified_away, 0);
}

#[test]
fn selective_caches_fetched_files_only_and_frees_them() {
    let s = setup();
    let (mut b, home, dir) = phone(&s, true);
    b.sync(None).unwrap();
    assert_eq!(state_of(&b, "docs", "trip/photo.bin"), "placeholder");
    assert_eq!(state_of(&b, "docs", "notes.bin"), "placeholder");
    assert!(objects(&home.join("block-cache")).is_empty());

    b.fetch_file("docs", "notes.bin").unwrap();
    assert_eq!(state_of(&b, "docs", "notes.bin"), "local");
    assert_eq!(state_of(&b, "docs", "trip/photo.bin"), "placeholder");
    let after_fetch = objects(&home.join("block-cache"));
    assert!(!after_fetch.is_empty());
    assert!(after_fetch.is_subset(&objects(&s.root.join("storage"))));
    // Pinned files stay cached through syncs; nothing else is fetched.
    b.sync(None).unwrap();
    assert_eq!(objects(&home.join("block-cache")), after_fetch);
    assert!(files(&dir).is_empty());
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes]);

    b.free_file("docs", "notes.bin").unwrap();
    assert_eq!(state_of(&b, "docs", "notes.bin"), "placeholder");
    assert!(objects(&home.join("block-cache")).is_empty());
    // The viewer still reads it, from the storage, in memory.
    assert_eq!(
        b.view_range("docs", "notes.bin", 0, 40_000).unwrap(),
        s.notes
    );
    assert!(objects(&home.join("block-cache")).is_empty());
}

#[test]
fn free_refuses_blocks_without_a_storage_copy() {
    let tmp = tempfile::tempdir().unwrap();
    // A device with no storage at all: what it writes exists only here.
    let (mut c, _) = Engine::init(&tmp.path().join("home"), "phone", PASS).unwrap();
    c.add_folder("notes", &tmp.path().join("notes")).unwrap();
    c.set_encrypted_here("notes", true).unwrap();
    let text = pseudo_random(5_000, 3);
    c.write_file("notes", "draft.bin", &text).unwrap();
    assert_eq!(state_of(&c, "notes", "draft.bin"), "local");
    let before = objects(&tmp.path().join("home/block-cache"));
    assert!(!before.is_empty());
    let err = c.free_file("notes", "draft.bin").unwrap_err();
    assert!(err.to_string().contains("not fully stored"), "{err}");
    assert_eq!(c.free_folder("notes").unwrap(), (0, 1));
    c.sync(None).unwrap();
    assert_eq!(objects(&tmp.path().join("home/block-cache")), before);
    assert_eq!(state_of(&c, "notes", "draft.bin"), "local");
    assert_eq!(c.read_file("notes", "draft.bin").unwrap(), text);
    assert_no_plaintext(&[tmp.path()], &[&text]);
}

#[test]
fn viewer_reads_from_the_cache_with_storages_unreachable() {
    let s = setup();
    let (mut b, home, dir) = phone(&s, false);
    b.sync(None).unwrap();
    // The storage goes away (offline phone).
    fs::rename(s.root.join("storage"), s.root.join("storage-away")).unwrap();
    assert_eq!(b.view_size("docs", "trip/photo.bin").unwrap(), 150_000);
    assert_eq!(
        b.view_range("docs", "trip/photo.bin", 0, 150_000).unwrap(),
        s.photo
    );
    assert_eq!(
        b.view_range("docs", "trip/photo.bin", 70_001, 99_999)
            .unwrap(),
        s.photo[70_001..99_999]
    );
    assert_eq!(b.read_file("docs", "notes.bin").unwrap(), s.notes);
    assert!(files(&dir).is_empty());
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes]);
}

#[test]
fn files_added_on_the_phone_reach_other_devices_without_plaintext_here() {
    let mut s = setup();
    let (mut b, home, dir) = phone(&s, true);
    b.sync(None).unwrap();
    // Small file through write_file, a large one streamed through a writer
    // (as /api/upload does, without the engine while the bytes arrive).
    let memo = pseudo_random(9_000, 21);
    let video = pseudo_random(400_000, 22);
    b.write_file("docs", "memo.bin", &memo).unwrap();
    let w = b.block_writer("docs").unwrap().expect("encrypted here");
    let staged = w.write(std::io::Cursor::new(video.clone())).unwrap();
    assert_eq!(staged.size(), 400_000);
    b.commit_staged("docs", "camera/video.bin", staged).unwrap();
    assert_eq!(state_of(&b, "docs", "camera/video.bin"), "local");
    // Pictures get their thumbnail from the cached blocks, in memory.
    let mut png = Vec::new();
    image::RgbImage::from_fn(600, 400, |x, y| image::Rgb([x as u8, y as u8, 7]))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let push = b.write_file("docs", "camera/pic.png", &png).unwrap();
    assert_eq!(push.thumbnails, 1);
    assert!(b.thumbnail("docs", "camera/pic.png").unwrap().is_some());
    b.mkdir("docs", "empty").unwrap();
    b.move_file("docs", "memo.bin", "kept/memo.bin").unwrap();
    assert_eq!(state_of(&b, "docs", "kept/memo.bin"), "local");
    assert_eq!(state_of(&b, "docs", "memo.bin"), "absent");
    assert!(files(&dir).is_empty() && !dir.join("empty").exists());
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes, &memo, &video, &png]);

    s.a.sync(None).unwrap();
    assert_eq!(fs::read(s.a_dir.join("kept/memo.bin")).unwrap(), memo);
    assert_eq!(fs::read(s.a_dir.join("camera/video.bin")).unwrap(), video);
    assert!(!s.a_dir.join("memo.bin").exists());

    // The uploaded blocks are on the storage: they can leave the phone.
    b.free_file("docs", "camera/video.bin").unwrap();
    assert_eq!(state_of(&b, "docs", "camera/video.bin"), "placeholder");
    // A change on the laptop to a cached file arrives cached; one to a
    // placeholder stays a placeholder.
    let memo2 = pseudo_random(9_500, 23);
    fs::write(s.a_dir.join("kept/memo.bin"), &memo2).unwrap();
    s.a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(state_of(&b, "docs", "kept/memo.bin"), "local");
    assert_eq!(b.read_file("docs", "kept/memo.bin").unwrap(), memo2);
    assert_eq!(state_of(&b, "docs", "notes.bin"), "placeholder");
    assert_no_plaintext(&[&home, &dir], &[&memo2]);
}

#[test]
fn plain_copies_from_the_previous_layout_are_converted() {
    let mut s = setup();
    let (home, dir) = (s.root.join("b-home"), s.root.join("b-docs"));
    // The phone as older versions left it: the folder was synced with plain
    // files while unlocked, one file was freed to a placeholder file, one
    // was changed on the phone and one added, neither synced yet.
    let mut b = Engine::join(&home, "phone", PASS, &s.key, s.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &dir, true).unwrap();
    b.sync(None).unwrap();
    for p in ["trip/photo.bin", "notes.bin"] {
        b.fetch_file("docs", p).unwrap();
    }
    b.free_file("docs", "trip/photo.bin").unwrap();
    assert!(dir.join("trip/photo.bin.varsto-placeholder").exists());
    let notes2 = pseudo_random(41_000, 31);
    let added = pseudo_random(20_000, 32);
    fs::write(dir.join("notes.bin"), &notes2).unwrap();
    fs::write(dir.join("added.bin"), &added).unwrap();
    b.set_encrypted_here("docs", true).unwrap();
    drop(b);

    // Next unlock and sync: everything plain goes, nothing is lost.
    let mut b = Engine::open(&home, PASS).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.sync(None).unwrap();
    assert!(files(&dir).is_empty(), "{:?}", files(&dir));
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes, &notes2, &added]);
    assert_eq!(state_of(&b, "docs", "notes.bin"), "local");
    assert_eq!(state_of(&b, "docs", "added.bin"), "local");
    assert_eq!(state_of(&b, "docs", "trip/photo.bin"), "placeholder");
    assert_eq!(b.read_file("docs", "notes.bin").unwrap(), notes2);
    s.a.sync(None).unwrap();
    assert_eq!(fs::read(s.a_dir.join("notes.bin")).unwrap(), notes2);
    assert_eq!(fs::read(s.a_dir.join("added.bin")).unwrap(), added);
    assert_eq!(fs::read(s.a_dir.join("trip/photo.bin")).unwrap(), s.photo);
    // Switching back to plain files is refused now; detach instead.
    assert!(b.set_encrypted_here("docs", false).is_err());
}

#[test]
fn locking_deletes_nothing_and_exports_are_removed() {
    let s = setup();
    let (mut b, home, dir) = phone(&s, false);
    b.sync(None).unwrap();
    // "Open in another app": the only decrypted copy, on explicit request.
    let out = b.export_file("docs", "trip/photo.bin").unwrap();
    assert!(out.starts_with(home.join("exports")));
    assert_eq!(fs::read(&out).unwrap(), s.photo);
    // Locking drops the keys (the engine) and the exported copies.
    drop(b);
    assert_eq!(Engine::clear_exports(&home), 1);
    assert!(!out.exists());
    let before = files(&home);
    // What the service does when it starts locked.
    assert_eq!(Engine::wipe_encrypted_folders_locked(&home).unwrap(), 0);
    assert_eq!(Engine::clear_exports(&home), 0);
    assert_eq!(files(&home), before, "nothing changes while locked");
    assert!(files(&dir).is_empty());
    assert_no_plaintext(&[&home, &dir], &[&s.photo, &s.notes]);
    // Unlocked again, everything is still there.
    let b = Engine::open(&home, PASS).unwrap();
    assert_eq!(state_of(&b, "docs", "trip/photo.bin"), "local");
    fs::rename(s.root.join("storage"), s.root.join("storage-away")).unwrap();
    assert_eq!(
        b.view_range("docs", "notes.bin", 0, 40_000).unwrap(),
        s.notes
    );
}
