// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder names are unique in the vault; a folder can be detached on one
//! device or removed from the vault on all of them, and files stay.

use std::fs;
use std::path::Path;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn files_under(p: &Path) -> usize {
    walkdir::WalkDir::new(p)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

#[test]
fn folders_are_unique_detachable_and_removable() {
    let t = tempfile::tempdir().unwrap();
    let st = t.path().join("storage");
    fs::create_dir_all(&st).unwrap();
    let spec = StorageSpec::LocalDir {
        name: "primary".into(),
        path: st.clone(),
        cold: false,
        carrier: false,
        place: String::new(),
    };
    let (mut a, key) = Engine::init(&t.path().join("a"), "laptop", PASS).unwrap();
    a.add_storage(spec.clone()).unwrap();
    let (a_photos, a_spare) = (t.path().join("a-photos"), t.path().join("a-spare"));
    a.add_folder("Photos", &a_photos).unwrap();
    a.add_folder("Spare", &a_spare).unwrap();
    fs::write(a_photos.join("cat.jpg"), vec![1u8; 40_000]).unwrap();
    fs::write(a_spare.join("x.txt"), b"spare").unwrap();
    a.sync(None).unwrap();

    let mut b = Engine::join(&t.path().join("b"), "phone", PASS, &key, spec).unwrap();
    // The same top-level name, in any case, is refused on another device.
    let e = b.add_folder("photos", &t.path().join("b-new")).unwrap_err();
    assert!(
        e.to_string().contains("already has a folder named Photos"),
        "{e}"
    );
    let b_spare = t.path().join("b-spare");
    b.attach_folder("Spare", &b_spare, false).unwrap();
    b.sync(None).unwrap();
    assert!(b_spare.join("x.txt").exists());

    // Detach on B: B stops syncing Spare, its files stay, the vault keeps it.
    b.detach_folder("Spare").unwrap();
    assert!(b
        .folders()
        .iter()
        .any(|(r, m)| r.name == "Spare" && m.is_none()));
    assert!(b_spare.join("x.txt").exists());

    // Remove Spare from the vault on A with its data: B forgets it on its
    // next sync, nobody syncs it, files on disk stay, storage loses its blocks.
    let before = files_under(&st.join("chunks"));
    let deleted = a.remove_folder("Spare", true).unwrap();
    assert!(deleted > 0);
    assert!(files_under(&st.join("chunks")) < before);
    assert!(a.folders().iter().all(|(r, _)| r.name != "Spare"));
    assert!(a_spare.join("x.txt").exists());
    b.sync(None).unwrap();
    assert!(b.folders().iter().all(|(r, _)| r.name != "Spare"));
    // The name is free again.
    a.add_folder("spare", &t.path().join("a-spare2")).unwrap();
    // Photos is untouched.
    b.attach_folder("Photos", &t.path().join("b-photos"), false)
        .unwrap();
    b.sync(None).unwrap();
    assert!(t.path().join("b-photos/cat.jpg").exists());
}
