// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Temporary files next to a folder's files (spec section 60): created
//! exclusively under unguessable names and with mode 0600, so a symbolic link
//! or file planted under the old predictable name (`.varsto-tmp-<pid>`) is
//! never written through.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_planted_link_under_the_old_temporary_name_is_not_written_through() {
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
    let (a_docs, b_docs) = (root.join("a-docs"), root.join("b-docs"));
    let (mut a, key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &a_docs).unwrap();
    fs::write(a_docs.join("report.txt"), b"the real report").unwrap();
    fs::set_permissions(a_docs.join("report.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    a.push("docs").unwrap();

    let mut b = common::join_approved(&root.join("b-home"), "desk", PASS, &key, storage, &mut a);
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &b_docs, false).unwrap();
    // Another local user plants links where the temporary files used to go.
    let victim = root.join("victim.txt");
    fs::write(&victim, b"precious").unwrap();
    let pid = std::process::id();
    for kind in ["tmp", "upload", "import"] {
        std::os::unix::fs::symlink(&victim, b_docs.join(format!(".varsto-{kind}-{pid}"))).unwrap();
    }
    b.pull("docs").unwrap();
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"precious",
        "written through a link"
    );
    let got = b_docs.join("report.txt");
    assert_eq!(fs::read(&got).unwrap(), b"the real report");
    // The recorded mode was set before the file got its name.
    assert_eq!(fs::metadata(&got).unwrap().mode() & 0o777, 0o640);

    // Writing a file through the engine does the same.
    b.write_file("docs", "note.txt", b"from b").unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"precious");
    assert_eq!(fs::read(b_docs.join("note.txt")).unwrap(), b"from b");
    // No temporary file is left behind.
    let leftovers: Vec<_> = fs::read_dir(&b_docs)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            n.starts_with(".varsto-") && !n.ends_with(&pid.to_string()) && n != ".varsto-folder"
        })
        .collect();
    assert!(
        leftovers.iter().all(|n| n.contains("folder")),
        "{leftovers:?}"
    );
}

#[test]
fn temporary_files_are_exclusive_private_and_unpredictable() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("file.txt");
    let (p1, f1) = varsto_core::util::temp_beside(&target, "tmp").unwrap();
    let (p2, _f2) = varsto_core::util::temp_beside(&target, "tmp").unwrap();
    assert_ne!(p1, p2);
    assert_eq!(f1.metadata().unwrap().mode() & 0o777, 0o600);
    assert!(p1
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with(&format!(".varsto-tmp-{}-", std::process::id())));
    // An existing name, a link included, is an error and is left alone.
    let victim = tmp.path().join("victim");
    fs::write(&victim, b"precious").unwrap();
    let planted = tmp.path().join("planted");
    std::os::unix::fs::symlink(&victim, &planted).unwrap();
    assert!(varsto_core::util::create_new_private(&planted).is_err());
    assert!(varsto_core::util::create_new_private(&victim).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"precious");
}
