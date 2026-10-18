// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ignore rules (`.varstoignore` and device-local patterns) and file
//! metadata (permissions, symbolic links, extended attributes, ownership)
//! between two devices through one storage.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::fsmeta::{Caps, MetaSettings, ModeCap};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

/// Device A with a folder "docs" holding `files`, pushed; device B joined
/// and attached. Returns both engines (B not pulled yet).
fn two(files: &[(&str, &[u8])]) -> (Lab, Engine, Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let lab = Lab {
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        root,
        _tmp: tmp,
    };
    let (mut a, vault_key) = Engine::init(&lab.root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    for (p, b) in files {
        write(&lab.a_dir, p, b);
    }
    a.push("docs").unwrap();
    let mut b = common::join_approved(
        &lab.root.join("b-home"),
        "desk",
        PASS,
        &vault_key,
        storage,
        &mut a,
    );
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    (lab, a, b)
}

fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

fn published(e: &Engine) -> Vec<String> {
    e.list_files("docs")
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect()
}

#[test]
fn ignored_paths_are_neither_published_nor_deleted_elsewhere() {
    let (lab, mut a, mut b) = two(&[
        (".varstoignore", b"# junk\n*.tmp\nbuild/\n"),
        ("a.txt", b"a"),
        ("x.tmp", b"scratch"),
        ("build/out.o", b"object"),
        ("sub/.varstoignore", b"!keep.tmp\n"),
        ("sub/keep.tmp", b"kept"),
        ("sub/drop.tmp", b"dropped"),
        ("old.log", b"log v1"),
    ]);
    assert_eq!(
        published(&a),
        vec![
            ".varstoignore",
            "a.txt",
            "old.log",
            "sub/.varstoignore",
            "sub/keep.tmp"
        ]
    );
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 5);
    assert!(
        lab.b_dir.join(".varstoignore").is_file(),
        "the rules are synced"
    );
    assert!(lab.b_dir.join("sub/keep.tmp").is_file());
    assert!(!lab.b_dir.join("x.tmp").exists());
    assert!(!lab.b_dir.join("build").exists());

    // A file in the vault that becomes ignored stays there: neither its
    // change nor its removal on A is published.
    fs::write(lab.a_dir.join(".varstoignore"), "*.tmp\nbuild/\n*.log\n").unwrap();
    fs::write(lab.a_dir.join("old.log"), b"log v2, not published").unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 1, "only .varstoignore changed");
    assert!(push.files_ignored >= 3);
    fs::remove_file(lab.a_dir.join("old.log")).unwrap();
    assert_eq!(a.push("docs").unwrap().files_changed, 0);
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_deleted, 0);
    assert_eq!(fs::read(lab.b_dir.join("old.log")).unwrap(), b"log v1");
    assert!(published(&a).contains(&"old.log".to_string()));

    // An ignored file appearing on B is not published either (B now has
    // the *.log rule through the synced file).
    write(&lab.b_dir, "b.log", b"from b");
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // check-ignore says why.
    let v = a
        .check_ignore("docs", "build/deep/x.c", None, None)
        .unwrap();
    assert!(v.ignored);
    assert_eq!(v.pattern.as_deref(), Some("build/"));
    assert_eq!(v.source.as_deref(), Some(".varstoignore"));
    assert!(
        !a.check_ignore("docs", "sub/keep.tmp", None, None)
            .unwrap()
            .ignored
    );
    // A preview of an edit that is not saved.
    assert!(
        !a.check_ignore("docs", "x.tmp", Some("*.log\n"), None)
            .unwrap()
            .ignored
    );
}

#[test]
fn local_rules_stay_on_the_device_and_incoming_files_are_skipped() {
    let (lab, mut a, mut b) = two(&[("a.txt", b"a")]);
    b.pull("docs").unwrap();
    assert!(b.ignore_add("docs", "*.iso", true).unwrap());
    assert!(
        !b.ignore_add("docs", "*.iso", true).unwrap(),
        "already there"
    );
    assert_eq!(b.folder_ignore("docs").unwrap().local, vec!["*.iso"]);
    assert!(a.folder_ignore("docs").unwrap().local.is_empty());
    assert!(!lab.b_dir.join(".varstoignore").exists(), "nothing synced");

    // A file of B's own that its local rule covers is not published.
    write(&lab.b_dir, "mine.iso", b"b's image");
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // An incoming file the rule covers is not written, and reported once.
    write(&lab.a_dir, "disk.iso", b"a's image");
    write(&lab.a_dir, "notes.txt", b"notes");
    a.push("docs").unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_ignored, vec!["disk.iso"]);
    assert!(lab.b_dir.join("notes.txt").is_file());
    assert!(!lab.b_dir.join("disk.iso").exists());
    write(&lab.a_dir, "more.txt", b"more");
    a.push("docs").unwrap();
    assert!(
        b.pull("docs").unwrap().files_ignored.is_empty(),
        "reported once"
    );
    // A deletion of an ignored path is not applied either.
    fs::remove_file(lab.a_dir.join("disk.iso")).unwrap();
    a.push("docs").unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_deleted, 0);
    assert_eq!(
        pull.files_ignored,
        vec!["disk.iso"],
        "a newer version is reported"
    );
    assert!(lab.b_dir.join("mine.iso").is_file());

    // Without the rule, what was held back arrives (here: the deletion,
    // which is newer than anything B had).
    write(&lab.a_dir, "disk.iso", b"a's image again");
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    assert!(b.ignore_remove("docs", "*.iso", true).unwrap());
    b.pull("docs").unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("disk.iso")).unwrap(),
        b"a's image again"
    );
    // B's own file is published now as well.
    b.push("docs").unwrap();
    a.pull("docs").unwrap();
    assert!(lab.a_dir.join("mine.iso").is_file());

    // The synced file is edited through the same calls.
    assert!(a.ignore_add("docs", "*.bak", false).unwrap());
    assert_eq!(
        fs::read_to_string(lab.a_dir.join(".varstoignore")).unwrap(),
        "*.bak\n"
    );
    assert!(a.ignore_remove("docs", "*.bak", false).unwrap());
    assert!(!a.ignore_remove("docs", "*.bak", false).unwrap());
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
fn chmod(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}

#[cfg(unix)]
#[test]
fn a_chmod_syncs_without_uploading_blocks() {
    let (lab, mut a, mut b) = two(&[("run.sh", b"#!/bin/sh\necho hi\n")]);
    chmod(&lab.a_dir.join("run.sh"), 0o644);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    assert_eq!(mode(&lab.b_dir.join("run.sh")), 0o644);

    chmod(&lab.a_dir.join("run.sh"), 0o755);
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 1);
    assert_eq!(push.metadata_changed, 1);
    assert_eq!(
        push.chunks_uploaded, 0,
        "a metadata change reuses the blocks"
    );
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 1);
    assert_eq!(pull.chunks_downloaded, 0, "nor is anything downloaded");
    assert_eq!(mode(&lab.b_dir.join("run.sh")), 0o755);
    let f = b.list_files("docs").unwrap();
    assert_eq!(f[0].mode_text.as_deref(), Some("rwxr-xr-x"));
    // Nothing flaps back.
    assert_eq!(b.push("docs").unwrap().files_changed, 0);
    assert_eq!(a.pull("docs").unwrap().files_updated, 0);
}

#[cfg(unix)]
#[test]
fn a_device_that_cannot_represent_a_property_does_not_publish_its_removal() {
    let (lab, mut a, mut b) = two(&[("run.sh", b"v1")]);
    chmod(&lab.a_dir.join("run.sh"), 0o750);
    a.push("docs").unwrap();
    // B is like a phone without mode bits.
    b.set_meta_caps(Caps {
        mode: ModeCap::None,
        ..Caps::here()
    });
    b.pull("docs").unwrap();
    fs::write(lab.b_dir.join("run.sh"), b"v2 from b").unwrap();
    let push = b.push("docs").unwrap();
    assert_eq!(push.files_changed, 1);
    a.pull("docs").unwrap();
    assert_eq!(fs::read(lab.a_dir.join("run.sh")).unwrap(), b"v2 from b");
    assert_eq!(
        mode(&lab.a_dir.join("run.sh")),
        0o750,
        "the mode survived B's edit"
    );
    assert_eq!(a.list_files("docs").unwrap()[0].mode, Some(0o750));
}

#[cfg(unix)]
#[test]
fn settings_off_means_not_synced() {
    let (lab, mut a, mut b) = two(&[("f.txt", b"x")]);
    chmod(&lab.a_dir.join("f.txt"), 0o644);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    b.set_folder_settings(
        "docs",
        MetaSettings {
            permissions: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!b.folder_settings("docs").unwrap().permissions);
    // Incoming permissions are not applied ...
    chmod(&lab.a_dir.join("f.txt"), 0o600);
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    assert_eq!(mode(&lab.b_dir.join("f.txt")), 0o644);
    // ... and B's own are not published.
    chmod(&lab.b_dir.join("f.txt"), 0o640);
    assert_eq!(b.push("docs").unwrap().files_changed, 0);
    // Ownership is off by default: no owner is published.
    assert!(a.list_files("docs").unwrap()[0].owner.is_none());
    a.set_folder_settings(
        "docs",
        MetaSettings {
            ownership: true,
            ..Default::default()
        },
    )
    .unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.metadata_changed, 1);
    assert!(a.list_files("docs").unwrap()[0].owner.is_some());
}

#[cfg(unix)]
#[test]
fn symbolic_links_round_trip_and_are_never_followed() {
    let tmp_out = tempfile::tempdir().unwrap();
    fs::write(tmp_out.path().join("secret.txt"), b"outside").unwrap();
    let (lab, mut a, mut b) = two(&[("a.txt", b"a"), ("sub/inner.txt", b"inner")]);
    let link =
        |target: &str, at: &str| std::os::unix::fs::symlink(target, lab.a_dir.join(at)).unwrap();
    link("a.txt", "rel");
    link("/etc/hostname", "abs");
    link("missing/nowhere", "dangling");
    link("sub", "dirlink");
    link(tmp_out.path().to_str().unwrap(), "out");
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 5);
    let paths = published(&a);
    assert!(
        !paths
            .iter()
            .any(|p| p.starts_with("dirlink/") || p.starts_with("out/")),
        "{paths:?}"
    );

    let pull = b.pull("docs").unwrap();
    assert!(pull.links_as_notes.is_empty());
    for (p, t) in [
        ("rel", "a.txt"),
        ("abs", "/etc/hostname"),
        ("dangling", "missing/nowhere"),
        ("dirlink", "sub"),
    ] {
        let at = lab.b_dir.join(p);
        assert!(
            fs::symlink_metadata(&at).unwrap().file_type().is_symlink(),
            "{p}"
        );
        assert_eq!(fs::read_link(&at).unwrap(), PathBuf::from(t));
    }
    let files = b.list_files("docs").unwrap();
    let abs = files.iter().find(|f| f.path == "abs").unwrap();
    assert!(abs.symlink_absolute);
    assert_eq!(abs.size, 0);
    let rel = files.iter().find(|f| f.path == "rel").unwrap();
    assert_eq!(rel.symlink.as_deref(), Some("a.txt"));
    assert!(!rel.symlink_absolute);
    assert_eq!(
        files.iter().find(|f| f.path == "dangling").unwrap().state,
        "local"
    );

    // Reading through Varsto never follows a link, nor goes through one.
    assert!(b.read_file("docs", "out").is_err());
    assert!(b.read_file("docs", "out/secret.txt").is_err());
    assert!(b.view_range("docs", "dirlink/inner.txt", 0, 10).is_err());

    // A changed target and a removed link arrive.
    fs::remove_file(lab.a_dir.join("rel")).unwrap();
    link("sub/inner.txt", "rel");
    fs::remove_file(lab.a_dir.join("dangling")).unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 2);
    assert_eq!(push.chunks_uploaded, 0);
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 1);
    assert_eq!(pull.files_deleted, 1);
    assert_eq!(
        fs::read_link(lab.b_dir.join("rel")).unwrap(),
        PathBuf::from("sub/inner.txt")
    );
    assert!(fs::symlink_metadata(lab.b_dir.join("dangling")).is_err());
    // Nothing flaps back.
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // Links off on a device: they are neither published nor created there.
    b.set_folder_settings(
        "docs",
        MetaSettings {
            symlinks: false,
            ..Default::default()
        },
    )
    .unwrap();
    std::os::unix::fs::symlink("a.txt", lab.b_dir.join("b-link")).unwrap();
    assert_eq!(b.push("docs").unwrap().files_changed, 0);
    link("a.txt", "new-link");
    a.push("docs").unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.links_skipped, vec!["new-link"]);
    assert!(fs::symlink_metadata(lab.b_dir.join("new-link")).is_err());
    // Turned on again, the held-back link is created.
    b.set_folder_settings("docs", MetaSettings::default())
        .unwrap();
    b.pull("docs").unwrap();
    assert!(fs::symlink_metadata(lab.b_dir.join("new-link"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(target_os = "linux")]
#[test]
fn extended_attributes_round_trip() {
    use varsto_core::fsmeta::{get_xattr, set_xattr};
    let (lab, mut a, mut b) = two(&[("tagged.txt", b"content")]);
    let f = lab.a_dir.join("tagged.txt");
    if set_xattr(&f, "user.varsto-test", b"blue").is_err() {
        eprintln!("the temporary filesystem has no user extended attributes; skipped");
        return;
    }
    let push = a.push("docs").unwrap();
    assert_eq!(push.metadata_changed, 1);
    assert_eq!(push.chunks_uploaded, 0);
    b.pull("docs").unwrap();
    let g = lab.b_dir.join("tagged.txt");
    match get_xattr(&g, "user.varsto-test") {
        Ok(v) => assert_eq!(v, b"blue"),
        Err(_) => {
            eprintln!("B's filesystem has no user extended attributes; skipped");
            return;
        }
    }
    assert_eq!(
        b.list_files("docs").unwrap()[0].xattrs,
        vec!["user.varsto-test"]
    );
    // Changed and removed on B: both arrive at A.
    set_xattr(&g, "user.varsto-test", b"green").unwrap();
    set_xattr(&g, "user.other", b"1").unwrap();
    assert_eq!(b.push("docs").unwrap().metadata_changed, 1);
    a.pull("docs").unwrap();
    assert_eq!(get_xattr(&f, "user.varsto-test").unwrap(), b"green");
    assert_eq!(get_xattr(&f, "user.other").unwrap(), b"1");
    // A device with attributes off keeps them as they are.
    b.set_folder_settings(
        "docs",
        MetaSettings {
            xattrs: false,
            ..Default::default()
        },
    )
    .unwrap();
    set_xattr(&g, "user.other", b"2").unwrap();
    assert_eq!(b.push("docs").unwrap().files_changed, 0);
}
