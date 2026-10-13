// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Importing a local directory, and removing its files once they are
//! safely stored and the folder's durability policy is met.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ImportOptions;
use varsto_core::import::dir::DirSource;
use varsto_core::policy::Policy;
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

fn storage(root: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    src: PathBuf,
    a: Engine,
    vault_key: String,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let src = root.join("old-drive");
    fs::create_dir_all(src.join("sub/deep")).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    fs::write(src.join("sub/deep/b.bin"), pseudo_random(200_000, 3)).unwrap();
    fs::write(src.join("sub/c.txt"), b"charlie").unwrap();
    fs::write(root.join("outside.txt"), b"not part of the source").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("outside.txt"), src.join("link.txt")).unwrap();
        std::process::Command::new("mkfifo")
            .arg(src.join("pipe"))
            .status()
            .unwrap();
    }
    let (mut a, vault_key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage(&root)).unwrap();
    Lab {
        _tmp: tmp,
        root,
        src,
        a,
        vault_key,
    }
}

fn import(lab: &mut Lab) -> varsto_core::engine::ImportReport {
    let mut s = DirSource::open(&lab.src).unwrap();
    lab.a
        .import_run(
            &mut s,
            &ImportOptions {
                folder: Some("archive".into()),
                dest: Some(lab.root.join("a-archive")),
                selective: true,
                remove_source: true,
                ..Default::default()
            },
        )
        .unwrap()
}

#[test]
fn remove_source_files_once_safe() {
    let mut lab = lab();
    let r = import(&mut lab);
    assert_eq!(r.imported_files, 3, "{r:#?}");
    #[cfg(unix)]
    {
        let skipped: Vec<&str> = r.skipped.iter().map(|n| n.path.as_str()).collect();
        assert_eq!(skipped, vec!["link.txt", "pipe"], "{r:#?}");
    }
    // The default policy wants a cloud copy and another device's check.
    let plan = lab.a.import_cleanup("archive", false).unwrap();
    assert_eq!(plan.eligible, 0);
    assert!(
        plan.waiting[0].reason.contains("waiting for the policy"),
        "{plan:#?}"
    );
    lab.a
        .set_policy(
            "archive",
            Some(Policy {
                min_copies: 1,
                ..Default::default()
            }),
        )
        .unwrap();
    // A file changed after the import stays.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(lab.src.join("sub/c.txt"), b"charlie, edited").unwrap();
    let plan = lab.a.import_cleanup("archive", false).unwrap();
    assert_eq!(plan.eligible, 2, "{plan:#?}");
    assert!(lab.src.join("a.txt").exists(), "a plan removes nothing");
    let done = lab.a.import_cleanup("archive", true).unwrap();
    assert_eq!(done.removed.len(), 2);
    assert_eq!(done.waiting.len(), 1);
    assert_eq!(done.waiting[0].path, "sub/c.txt");
    assert!(done.waiting[0].reason.contains("changed since"));
    assert!(!lab.src.join("a.txt").exists());
    assert!(
        !lab.src.join("sub/deep").exists(),
        "emptied directory removed"
    );
    assert!(lab.src.join("sub/c.txt").exists());
    assert!(lab.src.is_dir(), "the source itself stays");
    #[cfg(unix)]
    {
        assert!(fs::symlink_metadata(lab.src.join("link.txt")).is_ok());
        assert_eq!(
            fs::read(lab.root.join("outside.txt")).unwrap(),
            b"not part of the source"
        );
    }
    // The vault still has everything, the edited file comes over as a new
    // version when imported again, and then it can go too.
    assert_eq!(lab.a.read_file("archive", "a.txt").unwrap(), b"alpha");
    let r = import(&mut lab);
    assert_eq!(r.imported_files, 1, "{r:#?}");
    assert_eq!(
        r.gone_at_source, 2,
        "removed files are gone at the source, kept in Varsto"
    );
    let done = lab.a.import_cleanup("archive", true).unwrap();
    assert_eq!(done.removed.len(), 1);
    assert_eq!(
        lab.a.read_file("archive", "sub/c.txt").unwrap(),
        b"charlie, edited"
    );
    let st = &lab.a.import_status(Some("archive")).unwrap()[0];
    assert_eq!(st.removed_files, 3);
}

#[test]
fn files_wait_until_another_device_verified_them() {
    let mut lab = lab();
    import(&mut lab);
    lab.a
        .set_policy(
            "archive",
            Some(Policy {
                min_copies: 1,
                verified_within_days: Some(30),
                ..Default::default()
            }),
        )
        .unwrap();
    let plan = lab.a.import_cleanup("archive", true).unwrap();
    assert!(plan.removed.is_empty());
    assert_eq!(plan.waiting_count, 3);
    assert!(plan.waiting[0].reason.contains("waiting for the policy"));
    // Another device fetches (and so checks) every block.
    let mut b = Engine::join(
        &lab.root.join("b-home"),
        "desktop",
        PASS,
        &lab.vault_key,
        storage(&lab.root),
    )
    .unwrap();
    b.attach_folder("archive", &lab.root.join("b-archive"), false)
        .unwrap();
    b.pull("archive").unwrap();
    b.push("archive").unwrap();
    drop(b);
    lab.a.pull("archive").unwrap();
    let done = lab.a.import_cleanup("archive", true).unwrap();
    assert_eq!(done.removed.len(), 3, "{done:#?}");
}

#[test]
fn refused_sources() {
    let mut lab = lab();
    // A dry run creates and removes nothing.
    let mut s = DirSource::open(&lab.src).unwrap();
    let r = lab
        .a
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("x")),
                dry_run: true,
                remove_source: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(r.to_read_ids, 3);
    assert!(lab.a.folders().is_empty());
    // A folder of Varsto itself.
    lab.a.add_folder("docs", &lab.root.join("docs")).unwrap();
    let mut s = DirSource::open(&lab.root.join("docs")).unwrap();
    let err = lab
        .a
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("y")),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("overlaps the Varsto folder docs"),
        "{err:#}"
    );
    // Inside the Varsto home.
    let inner = lab.root.join("a-home").join("something");
    fs::create_dir_all(&inner).unwrap();
    let mut s = DirSource::open(&inner).unwrap();
    let err = lab
        .a
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("y")),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("Varsto home"), "{err:#}");
    // A git-annex repository is not emptied.
    let annex = lab.root.join("annex-repo");
    fs::create_dir_all(annex.join(".git/annex")).unwrap();
    fs::write(annex.join("f"), b"x").unwrap();
    let mut s = DirSource::open(&annex).unwrap();
    let err = lab
        .a
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("y")),
                remove_source: true,
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("import git-annex"), "{err:#}");
    // The destination inside the source.
    let mut s = DirSource::open(&lab.src).unwrap();
    let err = lab
        .a
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.src.join("inside")),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("overlap"), "{err:#}");
}
