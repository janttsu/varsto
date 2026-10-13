// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Importing a git-annex repository from two disks into one folder. The
//! fixtures are built in a temporary directory with the real git-annex
//! (`git annex get/drop` run on the fixture clones only); the import itself
//! never runs git-annex. Skipped when git-annex is not installed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ImportOptions;
use varsto_core::import::annex::AnnexSource;
use varsto_core::import::{Delivery, ImportSource, Listing, SourceInfo, Verdict, Wanted};
use varsto_core::policy::Policy;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn have_annex() -> bool {
    Command::new("git-annex")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(dir: &Path, args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} in {}: {}{}",
        dir.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

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

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.split('/').any(|c| c.starts_with(".varsto")) {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

/// A temporary directory that can be removed although git-annex made its
/// object directories read-only.
struct Scratch(tempfile::TempDir);

impl Scratch {
    fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(self.0.path())
            .status();
    }
}

struct Fixture {
    disk1: PathBuf,
    disk2: PathBuf,
    expected: BTreeMap<String, Vec<u8>>,
}

/// Disk one: everything but c.bin and d.bin (dropped), with b.jpg's object
/// damaged. Disk two (a clone): b.jpg, c.bin and d.bin only.
fn fixture(root: &Path) -> Fixture {
    let d1 = root.join("disk1").join("photos");
    fs::create_dir_all(&d1).unwrap();
    run(&d1, &["git", "init", "-q", "-b", "main"]);
    run(&d1, &["git", "annex", "init", "-q", "disk one"]);
    let mut expected = BTreeMap::new();
    let mut put = |rel: &str, bytes: Vec<u8>| {
        let p = d1.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, &bytes).unwrap();
        expected.insert(rel.to_string(), bytes);
    };
    put("a.txt", b"hello annex\n".to_vec());
    put("dup.txt", b"hello annex\n".to_vec());
    put("sub/deep/b.jpg", pseudo_random(300_000, 7));
    put("c.bin", pseudo_random(120_000, 11));
    put("d.bin", pseudo_random(5_000, 13));
    run(
        &d1,
        &[
            "git", "annex", "add", "-q", "a.txt", "dup.txt", "sub", "c.bin", "d.bin",
        ],
    );
    put("u.bin", pseudo_random(40_000, 17));
    run(&d1, &["git", "annex", "add", "-q", "u.bin"]);
    run(&d1, &["git", "annex", "unlock", "-q", "u.bin"]);
    put("w.dat", b"worm content".to_vec());
    run(
        &d1,
        &["git", "annex", "add", "-q", "--backend=WORM", "w.dat"],
    );
    put("small.txt", b"kept in git\n".to_vec());
    run(
        &d1,
        &[
            "git",
            "-c",
            "annex.largefiles=nothing",
            "annex",
            "add",
            "-q",
            "small.txt",
        ],
    );
    run(&d1, &["git", "commit", "-q", "-m", "photos"]);
    // Disk two: a clone that gets b.jpg, c.bin and d.bin.
    let d2 = root.join("disk2").join("photos");
    fs::create_dir_all(d2.parent().unwrap()).unwrap();
    run(
        root,
        &[
            "git",
            "clone",
            "-q",
            d1.to_str().unwrap(),
            d2.to_str().unwrap(),
        ],
    );
    run(&d2, &["git", "annex", "init", "-q", "disk two"]);
    run(
        &d2,
        &[
            "git",
            "annex",
            "get",
            "-q",
            "sub/deep/b.jpg",
            "c.bin",
            "d.bin",
        ],
    );
    // Disk one learns what disk two has, then lets go of c.bin and d.bin.
    run(
        &d1,
        &["git", "remote", "add", "disk2", d2.to_str().unwrap()],
    );
    run(&d1, &["git", "fetch", "-q", "disk2"]);
    run(
        &d1,
        &["git", "annex", "drop", "-q", "--force", "c.bin", "d.bin"],
    );
    // Bit rot on disk one: b.jpg's object.
    run(&d1, &["chmod", "-R", "u+w", ".git/annex/objects"]);
    let target = fs::read_link(d1.join("sub/deep/b.jpg")).unwrap();
    let object = d1.join("sub/deep").join(target);
    let mut bytes = fs::read(&object).unwrap();
    bytes[1000] ^= 0x55;
    fs::write(&object, bytes).unwrap();
    Fixture {
        disk1: d1,
        disk2: d2,
        expected,
    }
}

/// An import source that stops (as if the process died) after `n` files.
struct Interrupted<S: ImportSource> {
    inner: S,
    n: usize,
}

impl<S: ImportSource> ImportSource for Interrupted<S> {
    fn info(&self) -> &SourceInfo {
        self.inner.info()
    }
    fn list(&mut self) -> anyhow::Result<Listing> {
        self.inner.list()
    }
    fn deliver(
        &mut self,
        wanted: &[Wanted],
        sink: &mut varsto_core::import::Sink,
    ) -> anyhow::Result<()> {
        let mut left = self.n;
        let mut wrapped = |i: usize, d: Delivery| -> anyhow::Result<Verdict> {
            if left == 0 {
                anyhow::bail!("simulated crash");
            }
            left -= 1;
            sink(i, d)
        };
        self.inner.deliver(wanted, &mut wrapped)
    }
}

fn storage(root: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
    }
}

#[test]
fn import_annex_from_two_disks() {
    if !have_annex() {
        eprintln!("git-annex not installed; skipped");
        return;
    }
    let tmp = Scratch(tempfile::tempdir().unwrap());
    let root = tmp.path();
    let fx = fixture(root);

    let (mut a, vault_key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage(root)).unwrap();

    // The repository is recognised the same from both disks.
    let s1 = AnnexSource::open(&fx.disk1, "HEAD").unwrap();
    let s2 = AnnexSource::open(&fx.disk2, "HEAD").unwrap();
    assert!(s1
        .info()
        .identity
        .iter()
        .any(|i| s2.info().identity.contains(i)));
    assert_eq!(s1.info().instance_name, "disk one");
    assert_eq!(s1.info().default_folder, "photos");

    // Dry run: nothing is created.
    let opts = ImportOptions {
        dest: Some(root.join("a-photos")),
        selective: true,
        dry_run: true,
        ..Default::default()
    };
    let mut src = AnnexSource::open(&fx.disk1, "HEAD").unwrap();
    let dry = a.import_run(&mut src, &opts).unwrap();
    assert!(dry.dry_run && dry.created_folder);
    assert!(a.folders().is_empty());
    assert_eq!(dry.missing_ids, 2);

    // Disk one, interrupted after two files.
    let opts = ImportOptions {
        dry_run: false,
        ..opts
    };
    let mut src = Interrupted {
        inner: AnnexSource::open(&fx.disk1, "HEAD").unwrap(),
        n: 2,
    };
    let err = a.import_run(&mut src, &opts).unwrap_err();
    assert!(format!("{err:#}").contains("simulated crash"), "{err:#}");
    let st = &a.import_status(Some("photos")).unwrap()[0];
    let before = st.ids_imported;
    // Two files were handed over; one may have been the damaged b.jpg.
    assert!((1..=2).contains(&before), "{before}");

    // Run again: carries on.
    let mut src = AnnexSource::open(&fx.disk1, "HEAD").unwrap();
    let r1 = a.import_run(&mut src, &opts).unwrap();
    assert!(!r1.created_folder);
    assert_eq!(r1.already_ids, before);
    // a/dup (one key), u.bin, w.dat, small.txt: 4 keys in all.
    assert_eq!(r1.imported_ids + r1.already_ids, 4, "{r1:#?}");
    assert_eq!(r1.damaged.len(), 1, "{r1:#?}");
    assert_eq!(r1.damaged[0].path, "sub/deep/b.jpg");
    // c.bin, d.bin and the damaged b.jpg await another disk.
    assert_eq!(r1.missing_ids, 3);
    assert_eq!(r1.holders.len(), 1, "{r1:#?}");
    assert_eq!(r1.holders[0].name, "disk two");
    assert_eq!(r1.holders[0].items, 3);
    let st = &a.import_status(Some("photos")).unwrap()[0];
    assert_eq!(st.files_awaiting, 3);
    assert_eq!(st.ids_damaged, 1);
    let pending: Vec<String> = a
        .list_files_with_pending("photos")
        .unwrap()
        .into_iter()
        .filter(|f| f.state == "awaiting_import")
        .map(|f| f.path)
        .collect();
    assert_eq!(pending, vec!["c.bin", "d.bin", "sub/deep/b.jpg"]);
    let missing = a.import_missing("photos").unwrap();
    assert!(missing
        .iter()
        .all(|m| m.holders == vec!["disk two".to_string()]));
    // Selective: placeholders here, never an empty file in the manifest.
    assert!(a
        .list_files("photos")
        .unwrap()
        .iter()
        .all(|f| f.state == "placeholder"));
    assert!(a
        .list_files("photos")
        .unwrap()
        .iter()
        .all(|f| f.path != "c.bin"));
    assert!(!a.import_verify("photos").unwrap().complete);
    // A sync now changes nothing (placeholders are not deletions).
    let push = a.push("photos").unwrap();
    assert_eq!(push.files_changed, 0);
    drop(a);

    // Another device continues with disk two, keeping a full copy.
    let mut b = Engine::join(
        &root.join("b-home"),
        "desktop",
        PASS,
        &vault_key,
        storage(root),
    )
    .unwrap();
    b.chunker = ChunkerParams::SMALL;
    let st = &b.import_status(Some("photos")).unwrap()[0];
    assert_eq!(st.ids_missing, 3, "the book came through the storage");
    let mut src = AnnexSource::open(&fx.disk2, "HEAD").unwrap();
    let r2 = b
        .import_run(
            &mut src,
            &ImportOptions {
                dest: Some(root.join("b-photos")),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(r2.imported_ids, 3, "{r2:#?}");
    assert!(r2.damaged.is_empty());
    assert_eq!(r2.missing_ids, 0);
    assert_eq!(r2.already_ids, 4, "nothing already imported was read again");
    assert_eq!(tree(&root.join("b-photos")), fx.expected);
    b.set_policy(
        "photos",
        Some(Policy {
            min_copies: 1,
            ..Default::default()
        }),
    )
    .unwrap();
    let v = b.import_verify("photos").unwrap();
    assert!(v.complete, "{v:#?}");
    drop(b);

    // The first device gets the rest; a full copy elsewhere is byte-identical.
    let mut a = Engine::open(&root.join("a-home"), PASS).unwrap();
    a.pull("photos").unwrap();
    let st = &a.import_status(Some("photos")).unwrap()[0];
    assert_eq!(st.ids_missing, 0);
    assert_eq!(st.files_awaiting, 0);
    let mut c = Engine::join(
        &root.join("c-home"),
        "phone",
        PASS,
        &vault_key,
        storage(root),
    )
    .unwrap();
    c.attach_folder("photos", &root.join("c-photos"), false)
        .unwrap();
    c.pull("photos").unwrap();
    assert_eq!(tree(&root.join("c-photos")), fx.expected);
    // Running disk two again reads nothing.
    let mut src = AnnexSource::open(&fx.disk2, "HEAD").unwrap();
    let r3 = a.import_run(&mut src, &opts).unwrap();
    assert_eq!(r3.imported_ids, 0);
    assert_eq!(r3.to_read_ids, 0);
    // The repository's disks are left as they were.
    assert!(fs::read_link(fx.disk1.join("a.txt")).is_ok());
}

#[test]
fn name_clash_with_another_folder_is_refused() {
    if !have_annex() {
        return;
    }
    let tmp = Scratch(tempfile::tempdir().unwrap());
    let root = tmp.path();
    let fx = fixture(root);
    let (mut a, _) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.add_storage(storage(root)).unwrap();
    a.add_folder("photos", &root.join("other")).unwrap();
    let mut src = AnnexSource::open(&fx.disk1, "HEAD").unwrap();
    let err = a
        .import_run(
            &mut src,
            &ImportOptions {
                dest: Some(root.join("x")),
                selective: true,
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("already has a folder named photos"),
        "{err:#}"
    );
}
