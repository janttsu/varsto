// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The restic device's mirror: setup attaches every folder under one root
//! (refusing, or moving, folders attached elsewhere), new folders follow,
//! the completeness check finds missing, placeholder and damaged files and
//! fixes them, the cache of verified hashes spares re-reading, and a hold
//! keeps Varsto out of the mirror folders. restic itself is not needed
//! here (`crates/varsto-cli/tests/restic_cli.rs` runs it).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use varsto_core::engine::CheckOptions;
use varsto_core::restic::{
    FolderChoice, Keep, PasswordSource, ProblemKind, ResticConfig, HOLD_LEASE_SECS,
};
use varsto_core::storage::StorageSpec;
use varsto_core::vault::BackupSchedule;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn store(path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn config(root: &Path, pw: &Path) -> ResticConfig {
    ResticConfig {
        root: root.to_path_buf(),
        repository: "/nowhere/restic-repo".into(),
        password: PasswordSource::File(pw.to_path_buf()),
        env_file: None,
        binary: "restic".into(),
        folders: FolderChoice::All,
        include_shared: false,
        include_strongroom: false,
        keep: Keep::default(),
        check_every_days: 7,
        check_subset: "5%".into(),
        schedule: BackupSchedule::Manual,
        vault_short: String::new(),
        host: String::new(),
        created_utc: 0,
    }
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn p(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

/// Device A with folders docs and photos on one storage, device B joined.
fn two_devices() -> (Lab, Engine, Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let lab = Lab {
        root: tmp.path().to_path_buf(),
        _tmp: tmp,
    };
    let (mut a, key) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    a.add_storage(store(&lab.p("storage"))).unwrap();
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    a.add_folder("photos", &lab.p("a-photos")).unwrap();
    fs::create_dir_all(lab.p("a-docs/sub")).unwrap();
    fs::write(lab.p("a-docs/a.txt"), b"alpha").unwrap();
    fs::write(lab.p("a-docs/sub/b.txt"), vec![7u8; 200_000]).unwrap();
    fs::write(lab.p("a-photos/p.jpg"), b"not really a photo").unwrap();
    a.sync(None).unwrap();
    let mut b = Engine::join(
        &lab.p("b-home"),
        "nas",
        PASS,
        &key,
        store(&lab.p("storage")),
    )
    .unwrap();
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    fs::write(lab.p("pw"), b"secret").unwrap();
    (lab, a, b)
}

fn opts(fix: bool, rehash_all: bool) -> CheckOptions {
    CheckOptions {
        token: None,
        rehash_all,
        fix,
        quick: false,
    }
}

fn kinds(c: &varsto_core::restic::Completeness) -> Vec<(String, ProblemKind)> {
    c.folders
        .iter()
        .flat_map(|f| f.problems.iter().map(|p| (p.path.clone(), p.kind)))
        .collect()
}

#[test]
fn mirror_setup_completeness_cache_and_fixes() {
    let (lab, mut a, mut b) = two_devices();
    let root = lab.p("mirror");
    let r = b
        .restic_setup(config(&root, &lab.p("pw")), None, false)
        .unwrap();
    assert_eq!(r.attached, ["docs", "photos"]);
    let cfg = b.restic_config().unwrap().clone();
    assert_eq!(cfg.host, "nas");
    assert_eq!(cfg.vault_short, &b.vault_id().to_string()[..8]);
    b.sync(None).unwrap();
    let root = cfg.root.clone();
    assert_eq!(fs::read(root.join("docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(
        fs::read(root.join("photos/p.jpg")).unwrap(),
        b"not really a photo"
    );

    // Complete: everything hashed once, then taken from the cache.
    let c = b.restic_check(&opts(false, false)).unwrap();
    assert!(c.complete, "{}", c.describe());
    let files: u64 = c.folders.iter().map(|f| f.files).sum();
    assert_eq!(files, 3);
    assert_eq!(c.folders.iter().map(|f| f.rehashed).sum::<u64>(), 3);
    assert!(c.folders.iter().all(|f| !f.state_digest.is_empty()));
    let c = b.restic_check(&opts(false, false)).unwrap();
    assert!(c.complete);
    assert_eq!(c.folders.iter().map(|f| f.cached).sum::<u64>(), 3);
    assert_eq!(c.folders.iter().map(|f| f.rehashed).sum::<u64>(), 0);

    // A flipped byte under the same size and time: the cache vouches for
    // it until everything is hashed again; the fix restores it.
    let victim = root.join("docs/sub/b.txt");
    let t = fs::metadata(&victim).unwrap().modified().unwrap();
    let mut bytes = fs::read(&victim).unwrap();
    bytes[1000] ^= 1;
    fs::write(&victim, &bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&victim)
        .unwrap()
        .set_modified(t)
        .unwrap();
    assert!(b.restic_check(&opts(false, false)).unwrap().complete);
    let c = b.restic_check(&opts(false, true)).unwrap();
    assert!(!c.complete);
    assert_eq!(
        kinds(&c),
        [("sub/b.txt".to_string(), ProblemKind::HashMismatch)]
    );
    let c = b.restic_check(&opts(true, true)).unwrap();
    assert!(c.complete, "{}", c.describe());
    let docs = c.folders.iter().find(|f| f.folder == "docs").unwrap();
    assert_eq!(docs.fixed, ["sub/b.txt"]);
    assert_eq!(fs::read(&victim).unwrap(), vec![7u8; 200_000]);
    // The damaged copy is kept beside it, as a file the folder does not know yet.
    assert_eq!(docs.unknown.len(), 1, "{:?}", docs.unknown);

    // A missing file and a placeholder are fetched again.
    fs::remove_file(root.join("docs/a.txt")).unwrap();
    fs::remove_file(root.join("photos/p.jpg")).unwrap();
    fs::write(root.join("photos/p.jpg.varsto-placeholder"), b"{}").unwrap();
    let c = b.restic_check(&opts(false, false)).unwrap();
    let mut k = kinds(&c);
    k.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(
        k,
        [
            ("a.txt".to_string(), ProblemKind::Missing),
            ("p.jpg".to_string(), ProblemKind::Placeholder)
        ]
    );
    // A quick check (status) sees the same without hashing.
    let q = b
        .restic_check(&CheckOptions {
            quick: true,
            ..Default::default()
        })
        .unwrap();
    assert!(!q.complete && q.quick);
    let c = b.restic_check(&opts(true, false)).unwrap();
    assert!(c.complete, "{}", c.describe());
    assert_eq!(fs::read(root.join("docs/a.txt")).unwrap(), b"alpha");
    assert!(!root.join("photos/p.jpg.varsto-placeholder").exists());

    // A file edited on disk after the last sync is the next sync's, never overwritten.
    fs::write(root.join("docs/a.txt"), b"edited here").unwrap();
    let later = SystemTime::now() + Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(root.join("docs/a.txt"))
        .unwrap()
        .set_modified(later)
        .unwrap();
    let c = b.restic_check(&opts(true, false)).unwrap();
    assert_eq!(kinds(&c), [("a.txt".to_string(), ProblemKind::Changed)]);
    assert_eq!(fs::read(root.join("docs/a.txt")).unwrap(), b"edited here");
    b.sync(None).unwrap();
    assert!(b.restic_check(&opts(false, false)).unwrap().complete);

    // A folder added later is attached in the mirror at the next sync, once
    // the mirror device has it (format 2: it asks, the owner approves).
    a.add_folder("music", &lab.p("a-music")).unwrap();
    fs::write(lab.p("a-music/song.ogg"), b"la la").unwrap();
    a.sync(None).unwrap();
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    b.sync(None).unwrap();
    assert_eq!(fs::read(root.join("music/song.ogg")).unwrap(), b"la la");
    let c = b.restic_check(&opts(false, false)).unwrap();
    assert!(c.complete);
    assert_eq!(c.folders.len(), 3);

    // A file nobody can download (its blocks lost) keeps the mirror incomplete.
    let before = listing(&lab.p("storage"));
    fs::write(lab.p("a-docs/lost.bin"), vec![3u8; 50_000]).unwrap();
    a.sync(None).unwrap();
    for f in listing(&lab.p("storage")).difference(&before) {
        if f.starts_with("chunks/") || f.starts_with("packs/") {
            fs::remove_file(lab.p("storage").join(f)).unwrap();
        }
    }
    b.sync(None).unwrap();
    let c = b.restic_check(&opts(true, false)).unwrap();
    assert!(!c.complete);
    assert_eq!(
        kinds(&c),
        [("lost.bin".to_string(), ProblemKind::NotDownloaded)]
    );
}

fn listing(dir: &Path) -> std::collections::BTreeSet<String> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            e.path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn setup_refuses_folders_attached_elsewhere_unless_moved() {
    let (lab, _a, mut b) = two_devices();
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.p("b-docs"), true).unwrap();
    b.sync(None).unwrap();
    let root = lab.p("mirror");
    let err = b
        .restic_setup(config(&root, &lab.p("pw")), None, false)
        .unwrap_err();
    assert!(format!("{err:#}").contains("--move"), "{err:#}");
    assert!(b.restic_config().is_none());
    // A root inside an attached folder is refused even with --move.
    let err = b
        .restic_setup(config(&lab.p("b-docs/inner"), &lab.p("pw")), None, true)
        .unwrap_err();
    assert!(format!("{err:#}").contains("inside folder"), "{err:#}");
    // Only the chosen folder, moved in (selective sync turned off).
    let r = b
        .restic_setup(
            config(&root, &lab.p("pw")),
            Some(&["docs".to_string()]),
            true,
        )
        .unwrap();
    assert_eq!(r.moved.len(), 1, "{r:?}");
    assert_eq!(r.excluded.len(), 1);
    assert_eq!(r.excluded[0].folder, "photos");
    assert!(!lab.p("b-docs").exists());
    b.sync(None).unwrap();
    let root = b.restic_config().unwrap().root.clone();
    assert_eq!(fs::read(root.join("docs/a.txt")).unwrap(), b"alpha");
    assert!(!root.join("photos").exists());
    let c = b.restic_check(&opts(false, false)).unwrap();
    assert!(c.complete, "{}", c.describe());
    assert_eq!(c.excluded.len(), 1);
}

#[test]
fn hold_keeps_varsto_out_of_the_mirror_folders() {
    let (lab, mut a, mut b) = two_devices();
    b.restic_setup(config(&lab.p("mirror"), &lab.p("pw")), None, false)
        .unwrap();
    b.sync(None).unwrap();
    let root = b.restic_config().unwrap().root.clone();
    let held = b.restic_hold("run-1", std::process::id()).unwrap();
    assert_eq!(held, ["docs", "photos"]);
    assert!(
        b.restic_hold("run-2", std::process::id()).is_err(),
        "one hold at a time"
    );
    // A change elsewhere does not reach the held mirror.
    fs::write(lab.p("a-docs/new.txt"), b"new").unwrap();
    a.sync(None).unwrap();
    let r = b.sync(None).unwrap();
    assert!(r.is_empty(), "held folders are not synced");
    assert!(!root.join("docs/new.txt").exists());
    let err = b.pull("docs").unwrap_err();
    assert!(format!("{err:#}").contains("held"), "{err:#}");
    assert!(b.fetch_file("docs", "a.txt").is_err());
    // The run's own check works under its hold.
    let c = b
        .restic_check(&CheckOptions {
            token: Some("run-1".into()),
            fix: true,
            ..Default::default()
        })
        .unwrap();
    assert!(c.complete);
    varsto_core::restic::Hold::release(b.home(), "run-1");
    b.sync(None).unwrap();
    assert_eq!(fs::read(root.join("docs/new.txt")).unwrap(), b"new");
    // A hold whose lease ran out does not stop anything.
    b.restic_hold("run-3", std::process::id()).unwrap();
    let path = varsto_core::restic::Hold::path(b.home());
    let mut h: varsto_core::restic::Hold =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    h.until_utc -= HOLD_LEASE_SECS + 1;
    h.write(b.home()).unwrap();
    b.pull("docs").unwrap();
}
