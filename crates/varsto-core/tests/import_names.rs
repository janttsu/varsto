// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Imports keep file names as they are (`12:30.jpg` from a git-annex
//! repository, a directory or a cloud drive), and rclone downloads are
//! staged on the destination folder's filesystem with a free-space check.
//! The git-annex and rclone parts are skipped when those are not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ImportOptions;
use varsto_core::import::annex::AnnexSource;
use varsto_core::import::dir::DirSource;
use varsto_core::import::rclone::RcloneSource;
use varsto_core::pool::{set_fake_space, DiskSpace};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

/// Names a Linux disk takes that Windows does not.
const NAMES: &[&str] = &["12:30.jpg", "what?.txt", "CON.txt", "dir:1/star*.bin"];

fn engine(root: &Path) -> Engine {
    let (mut e, _) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    })
    .unwrap();
    e
}

fn write_names(dir: &Path) {
    for (i, n) in NAMES.iter().enumerate() {
        let p = dir.join(n);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, format!("{i}: {n} {}", "x".repeat(2000 * i))).unwrap();
    }
}

fn assert_names_kept(dest: &Path, e: &Engine, folder: &str) {
    for (i, n) in NAMES.iter().enumerate() {
        let got = fs::read_to_string(dest.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(got.starts_with(&format!("{i}: {n}")), "{n}");
    }
    let mut listed: Vec<String> = e
        .list_files(folder)
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect();
    listed.sort();
    let mut want: Vec<String> = NAMES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(listed, want);
}

fn opts(folder: &str, dest: PathBuf) -> ImportOptions {
    ImportOptions {
        folder: Some(folder.into()),
        dest: Some(dest),
        selective: false,
        ..Default::default()
    }
}

#[test]
fn directory_import_keeps_names() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = root.join("old-drive");
    write_names(&src);
    let mut e = engine(root);
    let mut s = DirSource::open(&src).unwrap();
    let r = e
        .import_run(&mut s, &opts("old", root.join("old")))
        .unwrap();
    assert_eq!(r.imported_files, NAMES.len() as u64, "{r:#?}");
    assert_eq!(r.skipped_count, 0, "{r:#?}");
    assert_eq!(r.mapped_on_windows, NAMES.len() as u64);
    assert_names_kept(&root.join("old"), &e, "old");
    // No staging directory for a source that reads in place.
    assert!(!root.join("old/.varsto-import-staging").exists());
    assert_eq!(e.push("old").unwrap().files_changed, 0);
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
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_annex_import_keeps_names() {
    if !Command::new("git-annex")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("git-annex not installed; skipped");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let repo = root.join("annex");
    fs::create_dir_all(&repo).unwrap();
    run(&repo, &["git", "init", "-q", "-b", "main"]);
    run(&repo, &["git", "annex", "init", "-q", "disk"]);
    write_names(&repo);
    // CON.txt stays in git, the others are annexed.
    run(
        &repo,
        &[
            "git",
            "annex",
            "add",
            "-q",
            "12:30.jpg",
            "what?.txt",
            "dir:1",
        ],
    );
    run(
        &repo,
        &[
            "git",
            "-c",
            "annex.largefiles=nothing",
            "annex",
            "add",
            "-q",
            "CON.txt",
        ],
    );
    run(&repo, &["git", "commit", "-q", "-m", "names"]);
    let mut e = engine(&root);
    let mut s = AnnexSource::open(&repo, "HEAD").unwrap();
    let r = e.import_run(&mut s, &opts("annexed", root.join("annexed")));
    // git-annex makes its objects read-only; let the directory go.
    let _ = Command::new("chmod")
        .args(["-R", "u+w"])
        .arg(&root)
        .status();
    let r = r.unwrap();
    assert_eq!(r.imported_files, NAMES.len() as u64, "{r:#?}");
    assert_eq!(r.skipped_count, 0, "{r:#?}");
    assert_eq!(r.mapped_on_windows, NAMES.len() as u64);
    assert_names_kept(&root.join("annexed"), &e, "annexed");
}

fn rclone_path() -> Option<String> {
    let out = Command::new("sh")
        .args(["-c", "command -v rclone"])
        .output()
        .ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!p.is_empty()).then_some(p)
}

/// One test: rclone settings live in process environment variables.
#[test]
fn rclone_import_keeps_names_and_stages_on_the_folder_disk() {
    let Some(rclone) = rclone_path() else {
        eprintln!("rclone not installed; skipped");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let conf = root.join("rclone.conf");
    fs::write(&conf, "[src]\ntype = local\n").unwrap();
    // An rclone that writes down where it copies to.
    let log = root.join("rclone.log");
    let script = root.join("rclone-logging.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nif [ \"$1\" = copy ]; then for a in \"$@\"; do last=\"$a\"; done; echo \"$last\" >> {}; fi\nexec {rclone} \"$@\"\n",
            log.display()
        ),
    )
    .unwrap();
    Command::new("chmod")
        .arg("+x")
        .arg(&script)
        .status()
        .unwrap();
    std::env::set_var("RCLONE_CONFIG", &conf);
    std::env::set_var("VARSTO_RCLONE", &script);
    let mut e = engine(&root);
    let open = |dir: &Path| {
        RcloneSource::open(
            &format!("src:{}", dir.display()),
            None,
            Some("none"),
            2,
            &root.join("home/state/import-downloads"),
        )
        .unwrap()
    };

    // Default: staged in the destination folder, removed afterwards.
    let cloud = root.join("cloud");
    write_names(&cloud);
    let dest = root.join("from-cloud");
    let r = e
        .import_run(&mut open(&cloud), &opts("cloud", dest.clone()))
        .unwrap();
    assert_eq!(r.imported_files, NAMES.len() as u64, "{r:#?}");
    assert_eq!(r.skipped_count, 0, "{r:#?}");
    assert_eq!(r.mapped_on_windows, NAMES.len() as u64);
    assert_names_kept(&dest, &e, "cloud");
    let targets = fs::read_to_string(&log).unwrap();
    let staged = dest.join(".varsto-import-staging");
    assert!(
        targets.lines().all(|l| Path::new(l).starts_with(&staged)),
        "{targets}"
    );
    assert!(!targets.is_empty());
    assert!(!staged.exists(), "the staging directory is removed");
    assert!(!root.join("home/state/import-downloads").exists());

    // --staging: there instead; a directory the import made goes again.
    fs::remove_file(&log).unwrap();
    let cloud2 = root.join("cloud2");
    write_names(&cloud2);
    let mut o = opts("cloud2", root.join("from-cloud2"));
    o.staging = Some(root.join("elsewhere/stage"));
    let r = e.import_run(&mut open(&cloud2), &o).unwrap();
    assert_eq!(r.imported_files, NAMES.len() as u64, "{r:#?}");
    let targets = fs::read_to_string(&log).unwrap();
    assert!(
        targets
            .lines()
            .all(|l| Path::new(l).starts_with(root.join("elsewhere/stage"))),
        "{targets}"
    );
    assert!(!root.join("elsewhere/stage").exists());
    assert!(root.join("elsewhere").exists());

    // Not enough room for a batch and 1 GiB: stopped with a clear message,
    // nothing left behind; with room the same import carries on.
    let cloud3 = root.join("cloud3");
    write_names(&cloud3);
    let dest3 = root.join("from-cloud3");
    fs::create_dir_all(&dest3).unwrap();
    set_fake_space(
        &dest3,
        Some(DiskSpace {
            free: 500 << 20,
            total: 1 << 40,
        }),
    );
    let err = e
        .import_run(&mut open(&cloud3), &opts("cloud3", dest3.clone()))
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("not enough free space"), "{msg}");
    assert!(msg.contains("--staging"), "{msg}");
    assert!(!dest3.join(".varsto-import-staging").exists());
    set_fake_space(&dest3, None);
    let r = e
        .import_run(&mut open(&cloud3), &opts("cloud3", dest3.clone()))
        .unwrap();
    assert_eq!(r.imported_files, NAMES.len() as u64, "{r:#?}");
    assert_names_kept(&dest3, &e, "cloud3");

    std::env::remove_var("VARSTO_RCLONE");
    std::env::remove_var("RCLONE_CONFIG");
}
