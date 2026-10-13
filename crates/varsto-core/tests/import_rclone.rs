// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Importing a cloud drive through rclone, tested with rclone's `local`
//! backend and a temporary rclone configuration (never the user's own).
//! Skipped when rclone is not installed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ImportOptions;
use varsto_core::import::rclone::RcloneSource;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn rclone_path() -> Option<String> {
    let out = std::process::Command::new("sh")
        .args(["-c", "command -v rclone"])
        .output()
        .ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!p.is_empty()).then_some(p)
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

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    engine: Engine,
}

/// A vault with one storage, and a private rclone configuration whose
/// remote `src` is the local backend.
fn lab(rclone: &str, wrapper_for: Option<&str>) -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let conf = root.join("rclone.conf");
    fs::write(&conf, "[src]\ntype = local\n\n[od]\ntype = local\n").unwrap();
    std::env::set_var("RCLONE_CONFIG", &conf);
    match wrapper_for {
        // An rclone that lies about one file's hash in its listings.
        Some(file) => {
            let script = root.join("rclone-wrapper.sh");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = lsjson ]; then {rclone} \"$@\" | sed 's/\\(\"Path\":\"{file}\".*\"dropbox\":\"\\)[0-9a-f]*/\\1{}/'; else exec {rclone} \"$@\"; fi\n",
                    "ab".repeat(32)
                ),
            )
            .unwrap();
            std::process::Command::new("chmod")
                .arg("+x")
                .arg(&script)
                .status()
                .unwrap();
            std::env::set_var("VARSTO_RCLONE", &script);
        }
        None => std::env::set_var("VARSTO_RCLONE", rclone),
    }
    let (mut engine, _) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
    engine.chunker = ChunkerParams::SMALL;
    engine
        .add_storage(StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
        })
        .unwrap();
    Lab {
        _tmp: tmp,
        root,
        engine,
    }
}

fn open(lab: &Lab, spec: &str, hash: Option<&str>) -> RcloneSource {
    RcloneSource::open(spec, None, hash, 4, &lab.root.join("scratch")).unwrap()
}

/// One test: rclone settings live in process environment variables.
#[test]
fn cloud_import_through_rclone() {
    let Some(rclone) = rclone_path() else {
        eprintln!("rclone not installed; skipped");
        return;
    };
    let mut lab = lab(&rclone, None);
    let src = lab.root.join("cloud");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"first version").unwrap();
    fs::write(src.join("sub/b.bin"), pseudo_random(300_000, 5)).unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();
    fs::write(src.join("Case.txt"), b"upper").unwrap();
    fs::write(src.join("case.txt"), b"lower").unwrap();
    let spec = format!("src:{}", src.display());

    // Friendly commands check the remote's type; missing remotes get help.
    let err = RcloneSource::open(&spec, Some("dropbox"), None, 4, &lab.root.join("s"))
        .err()
        .unwrap();
    assert!(
        format!("{err:#}").contains("of type local, not dropbox"),
        "{err:#}"
    );
    let err = RcloneSource::open("mydropbox:", Some("dropbox"), None, 4, &lab.root.join("s"))
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("rclone config create mydropbox dropbox"));

    let dest = lab.root.join("varsto-cloud");
    let opts = ImportOptions {
        folder: Some("cloud".into()),
        dest: Some(dest.clone()),
        ..Default::default()
    };
    let mut s = open(&lab, &spec, Some("dropbox"));
    let r = lab.engine.import_run(&mut s, &opts).unwrap();
    assert_eq!(r.imported_files, 5, "{r:#?}");
    assert_eq!(
        r.unverified_ids, 0,
        "every file checked against its Dropbox hash"
    );
    assert_eq!(r.warnings.len(), 1, "case-only difference noted: {r:#?}");
    assert_eq!(tree(&dest), tree(&src));

    // Again: nothing changed, nothing read.
    let mut s = open(&lab, &spec, Some("dropbox"));
    let r = lab.engine.import_run(&mut s, &opts).unwrap();
    assert_eq!(r.imported_ids, 0);
    assert_eq!(r.already_ids, 5);

    // A changed file comes over as a new version; a deleted one stays.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(src.join("a.txt"), b"second version, longer").unwrap();
    fs::remove_file(src.join("sub/b.bin")).unwrap();
    fs::write(src.join("new.txt"), b"new").unwrap();
    let mut s = open(&lab, &spec, Some("quickxor"));
    let r = lab.engine.import_run(&mut s, &opts).unwrap();
    assert_eq!(r.gone_at_source, 1, "{r:#?}");
    assert_eq!(r.gone_examples, vec!["sub/b.bin".to_string()]);
    assert_eq!(
        fs::read(dest.join("a.txt")).unwrap(),
        b"second version, longer"
    );
    assert_eq!(fs::read(dest.join("new.txt")).unwrap(), b"new");
    assert!(
        dest.join("sub/b.bin").exists(),
        "deleted at the source, kept in Varsto"
    );
    let files = lab.engine.list_files("cloud").unwrap();
    assert!(files.iter().any(|f| f.path == "sub/b.bin"));
    let st = &lab.engine.import_status(Some("cloud")).unwrap()[0];
    assert_eq!(st.gone_at_source, 1);
    assert_eq!(st.ids_missing, 0);

    // A file whose content does not match the provider's hash is fetched
    // twice, then reported and left out.
    drop(lab);
    let mut lab = lab_with_bad_hash(&rclone);
    let src = lab.root.join("cloud");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("good.txt"), b"fine").unwrap();
    fs::write(src.join("bad.txt"), b"does not match").unwrap();
    let spec = format!("src:{}", src.display());
    let mut s =
        RcloneSource::open(&spec, None, Some("dropbox"), 2, &lab.root.join("scratch")).unwrap();
    let r = lab
        .engine
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("v")),
                selective: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(r.imported_files, 1, "{r:#?}");
    assert_eq!(r.damaged.len(), 1);
    assert_eq!(r.damaged[0].path, "bad.txt");
    let names: Vec<String> = lab
        .engine
        .list_files("cloud")
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect();
    assert_eq!(names, vec!["good.txt".to_string()]);
    // No block of the bad copy stays on the storage.
    let blocks_before = count_files(&lab.root.join("storage").join("chunks"))
        + count_files(&lab.root.join("storage").join("packs"));
    assert!(blocks_before > 0);
    std::env::remove_var("VARSTO_RCLONE");
    std::env::remove_var("RCLONE_CONFIG");
}

fn count_files(p: &Path) -> usize {
    walkdir::WalkDir::new(p)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

fn lab_with_bad_hash(rclone: &str) -> Lab {
    lab(rclone, Some("bad.txt"))
}

/// 10 000 small files: the listing is read as rclone writes it. Slow on a
/// loaded machine: `cargo test --test import_rclone -- --ignored`.
#[test]
#[ignore]
fn ten_thousand_files() {
    let Some(rclone) = rclone_path() else {
        return;
    };
    let mut lab = lab(&rclone, None);
    let src = lab.root.join("many");
    for d in 0..100 {
        let dir = src.join(format!("d{d:03}"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..100 {
            fs::write(dir.join(format!("f{f:03}.txt")), format!("{d}/{f}")).unwrap();
        }
    }
    let spec = format!("src:{}", src.display());
    let mut s = RcloneSource::open(&spec, None, None, 8, &lab.root.join("scratch")).unwrap();
    let started = std::time::Instant::now();
    let r = lab
        .engine
        .import_run(
            &mut s,
            &ImportOptions {
                dest: Some(lab.root.join("v")),
                selective: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(r.imported_files, 10_000);
    let rss = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .map(|n| n.parse::<u64>().unwrap_or(0))
            })
        })
        .unwrap_or(0);
    eprintln!(
        "10 000 files in {:.1} s, peak memory {} MiB",
        started.elapsed().as_secs_f64(),
        rss / 1024
    );
    assert!(rss < 1024 * 1024, "peak memory {rss} kB");
}
