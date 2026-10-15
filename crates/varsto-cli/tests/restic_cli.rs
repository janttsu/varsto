// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto restic` with the real restic: device B keeps the mirror of the
//! vault device A fills, backs it up into a local repository, and what
//! `restic restore` gives back is A's folders byte for byte; a run with a
//! file nobody can download stops before restic; forget keeps the policy.
//! Skipped when restic is not installed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn varsto(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .output()
        .expect("run varsto")
}

/// Like `ok`, with the vault key in `VARSTO_VAULT_KEY` (`join` takes it from
/// the environment, a file or standard input, never from the command line).
fn ok_with_key(home: &Path, key: &str, args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_VAULT_KEY", key)
        .output()
        .expect("run varsto");
    assert!(
        out.status.success(),
        "varsto {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap_or_default()
}

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = varsto(home, args);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "varsto {:?} failed: {}\n{stdout}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

fn restic(repo: &Path, pw: &Path, args: &[&str]) -> Output {
    Command::new("restic")
        .args(args)
        .env("RESTIC_REPOSITORY", repo)
        .env("RESTIC_PASSWORD_FILE", pw)
        .env_remove("RESTIC_PASSWORD")
        .env_remove("RESTIC_PASSWORD_COMMAND")
        .output()
        .expect("run restic")
}

fn snapshot_count(repo: &Path, pw: &Path) -> usize {
    let out = restic(repo, pw, &["snapshots", "--json"]);
    assert!(out.status.success());
    serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
        .unwrap()
        .len()
}

/// Relative path -> bytes of every file under `dir`.
/// The files of a directory; Varsto's own (`.varsto*`, such as the folder
/// marker) are left out, as restic leaves them out.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| !e.file_name().to_string_lossy().starts_with(".varsto"))
        .map(|e| {
            (
                e.path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

fn storage_files(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

#[test]
fn restic_backup_of_the_mirror_restores_byte_for_byte() {
    if Command::new("restic").arg("version").output().is_err() {
        eprintln!("restic is not installed; skipped");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b) = (root.join("a"), root.join("b"));
    let storage = root.join("storage");
    let (docs, photos) = (root.join("docs"), root.join("photos"));
    let init = ok(&a, &["init", "--name", "laptop"]);
    let key = init["vault_key"].as_str().unwrap().to_string();
    ok(
        &a,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    ok(&a, &["folder", "add", "photos", photos.to_str().unwrap()]);
    fs::create_dir_all(docs.join("deep/er")).unwrap();
    fs::write(docs.join("a.txt"), b"alpha").unwrap();
    fs::write(docs.join("empty.txt"), b"").unwrap();
    fs::write(docs.join("Ääkköset ja välilyönnit.txt"), b"unicode").unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    fs::write(docs.join("deep/er/big.bin"), &big).unwrap();
    fs::write(photos.join("p.jpg"), b"not really a photo").unwrap();
    ok(&a, &["sync"]);
    ok_with_key(
        &b,
        &key,
        &[
            "join",
            "--name",
            "nas",
            "--storage-path",
            storage.to_str().unwrap(),
        ],
    );
    // Format 2: the NAS asks for both folders and the laptop approves.
    ok(&b, &["sync"]);
    ok(&b, &["folder", "request", "docs"]);
    ok(&b, &["folder", "request", "photos"]);
    ok(&a, &["sync"]);
    ok(&a, &["folder", "approve", "docs", "nas"]);
    ok(&a, &["folder", "approve", "photos", "nas"]);

    let mirror = root.join("mirror");
    let repo = root.join("repo");
    let pw = root.join("restic-pw");
    fs::write(&pw, b"restic test password\n").unwrap();
    // No repository yet: refused without --init, nothing attached.
    let out = varsto(
        &b,
        &[
            "restic",
            "setup",
            "--root",
            mirror.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--init"));
    let setup = ok(
        &b,
        &[
            "restic",
            "setup",
            "--root",
            mirror.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
            "--init",
            "--keep-daily",
            "1",
            "--keep-weekly",
            "0",
            "--keep-monthly",
            "0",
            "--manual",
        ],
    );
    assert_eq!(setup["repository_created"], true);
    assert_eq!(
        setup["setup"]["attached"],
        serde_json::json!(["docs", "photos"])
    );
    let cfg = &setup["config"];
    let vault_short = cfg["vault_short"].as_str().unwrap().to_string();
    let mirror = PathBuf::from(cfg["root"].as_str().unwrap());
    // No secret in the configuration: only where the password is.
    let config_text = fs::read_to_string(b.join("config.json")).unwrap();
    assert!(!config_text.contains("restic test password"));

    // A temporary file of Varsto's in the mirror is not backed up.
    fs::create_dir_all(mirror.join("docs")).unwrap();
    fs::write(mirror.join("docs/.varsto-tmp-99"), b"partial").unwrap();
    let run = ok(&b, &["restic", "run"]);
    assert_eq!(run["result"], "ok", "{run}");
    let snap = run["record"]["snapshot_id"].as_str().unwrap().to_string();
    assert!(run["completeness"]["complete"].as_bool().unwrap());
    assert_eq!(snapshot_count(&repo, &pw), 1);
    // The first run checks the repository too (it was never checked).
    assert_eq!(run["repository_check"]["ok"], true, "{run}");

    // restic alone gives back A's folders byte for byte.
    let target = root.join("restored");
    let out = restic(
        &repo,
        &pw,
        &[
            "restore",
            &snap,
            "--tag",
            &format!("varsto,vault:{vault_short}"),
            "--target",
            target.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let back = target.join(mirror.strip_prefix("/").unwrap());
    assert_eq!(tree(&back.join("docs")), tree(&docs));
    assert_eq!(tree(&back.join("photos")), tree(&photos));
    let desc = fs::read_to_string(back.join("VARSTO-SNAPSHOT.txt")).unwrap();
    assert!(desc.contains(&format!("vault: {vault_short}")), "{desc}");
    assert!(desc.contains("device: nas"));
    assert!(desc.contains("folder: docs") && desc.contains("folder: photos"));

    // A file whose blocks are lost: the mirror cannot be complete, restic
    // does not run, no snapshot is added.
    let before = storage_files(&storage);
    fs::write(docs.join("lost.bin"), vec![9u8; 40_000]).unwrap();
    ok(&a, &["sync"]);
    for f in storage_files(&storage) {
        let rel = f
            .strip_prefix(&storage)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if !before.contains(&f) && (rel.starts_with("chunks/") || rel.starts_with("packs/")) {
            fs::remove_file(&f).unwrap();
        }
    }
    let out = varsto(&b, &["restic", "run"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["result"], "incomplete");
    assert_eq!(
        r["completeness"]["folders"][0]["problems"][0]["path"],
        "lost.bin"
    );
    assert_eq!(snapshot_count(&repo, &pw), 1);
    let st = ok(&b, &["restic", "status"]);
    assert_eq!(st["state"]["last_run"]["result"], "incomplete");
    assert_eq!(
        st["state"]["last_success"]["snapshot_id"].as_str(),
        Some(snap.as_str())
    );
    assert!(!st["held_now"].as_bool().unwrap(), "the hold was released");

    // The lost file deleted: complete again; forget keeps one daily snapshot.
    fs::remove_file(docs.join("lost.bin")).unwrap();
    fs::write(docs.join("a.txt"), b"alpha, edited").unwrap();
    ok(&a, &["sync"]);
    let run = ok(&b, &["restic", "run"]);
    assert_eq!(run["result"], "ok", "{run}");
    assert_eq!(run["record"]["forget"], serde_json::json!([1, 1]));
    assert_eq!(snapshot_count(&repo, &pw), 1);
    let run = ok(&b, &["restic", "run", "--no-forget", "--no-check"]);
    assert_eq!(run["result"], "ok");
    assert!(run["record"]["forget"].is_null());
    assert!(run["repository_check"].is_null());
    assert_eq!(snapshot_count(&repo, &pw), 2);
    // The cache spared re-reading what did not change.
    let docs_check = &run["completeness"]["folders"][0];
    assert_eq!(docs_check["folder"], "docs");
    assert_eq!(docs_check["rehashed"], 0, "{docs_check}");

    let st = ok(&b, &["restic", "status"]);
    assert_eq!(st["complete_now"], true);
    assert_eq!(st["state"]["last_run"]["result"], "ok");
    let hint = ok(&b, &["restic", "restore-hint"]);
    assert!(hint["hint"]
        .as_str()
        .unwrap()
        .contains(repo.to_str().unwrap()));
    let snaps = ok(&b, &["restic", "snapshots"]);
    assert_eq!(snaps.as_array().map(|a| a.len()), Some(2), "{snaps}");
    let kit = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .args(["--home", b.to_str().unwrap(), "recovery", "kit"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    let kit = String::from_utf8_lossy(&kit.stdout);
    assert!(kit.contains(repo.to_str().unwrap()), "{kit}");
    assert!(!kit.contains("restic test password"));
}
