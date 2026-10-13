// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto history` through the binary: list, status, set, restore.

use std::fs;
use std::path::Path;
use std::process::Command;

fn run(home: &Path, args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .expect("run varsto");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout));
    (
        out.status.success(),
        v,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let (success, v, err) = run(home, args);
    assert!(success, "varsto {args:?} failed: {err}");
    v
}

#[test]
fn history_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("a");
    let docs = root.join("docs");
    ok(&home, &["init", "--name", "laptop"]);
    ok(
        &home,
        &[
            "storage",
            "add-local",
            "box",
            root.join("storage").to_str().unwrap(),
        ],
    );
    ok(&home, &["folder", "add", "docs", docs.to_str().unwrap()]);
    fs::write(docs.join("a.txt"), b"first words").unwrap();
    ok(&home, &["push", "docs"]);
    fs::write(docs.join("a.txt"), b"second words").unwrap();
    ok(&home, &["push", "docs"]);

    let list = ok(&home, &["history", "docs", "a.txt"]);
    let versions = list["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["replaced_by"], "laptop");
    assert_eq!(list["days"], 90);
    let id = versions[0]["id"].as_str().unwrap()[..8].to_string();

    let st = ok(&home, &["history", "status"]);
    assert_eq!(st["days"], 90);
    assert_eq!(st["versions"], 1);
    let st = ok(&home, &["history", "set", "--days", "30"]);
    assert_eq!(st["days"], 30);
    let st = ok(
        &home,
        &["history", "set", "--folder", "docs", "--days", "7"],
    );
    assert_eq!(st["folder_days"]["docs"], 7);
    let (success, _, _) = run(&home, &["history", "set"]);
    assert!(!success);
    let (success, _, _) = run(&home, &["history", "set", "--days", "5", "--off"]);
    assert!(!success);

    // As a copy, then over the current file (which becomes a version).
    let r = ok(
        &home,
        &[
            "history", "restore", "docs", "a.txt", &id, "--as", "old.txt",
        ],
    );
    assert_eq!(r["to"], "old.txt");
    assert_eq!(fs::read(docs.join("old.txt")).unwrap(), b"first words");
    let (success, _, _) = run(
        &home,
        &[
            "history", "restore", "docs", "a.txt", &id, "--as", "old.txt",
        ],
    );
    assert!(!success, "an existing name is never overwritten");
    let r = ok(&home, &["history", "restore", "docs", "a.txt", &id]);
    assert_eq!(r["replaced_current"], true);
    assert_eq!(fs::read(docs.join("a.txt")).unwrap(), b"first words");
    let list = ok(&home, &["history", "docs", "a.txt"]);
    assert_eq!(list["versions"].as_array().unwrap().len(), 2);

    // Off for the folder: no new versions.
    let st = ok(&home, &["history", "set", "--folder", "docs", "--off"]);
    assert_eq!(st["folder_days"]["docs"], 0);
    fs::write(docs.join("a.txt"), b"third words").unwrap();
    ok(&home, &["push", "docs"]);
    let list = ok(&home, &["history", "docs", "a.txt"]);
    assert!(list["days"].is_null());
    assert_eq!(list["versions"].as_array().unwrap().len(), 2);
    // The human output names the versions.
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&home)
        .args(["history", "docs", "a.txt"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&id) || text.contains("by laptop"), "{text}");
    assert!(text.contains("history of this folder is off"), "{text}");
}
