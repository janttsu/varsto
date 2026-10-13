// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto trash` through the binary: list, status, set, restore, purge.

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
fn trash_commands() {
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
    fs::create_dir_all(docs.join("sub")).unwrap();
    fs::write(docs.join("sub/a.txt"), b"first file").unwrap();
    fs::write(docs.join("b.txt"), b"second file").unwrap();
    ok(&home, &["push", "docs"]);
    fs::remove_file(docs.join("sub/a.txt")).unwrap();
    fs::remove_file(docs.join("b.txt")).unwrap();
    ok(&home, &["push", "docs"]);

    let list = ok(&home, &["trash", "list"]);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["deleted_by"], "laptop");
    let st = ok(&home, &["trash", "status"]);
    assert_eq!(st["days"], 30);
    assert_eq!(st["entries"], 2);

    let st = ok(&home, &["trash", "set", "--days", "10"]);
    assert_eq!(st["days"], 10);
    let st = ok(&home, &["trash", "set", "--folder", "docs", "--days", "45"]);
    assert_eq!(st["folder_days"]["docs"], 45);
    let (success, _, _) = run(&home, &["trash", "set", "--storage", "nowhere"]);
    assert!(!success);

    let r = ok(&home, &["trash", "restore", "docs", "sub"]);
    assert_eq!(r["restored"][0]["to"], "sub/a.txt");
    assert_eq!(fs::read(docs.join("sub/a.txt")).unwrap(), b"first file");
    let list = ok(&home, &["trash", "list", "--folder", "docs"]);
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Without --yes and without a terminal the answer is no.
    let (success, _, _) = run(&home, &["trash", "purge", "--all"]);
    assert!(!success);
    let r = ok(&home, &["trash", "purge", "--all", "--yes"]);
    assert_eq!(r["entries"], 1);
    let list = ok(&home, &["trash", "list"]);
    assert!(list.as_array().unwrap().is_empty());
    ok(&home, &["trash", "upkeep"]);
}
