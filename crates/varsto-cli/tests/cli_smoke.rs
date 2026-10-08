// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! End-to-end smoke test of the `varsto` binary: two device directories, one
//! shared local storage, JSON output on every step.

use std::fs;
use std::path::Path;
use std::process::Command;

fn varsto(home: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .expect("run varsto");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let (success, stdout, stderr) = varsto(home, args);
    assert!(success, "varsto {:?} failed: {stderr}", args);
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

#[test]
fn two_devices_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b) = (root.join("a"), root.join("b"));
    let storage = root.join("storage");
    let (a_docs, b_docs) = (root.join("a-docs"), root.join("b-docs"));
    let storage_s = storage.to_str().unwrap();

    let init = ok(&a, &["init", "--name", "laptop"]);
    let vault_key = init["vault_key"].as_str().unwrap().to_string();
    assert_eq!(vault_key.len(), 64);
    ok(&a, &["storage", "add-local", "box", storage_s]);
    ok(&a, &["folder", "add", "docs", a_docs.to_str().unwrap()]);
    fs::write(a_docs.join("note.txt"), b"first note").unwrap();
    let push = ok(&a, &["push", "docs"]);
    assert_eq!(push["files_changed"], 1);

    ok(
        &b,
        &[
            "join",
            "--name",
            "phone",
            "--vault-key",
            &vault_key,
            "--storage-path",
            storage_s,
        ],
    );
    ok(&b, &["folder", "attach", "docs", b_docs.to_str().unwrap()]);
    let sync = ok(&b, &["sync"]);
    assert_eq!(sync[0][0]["files_updated"], 1);
    assert_eq!(fs::read(b_docs.join("note.txt")).unwrap(), b"first note");

    let status = ok(&b, &["status"]);
    assert_eq!(status["devices"].as_object().unwrap().len(), 2);
    assert_eq!(status["folders"][0]["chunks_without_storage_copy"], 0);
    let fsck = ok(&b, &["fsck", "--verify"]);
    assert_eq!(fsck["chunks_missing"].as_array().unwrap().len(), 0);
    let ledger = ok(&b, &["ledger"]);
    assert!(ledger.as_array().unwrap().len() >= 3);

    // Wrong passphrase is refused.
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .args(["--home", a.to_str().unwrap(), "status"])
        .env("VARSTO_PASSPHRASE", "wrong")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unlock failed"));
}
