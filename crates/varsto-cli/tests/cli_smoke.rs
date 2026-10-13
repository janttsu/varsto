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

#[test]
fn disk_list_sorts_and_disk_suggest_names_the_command() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    let mounts = root.join("mounts");
    for d in ["zeta", "alpha"] {
        fs::create_dir_all(mounts.join(d)).unwrap();
    }
    ok(&home, &["init", "--name", "laptop"]);
    ok(
        &home,
        &[
            "storage",
            "add-local",
            "box",
            root.join("box").to_str().unwrap(),
        ],
    );
    ok(
        &home,
        &[
            "storage",
            "add-pool",
            "shelf",
            "--scan-root",
            mounts.to_str().unwrap(),
        ],
    );
    for (dir, label) in [("zeta", "Zeta disk"), ("alpha", "Alpha disk")] {
        ok(
            &home,
            &[
                "disk",
                "add",
                mounts.join(dir).to_str().unwrap(),
                "--pool",
                "shelf",
                "--label",
                label,
            ],
        );
    }
    let labels = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|d| d["label"].as_str().unwrap().to_string())
            .collect()
    };
    let list = ok(&home, &["disk", "list"]);
    assert_eq!(labels(&list), ["Alpha disk", "Zeta disk"]);
    for k in [
        "free_bytes",
        "reserve_bytes",
        "reclaimable_bytes",
        "oldest_check_utc",
        "last_seen_utc",
        "fsck",
    ] {
        assert!(list[0].get(k).is_some(), "disk list --json lacks {k}");
    }
    let list = ok(&home, &["disk", "list", "--sort", "name", "--reverse"]);
    assert_eq!(labels(&list), ["Zeta disk", "Alpha disk"]);
    ok(&home, &["disk", "list", "--sort", "free"]);
    ok(&home, &["disk", "list", "--sort", "seen", "--reverse"]);
    let (success, _, stderr) = varsto(&home, &["disk", "list", "--sort", "colour"]);
    assert!(!success);
    assert!(stderr.contains("unknown sort column colour"), "{stderr}");

    let s = ok(&home, &["disk", "suggest", "--remind", "off"]);
    assert_eq!(s["settings"]["notify_overdue"], false);
    let attached = s["suggestions"]["attached"].as_array().unwrap();
    assert_eq!(attached.len(), 2);
    assert!(attached
        .iter()
        .any(|d| d["command"] == "varsto disk insert \"Zeta disk\""));

    // Text: the table and the suggestion.
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .args([
            "--home",
            home.to_str().unwrap(),
            "disk",
            "list",
            "--sort",
            "name",
        ])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("NAME") && text.contains("FREE / TOTAL") && text.contains("LAST SEEN"),
        "{text}"
    );
    assert!(text.find("Alpha disk").unwrap() < text.find("Zeta disk").unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .args(["--home", home.to_str().unwrap(), "disk", "suggest"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("No disk needs docking now."), "{text}");
    assert!(text.contains("Attached now"), "{text}");
}
