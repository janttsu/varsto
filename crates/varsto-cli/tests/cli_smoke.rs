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
    let (success, stdout, stderr) = varsto(home, args);
    assert!(success, "varsto {:?} failed: {stderr}", args);
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

/// `varsto mailbox`: status, settings and a run without a service.
#[test]
fn mailbox_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("a");
    ok(&home, &["init", "--name", "laptop"]);
    let s = ok(&home, &["mailbox"]);
    assert_eq!(s["enabled"], true);
    assert_eq!(s["keep_free"], serde_json::json!(["15%", "50000000000"]));
    let s = ok(
        &home,
        &[
            "mailbox",
            "set",
            "--keep-free",
            "20%",
            "--keep-free",
            "100GB",
        ],
    );
    assert_eq!(s["keep_free"], serde_json::json!(["20%", "100000000000"]));
    let s = ok(&home, &["mailbox", "set", "--off"]);
    assert_eq!(s["enabled"], false);
    let (fine, _, err) = varsto(&home, &["mailbox", "set", "--keep-free", "lots"]);
    assert!(!fine && err.contains("lots"), "{err}");
    let s = ok(&home, &["mailbox", "set", "--on", "--default-keep-free"]);
    assert_eq!(s["enabled"], true);
    assert_eq!(s["keep_free"], serde_json::json!(["15%", "50000000000"]));
    let r = ok(&home, &["mailbox", "run"]);
    assert_eq!(r["staged"], 0);
}

#[test]
#[ignore = "f3-switch: port in part B (membership)"]
// Waits for the format-3 ledger_entries listing.
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

    ok_with_key(
        &b,
        &vault_key,
        &["join", "--name", "phone", "--storage-path", storage_s],
    );
    // The phone asks for the folder, the laptop approves it.
    ok(&b, &["folder", "request", "docs"]);
    ok(&a, &["folder", "approve", "docs", "phone", "--yes"]);
    // A sync reads the grant, then the folder attaches.
    ok(&b, &["sync"]);
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

    // Who changed what: the file's history, from the signed manifests.
    let changes = ok(&b, &["changes", "docs", "note.txt"]);
    assert_eq!(changes["file"], true);
    assert_eq!(changes["changes"][0]["action"], "created");
    assert_eq!(changes["changes"][0]["device_name"], "laptop");
    assert_eq!(changes["changes"][0]["verified"], true);
    let none = ok(&b, &["changes", "docs", "--device", "phone"]);
    assert_eq!(none["changes"].as_array().unwrap().len(), 0);

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

#[test]
fn folder_ignore_rules_and_metadata_settings_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let a = root.join("a");
    let docs = root.join("docs");
    ok(&a, &["init", "--name", "laptop"]);
    ok(
        &a,
        &[
            "storage",
            "add-local",
            "box",
            root.join("storage").to_str().unwrap(),
        ],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);

    let info = ok(
        &a,
        &[
            "folder", "ignore", "docs", "--add", "*.tmp", "--add", "build/",
        ],
    );
    assert_eq!(info["synced"], "*.tmp\nbuild/\n");
    assert_eq!(
        fs::read_to_string(docs.join(".varstoignore")).unwrap(),
        "*.tmp\nbuild/\n"
    );
    let info = ok(
        &a,
        &["folder", "ignore", "docs", "--local", "--add", "*.iso"],
    );
    assert_eq!(info["local"], serde_json::json!(["*.iso"]));
    assert!(info["suggested"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == ".DS_Store"));

    let v = ok(&a, &["folder", "check-ignore", "docs", "sub/x.tmp"]);
    assert_eq!(v["ignored"], true);
    assert_eq!(v["pattern"], "*.tmp");
    assert_eq!(v["source"], ".varstoignore");
    let v = ok(&a, &["folder", "check-ignore", "docs", "build/deep/file.c"]);
    assert_eq!(v["matched_path"], "build");
    let v = ok(&a, &["folder", "check-ignore", "docs", "disk.iso"]);
    assert_eq!(v["source"], "local");
    let v = ok(&a, &["folder", "check-ignore", "docs", "notes.txt"]);
    assert_eq!(v["ignored"], false);

    let info = ok(&a, &["folder", "ignore", "docs", "--remove", "build/"]);
    assert_eq!(info["synced"], "*.tmp\n");

    // Ignored files stay out of the push; the rules file itself is synced.
    fs::write(docs.join("keep.txt"), b"k").unwrap();
    fs::write(docs.join("scratch.tmp"), b"s").unwrap();
    let push = ok(&a, &["push", "docs"]);
    assert_eq!(push["files_changed"], 2);

    let s = ok(&a, &["folder", "set", "docs"]);
    assert_eq!(
        s,
        serde_json::json!({"permissions": true, "symlinks": true, "xattrs": true, "ownership": false})
    );
    let s = ok(
        &a,
        &[
            "folder",
            "set",
            "docs",
            "--ownership",
            "on",
            "--xattrs",
            "off",
        ],
    );
    assert_eq!(s["ownership"], true);
    assert_eq!(s["xattrs"], false);
    assert_eq!(ok(&a, &["folder", "set", "docs"])["ownership"], true);
    let (success, _, stderr) = varsto(&a, &["folder", "set", "docs", "--permissions", "maybe"]);
    assert!(!success, "{stderr}");
}

#[test]
fn staged_move_jobs_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    let mounts = root.join("mounts");
    let docs = root.join("docs");
    fs::create_dir_all(mounts.join("d1")).unwrap();
    fs::create_dir_all(docs.join("sub")).unwrap();
    fs::write(docs.join("sub/a.txt"), vec![7u8; 5000]).unwrap();
    fs::write(docs.join("b.txt"), vec![9u8; 5000]).unwrap();
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
    ok(&home, &["folder", "add", "docs", docs.to_str().unwrap()]);
    ok(&home, &["folder", "placement", "docs", "--storage", "box"]);
    ok(&home, &["push", "docs"]);

    // No disk yet: the job is recorded and waits.
    let run = ok(
        &home,
        &["move", "docs", "--from", "box", "--to", "shelf", "--yes"],
    );
    assert_eq!(run["ran"], true);
    let id = run["job"]["id"].as_str().unwrap().to_string();
    assert_eq!(run["job"]["state"], "open");
    assert_eq!(run["job"]["waiting"]["kind"], "disk");
    assert!(run["job"]["bytes_remaining"].as_u64().unwrap() > 0);
    assert!(root
        .join("home/state/moves")
        .join(format!("{id}.json"))
        .is_file());
    let status = ok(&home, &["move", "status"]);
    assert_eq!(status.as_array().unwrap().len(), 1);
    let s = ok(&home, &["disk", "suggest"]);
    assert_eq!(
        s["suggestions"]["new_disk_needed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Paused, then resumed with a disk attached: moves only the path asked for.
    ok(&home, &["move", "pause", &id]);
    assert_eq!(ok(&home, &["move", "status", &id])[0]["state"], "paused");
    let (success, _, stderr) = varsto(&home, &["move", "resume", "mv-nope"]);
    assert!(!success && stderr.contains("no move job"), "{stderr}");
    ok(&home, &["move", "cancel", &id]);
    assert_eq!(ok(&home, &["move", "status"]).as_array().unwrap().len(), 0);

    ok(
        &home,
        &[
            "disk",
            "add",
            mounts.join("d1").to_str().unwrap(),
            "--pool",
            "shelf",
            "--label",
            "data-01",
        ],
    );
    let run = ok(
        &home,
        &[
            "move",
            "docs",
            "--from",
            "box",
            "--to",
            "shelf",
            "--path",
            "sub",
            "--keep-source",
            "--yes",
        ],
    );
    assert_eq!(run["job"]["state"], "done", "{run}");
    assert_eq!(run["job"]["paths"][0], "sub");
    assert_eq!(run["job"]["keep_source"], true);
    assert_eq!(run["job"]["disks_used"][0], "data-01");
}

#[test]
fn secrets_stay_off_the_command_line() {
    use std::io::Write;
    use std::process::Stdio;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b) = (root.join("a"), root.join("b"));
    let storage = root.join("storage");
    let storage_s = storage.to_str().unwrap();

    // A short passphrase is refused and leaves nothing behind.
    let short = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&a)
        .args(["init", "--name", "laptop"])
        .env("VARSTO_PASSPHRASE", "too short")
        .output()
        .unwrap();
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).contains("at least 12 characters"));
    assert!(!a.join("keys.enc").exists());

    let init = ok(&a, &["init", "--name", "laptop"]);
    let key = init["vault_key"].as_str().unwrap().to_string();
    ok(&a, &["storage", "add-local", "box", storage_s]);

    // The option that carried the key is gone.
    let (okk, _, err) = varsto(
        &b,
        &[
            "join",
            "--name",
            "phone",
            "--vault-key",
            &key,
            "--storage-path",
            storage_s,
        ],
    );
    assert!(!okk);
    assert!(err.contains("--vault-key"), "{err}");
    let (okk, _, _) = varsto(
        &b,
        &[
            "join",
            "--name",
            "phone",
            "--words",
            "a b c",
            "--storage-path",
            storage_s,
        ],
    );
    assert!(!okk);

    // Without a terminal, `join` reads the key from standard input.
    let mut child = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&b)
        .arg("--json")
        .args(["join", "--name", "phone", "--storage-path", storage_s])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env_remove("VARSTO_VAULT_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{key}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(b.join("keys.enc").exists());

    // A wrong key on standard input is an error, not a hang.
    let c = root.join("c");
    let mut child = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&c)
        .args(["join", "--name", "tablet", "--storage-path", storage_s])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env_remove("VARSTO_VAULT_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"not a key\n")
        .unwrap();
    assert!(!child.wait_with_output().unwrap().status.success());
}
