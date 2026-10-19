// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto ledger status` and `varsto ledger rebuild` through the binary,
//! and what the other commands say when the local ledger was lost.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(home: &Path, args: &[&str]) -> Output {
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

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = run(home, args);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "varsto {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

fn own_head(st: &serde_json::Value) -> u64 {
    st["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["this_device"] == true)
        .unwrap()["head"]
        .as_u64()
        .unwrap()
}

#[test]
fn lost_local_ledger_is_reported_and_rebuilt() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let a = root.join("a");
    let storage = root.join("storage");
    let docs = root.join("docs");
    ok(&a, &["init", "--name", "laptop"]);
    ok(
        &a,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    fs::write(docs.join("one.txt"), b"one").unwrap();
    ok(&a, &["sync"]);

    let st = ok(&a, &["ledger", "status"]);
    assert_eq!(st["health"]["state"], "ok");
    let head = own_head(&st);
    let held: Vec<&str> = st["devices"][0]["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["place"].as_str().unwrap())
        .collect();
    assert_eq!(held, vec!["this device", "box"]);

    fs::remove_dir_all(a.join("ledger")).unwrap();
    // Reading goes on with a warning; status carries the state.
    let out = run(&a, &["status"]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("rebuild recommended: run `varsto ledger rebuild`"),
        "{stderr}"
    );
    let s: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(s["ledger_health"]["state"], "rebuild_needed");
    // `ledger status` says so and exits with 1.
    assert_eq!(run(&a, &["ledger", "status"]).status.code(), Some(1));
    // Signing stops with the advice.
    fs::write(docs.join("two.txt"), b"two").unwrap();
    let out = run(&a, &["sync"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("varsto ledger rebuild"), "{stderr}");

    let r = ok(&a, &["ledger", "rebuild"]);
    assert_eq!(r["own_head_after"].as_u64(), Some(head));
    assert_eq!(r["health"]["state"], "ok");
    ok(&a, &["sync"]);
    let st = ok(&a, &["ledger", "status"]);
    assert_eq!(own_head(&st), head + 1);
    let list = ok(&a, &["ledger"]);
    assert_eq!(list.as_array().unwrap().len() as u64, head + 1);
    let human = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&a)
        .args(["ledger", "status"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.starts_with("ledger: ok"), "{text}");
    assert!(text.contains("laptop (this device)"), "{text}");
}
