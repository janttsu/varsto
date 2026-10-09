// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto verify`, `varsto storage price` and `varsto advice` through the binary.

use std::fs;
use std::path::Path;
use std::process::Command;

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .expect("run varsto");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "varsto {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

#[test]
fn verify_price_and_advice_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b) = (root.join("a"), root.join("b"));
    let storage = root.join("storage");
    let docs = root.join("docs");
    let init = ok(&a, &["init", "--name", "laptop"]);
    let key = init["vault_key"].as_str().unwrap().to_string();
    ok(
        &a,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    fs::write(docs.join("old.txt"), b"an idle file").unwrap();
    ok(&a, &["push", "docs"]);

    // Prices: set, shown in the list, cleared.
    let p = ok(
        &a,
        &[
            "storage",
            "price",
            "box",
            "--gb-month",
            "0.006",
            "--egress",
            "0.01",
            "--currency",
            "EUR",
        ],
    );
    assert_eq!(p["storage_per_gb_month"], 0.006);
    assert_eq!(p["currency"], "EUR");
    let list = ok(&a, &["storage", "list"]);
    assert_eq!(list[0]["name"], "box");
    assert_eq!(list[0]["price"]["egress_per_gb"], 0.01);
    assert!(list[0]["monthly_cost"].as_f64().unwrap() > 0.0);

    // Automatic verification on another device, which names the storage
    // "primary": the writer's own run publishes that its "box" is the same one.
    let run = ok(&a, &["verify", "run"]);
    assert_eq!(
        run["blocks_verified"], 0,
        "the writer does not verify itself"
    );
    ok(
        &b,
        &[
            "join",
            "--name",
            "nas",
            "--vault-key",
            &key,
            "--storage-path",
            storage.to_str().unwrap(),
        ],
    );
    let st = ok(
        &b,
        &["verify", "set", "--interval-hours", "12", "--max-mib", "64"],
    );
    assert_eq!(st["schedule"]["interval_hours"], 12);
    assert_eq!(st["schedule"]["max_bytes"], 64 * 1024 * 1024);
    let run = ok(&b, &["verify", "run"]);
    assert!(run["blocks_verified"].as_u64().unwrap() >= 1, "{run}");
    let st = ok(&b, &["verify"]);
    assert!(st["last_run_utc"].as_i64().is_some());
    assert!(st["next_run_utc"].as_i64().is_some());

    // Advice: the idle file can be freed; apply needs --yes without a terminal.
    let adv = ok(&a, &["advice", "--idle-days", "0"]);
    assert_eq!(adv["suggestions"][0]["id"], "free-idle:docs");
    assert!(adv["folders"][0]["monthly"]["EUR"].as_f64().unwrap() > 0.0);
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .args([
            "--home",
            a.to_str().unwrap(),
            "advice",
            "apply",
            "free-idle:docs",
            "--idle-days",
            "0",
        ])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success(), "no confirmation, no change");
    assert!(docs.join("old.txt").exists());
    let r = ok(
        &a,
        &[
            "advice",
            "apply",
            "free-idle:docs",
            "--idle-days",
            "0",
            "--yes",
        ],
    );
    assert_eq!(r["files_freed"], 1, "{r}");
    assert!(!docs.join("old.txt").exists());
    assert!(docs.join("old.txt.varsto-placeholder").exists());
    let p = ok(&a, &["storage", "price", "box", "--clear"]);
    assert!(p.is_null());
}
