// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto verify`, `varsto storage price` and `varsto advice` through the binary.

use std::fs;
use std::path::Path;
use std::process::Command;

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
#[ignore = "f3-switch: port in part B (verification)"]
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

#[test]
#[ignore = "f3-switch: port in part B (verification)"]
fn scrub_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let a = root.join("a");
    let storage = root.join("storage");
    let deep = root.join("deep");
    let docs = root.join("docs");
    ok(&a, &["init", "--name", "laptop"]);
    ok(
        &a,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(
        &a,
        &[
            "storage",
            "add-local",
            "deep",
            deep.to_str().unwrap(),
            "--cold",
        ],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    fs::write(docs.join("a.txt"), b"some text to keep").unwrap();
    ok(&a, &["sync"]);

    let r = ok(&a, &["scrub", "--full"]);
    assert!(r["scrub"]["objects_checked"].as_u64().unwrap() > 0, "{r}");
    assert_eq!(r["scrub"]["files_checked"], 1);
    assert!(r["repair"].is_null());
    let skipped = r["scrub"]["skipped"].to_string();
    assert!(skipped.contains("deep (cold"), "{skipped}");

    let r = ok(&a, &["scrub", "--storage", "box"]);
    assert_eq!(r["scrub"]["files_checked"], 0);

    // A cold storage only with the confirmation.
    let refused = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&a)
        .args(["scrub", "--include-cold"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let r = ok(
        &a,
        &[
            "scrub",
            "--storage",
            "deep",
            "--include-cold",
            "--confirm-cold-read",
        ],
    );
    assert!(r["scrub"]["objects_checked"].as_u64().unwrap() > 0, "{r}");

    let st = ok(
        &a,
        &[
            "scrub",
            "set",
            "--days",
            "30",
            "--local-mib",
            "100",
            "--cold",
            "deep",
            "--confirm-cold-read",
        ],
    );
    assert_eq!(st["schedule"]["scrub_days"], 30);
    assert_eq!(st["schedule"]["max_local_bytes"], 100 * 1024 * 1024);
    assert_eq!(st["schedule"]["cold"][0], "deep");
    let st = ok(&a, &["scrub", "status"]);
    assert!(st["last_run_utc"].is_number());
    assert!(st["targets"]["storage:box"].is_object(), "{st}");
}

#[test]
fn quota_and_drain_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let a = root.join("a");
    let (old, new) = (root.join("old"), root.join("new"));
    let docs = root.join("docs");
    ok(&a, &["init", "--name", "laptop"]);
    ok(
        &a,
        &[
            "storage",
            "add-local",
            "old",
            old.to_str().unwrap(),
            "--place",
            "cloud",
        ],
    );
    ok(&a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    fs::write(docs.join("a.bin"), vec![7u8; 300_000]).unwrap();
    fs::write(docs.join("b.txt"), b"bee").unwrap();
    ok(&a, &["sync"]);

    // A quota: set in decimal units, shown in the list, measured, cleared.
    let q = ok(&a, &["storage", "quota", "old", "--bytes", "2GB"]);
    assert_eq!(q["quota_bytes"], 2_000_000_000u64);
    assert_eq!(q["state"], "ok");
    let list = ok(&a, &["storage", "list"]);
    assert_eq!(list[0]["quota"]["quota_bytes"], 2_000_000_000u64);
    let m = ok(&a, &["storage", "quota", "old", "--measure"]);
    assert!(m["measured_utc"].as_i64().is_some());
    assert!(m["used_objects"].as_u64().unwrap() > 0);
    let q = ok(&a, &["storage", "quota", "old", "--clear"]);
    assert!(q.get("quota_bytes").is_none());
    let bad = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&a)
        .args(["storage", "quota", "old", "--bytes", "lots"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    assert!(!bad.status.success());

    // Draining the only storage is refused; with another one it plans,
    // runs and removes the storage when empty.
    let alone = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&a)
        .args(["storage", "drain", "old"])
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .output()
        .unwrap();
    assert!(!alone.status.success());
    assert!(String::from_utf8_lossy(&alone.stderr).contains("only storage"));
    ok(
        &a,
        &[
            "storage",
            "add-local",
            "new",
            new.to_str().unwrap(),
            "--place",
            "cloud",
        ],
    );
    let plan = ok(&a, &["storage", "drain", "old", "--plan"]);
    assert_eq!(plan["policy"], "ok");
    assert!(plan["blocks_to_copy"].as_u64().unwrap() > 0);
    assert_eq!(
        ok(&a, &["storage", "drain", "status"]),
        serde_json::json!([])
    );
    let r = ok(
        &a,
        &[
            "storage",
            "drain",
            "old",
            "--remove-when-empty",
            "--budget-gb-per-day",
            "5",
        ],
    );
    assert_eq!(r["run"]["drained"], true, "{r}");
    assert_eq!(r["run"]["removed"], true);
    let list = ok(&a, &["storage", "list"]);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["name"], "new");
}
