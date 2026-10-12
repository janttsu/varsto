// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The `varsto org` commands end to end: create, request and approve, join
//! with the token, status, policy, remove a user, log; all with JSON output.

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

fn fails(home: &Path, args: &[&str]) -> String {
    let (success, _, stderr) = varsto(home, args);
    assert!(!success, "varsto {:?} should have failed", args);
    stderr
}

#[test]
fn organization_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
    let storage = root.join("storage");
    let storage_s = storage.to_str().unwrap();
    let a_docs = root.join("a-docs");

    let init = ok(&a, &["init", "--name", "hq"]);
    let vault_key = init["vault_key"].as_str().unwrap().to_string();
    ok(&a, &["storage", "add-local", "box", storage_s]);
    ok(&a, &["folder", "add", "docs", a_docs.to_str().unwrap()]);
    fs::write(a_docs.join("note.txt"), b"first note").unwrap();
    ok(&a, &["push", "docs"]);
    ok(
        &b,
        &[
            "join",
            "--name",
            "b-phone",
            "--vault-key",
            &vault_key,
            "--storage-path",
            storage_s,
        ],
    );
    ok(&b, &["sync"]);
    ok(&a, &["sync"]);

    // No organization yet.
    assert_eq!(ok(&a, &["org", "status"])["exists"], false);

    let created = ok(&a, &["org", "create", "--name", "Acme", "--user", "alice"]);
    assert_eq!(
        created["root_words"].as_str().unwrap().split(' ').count(),
        24
    );
    assert_eq!(created["devices"].as_array().unwrap().len(), 2);
    let status = ok(&a, &["org", "status"]);
    assert_eq!(status["name"], "Acme");
    assert_eq!(status["this_device_admin"], true);
    assert_eq!(status["users"][0]["user"], "alice");
    assert_eq!(status["users"][0]["devices"].as_array().unwrap().len(), 2);

    // B sees it after a sync and is a member; it cannot approve or remove.
    ok(&b, &["sync"]);
    let sb = ok(&b, &["org", "status"]);
    assert_eq!(sb["this_device_admin"], false);
    assert_eq!(sb["this_user"], "alice");
    assert!(fails(&b, &["org", "remove-user", "alice", "--yes"]).contains("administrator"));
    let devices = ok(&b, &["device", "list"]);
    assert!(devices
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d["user"] == "alice"));

    // C requests, A approves with the fingerprint, C joins with the token.
    let req = ok(&c, &["org", "request", "--name", "c-laptop"]);
    let code = req["request_code"].as_str().unwrap().to_string();
    let fp = req["fingerprint"].as_str().unwrap().to_string();
    assert!(fails(
        &a,
        &[
            "org",
            "approve",
            &code,
            "--user",
            "carol",
            "--fingerprint",
            "wrong words"
        ]
    )
    .contains("fingerprint"));
    let approved = ok(
        &a,
        &[
            "org",
            "approve",
            &code,
            "--user",
            "carol",
            "--fingerprint",
            &fp,
        ],
    );
    let token = approved["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("vot1."));
    let joined = ok(
        &c,
        &["org", "join", "--name", "c-laptop", "--token", &token],
    );
    assert_eq!(joined["organization"], "Acme");
    assert_eq!(joined["user"], "carol");
    assert_eq!(joined["device_id"], approved["device_id"]);
    let c_docs = root.join("c-docs");
    ok(&c, &["folder", "attach", "docs", c_docs.to_str().unwrap()]);
    ok(&c, &["sync"]);
    assert_eq!(fs::read(c_docs.join("note.txt")).unwrap(), b"first note");
    let sc = ok(&c, &["org", "status"]);
    assert_eq!(sc["this_user"], "carol");
    assert_eq!(sc["this_device_listed"], true);

    // Policy: show, then open sharing up.
    let p = ok(&a, &["org", "policy"]);
    assert_eq!(p["members_may_share"], false);
    let p = ok(&a, &["org", "policy", "--allow", "share,add-devices"]);
    assert_eq!(p["members_may_share"], true);
    assert_eq!(p["members_may_add_devices"], true);
    assert_eq!(p["members_may_add_storages"], false);
    assert!(fails(&a, &["org", "policy", "--allow", "fly"]).contains("unknown permission"));

    // Remove carol: needs --yes, then revokes c in one epoch.
    assert!(fails(&a, &["org", "remove-user", "carol"]).contains("--yes"));
    let r = ok(&a, &["org", "remove-user", "carol", "--yes"]);
    assert_eq!(r["devices"][0], "c-laptop");
    assert_eq!(r["revoke"]["key_epoch"], 1);
    let (success, _, stderr) = varsto(&c, &["sync"]);
    assert!(
        !success && stderr.contains("removed from the vault"),
        "{stderr}"
    );
    let s = ok(&a, &["org", "status"]);
    assert_eq!(s["users"].as_array().unwrap().len(), 1);
    assert_eq!(s["removed"].as_array().unwrap().len(), 1);

    // The log tells the story, oldest first.
    let log = ok(&a, &["org", "log"]);
    let texts: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["text"].as_str().unwrap())
        .collect();
    assert!(texts[0].contains("created the organization Acme"));
    assert!(texts
        .iter()
        .any(|t| t.contains("approved c-laptop for carol")));
    assert!(texts.iter().any(|t| t.contains("changed the policy")));
    assert!(texts.last().unwrap().contains("removed carol"));
    ok(&b, &["sync"]);
    assert_eq!(
        ok(&b, &["org", "log"]).as_array().unwrap().len(),
        texts.len()
    );
}
