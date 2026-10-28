// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder membership of storage format 3 through the binary (work package
//! 8b): request, requests, approve (the fingerprint question and `--yes`),
//! members, deny, role, remove (a new folder epoch), resolve-epoch, the
//! recovery copies and the warning of `varsto status`.
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_with(home: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_varsto"));
    cmd.arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .env("VARSTO_RENDEZVOUS", "off")
        .env_remove("VARSTO_RECOVERY_WORDS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("run varsto");
    {
        let mut si = child.stdin.take().unwrap();
        if let Some(text) = stdin {
            si.write_all(text.as_bytes()).unwrap();
        }
    }
    child.wait_with_output().expect("wait")
}

fn run(home: &Path, args: &[&str]) -> Output {
    run_with(home, args, None, &[])
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn ok(home: &Path, args: &[&str]) -> Value {
    let o = run(home, args);
    assert!(o.status.success(), "varsto {args:?}: {}", text(&o.stderr));
    serde_json::from_str(&text(&o.stdout)).unwrap_or(Value::Null)
}

fn fails(home: &Path, args: &[&str]) -> String {
    let o = run(home, args);
    assert!(!o.status.success(), "varsto {args:?} should have failed");
    text(&o.stderr)
}

fn join(home: &Path, key: &str, name: &str, storage: &str) {
    let o = run_with(
        home,
        &["join", "--name", name, "--storage-path", storage],
        None,
        &[("VARSTO_VAULT_KEY", key)],
    );
    assert!(o.status.success(), "join {name}: {}", text(&o.stderr));
}

struct Vault {
    _tmp: tempfile::TempDir,
    a: std::path::PathBuf,
    b: std::path::PathBuf,
    c: std::path::PathBuf,
    key: String,
    storage: String,
}

/// Device A with a format-3 folder `docs`, and B and C joined to the vault.
fn vault() -> Vault {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
    let storage = root.join("storage");
    let s = storage.to_str().unwrap().to_string();
    let init = ok(&a, &["init", "--name", "alpha"]);
    let key = init["vault_key"].as_str().unwrap().to_string();
    ok(&a, &["storage", "add-local", "box", &s]);
    ok(&a, &["folder", "create-f3", "docs"]);
    join(&b, &key, "bravo", &s);
    join(&c, &key, "charlie", &s);
    Vault {
        _tmp: tmp,
        a,
        b,
        c,
        key,
        storage: s,
    }
}

fn roles(members: &Value) -> Vec<(String, String)> {
    members["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["device"].as_str().unwrap().to_string(),
                p["role"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn request_approve_members_deny_and_remove() {
    let v = vault();
    assert!(!v.key.is_empty() && !v.storage.is_empty());

    // B asks; it prints its six words, A lists the same words.
    let req = ok(&v.b, &["folder", "request", "docs", "--role", "editor"]);
    let words = req["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(words.split(' ').count(), 6, "{words}");
    let listed = ok(&v.a, &["folder", "requests"]);
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["device"], "bravo");
    assert_eq!(listed[0]["folder"], "docs");
    assert_eq!(listed[0]["fingerprint"].as_str().unwrap(), words);
    // The owner's own request list for one folder says the same.
    assert_eq!(
        ok(&v.a, &["folder", "requests", "docs"])
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Without a yes nothing is granted: no answer, "n", and an empty line.
    for answer in [None, Some("n\n"), Some("\n")] {
        let o = run_with(&v.a, &["folder", "approve", "docs", "bravo"], answer, &[]);
        assert!(!o.status.success());
        let err = text(&o.stderr);
        assert!(err.contains("Do the six words match?"), "{err}");
        assert!(err.contains(&words), "the question shows the words: {err}");
        assert!(err.contains("bravo"), "{err}");
        assert!(err.contains("not approved"), "{err}");
    }
    let members = ok(&v.a, &["folder", "members", "docs"]);
    assert_eq!(roles(&members), vec![("alpha".into(), "owner".into())]);
    assert_eq!(members["pending"].as_array().unwrap().len(), 1);

    // "y" approves; the members show the grant, as the role asked for.
    let o = run_with(
        &v.a,
        &["folder", "approve", "docs", "bravo"],
        Some("y\n"),
        &[],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    let members = ok(&v.a, &["folder", "members", "docs"]);
    let mut got = roles(&members);
    got.sort();
    assert_eq!(
        got,
        vec![
            ("alpha".to_string(), "owner".to_string()),
            ("bravo".to_string(), "editor".to_string())
        ]
    );
    assert!(members["pending"].as_array().unwrap().is_empty());
    assert!(ok(&v.a, &["folder", "requests"])
        .as_array()
        .unwrap()
        .is_empty());
    // B sees its own grant.
    let mine = ok(&v.b, &["folder", "members", "docs"]);
    assert_eq!(mine["your_role"], "editor");

    // --yes skips the question; --role overrides what was asked.
    ok(&v.c, &["folder", "request", "docs", "--role", "editor"]);
    ok(
        &v.a,
        &[
            "folder", "approve", "docs", "charlie", "--yes", "--role", "viewer",
        ],
    );
    let members = ok(&v.a, &["folder", "members", "docs"]);
    assert!(roles(&members).contains(&("charlie".to_string(), "viewer".to_string())));

    // A role change is a record by an owner; a viewer becomes an editor.
    ok(&v.a, &["folder", "role", "docs", "charlie", "editor"]);
    let members = ok(&v.a, &["folder", "members", "docs"]);
    assert!(roles(&members).contains(&("charlie".to_string(), "editor".to_string())));
    // The only owner cannot demote itself.
    assert!(fails(&v.a, &["folder", "role", "docs", "alpha", "viewer"]).contains("only owner"));
    // Nobody but an owner changes roles.
    assert!(fails(&v.b, &["folder", "role", "docs", "charlie", "viewer"]).contains("not an owner"));

    // Removing asks first (no answer is no) and then starts folder epoch 1.
    let o = run(&v.a, &["folder", "remove", "docs", "bravo"]);
    assert!(!o.status.success());
    assert!(
        text(&o.stderr).contains("new folder epoch"),
        "{}",
        text(&o.stderr)
    );
    assert_eq!(ok(&v.a, &["folder", "members", "docs"])["epoch"], 0);
    let removed = ok(&v.a, &["folder", "remove", "docs", "bravo", "--yes"]);
    assert_eq!(removed["epoch"], 1);
    assert_eq!(removed["removed"], "bravo");
    assert_eq!(removed["granted_to"].as_array().unwrap().len(), 2);
    let members = ok(&v.a, &["folder", "members", "docs"]);
    assert_eq!(members["epoch"], 1);
    let names: Vec<String> = roles(&members).into_iter().map(|r| r.0).collect();
    assert!(!names.contains(&"bravo".to_string()), "{names:?}");
    assert!(members["denied"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["device"] == "bravo"));
    // C, which stays, holds the new epoch's key and reads it.
    assert_eq!(ok(&v.c, &["folder", "members", "docs"])["epoch"], 1);
    // B no longer has a role at the new epoch.
    assert!(ok(&v.b, &["folder", "members", "docs"])["your_role"].is_null());
}

#[test]
fn deny_hides_the_request_and_resolve_epoch_needs_a_fork() {
    let v = vault();
    ok(&v.b, &["folder", "request", "docs", "--role", "viewer"]);
    assert_eq!(
        ok(&v.a, &["folder", "requests"]).as_array().unwrap().len(),
        1
    );
    let denied = ok(&v.a, &["folder", "deny", "docs", "bravo"]);
    assert!(denied["denied"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["device"] == "bravo"));
    assert!(ok(&v.a, &["folder", "requests"])
        .as_array()
        .unwrap()
        .is_empty());
    // A denied device cannot be approved afterwards (nothing is pending).
    let err = fails(&v.a, &["folder", "approve", "docs", "bravo", "--yes"]);
    assert!(err.contains("no pending request"), "{err}");

    // Nothing to resolve without two records under one number.
    let err = fails(
        &v.a,
        &["folder", "resolve-epoch", "docs", "1", "--keep", "alpha"],
    );
    assert!(!err.is_empty());
    // A folder that does not exist, and a role that does not exist.
    assert!(fails(&v.a, &["folder", "members", "nothing"]).contains("no folder"));
    assert!(fails(&v.c, &["folder", "request", "docs", "--role", "boss"]).contains("unknown role"));
    // Owners are not requested.
    assert!(
        fails(&v.c, &["folder", "request", "docs", "--role", "owner"]).contains("editor or viewer")
    );
}

#[test]
fn escrow_writes_the_missing_copies_and_status_stops_warning() {
    let v = vault();
    let warning = "folder docs has no recovery copy: run varsto recovery escrow docs";
    let st = run(&v.a, &["status"]);
    assert!(st.status.success(), "{}", text(&st.stderr));
    assert!(text(&st.stderr).contains(warning), "{}", text(&st.stderr));

    // The recovery words: a kit with a new key prints both sets.
    let kit = run(&v.a, &["recovery", "kit", "--new-recovery-key"]);
    assert!(kit.status.success(), "{}", text(&kit.stderr));
    let kit_text = text(&kit.stdout);
    assert!(kit_text.contains("VAULT WORDS"), "{kit_text}");
    assert!(kit_text.contains("RECOVERY WORDS"), "{kit_text}");

    let k1 = varsto_core::membership3::RecoveryKey::generate();
    let words = k1.words().unwrap().to_string();
    // Without the words nothing is written (no terminal, no input).
    let o = run(&v.a, &["recovery", "escrow", "docs"]);
    assert!(!o.status.success());
    // Wrong words do not pass the checksum.
    let o = run_with(
        &v.a,
        &["recovery", "escrow", "docs", "--with-recovery-key"],
        None,
        &[("VARSTO_RECOVERY_WORDS", "abandon abandon abandon")],
    );
    assert!(!o.status.success());
    assert!(text(&run(&v.a, &["status"]).stderr).contains(warning));

    let o = run_with(
        &v.a,
        &["recovery", "escrow", "--with-recovery-key"],
        None,
        &[("VARSTO_RECOVERY_WORDS", &words)],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    let written: Value = serde_json::from_str(&text(&o.stdout)).unwrap();
    assert_eq!(written.as_array().unwrap().len(), 1);
    assert_eq!(written[0]["folder"], "docs");
    assert_eq!(written[0]["epoch"], 0);
    let st = run(&v.a, &["status"]);
    assert!(
        !text(&st.stderr).contains("no recovery copy"),
        "{}",
        text(&st.stderr)
    );
    // Nothing left: the command says so and does not ask for the words.
    let o = run(&v.a, &["recovery", "escrow"]);
    assert!(o.status.success(), "{}", text(&o.stderr));

    // The words from a file work too, and a removal's new epoch is missing
    // a copy again until the escrow runs.
    ok(&v.b, &["folder", "request", "docs"]);
    ok(&v.a, &["folder", "approve", "docs", "bravo", "--yes"]);
    ok(&v.a, &["folder", "remove", "docs", "bravo", "--yes"]);
    assert!(text(&run(&v.a, &["status"]).stderr).contains(warning));
    let file = v._tmp.path().join("words.txt");
    std::fs::write(&file, &words).unwrap();
    ok(
        &v.a,
        &[
            "recovery",
            "escrow",
            "docs",
            "--recovery-file",
            file.to_str().unwrap(),
        ],
    );
    assert!(!text(&run(&v.a, &["status"]).stderr).contains("no recovery copy"));
}
