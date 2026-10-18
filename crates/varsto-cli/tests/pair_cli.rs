// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pairing through the binary (storage format 3, `pair::v3`): `pair offer
//! --folders` shows the joining device's name and six words and asks, the
//! joining side shows the same six words, the ticked folder is granted and
//! no other, and a device the person declines gets nothing.
#![cfg(feature = "format3")]

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .env_remove("VARSTO_RECOVERY_WORDS");
    c
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn ok(home: &Path, args: &[&str]) -> Value {
    let o = cmd(home).arg("--json").args(args).output().unwrap();
    assert!(o.status.success(), "varsto {args:?}: {}", text(&o.stderr));
    serde_json::from_str(&text(&o.stdout)).unwrap_or(Value::Null)
}

/// `pair offer` with `answer` on its standard input; returns the child
/// (still running) and the code and port it printed.
fn offer(home: &Path, args: &[&str], answer: &str) -> (Child, String, u16) {
    let mut child = cmd(home)
        .arg("--json")
        .args(["pair", "offer"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let v: Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("{e}: {line}"));
    // The rest of the output is read when the child ends.
    std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = out.read_to_string(&mut rest);
    });
    (
        child,
        v["code"].as_str().unwrap().to_string(),
        v["port"].as_u64().unwrap() as u16,
    )
}

fn join(home: &Path, name: &str, code: &str, port: u16) -> Output {
    cmd(home)
        .args(["pair", "join", "--name", name, "--code", code])
        .arg("--address")
        .arg(format!("127.0.0.1:{port}"))
        .output()
        .unwrap()
}

/// The six words after `prefix` in `s`.
fn words_after(s: &str, prefix: &str) -> String {
    let at = s
        .find(prefix)
        .unwrap_or_else(|| panic!("no {prefix:?} in {s}"));
    s[at + prefix.len()..]
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn pairing_asks_shows_both_sides_the_words_and_grants_only_the_named_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
    let storage = root.join("storage");
    ok(&a, &["init", "--name", "alpha"]);
    ok(
        &a,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(&a, &["folder", "create-f3", "docs"]);
    ok(&a, &["folder", "create-f3", "photos"]);

    let (child, code, port) = offer(&a, &["--folders", "docs"], "y\n");
    let joined = join(&b, "phone", &code, port);
    let offered = child.wait_with_output().unwrap();
    let (jerr, oerr) = (text(&joined.stderr), text(&offered.stderr));
    assert!(joined.status.success(), "join: {jerr}");
    assert!(offered.status.success(), "offer: {oerr}");
    // Both sides show the same six words: the joining device its own, the
    // offering device the joiner's, with its name, before the question.
    let mine = words_after(&jerr, "This device's six words: ");
    assert_eq!(mine.split(' ').count(), 6, "{mine}");
    assert_eq!(
        words_after(&oerr, "phone asks to join. Its six words: "),
        mine
    );
    assert!(oerr.contains("Do the six words match?"), "{oerr}");
    assert!(
        text(&joined.stdout).contains("joined vault"),
        "{}",
        text(&joined.stdout)
    );

    // The named folder is granted to the new device, the other is not.
    let has = |folder: &str| {
        ok(&a, &["folder", "members", folder])["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["device"] == "phone")
    };
    assert!(has("docs"));
    assert!(!has("photos"));

    // A device the person says no to gets nothing and learns so.
    let (child, code, port) = offer(&a, &["--folders", "docs"], "n\n");
    let refused = join(&c, "stranger", &code, port);
    let offered = child.wait_with_output().unwrap();
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("did not let this one join"),
        "{}",
        text(&refused.stderr)
    );
    assert!(!offered.status.success(), "the offer closes declined");
    assert!(!c.join("vault.json").exists());
    let members = ok(&a, &["folder", "members", "docs"]);
    assert!(!members.to_string().contains("stranger"), "{members}");
}
