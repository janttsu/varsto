// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto p2p rendezvous status | set <url> | on | --off` through the
//! binary, with no background service running: the setting is saved in the
//! device's configuration, a service that does not answer only warns, and a
//! bad address is refused.
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

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

fn run(home: &Path, args: &[&str]) -> Output {
    cmd(home).args(args).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn status(home: &Path) -> Value {
    let o = run(home, &["--json", "p2p", "rendezvous", "status"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    serde_json::from_str(&text(&o.stdout)).unwrap()
}

#[test]
fn rendezvous_setting_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("laptop");
    let o = run(&home, &["init", "--name", "laptop"]);
    assert!(o.status.success(), "{}", text(&o.stderr));

    // The default is on, with the default address.
    let s = status(&home);
    assert_eq!(s["enabled"], true);
    assert_eq!(s["url"], s["default_url"]);

    // A bad address is refused and nothing changes.
    let o = run(&home, &["p2p", "rendezvous", "set", "ftp://nope"]);
    assert!(!o.status.success());
    assert_eq!(status(&home)["enabled"], true);

    // A self-hosted address on a port nothing listens on: warned, saved anyway.
    let o = run(
        &home,
        &["p2p", "rendezvous", "set", "http://127.0.0.1:9/rv/"],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("does not answer"),
        "{}",
        text(&o.stderr)
    );
    let s = status(&home);
    assert_eq!(s["url"], "http://127.0.0.1:9/rv");
    assert_eq!(s["state"], "not running");

    // Off, in both spellings, then back to the default.
    let o = run(&home, &["p2p", "rendezvous", "--off"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let s = status(&home);
    assert_eq!(s["enabled"], false);
    assert!(s["url"].is_null());
    let o = run(&home, &["p2p", "rendezvous", "off"]);
    assert!(o.status.success());
    let o = run(&home, &["p2p", "rendezvous", "on"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let s = status(&home);
    assert_eq!(s["enabled"], true);
    assert_eq!(s["url"], s["default_url"]);

    // The plain-text status says the same in words.
    let o = run(&home, &["p2p", "rendezvous", "status"]);
    assert!(
        text(&o.stdout).starts_with("rendezvous: https://"),
        "{}",
        text(&o.stdout)
    );
}
