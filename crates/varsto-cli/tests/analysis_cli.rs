// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto analysis` and `varsto search`, first with the vault opened by the
//! command itself, then through a running service's local API
//! (`/api/analysis`, `/api/analyses`, `/api/analysis/clear`,
//! `/api/analysis/search`). In a temporary directory with HOME and the XDG
//! directories pointed there.
#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn cmd(root: &Path, home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .env("VARSTO_RENDEZVOUS", "off")
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    c
}

fn run(root: &Path, home: &Path, args: &[&str]) -> (bool, String, String) {
    let out = cmd(root, home).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ok(root: &Path, home: &Path, args: &[&str]) -> String {
    let (good, out, err) = run(root, home, args);
    assert!(good, "varsto {args:?} failed: {err}");
    out
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn analyses_from_the_command_line_and_the_local_api() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("receipt.txt"), "Hardware store: screws").unwrap();
    fs::write(docs.join("trip.txt"), "Train to Lyon").unwrap();
    ok(root, &home, &["init", "--name", "laptop"]);
    let storage = root.join("storage");
    ok(
        root,
        &home,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(
        root,
        &home,
        &["folder", "add", "docs", docs.to_str().unwrap()],
    );
    ok(root, &home, &["sync"]);

    // Without a service: the command opens the vault.
    let out = ok(
        root,
        &home,
        &[
            "analysis",
            "set",
            "docs",
            "receipt.txt",
            "--text",
            "A receipt for screws",
            "--tag",
            "receipt",
            "--by",
            "me",
        ],
    );
    assert!(
        out.contains("recorded the analysis of receipt.txt"),
        "{out}"
    );
    let out = ok(root, &home, &["analysis", "show", "docs", "receipt.txt"]);
    assert!(
        out.contains("A receipt for screws") && out.contains("tags: receipt"),
        "{out}"
    );
    let out = ok(root, &home, &["search", "screws"]);
    assert!(out.contains("docs/receipt.txt [receipt]"), "{out}");
    let (good, _, err) = run(
        root,
        &home,
        &["analysis", "set", "docs", "nope.txt", "--text", "x"],
    );
    assert!(!good && err.contains("unknown file"), "{err}");

    // With the service: the same through its API.
    let _service = Kill(
        cmd(root, &home)
            .args(["service", "run", "--port", "0", "--interval", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let t0 = Instant::now();
    while !run(root, &home, &["service", "status"])
        .1
        .contains("running:")
    {
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "the service did not come up"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let text_file = root.join("analysis.txt");
    fs::write(&text_file, "Train ticket to Lyon, December\n").unwrap();
    ok(
        root,
        &home,
        &[
            "analysis",
            "set",
            "docs",
            "trip.txt",
            "--from-file",
            text_file.to_str().unwrap(),
            "--tag",
            "travel",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&ok(
        root,
        &home,
        &["--json", "analysis", "show", "docs", "trip.txt"],
    ))
    .unwrap();
    assert_eq!(v["analysis"], "Train ticket to Lyon, December");
    assert_eq!(v["tags"], serde_json::json!(["travel"]));
    assert_eq!(v["author"], "laptop");
    assert_eq!(v["stale"], false);
    let list: serde_json::Value =
        serde_json::from_str(&ok(root, &home, &["--json", "analysis", "list", "docs"])).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
    let hits: serde_json::Value = serde_json::from_str(&ok(
        root,
        &home,
        &["--json", "search", "lyon", "--tag", "travel"],
    ))
    .unwrap();
    assert_eq!(hits.as_array().unwrap().len(), 1, "{hits}");
    assert_eq!(hits[0]["path"], "trip.txt");
    let out = ok(root, &home, &["analysis", "clear", "docs", "trip.txt"]);
    assert!(out.contains("cleared"), "{out}");
    let out = ok(root, &home, &["analysis", "show", "docs", "trip.txt"]);
    assert!(out.contains("has no analysis"), "{out}");
    // The service lists it with the files.
    let files: serde_json::Value =
        serde_json::from_str(&ok(root, &home, &["--json", "folder", "files", "docs"])).unwrap();
    assert!(files
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["path"] == "receipt.txt" && f["analysis"] == "A receipt for screws"));
}
