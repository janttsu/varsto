// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto activity` and the service's `/api/activity`: a command run in a
//! terminal (`fsck --verify`, slowed down by the test hook) reports its task
//! to the running service, which lists it as this device's activity. In a
//! temporary directory with HOME and the XDG directories pointed there.
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

fn ok(root: &Path, home: &Path, args: &[&str]) -> String {
    let out = cmd(root, home).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "varsto {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Kills the child whatever the test outcome.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_command_reports_its_task_to_the_service() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    for i in 0..120 {
        fs::write(
            docs.join(format!("f{i}.txt")),
            format!("file {i} ").repeat(40),
        )
        .unwrap();
    }
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
    ok(root, &home, &["push", "docs"]);

    // Without a service there is nothing to ask.
    let out = cmd(root, &home).args(["activity"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not running"));

    let _service = Kill(
        cmd(root, &home)
            .args(["service", "run", "--port", "0", "--interval", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let t0 = Instant::now();
    let me = loop {
        let out = cmd(root, &home)
            .args(["--json", "activity"])
            .output()
            .unwrap();
        if out.status.success() {
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            if v["me"]["name"] == "laptop" {
                break v["me"].clone();
            }
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "the service did not come up"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(me["state"], "idle", "{me}");
    let text = ok(root, &home, &["activity"]);
    assert!(text.contains("laptop (this device): idle"), "{text}");

    // A long fsck in another process: about 6 s at 50 ms per block.
    let _fsck = Kill(
        cmd(root, &home)
            .args(["fsck", "--verify"])
            .env("VARSTO_ACTIVITY_TEST_DELAY_MS", "50")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let t0 = Instant::now();
    let task = loop {
        let v: serde_json::Value =
            serde_json::from_str(&ok(root, &home, &["--json", "activity"])).unwrap();
        let found = v["me"]["tasks"].as_array().and_then(|a| {
            a.iter()
                .find(|t| {
                    t["kind"] == "fsck" && t["phase"] == "verify" && t["done"].as_u64() > Some(0)
                })
                .cloned()
        });
        if let Some(t) = found {
            assert_eq!(v["me"]["state"], "busy");
            break t;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "the fsck never showed up: {v}"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(task["total"].as_u64().unwrap() >= 100, "{task}");
    assert_eq!(task["unit"], "items");
    let text = ok(root, &home, &["activity"]);
    assert!(
        text.contains("laptop (this device): verifying every block of the vault")
            || text.contains("laptop (this device): idle"),
        "{text}"
    );
}
