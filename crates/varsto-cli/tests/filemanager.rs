// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The commands behind the file-manager actions: `varsto paths fetch|free`
//! and `varsto open-placeholder`, first on the vault directly, then through
//! a running background service. Everything runs in a temporary directory
//! with HOME and the XDG directories pointed there and no desktop session,
//! so nothing reaches the real desktop.
#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

fn cmd(root: &Path, home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
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

/// Stops the service by its own process id, whatever the test outcome.
struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn paths_and_open_placeholder() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    let storage = root.join("storage");
    let docs = root.join("docs");
    ok(root, &home, &["init", "--name", "laptop"]);
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
    fs::write(docs.join("a.txt"), b"alpha").unwrap();
    fs::write(docs.join("b.txt"), b"beta").unwrap();
    ok(root, &home, &["sync"]);
    let ph = |n: &str| docs.join(format!("{n}.varsto-placeholder"));

    // No service: the vault is opened directly.
    ok(
        root,
        &home,
        &[
            "paths",
            "free",
            docs.join("a.txt").to_str().unwrap(),
            docs.join("b.txt").to_str().unwrap(),
        ],
    );
    assert!(ph("a.txt").exists() && !docs.join("a.txt").exists());
    assert!(ph("b.txt").exists());
    let out = ok(
        root,
        &home,
        &["paths", "fetch", ph("a.txt").to_str().unwrap()],
    );
    assert!(out.contains("fetched"), "{out}");
    assert_eq!(fs::read(docs.join("a.txt")).unwrap(), b"alpha");
    // A path outside every folder fails with exit code 1.
    let bad = cmd(root, &home)
        .args([
            "paths",
            "fetch",
            root.join("elsewhere.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));

    // open-placeholder: the opener receives the real path.
    let opened = root.join("opened.txt");
    let opener = root.join("opener.sh");
    fs::write(
        &opener,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n",
            opened.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&opener, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = cmd(root, &home)
        .args(["open-placeholder", ph("b.txt").to_str().unwrap()])
        .env("VARSTO_OPENER", &opener)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(docs.join("b.txt")).unwrap(), b"beta");
    assert!(!ph("b.txt").exists());
    assert_eq!(
        fs::read_to_string(&opened).unwrap().trim(),
        docs.join("b.txt").display().to_string()
    );

    // With a running service, the same commands go through /api/paths.
    let _service = Service(
        cmd(root, &home)
            .args(["service", "run", "--port", "0", "--interval", "3600"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut up = false;
    for _ in 0..100 {
        if cmd(root, &home)
            .args(["service", "status"])
            .output()
            .unwrap()
            .status
            .success()
        {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(up, "the service did not come up");
    // A wrong passphrase in the environment proves the service did the work.
    let through_service = |args: &[&str]| {
        let out = cmd(root, &home)
            .args(args)
            .env("VARSTO_PASSPHRASE", "wrong")
            .env("VARSTO_OPENER", &opener)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    // The service unlocks itself from VARSTO_PASSPHRASE shortly after start.
    for _ in 0..50 {
        let out = cmd(root, &home)
            .args(["paths", "free", docs.join("a.txt").to_str().unwrap()])
            .env("VARSTO_PASSPHRASE", "wrong")
            .output()
            .unwrap();
        if out.status.success() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(ph("a.txt").exists() && !docs.join("a.txt").exists());
    through_service(&["open-placeholder", ph("a.txt").to_str().unwrap()]);
    assert_eq!(fs::read(docs.join("a.txt")).unwrap(), b"alpha");
    assert!(fs::read_to_string(&opened).unwrap().contains("a.txt"));
}

#[test]
fn install_writes_file_manager_entries_into_a_temp_home() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    // No systemctl on PATH: the real user session is never touched.
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let run = |args: &[&str]| {
        let out = cmd(root, &home)
            .args(args)
            .env("PATH", &bin)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let report = run(&["install"]);
    assert!(report.contains("file managers"), "{report}");
    let data = root.join("xdg-data");
    for f in [
        "mime/packages/varsto-placeholder.xml",
        "applications/varsto-placeholder.desktop",
        "nautilus/scripts/Varsto/Download",
        "nautilus/scripts/Varsto/Free up space",
        "kio/servicemenus/varsto.desktop",
        "nemo/actions/varsto-fetch.nemo_action",
        "nemo/actions/varsto-free.nemo_action",
    ] {
        assert!(data.join(f).exists(), "{f} missing");
    }
    let handler = fs::read_to_string(data.join("applications/varsto-placeholder.desktop")).unwrap();
    assert!(handler.contains(&format!(
        "{} --home",
        root.join(".local/bin/varsto").display()
    )));
    let mimeapps = fs::read_to_string(root.join("xdg-config/mimeapps.list")).unwrap();
    assert!(mimeapps.contains("application/x-varsto-placeholder=varsto-placeholder.desktop"));
    run(&["uninstall"]);
    assert!(!data.join("kio/servicemenus/varsto.desktop").exists());
    assert!(!data.join("nautilus/scripts/Varsto").exists());
    assert!(!fs::read_to_string(root.join("xdg-config/mimeapps.list"))
        .unwrap()
        .contains("varsto"));
}
