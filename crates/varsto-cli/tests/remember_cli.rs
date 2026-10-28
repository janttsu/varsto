// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto service remember` and `forget` without a desktop session (spec
//! section 72). In a temporary directory; the session looks like an SSH
//! login, so the desktop keyring is skipped and the next store is used.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

const PASS: &str = "remember test passphrase";

fn cmd(root: &Path, home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", PASS)
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .env("VARSTO_RENDEZVOUS", "off")
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    c
}

fn run(root: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    cmd(root, home).args(args).output().unwrap()
}

#[test]
fn remember_without_a_desktop_session_names_the_store_and_forget_removes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    let init = run(root, &home, &["init", "--name", "laptop"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let out = run(root, &home, &["service", "remember"]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!stdout.contains(PASS) && !stderr.contains(PASS));
    let cred = home.join("passphrase.cred");
    if out.status.success() {
        assert!(
            stdout.contains("systemd-creds") || stdout.contains("kernel keyring"),
            "{stdout}"
        );
        // The keyring was skipped for a reason and the text says so.
        assert!(stdout.contains("not used: desktop keyring"), "{stdout}");
        if cred.exists() {
            assert!(stdout.contains("systemd-creds"), "{stdout}");
            let raw = std::fs::read(&cred).unwrap();
            assert!(!String::from_utf8_lossy(&raw).contains(PASS));
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
                0o600
            );
        } else {
            assert!(stdout.contains("kernel keyring"), "{stdout}");
        }
        let f = run(root, &home, &["service", "forget"]);
        let ftxt = String::from_utf8_lossy(&f.stdout).to_string();
        assert!(f.status.success() && ftxt.contains("forgot"), "{ftxt}");
        assert!(!cred.exists());
    } else {
        // Neither store works here: the error lists what was tried.
        assert!(stderr.contains("Tried:"), "{stderr}");
        for s in [
            "desktop keyring",
            "systemd-creds",
            "kernel keyring",
            "varsto unlock",
        ] {
            assert!(stderr.contains(s), "{stderr}");
        }
    }
    let again = run(root, &home, &["service", "forget"]);
    assert!(again.status.success());
    let text = String::from_utf8_lossy(&again.stdout).to_string();
    assert!(text.contains("no passphrase was remembered"), "{text}");
}

#[test]
fn a_wrong_passphrase_is_not_remembered() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("device");
    assert!(run(root, &home, &["init", "--name", "laptop"])
        .status
        .success());
    let out = cmd(root, &home)
        .env("VARSTO_PASSPHRASE", "not the passphrase")
        .args(["service", "remember"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!home.join("passphrase.cred").exists());
}
