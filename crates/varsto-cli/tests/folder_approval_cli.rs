// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage format 2, design section 4: a device that joined with the vault
//! words asks for a folder; the owner's background service sees the request
//! and never approves it; `varsto folder approve` does. In a temporary
//! directory with HOME and the XDG directories pointed there.
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
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("VARSTO_VAULT_KEY")
        .env_remove("VARSTO_RECOVERY_WORDS");
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

fn json(root: &Path, home: &Path, args: &[&str]) -> serde_json::Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    serde_json::from_str(&ok(root, home, &a)).unwrap()
}

/// Kills the child whatever the test outcome.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn without_key(root: &Path, home: &Path) -> Vec<String> {
    let st = json(root, home, &["status"]);
    st["folders_without_key"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_service_shows_a_request_and_only_a_person_approves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let a = root.join("a");
    let b = root.join("b");
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("plan.txt"), b"the secret plan").unwrap();
    let init = json(root, &a, &["init", "--name", "laptop"]);
    let key = init["vault_key"].as_str().unwrap().to_string();
    let storage = root.join("storage");
    let storage_s = storage.to_str().unwrap();
    ok(root, &a, &["storage", "add-local", "box", storage_s]);
    ok(root, &a, &["folder", "add", "docs", docs.to_str().unwrap()]);
    ok(root, &a, &["sync"]);

    // B joins with the vault key only: names and sizes, no content.
    let out = cmd(root, &b)
        .args([
            "--json",
            "join",
            "--name",
            "desk",
            "--storage-path",
            storage_s,
        ])
        .env("VARSTO_VAULT_KEY", &key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    ok(root, &b, &["sync"]);
    assert_eq!(without_key(root, &b), vec!["docs".to_string()]);
    let bdocs = root.join("b-docs");
    let out = cmd(root, &b)
        .args(["folder", "attach", "docs", bdocs.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("varsto folder request"));
    ok(root, &b, &["folder", "request", "docs"]);
    let b_id = json(root, &b, &["status"])["device_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A's background service runs its passes: it notes the request for the
    // interface and grants nothing.
    {
        let _service = Kill(
            cmd(root, &a)
                .args(["service", "run", "--port", "0", "--interval", "15"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let seen = a.join("state/folder-requests-seen.json");
        let t0 = Instant::now();
        loop {
            if fs::read_to_string(&seen).is_ok_and(|t| t.contains(&b_id)) {
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(120),
                "the service never noted the request"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        // Another pass at least.
        std::thread::sleep(Duration::from_secs(17));
    }
    let grants = storage.join("vault/grants");
    let to_b = files(&grants)
        .iter()
        .filter(|p| p.to_string_lossy().contains(&format!("/{b_id}/")))
        .count();
    assert_eq!(to_b, 0, "the service sealed a folder key to the requester");
    ok(root, &b, &["sync"]);
    assert_eq!(without_key(root, &b), vec!["docs".to_string()]);

    // The person at A approves: B reads the folder.
    let reqs = json(root, &a, &["folder", "requests"]);
    assert_eq!(reqs.as_array().map(|r| r.len()), Some(1), "{reqs}");
    ok(root, &a, &["folder", "approve", "docs", &b_id[..8]]);
    let p = json(root, &a, &["folder", "participants", "docs"]);
    let roles: Vec<(String, String)> = p["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["device"].as_str().unwrap().to_string(),
                d["role"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(roles.contains(&("laptop".into(), "owner".into())), "{p}");
    assert!(roles.contains(&("desk".into(), "owner".into())), "{p}");
    ok(root, &b, &["sync"]);
    assert!(without_key(root, &b).is_empty());
    ok(
        root,
        &b,
        &["folder", "attach", "docs", bdocs.to_str().unwrap()],
    );
    ok(root, &b, &["sync"]);
    assert_eq!(
        fs::read(bdocs.join("plan.txt")).unwrap(),
        b"the secret plan".to_vec()
    );
}
