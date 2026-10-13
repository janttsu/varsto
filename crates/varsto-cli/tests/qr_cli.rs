// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! QR invitations through the `varsto` binary and the local service
//! (`docs/spec/alpha-0-format.md` section 43): a share made with the
//! `varsto://` links only, the interface's QR and scan endpoints, and a link
//! handed over by `varsto open-link`.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const PASS: &str = "test passphrase";

/// `varsto` with HOME and the XDG directories in the test directory.
fn varsto(root: &Path, home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", PASS)
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_OPENER", "true")
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    c
}

fn ok(root: &Path, home: &Path, args: &[&str]) -> serde_json::Value {
    let out = varsto(root, home)
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "varsto {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

/// One request to the local service: (status, body). HTTP/1.0, so the
/// answer is not chunked.
fn call(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> (u16, serde_json::Value) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nX-Varsto-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(body).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        status,
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    )
}

struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_share_with_qr_links_and_the_service_endpoints() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (owner, robin) = (root.join("owner"), root.join("robin"));
    let storage = root.join("storage");
    let docs = root.join("docs");
    ok(root, &owner, &["init", "--name", "laptop"]);
    ok(
        root,
        &owner,
        &["storage", "add-local", "box", storage.to_str().unwrap()],
    );
    ok(
        root,
        &owner,
        &["folder", "add", "docs", docs.to_str().unwrap()],
    );
    std::fs::write(docs.join("a.txt"), b"by qr").unwrap();
    ok(root, &owner, &["push", "docs"]);

    // Robin's request as a link; the owner seals to the link and answers
    // with the token's link; Robin accepts the link.
    let req = ok(root, &robin, &["share", "request", "--name", "Robin"]);
    let qr = ok(
        root,
        &robin,
        &["share", "qr", req["request_code"].as_str().unwrap()],
    );
    let req_uri = qr["uris"][0].as_str().unwrap().to_string();
    assert!(req_uri.starts_with("varsto://share/request?c="));
    assert_eq!(qr["fingerprint"], req["fingerprint"]);
    let made = ok(
        root,
        &owner,
        &[
            "share",
            "create",
            "docs",
            "--to",
            &req_uri,
            "--fingerprint",
            req["fingerprint"].as_str().unwrap(),
        ],
    );
    let tq = ok(
        root,
        &owner,
        &["share", "qr", made["token"].as_str().unwrap()],
    );
    let token_uri = tq["uris"][0].as_str().unwrap().to_string();
    assert!(token_uri.starts_with("varsto://share/token?t="));
    let parts = ok(root, &owner, &["share", "qr", "--parts", &token_uri]);
    assert!(parts["uris"].as_array().unwrap().len() > 1);
    ok(
        root,
        &robin,
        &[
            "share",
            "accept",
            &token_uri,
            "--name",
            "robin",
            "--storage-path",
            storage.to_str().unwrap(),
        ],
    );
    // A plain token never becomes a QR code.
    let out = varsto(root, &owner)
        .args(["share", "qr", "00aa.11bb.22cc33dd.docs"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("folder key"));
    // The terminal code.
    let out = varsto(root, &owner)
        .args(["share", "qr", &token_uri])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains('█') && text.contains("Sealed share token for docs"),
        "{text}"
    );

    // The service: QR images, parsing scanned parts, a camera frame, a link
    // from the system.
    let _service = Kill(
        varsto(root, &owner)
            .args(["service", "run", "--port", "0", "--interval", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let t0 = std::time::Instant::now();
    let (port, token) = loop {
        if let Ok(b) = std::fs::read(owner.join("service.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                if let (Some(p), Some(t)) = (v["port"].as_u64(), v["token"].as_str()) {
                    if std::net::TcpStream::connect(("127.0.0.1", p as u16)).is_ok() {
                        break (p as u16, t.to_string());
                    }
                }
            }
        }
        assert!(t0.elapsed().as_secs() < 30, "the service did not come up");
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let body = serde_json::json!({"text": req_uri}).to_string();
    let (st, v) = call(port, &token, "POST", "/api/qr", body.as_bytes());
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["kind"], "request", "{v}");
    assert_eq!(v["fingerprint"], req["fingerprint"]);
    assert!(v["codes"][0]["svg"].as_str().unwrap().contains("<svg"));
    let body = serde_json::json!({"text": token_uri, "parts": true}).to_string();
    let (_, v) = call(port, &token, "POST", "/api/qr", body.as_bytes());
    let n = v["codes"].as_array().unwrap().len();
    assert!(n > 1);
    let part_uris: Vec<String> = parts["uris"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect();
    let body = serde_json::json!({"texts": [part_uris[0]]}).to_string();
    let (_, v) = call(port, &token, "POST", "/api/link/parse", body.as_bytes());
    assert_eq!(v["count"], part_uris.len());
    let body = serde_json::json!({"texts": part_uris}).to_string();
    let (_, v) = call(port, &token, "POST", "/api/link/parse", body.as_bytes());
    assert_eq!(v["kind"], "token");
    assert_eq!(v["folder"], "docs");
    // A grey camera frame with the request code in it.
    let (side, px) = varsto_core::qr::to_luma(&req_uri, 2).unwrap();
    let (st, v) = call(
        port,
        &token,
        "POST",
        &format!("/api/qr/scan?w={side}&h={side}"),
        &px,
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["texts"][0], req_uri.as_str());
    let (st, _) = call(port, &token, "POST", "/api/qr/scan?w=0&h=5", b"");
    assert_eq!(st, 400);
    // `varsto open-link`: the service keeps the link until the page takes it.
    let out = varsto(root, &owner)
        .args(["open-link", &req_uri])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_, v) = call(port, &token, "GET", "/api/link", b"");
    assert_eq!(v["uri"], req_uri.as_str());
    let (_, v) = call(port, &token, "GET", "/api/link", b"");
    assert!(v.get("uri").is_none());
    let out = varsto(root, &owner)
        .args(["open-link", "varsto://elsewhere?x=1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    // Without the session token nothing answers.
    let (st, _) = call(port, "wrong", "POST", "/api/qr", b"{}");
    assert_ne!(st, 200);
}
