// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! S3 and rclone backends, exercised through a real `rclone` binary: the S3
//! backend against `rclone serve s3` (a local S3 server), the rclone backend
//! against a local-path remote. Both tests skip when rclone is not installed.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::Engine;
use varsto_core::storage::{Storage, StorageSpec};

const PASS: &str = "correct horse battery staple";

fn have_rclone() -> bool {
    Command::new("rclone")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct S3Server {
    child: Child,
    endpoint: String,
}

impl S3Server {
    fn start(root: &Path) -> S3Server {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new("rclone")
            .args([
                "serve",
                "s3",
                "--addr",
                &format!("127.0.0.1:{port}"),
                "--auth-key",
                "testkey,testsecret",
                "--force-path-style",
                root.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rclone serve s3");
        let endpoint = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        S3Server { child, endpoint }
    }
}

impl Drop for S3Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn storage_contract(st: &dyn Storage) {
    assert_eq!(st.list("").unwrap(), Vec::<String>::new());
    assert!(!st.exists("a/b.bin").unwrap());
    assert_eq!(st.get("a/b.bin").unwrap(), None);
    assert!(st.put_if_absent("a/b.bin", b"one").unwrap());
    assert!(
        !st.put_if_absent("a/b.bin", b"two").unwrap(),
        "must not overwrite"
    );
    assert_eq!(st.get("a/b.bin").unwrap().as_deref(), Some(&b"one"[..]));
    assert!(st.put_if_absent("a/c.bin", b"three").unwrap());
    assert!(st.put_if_absent("z.bin", b"z").unwrap());
    assert_eq!(
        st.list("a/").unwrap(),
        vec!["a/b.bin".to_string(), "a/c.bin".to_string()]
    );
    assert_eq!(st.list("").unwrap().len(), 3);
    st.delete("a/b.bin").unwrap();
    assert!(!st.exists("a/b.bin").unwrap());
    st.delete("a/b.bin").unwrap(); // idempotent
                                   // Larger object round-trips exactly.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    assert!(st.put_if_absent("big/obj", &big).unwrap());
    assert_eq!(st.get("big/obj").unwrap().unwrap(), big);
}

fn two_devices_through(spec_a: StorageSpec, secret: Option<String>, spec_b: StorageSpec) {
    let root = tempfile::tempdir().unwrap();
    let (a_home, b_home) = (root.path().join("a"), root.path().join("b"));
    let (a_dir, b_dir) = (root.path().join("a_files"), root.path().join("b_files"));
    fs::create_dir_all(&a_dir).unwrap();
    let (mut a, key) = Engine::init(&a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage_with_secret(spec_a, secret.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    fs::write(a_dir.join("report.txt"), b"synced through a remote bucket").unwrap();
    a.push("docs").unwrap();

    // Join needs an openable spec: give the secret through the environment for the join step.
    if let (StorageSpec::S3 { name, .. }, Some(s)) = (&spec_b, &secret) {
        let var = format!(
            "VARSTO_S3_SECRET_{}",
            name.to_uppercase()
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        );
        std::env::set_var(var, s);
    }
    let mut b = Engine::join(&b_home, "desk", PASS, &key, spec_b).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.pull("docs").unwrap();
    assert_eq!(
        fs::read(b_dir.join("report.txt")).unwrap(),
        b"synced through a remote bucket"
    );
    let status = a.status().unwrap();
    assert_eq!(status.folders.len(), 1);
}

#[test]
fn s3_backend_against_local_s3_server() {
    if !have_rclone() {
        eprintln!("rclone not installed; skipping");
        return;
    }
    let data = tempfile::tempdir().unwrap();
    fs::create_dir_all(data.path().join("bucket1")).unwrap();
    let server = S3Server::start(data.path());
    let spec = StorageSpec::S3 {
        name: "s3test".into(),
        endpoint: server.endpoint.clone(),
        region: "us-east-1".into(),
        bucket: "bucket1".into(),
        prefix: "varsto".into(),
        access_key_id: "testkey".into(),
        secret_ref: String::new(),
        path_style: true,
        storage_class: None,
        cold: false,
    };
    let secrets = |_: &str| Some("testsecret".to_string());
    let st = spec.open_with(&secrets).unwrap();
    storage_contract(st.as_ref());
    // Wrong secret is rejected by the server.
    let bad = spec.open_with(&|_| Some("wrong".to_string())).unwrap();
    assert!(bad.put_if_absent("x", b"y").is_err());
    two_devices_through(spec.clone(), Some("testsecret".into()), spec);
}

#[test]
fn rclone_backend_against_local_remote() {
    if !have_rclone() {
        eprintln!("rclone not installed; skipping");
        return;
    }
    let data = tempfile::tempdir().unwrap();
    let remote = format!(":local:{}", data.path().join("store").display());
    let spec = StorageSpec::Rclone {
        name: "rc".into(),
        remote: remote.clone(),
        cold: false,
    };
    let st = spec.open().unwrap();
    storage_contract(st.as_ref());
    two_devices_through(spec.clone(), None, spec);
}
