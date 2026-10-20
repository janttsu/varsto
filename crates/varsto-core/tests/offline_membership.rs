// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Membership changes while the vault's storage does not answer: they are
//! made from this device's copy of the records, kept in its outbox, counted
//! as waiting to upload, and sent by the next refresh once the storage is
//! back. Runs against `rclone serve s3` (a local S3 server) and skips when
//! rclone 1.65+ is not installed.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use varsto_core::engine::Engine;
use varsto_core::storage::StorageSpec;

const PASS: &str = "correct horse battery staple";

fn have_rclone_s3_server() -> bool {
    Command::new("rclone")
        .args(["serve", "s3", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct S3Server {
    child: Child,
}

impl S3Server {
    fn start_on(root: &Path, port: u16) -> S3Server {
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
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        S3Server { child }
    }
}

impl Drop for S3Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn membership_changes_wait_on_the_device_while_the_bucket_is_away() {
    if !have_rclone_s3_server() {
        eprintln!("rclone 1.65+ with `serve s3` not installed; skipping");
        return;
    }
    let data = tempfile::tempdir().unwrap();
    fs::create_dir_all(data.path().join("bucket1")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server = S3Server::start_on(data.path(), port);
    let spec = StorageSpec::S3 {
        name: "offline".into(),
        endpoint: format!("http://127.0.0.1:{port}"),
        region: "us-east-1".into(),
        bucket: "bucket1".into(),
        prefix: "varsto".into(),
        access_key_id: "testkey".into(),
        secret_ref: String::new(),
        path_style: true,
        storage_class: None,
        cold: false,
        place: String::new(),
        allow_insecure_http: false,
    };
    std::env::set_var("VARSTO_S3_SECRET_OFFLINE", "testsecret");
    let root = tempfile::tempdir().unwrap();
    let (a_home, b_home) = (root.path().join("a"), root.path().join("b"));
    let (docs, photos) = (root.path().join("docs"), root.path().join("photos"));
    let (mut a, key) = Engine::init(&a_home, "laptop", PASS).unwrap();
    a.add_storage_with_secret(spec.clone(), Some("testsecret".into()))
        .unwrap();
    a.add_folder("docs", &docs).unwrap();
    let mut b = Engine::join(&b_home, "desk", PASS, &key, spec).unwrap();
    // While the bucket answers: the desk asks for docs, and the laptop
    // reads the request (into its copy of the records).
    let asked = b.f3_folder_request("docs", "viewer").unwrap();
    assert_eq!(a.f3_requests(None).unwrap().len(), 1);
    assert_eq!(a.records_waiting3(), 0);

    // The bucket goes away.
    drop(server);
    // Adding a folder works and its records wait here.
    a.add_folder("photos", &photos).unwrap();
    assert!(a.folders().iter().any(|(r, _)| r.name == "photos"));
    let after_add = a.records_waiting3();
    assert!(after_add >= 2, "folder record and grant wait: {after_add}");
    // Approving the request works from this device's copy.
    let m = a
        .f3_approve("docs", &asked.device_id, None, Some(&asked.fingerprint))
        .unwrap();
    assert!(m
        .participants
        .iter()
        .any(|p| p.device_id == asked.device_id && p.role == "viewer"));
    assert!(a.records_waiting3() > after_add);
    // The status check of recovery copies answers without the network.
    assert!(!a.f3_missing_escrows().unwrap().is_empty());
    // The members page answers too, from this device's copy.
    assert!(a.f3_members("photos").is_ok());

    // The bucket is back: the next refresh sends everything once.
    let _server = S3Server::start_on(data.path(), port);
    a.refresh_devices().unwrap();
    assert_eq!(a.records_waiting3(), 0);
    b.refresh_devices().unwrap();
    let mine = b.f3_members("docs").unwrap();
    assert_eq!(mine.your_role.as_deref(), Some("viewer"));
    assert!(b.f3_folders().unwrap().iter().any(|f| f.folder == "photos"));
}
