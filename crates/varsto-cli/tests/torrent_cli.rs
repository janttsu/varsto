// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto torrent` through the binary, against the in-process fake
//! transmission: add, run to completion, list, status, remove.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use varsto_core::transmission::{fake::FakeTransmission, make_metainfo};

fn run(home: &Path, args: &[&str], json: bool) -> (bool, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home").arg(home);
    if json {
        c.arg("--json");
    }
    let out = c
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        // New folders go next to the device directory, never into ~/Varsto.
        .env("VARSTO_FOLDER_ROOT", home.parent().unwrap().join("folders"))
        .env_remove("VARSTO_TRANSMISSION_URL")
        .output()
        .expect("run varsto");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ok(home: &Path, args: &[&str]) -> serde_json::Value {
    let (success, stdout, stderr) = run(home, args, true);
    assert!(success, "varsto {args:?} failed: {stderr}");
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout))
}

#[test]
fn a_torrent_job_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home");
    ok(&home, &["init", "--name", "laptop"]);
    ok(
        &home,
        &[
            "storage",
            "add-local",
            "box",
            root.join("box").to_str().unwrap(),
        ],
    );
    let a = b"first file of the torrent".repeat(50);
    let b = b"second one".repeat(300);
    let meta = make_metainfo("Album", &[("a.flac", &a), ("disc 2/b.flac", &b)], 1024);
    fs::write(root.join("album.torrent"), &meta).unwrap();
    let fake = Arc::new(FakeTransmission::start(root));
    fake.provide(&meta, &[a.clone(), b.clone()]);
    let url = fake.settings().url;
    // The daemon downloads whatever is wanted, a little at a time.
    let stop = Arc::new(AtomicBool::new(false));
    let stepper = {
        let (fake, stop) = (fake.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                fake.step(4096);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    let dl = root.join("dl");
    let job = ok(
        &home,
        &[
            "torrent",
            "add",
            root.join("album.torrent").to_str().unwrap(),
            "--folder",
            "album",
            "--storage",
            "box",
            "--download-dir",
            dl.to_str().unwrap(),
            "--free-min",
            "1%",
            "--rpc-url",
            &url,
        ],
    );
    let hash = job["hash"].as_str().unwrap().to_string();
    assert_eq!(job["files"].as_array().unwrap().len(), 2);
    // A bad reserve is refused.
    let (fine, _, err) = run(
        &home,
        &[
            "torrent",
            "add",
            "x.torrent",
            "--folder",
            "x",
            "--free-min",
            "lots",
        ],
        true,
    );
    assert!(!fine && err.contains("lots"), "{err}");
    let (fine, out, _) = run(&home, &["status"], false);
    assert!(fine);
    assert!(out.contains("torrent ") && out.contains("Album"), "{out}");

    let done = ok(
        &home,
        &[
            "torrent",
            "run",
            &hash[..10],
            "--interval",
            "1",
            "--rpc-url",
            &url,
        ],
    );
    stop.store(true, Ordering::Relaxed);
    stepper.join().unwrap();
    assert_eq!(done["state"], "complete", "{done:#}");
    assert_eq!(done["bytes_stored"], (a.len() + b.len()) as u64);
    assert_eq!(fs::read_dir(&dl).unwrap().count(), 0);
    assert!(
        root.join("folders/album/Album/a.flac.varsto-placeholder")
            .is_file(),
        "the folder is attached selectively under the folder root"
    );

    let list = ok(&home, &["torrent", "list"]);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (fine, out, _) = run(&home, &["torrent", "status", "album"], false);
    assert!(fine && out.contains("complete"), "{out}");
    let (_, out, _) = run(&home, &["status"], false);
    assert!(!out.contains("Album"), "complete jobs are not shown: {out}");

    ok(&home, &["torrent", "remove", "album", "--rpc-url", &url]);
    assert!(!fake.has(&hash));
    assert!(ok(&home, &["torrent", "list"])
        .as_array()
        .unwrap()
        .is_empty());
}
