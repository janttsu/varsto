// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The recovery package guide of a vault with every kind of storage, a disk
//! pool, a Strongroom folder and restic settings: every item is there, and
//! no secret is anywhere in it, in any format.

use std::fs;
use varsto_core::engine::Engine;
use varsto_core::recovery_guide::{self, Status};
use varsto_core::storage::StorageSpec;
use varsto_core::strongroom::{Method, SoftwareKey};

const PASS: &str = "guide-test-passphrase-7731";
const S3_SECRET: &str = "S3SECRETdoNotLeak/9f8e7d6c5b4a";
const RESTIC_PASSWORD: &str = "restic-password-never-shown-4411";
const RCLONE_TOKEN: &str = "rclone-token-never-shown-0937";

#[test]
fn guide_covers_every_storage_and_holds_no_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let (mut e, key_hex) = Engine::init(&home, "laptop", PASS).unwrap();
    let words = varsto_core::recovery::key_from_words(
        &varsto_core::recovery::words_from_key(&key_hex).unwrap(),
    )
    .unwrap();
    assert_eq!(words, key_hex);
    let words = varsto_core::recovery::words_from_key(&key_hex).unwrap();

    let nas = tmp.path().join("nas");
    e.add_storage(StorageSpec::LocalDir {
        name: "nas".into(),
        path: nas.clone(),
        cold: false,
        carrier: false,
        place: "home".into(),
    })
    .unwrap();
    e.add_storage(StorageSpec::Pool {
        name: "shelf".into(),
        place: "offsite".into(),
        reserve_percent: 5,
        min_reserve_bytes: 0,
        disks: vec![],
        scan_roots: vec![],
        copies: 2,
        verify_after_days: 180,
    })
    .unwrap();
    let docs = tmp.path().join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("a.txt"), b"hello").unwrap();
    e.add_folder("docs", &docs).unwrap();
    let sk = SoftwareKey {
        path: home.join("software-security-key"),
    };
    e.create_strongroom(
        "private",
        &tmp.path().join("private"),
        Method::Software,
        &sk,
        15,
    )
    .unwrap();
    e.store_secret("bucket", S3_SECRET).unwrap();
    drop(e);

    // A bucket and an rclone remote, written into the configuration as the
    // command line would (without reaching a server), a disk of the pool,
    // its disks.conf line and restic settings from a newer version.
    let cfg_path = home.join("config.json");
    let mut cfg: serde_json::Value = serde_json::from_slice(&fs::read(&cfg_path).unwrap()).unwrap();
    let storages = cfg["storages"].as_array_mut().unwrap();
    storages.push(serde_json::json!({
        "kind": "s3", "name": "bucket", "endpoint": "https://s3.fr-par.scw.cloud",
        "region": "fr-par", "bucket": "varsto-test-3", "prefix": "", "access_key_id": "SCWACCESSKEYID123",
        "secret_ref": "bucket", "path_style": true, "storage_class": "GLACIER", "cold": true, "place": "cloud"
    }));
    storages.push(serde_json::json!({
        "kind": "s3", "name": "hot", "endpoint": "https://s3.eu-central-003.backblazeb2.com",
        "region": "eu-central-003", "bucket": "varsto-hot", "prefix": "v1", "access_key_id": "B2KEYID456",
        "secret_ref": "", "path_style": true
    }));
    storages
        .push(serde_json::json!({ "kind": "rclone", "name": "drive", "remote": "gdrive:varsto" }));
    for s in storages.iter_mut() {
        if s["kind"] == "pool" {
            s["disks"] = serde_json::json!([{ "id": "00112233445566778899aabbccddeeff", "label": "Blue 4TB",
                "last_seen_utc": 1791849600, "place": "office" }]);
        }
    }
    cfg["restic"] = serde_json::json!({
        "root": "/srv/mirror",
        "repository": "rest:https://bob:hunter2pass@backup.example:8000/vault",
        "password": { "file": home.join("restic-password").display().to_string() },
        "env_file": home.join("restic.env").display().to_string()
    });
    fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    fs::write(home.join("restic-password"), RESTIC_PASSWORD).unwrap();
    fs::write(
        home.join("restic.env"),
        format!("B2_ACCOUNT_KEY={RCLONE_TOKEN}\n"),
    )
    .unwrap();
    fs::write(
        home.join("disks.conf"),
        "# drives\n0f1e2d3c-0000-4000-8000-000000000001\tshelf\tBlue 4TB\n",
    )
    .unwrap();

    let e = Engine::open(&home, PASS).unwrap();
    let mut g = e.recovery_guide();
    // Before the kit is printed Varsto cannot know; after, it does.
    assert_eq!(g.items[0].kind, "recovery_kit");
    assert_eq!(g.items[0].status, Status::Check);
    recovery_guide::record_kit_printed(&home, e.key_epoch(), false).unwrap();
    g = e.recovery_guide();
    assert_eq!(g.items[0].status, Status::Done);

    let kinds: Vec<&str> = g.items.iter().map(|i| i.kind.as_str()).collect();
    for k in [
        "recovery_kit",
        "local_dir",
        "pool",
        "s3",
        "rclone",
        "strongroom",
        "restic",
    ] {
        assert!(kinds.contains(&k), "no {k} item in {kinds:?}");
    }
    let ids: Vec<&str> = g.items.iter().map(|i| i.id.as_str()).collect();
    for id in [
        "storage:nas",
        "storage:shelf",
        "storage:bucket",
        "storage:hot",
        "storage:drive",
        "strongroom:private",
        "restic",
    ] {
        assert!(ids.contains(&id), "no {id} in {ids:?}");
    }
    let step_ids: Vec<&str> = g.steps.iter().map(|s| s.id.as_str()).collect();
    for id in [
        "install",
        "shares",
        "join",
        "storages",
        "pool:shelf",
        "folders",
        "strongroom",
        "cold",
        "after",
    ] {
        assert!(step_ids.contains(&id), "no step {id} in {step_ids:?}");
    }
    assert_eq!(g.alternatives.len(), 1, "restic restore");

    let text = recovery_guide::render_text(&g);
    let md = recovery_guide::render_markdown(&g);
    let html = recovery_guide::render_html(&g);
    let json = serde_json::to_string(&g).unwrap();
    // Facts that belong in it.
    for want in [
        "varsto-test-3",
        "s3.fr-par.scw.cloud",
        "gdrive:varsto",
        "Blue 4TB",
        "office",
        "0f1e2d3c-0000-4000-8000-000000000001",
        "private",
        "backup.example",
        &nas.display().to_string(),
        "varsto join --words \"<24 recovery words>\" --storage-name \"hot\"",
        "varsto storage add-pool \"shelf\" --place \"offsite\" --copies 2",
        "varsto strongroom unlock \"private\"",
        "restic -r \"rest:https://<user>:<password>@backup.example:8000/vault\"",
    ] {
        assert!(text.contains(want), "text lacks {want}:\n{text}");
    }
    // Secrets that never do.
    let first_words: String = words.split(' ').take(3).collect::<Vec<_>>().join(" ");
    for (label, secret) in [
        ("vault key", key_hex.as_str()),
        ("words", words.as_str()),
        ("first words", first_words.as_str()),
        ("passphrase", PASS),
        ("s3 secret", S3_SECRET),
        ("s3 access key id", "SCWACCESSKEYID123"),
        ("restic password", RESTIC_PASSWORD),
        ("restic repository password", "hunter2pass"),
        ("credentials file", RCLONE_TOKEN),
    ] {
        for (fmt, body) in [
            ("text", &text),
            ("markdown", &md),
            ("html", &html),
            ("json", &json),
        ] {
            assert!(!body.contains(secret), "{label} appears in the {fmt} guide");
        }
    }
}

#[test]
fn a_member_device_is_told_to_ask_for_the_share_again() {
    let inputs = recovery_guide::Inputs {
        vault_id: "v".into(),
        device: "phone".into(),
        member: true,
        folders: vec![recovery_guide::FolderInput {
            name: "family photos".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let g = recovery_guide::build(&inputs);
    assert!(g.member);
    assert_eq!(g.items.len(), 1);
    assert_eq!(g.items[0].kind, "shared_folder");
    assert!(recovery_guide::render_text(&g).contains("varsto share request"));
    assert!(!g.items.iter().any(|i| i.kind == "recovery_kit"));
}

#[test]
fn an_old_kit_is_out_of_date_after_a_key_change() {
    let inputs = recovery_guide::Inputs {
        vault_id: "v".into(),
        device: "laptop".into(),
        key_epoch: 2,
        kit: Some(recovery_guide::KitRecord {
            printed_utc: 1_791_849_600,
            key_epoch: 1,
            shares: false,
        }),
        ..Default::default()
    };
    let g = recovery_guide::build(&inputs);
    assert_eq!(g.items[0].status, Status::Outdated);
    assert!(g.items[0]
        .status_note
        .as_ref()
        .unwrap()
        .render()
        .contains("2026-10-13"));
}
