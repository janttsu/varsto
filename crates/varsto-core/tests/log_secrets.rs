// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Canary test of the local debug log: every kind of secret is logged
//! through every macro form (Debug, Display, fields, message text) at every
//! level, and none may appear in the log files or in a diagnostics bundle.

use varsto_core::crypto::{SecretKey, SigningKey};
use varsto_core::logging::{self, Options};
use varsto_core::replica::ReplicaToken;
use varsto_core::s3::S3Config;
use varsto_core::vault::{SecretStore, ShareToken};

#[test]
fn no_secret_reaches_the_log() {
    let home = tempfile::tempdir().unwrap();
    // A passphrase in the environment is registered at start.
    let passphrase = "canary passphrase Kx7-q2";
    std::env::set_var("VARSTO_PASSPHRASE", passphrase);
    std::env::remove_var("VARSTO_LOG");
    let mut o = Options::new(home.path(), "test");
    o.level = Some("trace,log_secrets=trace".into());
    logging::init(o).unwrap();

    // Key material.
    let master = SecretKey::random();
    let master_hex = master.to_hex();
    logging::register_key(master.as_bytes());
    let signer = SigningKey::generate();
    let signer_hex = hex::encode(signer.to_bytes());
    let folder_key = SecretKey::random();
    let folder_hex = folder_key.to_hex();
    // Tokens.
    let vault = "1a".repeat(16);
    let folder = "2b".repeat(16);
    let share = ShareToken::decode(&format!("{vault}.{folder}.{folder_hex}.Photos")).unwrap();
    let share_text = share.encode();
    let replica_hex = SecretKey::random().to_hex();
    let replica = ReplicaToken {
        vault_id: share.vault_id.clone(),
        replica_key_hex: replica_hex.clone(),
    };
    let replica_text = replica.encode();
    let sealed = "vst2.Zm9vYmFyLXNlYWxlZC1jYW5hcnktdG9rZW4";
    let mcp_key = "vmk_c4n4ryM0d3lK3yS3cr3t";
    let service_token = hex::encode([0x5au8; 32]);
    logging::register_secret(&service_token);
    // Storage credentials.
    let s3_secret = "canary/S3+secret+AKIAEXAMPLEKEY";
    let s3 = S3Config {
        name: "bucket-store".into(),
        endpoint: "https://s3.example.test".into(),
        region: "eu".into(),
        bucket: "b".into(),
        prefix: String::new(),
        access_key_id: "AKIDCANARY".into(),
        secret_access_key: s3_secret.into(),
        path_style: true,
        storage_class: None,
    };
    // Constructing the storage registers its secret; here register directly.
    logging::register_secret(s3_secret);
    let mut store = SecretStore::default();
    store
        .secrets
        .insert("bucket-store".into(), s3_secret.into());
    let rclone_token = r#"{"access_token":"ya29.canaryRcloneAccessToken"}"#;
    let restic_password = "canary-restic-pw-991";
    // Recovery words.
    let words = varsto_core::recovery::words_from_key(&master_hex).unwrap();
    let shares = varsto_core::recovery::split(&master_hex, 2, 3).unwrap();
    // As `FolderKeys` does for every folder key it derives from.
    logging::register_key(folder_key.as_bytes());

    let secrets: Vec<(&str, String)> = vec![
        ("passphrase", passphrase.to_string()),
        ("master", master_hex.clone()),
        ("signer", signer_hex.clone()),
        ("folder key", folder_hex.clone()),
        ("replica key", replica_hex.clone()),
        ("sealed", "Zm9vYmFyLXNlYWxlZC1jYW5hcnktdG9rZW4".to_string()),
        ("mcp", "c4n4ryM0d3lK3yS3cr3t".to_string()),
        ("service token", service_token.clone()),
        ("s3", s3_secret.to_string()),
        ("rclone", "ya29.canaryRcloneAccessToken".to_string()),
        ("restic", restic_password.to_string()),
        // Any five consecutive words of the phrase.
        (
            "words",
            words
                .split_whitespace()
                .take(5)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        (
            "share words",
            shares[0]
                .words
                .split_whitespace()
                .skip(3)
                .take(5)
                .collect::<Vec<_>>()
                .join(" "),
        ),
    ];

    // Debug of the secret types.
    log::debug!("keys {master:?} {signer:?} {folder_key:?}");
    log::info!("share {share:?} replica {replica:?} s3 {s3:?} store {store:?}");
    log::trace!("recovery share {:?}", shares[0]);
    // Display / encoded forms in message text.
    log::warn!(
        "share token {share_text} replica token {replica_text} sealed {sealed} mcp {mcp_key}"
    );
    log::error!(
        "failed: {}",
        format_args!("http://127.0.0.1:1/?token={service_token}&x=1")
    );
    log::debug!(
        "restic env RESTIC_PASSWORD={restic_password} rclone config token = {rclone_token}"
    );
    log::debug!("recovery words: {}", words.as_str());
    log::debug!("kit:\n1: {}\n2: {}", shares[0].words, shares[1].words);
    log::debug!("master hex by mistake {master_hex} and folder key {folder_hex}");
    // Fields in every capture form.
    log::debug!(token = service_token.as_str(), passphrase = passphrase, key_hex:% = folder_hex, secret:? = s3_secret; "fields with secret names");
    log::debug!(value:% = share_text, other:? = replica_text, plain = mcp_key, words = words.as_str(); "fields with neutral names");
    log::debug!(key:? = master, s:? = signer, cfg:? = s3; "typed fields");
    log::info!(path = "Photos/2026/IMG_0001.jpg", bytes = 42u64; "allowed: names and sizes");
    logging::flush();

    let dir = logging::dir(home.path());
    let mut text = String::new();
    for f in logging::files::list(&dir) {
        text.push_str(&logging::files::read_text(&f.path).unwrap());
    }
    if std::env::var_os("VARSTO_SHOW_LOG").is_some() {
        eprintln!("{text}");
    }
    assert!(text.contains("allowed: names and sizes"), "{text}");
    assert!(
        text.contains("Photos/2026/IMG_0001.jpg"),
        "file names are allowed in the local log"
    );
    assert!(text.contains("[redacted]"));
    for (what, s) in &secrets {
        assert!(
            !text.contains(s.as_str()),
            "{what} leaked into the log:\n{text}"
        );
    }

    // The bundle is scrubbed again and holds the extras.
    let extra = vec![(
        "note.txt".to_string(),
        format!("token={service_token}").into_bytes(),
    )];
    let bundle = logging::bundle(home.path(), &extra, Vec::new()).unwrap();
    let tar = zstd::decode_all(&bundle[..]).unwrap();
    let tar = String::from_utf8_lossy(&tar);
    assert!(tar.contains("varsto-logs/varsto-test.log"));
    assert!(tar.contains("varsto-logs/note.txt"));
    for (what, s) in &secrets {
        assert!(!tar.contains(s.as_str()), "{what} leaked into the bundle");
    }

    // The log files are private to the user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(logging::files::active_path(&dir, "test")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        let d = std::fs::metadata(&dir).unwrap();
        assert_eq!(d.permissions().mode() & 0o777, 0o700);
    }
}
