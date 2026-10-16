// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `reset --yes` leaves a home where a new vault can be set up again.

use std::path::Path;
use std::process::{Command, Output};

fn varsto(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_NO_INSTALL", "1")
        .output()
        .expect("run varsto")
}

#[test]
fn init_works_again_after_reset() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");

    let first = varsto(&home, &["init", "--name", "orca"]);
    assert!(
        first.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(home.join("vault.json").exists());

    let reset = varsto(&home, &["reset", "--yes"]);
    assert!(
        reset.status.success(),
        "reset failed: {}",
        String::from_utf8_lossy(&reset.stderr)
    );
    assert!(!home.join("vault.json").exists(), "reset left vault.json");

    let again = varsto(&home, &["init", "--name", "orca"]);
    assert!(
        again.status.success(),
        "init after reset failed: {}",
        String::from_utf8_lossy(&again.stderr)
    );
}
