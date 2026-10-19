// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Two engines on one device directory: the background service keeps its
//! engine open while a command-line `varsto sync` opens another. Their syncs
//! must not undo each other's local state (block map tables, ledger).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

struct Lab {
    _tmp: tempfile::TempDir,
    storage: StorageSpec,
    home: PathBuf,
    dir: PathBuf,
    root: PathBuf,
}

fn lab() -> (Lab, String) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    let home = root.join("home");
    let dir = root.join("docs");
    let (mut e, words) = Engine::init(&home, "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(storage.clone()).unwrap();
    e.add_folder("docs", &dir).unwrap();
    fs::write(dir.join("first.bin"), data(40_000, 1)).unwrap();
    e.sync(None).unwrap();
    (
        Lab {
            _tmp: tmp,
            storage,
            home,
            dir,
            root,
        },
        words,
    )
}

/// Every file of the folder arrives on a fresh device, and fsck finds
/// nothing wrong at home.
fn assert_consistent(lab: &Lab, words: &str, expect: &[&str]) {
    let mut e = open(&lab.home);
    let report = e.fsck(true).unwrap();
    let f3 = report.format3.as_ref().expect("a format-3 report");
    assert!(
        f3.is_clean(),
        "fsck after the two engines: {}",
        f3.describe()
    );
    assert!(
        e.ledger_health().is_ok(),
        "{}",
        e.ledger_health().describe()
    );
    let other_home = lab.root.join("other-home");
    let other_dir = lab.root.join("other-docs");
    let mut b = Engine::join(&other_home, "desk", PASS, words, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    common::approve_all(&mut e, &mut b);
    b.attach_folder("docs", &other_dir, false).unwrap();
    b.pull("docs").unwrap();
    for name in expect {
        assert_eq!(
            fs::read(other_dir.join(name)).ok(),
            fs::read(lab.dir.join(name)).ok(),
            "{name} did not arrive"
        );
    }
}

#[test]
fn a_second_engine_on_the_same_home_does_not_break_the_first() {
    let (lab, words) = lab();
    // The service's engine, open for the whole test.
    let mut service = open(&lab.home);
    service.sync(None).unwrap();
    // The command line syncs new files with an engine of its own.
    fs::write(lab.dir.join("cli.bin"), data(50_000, 2)).unwrap();
    {
        let mut cli = open(&lab.home);
        cli.sync(None).unwrap();
    }
    // The service goes on syncing.
    fs::write(lab.dir.join("service.bin"), data(60_000, 3)).unwrap();
    service.sync(None).unwrap();
    fs::write(lab.dir.join("cli2.bin"), data(30_000, 4)).unwrap();
    {
        let mut cli = open(&lab.home);
        cli.sync(None).unwrap();
    }
    fs::write(lab.dir.join("service2.bin"), data(20_000, 5)).unwrap();
    service.sync(None).unwrap();
    drop(service);
    assert_consistent(
        &lab,
        &words,
        &[
            "first.bin",
            "cli.bin",
            "service.bin",
            "cli2.bin",
            "service2.bin",
        ],
    );
}

#[test]
fn concurrent_syncs_of_two_engines_on_one_home_stay_consistent() {
    let (lab, words) = lab();
    let mut service = open(&lab.home);
    let mut cli = open(&lab.home);
    let dir = lab.dir.clone();
    for round in 0..4u64 {
        fs::write(dir.join(format!("s{round}.bin")), data(30_000, 10 + round)).unwrap();
        fs::write(dir.join(format!("c{round}.bin")), data(30_000, 20 + round)).unwrap();
        std::thread::scope(|s| {
            let a = s.spawn(|| service.sync(None).map(|_| ()));
            let b = s.spawn(|| cli.sync(None).map(|_| ()));
            a.join().unwrap().unwrap();
            b.join().unwrap().unwrap();
        });
    }
    service.sync(None).unwrap();
    cli.sync(None).unwrap();
    drop(service);
    drop(cli);
    let names: Vec<String> = (0..4)
        .flat_map(|r| [format!("s{r}.bin"), format!("c{r}.bin")])
        .collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_consistent(&lab, &words, &names);
}
