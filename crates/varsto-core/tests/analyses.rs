// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! File analyses (`docs/spec/alpha-0-format.md`, section "File analyses"):
//! set and read back, shown in listings, merged across two devices newest
//! first, following a rename by content hash and a move directly, stale after
//! the file changed, dropped with a deleted file, size limits, and kept
//! encrypted on the storage.

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Lab {
            storage: StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("storage"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            },
            root,
            _tmp: tmp,
        }
    }
    fn home(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-home"))
    }
    fn dir(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-docs"))
    }
}

fn small(mut e: Engine) -> Engine {
    e.chunker = ChunkerParams::SMALL;
    e
}

/// Device A with folder "docs" holding two files, synced.
fn device_a(lab: &Lab) -> (Engine, String) {
    let (a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    fs::create_dir_all(lab.dir("a")).unwrap();
    fs::write(
        lab.dir("a").join("receipt.txt"),
        b"Hardware store, 3 boxes of screws, 12.40 EUR",
    )
    .unwrap();
    fs::write(lab.dir("a").join("trip.txt"), b"Train to Lyon, 9 December").unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    a.sync(None).unwrap();
    (a, key)
}

fn device_b(lab: &Lab, a: &mut Engine, key: &str) -> Engine {
    let mut b =
        small(Engine::join(&lab.home("b"), "phone", PASS, key, lab.storage.clone()).unwrap());
    Engine::grant_all_for_tests(a, &mut b).unwrap();
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    b
}

fn tags(t: &[&str]) -> Vec<String> {
    t.iter().map(|s| s.to_string()).collect()
}

#[test]
fn set_read_list_and_limits() {
    let lab = Lab::new();
    let (mut a, _) = device_a(&lab);
    assert!(a.analysis("docs", "receipt.txt").unwrap().is_none());
    let set = a
        .set_analysis(
            "docs",
            "receipt.txt",
            "A receipt from a hardware store: screws, 12.40 EUR.",
            &tags(&["receipt", "hardware", "receipt"]),
            Some("qwen3:8b"),
        )
        .unwrap();
    assert_eq!(set.tags, tags(&["receipt", "hardware"]));
    assert!(!set.stale);
    let got = a.analysis("docs", "receipt.txt").unwrap().unwrap();
    assert_eq!(got, set);
    assert_eq!(got.author, "laptop");
    assert_eq!(got.by.as_deref(), Some("qwen3:8b"));

    // Listings carry it, cut to LISTING_CHARS.
    let long = "word ".repeat(400);
    a.set_analysis("docs", "trip.txt", &long, &[], None)
        .unwrap();
    let list = a.list_files("docs").unwrap();
    let trip = list.iter().find(|f| f.path == "trip.txt").unwrap();
    assert!(trip.analysis_truncated);
    assert_eq!(
        trip.analysis.as_ref().unwrap().chars().count(),
        varsto_core::engine::LISTING_CHARS
    );
    let receipt = list.iter().find(|f| f.path == "receipt.txt").unwrap();
    assert!(!receipt.analysis_truncated);
    assert_eq!(receipt.analysis_tags, tags(&["receipt", "hardware"]));
    assert_eq!(receipt.analysis_by.as_deref(), Some("qwen3:8b"));
    // The full text is there.
    assert_eq!(
        a.analysis("docs", "trip.txt").unwrap().unwrap().analysis,
        long.trim_end()
    );

    // Limits: text, tags, unknown files.
    let too_long = "x".repeat(varsto_core::engine::ANALYSIS_MAX_BYTES + 1);
    assert!(a
        .set_analysis("docs", "trip.txt", &too_long, &[], None)
        .is_err());
    let many: Vec<String> = (0..33).map(|i| format!("t{i}")).collect();
    assert!(a
        .set_analysis("docs", "trip.txt", "ok", &many, None)
        .is_err());
    assert!(a
        .set_analysis("docs", "trip.txt", "ok", &["x".repeat(65)], None)
        .is_err());
    assert!(a
        .set_analysis("docs", "nothing.txt", "ok", &[], None)
        .is_err());

    // Search: words in text, tags and paths.
    let hits = a.search_analyses("docs", "SCREWS", &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "receipt.txt");
    assert!(hits[0].snippet.contains("screws"));
    assert_eq!(hits[0].state, "local");
    assert!(hits[0].disk.ends_with("receipt.txt"));
    let by_tag = a.search_analyses("docs", "", &tags(&["Hardware"])).unwrap();
    assert_eq!(by_tag.len(), 1);
    let by_path = a.search_analyses("docs", "trip", &[]).unwrap();
    assert_eq!(by_path[0].path, "trip.txt");
    assert!(a
        .search_analyses("docs", "screws lyon", &[])
        .unwrap()
        .is_empty());

    // Clearing.
    assert!(a.clear_analysis("docs", "trip.txt").unwrap());
    assert!(!a.clear_analysis("docs", "trip.txt").unwrap());
    assert!(a.analysis("docs", "trip.txt").unwrap().is_none());
}

#[test]
fn analyses_merge_across_devices_newest_first() {
    let lab = Lab::new();
    let (mut a, key) = device_a(&lab);
    let mut b = device_b(&lab, &mut a, &key);
    a.set_analysis(
        "docs",
        "trip.txt",
        "train ticket",
        &tags(&["travel"]),
        Some("model-a"),
    )
    .unwrap();
    assert_eq!(a.exchange_notes().unwrap().published, 1);
    // Sealed on the storage: no text, tag or path in the clear.
    let mut found = 0;
    for e in walkdir::WalkDir::new(lab.root.join("storage").join("vault/notes"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        found += 1;
        let raw = fs::read(e.path()).unwrap();
        for needle in [&b"train ticket"[..], b"travel", b"trip.txt"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
    }
    assert_eq!(found, 1);

    assert_eq!(b.exchange_notes().unwrap().received, 1);
    let got = b.analysis("docs", "trip.txt").unwrap().unwrap();
    assert_eq!(got.analysis, "train ticket");
    assert_eq!(got.author, "laptop");

    // B writes a newer one; A takes it.
    b.set_analysis(
        "docs",
        "trip.txt",
        "train ticket to Lyon",
        &[],
        Some("model-b"),
    )
    .unwrap();
    b.exchange_notes().unwrap();
    // A learns of B (the vault registry) with a sync, then reads its record.
    a.sync(None).unwrap();
    a.exchange_notes().unwrap();
    let got = a.analysis("docs", "trip.txt").unwrap().unwrap();
    assert_eq!(got.analysis, "train ticket to Lyon");
    assert_eq!(got.author, "phone");
    // A's older record does not bring the old text back on B.
    b.exchange_notes().unwrap();
    assert_eq!(
        b.analysis("docs", "trip.txt").unwrap().unwrap().analysis,
        "train ticket to Lyon"
    );

    // A clears it: cleared everywhere.
    assert!(a.clear_analysis("docs", "trip.txt").unwrap());
    a.exchange_notes().unwrap();
    b.exchange_notes().unwrap();
    assert!(b.analysis("docs", "trip.txt").unwrap().is_none());
    // One record per device.
    let records = walkdir::WalkDir::new(lab.root.join("storage").join("vault/notes"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(records, 2);
}

#[test]
fn analyses_follow_renames_and_moves_and_go_stale_or_away() {
    let lab = Lab::new();
    let (mut a, key) = device_a(&lab);
    a.set_analysis("docs", "receipt.txt", "screws", &tags(&["receipt"]), None)
        .unwrap();
    a.set_analysis("docs", "trip.txt", "train", &[], None)
        .unwrap();

    // Renamed on disk: the scan sees a deletion and a new file with the
    // same content; the analysis follows by content hash.
    fs::create_dir_all(lab.dir("a").join("2026")).unwrap();
    fs::rename(
        lab.dir("a").join("receipt.txt"),
        lab.dir("a").join("2026/receipt.txt"),
    )
    .unwrap();
    a.sync(None).unwrap();
    assert!(a.analysis("docs", "receipt.txt").is_err(), "gone");
    let moved = a.analysis("docs", "2026/receipt.txt").unwrap().unwrap();
    assert_eq!(moved.analysis, "screws");
    assert!(!moved.stale);

    // move_file carries it directly.
    a.move_file("docs", "trip.txt", "travel/trip.txt").unwrap();
    assert_eq!(
        a.analysis("docs", "travel/trip.txt")
            .unwrap()
            .unwrap()
            .analysis,
        "train"
    );

    // The other device sees both where the files are now.
    let mut b = device_b(&lab, &mut a, &key);
    b.exchange_notes().unwrap();
    assert_eq!(
        b.analysis("docs", "2026/receipt.txt")
            .unwrap()
            .unwrap()
            .analysis,
        "screws"
    );
    assert!(b.analysis("docs", "travel/trip.txt").unwrap().is_some());

    // Edited: stale, also in listings and on the other device.
    fs::write(
        lab.dir("a").join("travel/trip.txt"),
        b"Train to Lyon, 10 December",
    )
    .unwrap();
    a.sync(None).unwrap();
    assert!(
        a.analysis("docs", "travel/trip.txt")
            .unwrap()
            .unwrap()
            .stale
    );
    let list = a.list_files("docs").unwrap();
    assert!(list
        .iter()
        .any(|f| f.path == "travel/trip.txt" && f.analysis_stale));
    b.sync(None).unwrap();
    assert!(
        b.analysis("docs", "travel/trip.txt")
            .unwrap()
            .unwrap()
            .stale
    );

    // Deleted: dropped, also on the other device.
    fs::remove_file(lab.dir("a").join("2026/receipt.txt")).unwrap();
    a.sync(None).unwrap();
    a.exchange_notes().unwrap();
    assert!(a
        .analyses("docs")
        .unwrap()
        .iter()
        .all(|x| x.path != "2026/receipt.txt"));
    b.sync(None).unwrap();
    b.exchange_notes().unwrap();
    assert_eq!(b.analyses("docs").unwrap().len(), 1);
    // A new file with the same content does not bring it back: it was dropped.
    fs::write(
        lab.dir("a").join("again.txt"),
        b"Hardware store, 3 boxes of screws, 12.40 EUR",
    )
    .unwrap();
    a.sync(None).unwrap();
    assert!(a.analysis("docs", "again.txt").unwrap().is_none());
}
