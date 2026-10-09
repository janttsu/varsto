// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Incremental manifest listing and pruning (`docs/spec/alpha-0-format.md`
//! section 23): a pull lists only manifests the ledger announced since the
//! last one applied, and a device deletes its superseded manifests only once
//! every other full device has acknowledged a batch announcing a newer one.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ManifestPolicy;
use varsto_core::storage::{CallCounts, StorageCalls, StorageSpec};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
        },
        root,
        _tmp: tmp,
    }
}

impl Lab {
    fn dir(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-docs"))
    }
}

/// Device "a" with folder "docs", and `others` joined and attached.
fn devices(lab: &Lab, others: &[&str]) -> Vec<Engine> {
    let (mut a, key) = Engine::init(&lab.root.join("a-home"), "a", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("note.txt"), b"version 0").unwrap();
    a.sync(None).unwrap();
    let mut out = vec![a];
    for who in others {
        let mut e = Engine::join(
            &lab.root.join(format!("{who}-home")),
            who,
            PASS,
            &key,
            lab.storage.clone(),
        )
        .unwrap();
        e.chunker = ChunkerParams::SMALL;
        e.attach_folder("docs", &lab.dir(who), false).unwrap();
        e.sync(None).unwrap();
        out.push(e);
    }
    out
}

fn measure<T>(e: &mut Engine, f: impl FnOnce(&mut Engine) -> T) -> (T, CallCounts, f64) {
    let calls = Arc::new(StorageCalls::default());
    e.count_storage_calls(calls.clone());
    let t = Instant::now();
    let out = f(e);
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    e.count_storage_calls(Arc::new(StorageCalls::default()));
    (out, calls.snapshot(), ms)
}

/// Manifest objects of `device` on the storage.
fn stored(lab: &Lab, folder: &str, device: &str) -> Vec<u64> {
    let d = lab.root.join("storage/manifests").join(folder).join(device);
    let mut out: Vec<u64> = fs::read_dir(&d)
        .map(|r| {
            r.filter_map(|e| {
                e.ok()?
                    .file_name()
                    .to_string_lossy()
                    .strip_suffix(".enc")?
                    .parse()
                    .ok()
            })
            .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn folder_id(e: &Engine) -> String {
    e.status()
        .unwrap()
        .folders
        .iter()
        .find(|f| f.name == "docs")
        .unwrap()
        .folder_id
        .clone()
}

fn edit(lab: &Lab, e: &mut Engine, who: &str, text: &str) {
    fs::write(lab.dir(who).join("note.txt"), text).unwrap();
    e.sync(None).unwrap();
}

#[test]
fn pull_lists_only_new_manifests() {
    let lab = lab();
    let mut devs = devices(&lab, &["b"]);
    for i in 1..=5 {
        let (a, _) = devs.split_at_mut(1);
        edit(&lab, &mut a[0], "a", &format!("version {i}"));
    }
    let b = &mut devs[1];
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.dir("b").join("note.txt")).unwrap(),
        b"version 5"
    );
    // Nothing new: not a single manifest key listed or read.
    let (_, c, _) = measure(b, |e| e.sync(None).unwrap());
    assert_eq!(
        (c.manifest_lists, c.manifest_listed_keys, c.manifest_gets),
        (0, 0, 0),
        "{c:?}"
    );
    // One new manifest of A: one short listing after the one applied, one read.
    edit(&lab, &mut devs[0], "a", "version 6");
    let b = &mut devs[1];
    let (r, c, _) = measure(b, |e| e.pull("docs").unwrap());
    assert_eq!(r.manifests_applied, 1);
    assert_eq!(c.manifest_listed_keys, 1, "{c:?}");
    assert_eq!(c.manifest_gets, 1, "{c:?}");
    assert_eq!(
        fs::read(lab.dir("b").join("note.txt")).unwrap(),
        b"version 6"
    );

    // A full listing (the periodic sweep) finds the same and applies nothing twice.
    b.set_manifest_policy(ManifestPolicy {
        sweep_secs: 0,
        prune: true,
    });
    let (r, c, _) = measure(b, |e| e.sync(None).unwrap());
    assert_eq!(r[0].0.manifests_applied, 0);
    assert!(c.manifest_lists >= 1, "{c:?}");
}

#[test]
fn pruning_waits_for_every_reader() {
    let lab = lab();
    let mut devs = devices(&lab, &["b", "c"]);
    let folder = folder_id(&devs[0]);
    let a_id = devs[0].device_id().to_string();
    // Everyone has seen everything once.
    for e in devs.iter_mut() {
        e.sync(None).unwrap();
    }
    // C goes quiet; A and B keep working.
    for i in 1..=6 {
        edit(&lab, &mut devs[0], "a", &format!("version {i}"));
        devs[1].sync(None).unwrap();
    }
    devs[0].sync(None).unwrap();
    let left = stored(&lab, &folder, &a_id);
    let newest = *left.last().unwrap();
    assert!(
        left.len() as u64 >= newest - 1,
        "C has not acknowledged the newer ones: {left:?}"
    );

    // C catches up: it reads only A's newest manifest and gets the newest content.
    let (r, c, _) = measure(&mut devs[2], |e| e.sync(None).unwrap());
    assert_eq!(r[0].0.manifests_applied, 2, "A's and B's newest");
    let b_id = devs[1].device_id().to_string();
    let b_left = stored(&lab, &folder, &b_id);
    assert!(
        c.manifest_listed_keys <= (left.len() + b_left.len()) as u64,
        "{c:?}"
    );
    assert_eq!(c.manifest_gets, 2, "one manifest of each: {c:?}");
    assert_eq!(
        fs::read(lab.dir("c").join("note.txt")).unwrap(),
        b"version 6"
    );
    // Once B and C have acknowledged A's newest batch, A keeps only its newest.
    devs[1].sync(None).unwrap();
    edit(&lab, &mut devs[1], "b", "from b");
    devs[2].sync(None).unwrap();
    edit(&lab, &mut devs[2], "c", "from c");
    devs[0].sync(None).unwrap();
    devs[0].sync(None).unwrap();
    let left = stored(&lab, &folder, &a_id);
    assert!(left.len() <= 2, "superseded manifests pruned: {left:?}");
    assert!(left.contains(&newest) || left.iter().any(|s| *s > newest));

    // Everyone still converges, and a device joining now reads the few left.
    edit(&lab, &mut devs[0], "a", "after pruning");
    for e in devs[1..].iter_mut() {
        e.sync(None).unwrap();
    }
    for who in ["b", "c"] {
        assert_eq!(
            fs::read(lab.dir(who).join("note.txt")).unwrap(),
            b"after pruning"
        );
    }
    let key = devs[0].export_vault_key().unwrap();
    let mut d = Engine::join(
        &lab.root.join("d-home"),
        "d",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    d.chunker = ChunkerParams::SMALL;
    d.attach_folder("docs", &lab.dir("d"), false).unwrap();
    d.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.dir("d").join("note.txt")).unwrap(),
        b"after pruning"
    );
}

/// Pull cost on a vault with many manifests, before (a full listing on every
/// pull, as earlier versions did) and after (incremental listing, then
/// pruning). `VARSTO_BENCH_MANIFESTS` (default 300) versions written by A.
/// Run with `cargo test --release -p varsto-core --test manifests
/// manifest_listing_benchmark -- --ignored --nocapture`.
#[test]
#[ignore]
fn manifest_listing_benchmark() {
    let n: u64 = std::env::var("VARSTO_BENCH_MANIFESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let lab = lab();
    let mut devs = devices(&lab, &["b", "c"]);
    let folder = folder_id(&devs[0]);
    let a_id = devs[0].device_id().to_string();
    let keep_all = ManifestPolicy {
        sweep_secs: i64::MAX,
        prune: false,
    };
    for e in devs.iter_mut() {
        e.set_manifest_policy(keep_all);
    }
    let t = Instant::now();
    for i in 1..=n {
        edit(&lab, &mut devs[0], "a", &format!("version {i}"));
        if i % 50 == 0 {
            devs[1].sync(None).unwrap();
        }
    }
    eprintln!(
        "setup: {n} manifests of A in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    let report = |what: &str, c: CallCounts, ms: f64| {
        eprintln!(
            "{what:<46} {ms:>8.1} ms  manifests: lists {:>3} keys {:>5} gets {:>3} | all: lists {:>3} keys {:>5} gets {:>4}",
            c.manifest_lists, c.manifest_listed_keys, c.manifest_gets, c.lists, c.listed_keys, c.gets
        );
    };
    let c = &mut devs[2];
    c.sync(None).unwrap();
    c.set_manifest_policy(ManifestPolicy {
        sweep_secs: 0,
        prune: false,
    });
    let (_, calls, ms) = measure(c, |e| e.sync(None).unwrap());
    report("before: sync, nothing new (full listing)", calls, ms);
    c.set_manifest_policy(keep_all);
    let (_, calls, ms) = measure(c, |e| e.sync(None).unwrap());
    report("after: sync, nothing new (incremental)", calls, ms);
    edit(&lab, &mut devs[0], "a", "one more");
    let c = &mut devs[2];
    let (_, calls, ms) = measure(c, |e| e.sync(None).unwrap());
    report("after: sync, one new manifest", calls, ms);
    eprintln!(
        "manifests of A on the storage: {}",
        stored(&lab, &folder, &a_id).len()
    );

    // Pruning: B and C acknowledge A's newest batch, then A prunes.
    for e in devs.iter_mut() {
        e.set_manifest_policy(ManifestPolicy::default());
    }
    edit(&lab, &mut devs[1], "b", "from b");
    edit(&lab, &mut devs[2], "c", "from c");
    devs[0].sync(None).unwrap();
    // Acknowledgements travel in the readers' next batches.
    edit(&lab, &mut devs[1], "b", "from b again");
    edit(&lab, &mut devs[2], "c", "from c again");
    let t = Instant::now();
    devs[0].sync(None).unwrap();
    eprintln!(
        "A's sync with pruning: {:.1} ms; manifests of A left: {:?}",
        t.elapsed().as_secs_f64() * 1000.0,
        stored(&lab, &folder, &a_id)
    );
    let c = &mut devs[2];
    c.set_manifest_policy(ManifestPolicy {
        sweep_secs: 0,
        prune: true,
    });
    let (_, calls, ms) = measure(c, |e| e.sync(None).unwrap());
    report("after pruning: sync, full listing", calls, ms);
    let usage: u64 = walkdir::WalkDir::new(lab.root.join("storage/manifests"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    eprintln!("storage manifests/: {:.1} KB", usage as f64 / 1e3);
}
