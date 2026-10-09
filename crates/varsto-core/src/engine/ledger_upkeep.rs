// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Keeping the ledger cheap as it grows: measurements of the mailbox and the
//! location view on a vault with many batches.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::storage::{CallCounts, StorageCalls};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const PASS: &str = "correct horse battery staple";

    /// A few plausible events for synthetic batch `i` of device number `d`.
    fn synthetic_events(d: u64, i: u64, folder: &FolderId) -> Vec<Event> {
        let chunk =
            ChunkId::from_bytes(&crypto::hash(&[d.to_le_bytes(), i.to_le_bytes()].concat()));
        let object = ObjectName::from_bytes(&crypto::hash(chunk.as_str().as_bytes()));
        let mut evs = vec![
            Event::ChunkStored {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                storage: "box".into(),
                size: 4096 + i,
            },
            Event::ChunkOnDevice {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                size: 4096 + i,
            },
        ];
        if i % 3 == 0 && i > 0 {
            // Verify a chunk another device wrote earlier.
            let other = ChunkId::from_bytes(&crypto::hash(
                &[((d + 1) % 3).to_le_bytes(), (i - 1).to_le_bytes()].concat(),
            ));
            evs.push(Event::ChunkVerified {
                folder: folder.clone(),
                object: ObjectName::from_bytes(&crypto::hash(other.as_str().as_bytes())),
                chunk: other,
                storage: "box".into(),
            });
        }
        evs
    }

    /// Append `n` synthetic batches to this device's ledger without pushing.
    pub(crate) fn append_synthetic(e: &mut Engine, d: u64, n: u64, folder: &FolderId) {
        for i in 0..n {
            let lamport = e.tick().unwrap();
            let (key_id, key) = e.ledger_key_now();
            e.ledger
                .append_own_with(
                    &e.vault.device_id.clone(),
                    synthetic_events(d, i, folder),
                    lamport,
                    &key,
                    &key_id,
                    &e.keys.signer,
                )
                .unwrap();
        }
    }

    pub(crate) struct Lab {
        pub root: PathBuf,
        pub storage: StorageSpec,
    }

    pub(crate) fn lab(tag: &str) -> (tempfile::TempDir, Lab) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(tag);
        let storage = StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
        };
        (tmp, Lab { root, storage })
    }

    pub(crate) fn devices(lab: &Lab, n: usize) -> Vec<Engine> {
        let (mut a, key) = Engine::init(&lab.root.join("dev0"), "dev0", PASS).unwrap();
        a.add_storage(lab.storage.clone()).unwrap();
        let mut out = vec![a];
        for i in 1..n {
            let name = format!("dev{i}");
            out.push(
                Engine::join(
                    &lab.root.join(&name),
                    &name,
                    PASS,
                    &key,
                    lab.storage.clone(),
                )
                .unwrap(),
            );
        }
        // Everyone learns everyone's device record.
        for e in out.iter_mut() {
            e.pull_ledger().unwrap();
        }
        out
    }

    fn measure<T>(e: &mut Engine, f: impl FnOnce(&mut Engine) -> T) -> (T, Duration, CallCounts) {
        let calls = Arc::new(StorageCalls::default());
        e.count_storage_calls(calls.clone());
        let t = Instant::now();
        let out = f(e);
        let took = t.elapsed();
        e.storage_calls = None;
        (out, took, calls.snapshot())
    }

    fn report(what: &str, took: Duration, c: CallCounts) {
        eprintln!(
            "{what:<34} {:>9.1} ms  lists {:>4} (keys {:>6})  gets {:>6}  puts {:>6}  exists {:>5}  deletes {:>5}",
            took.as_secs_f64() * 1000.0,
            c.lists,
            c.listed_keys,
            c.gets,
            c.puts,
            c.exists,
            c.deletes
        );
    }

    /// Measures the mailbox and the view on a vault with many batches:
    /// `VARSTO_BENCH_BATCHES` (default 20000) synthetic batches from three
    /// devices on one local directory. Run with
    /// `cargo test --release -p varsto-core ledger_scale_benchmark -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn ledger_scale_benchmark() {
        let total: u64 = std::env::var("VARSTO_BENCH_BATCHES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let (_tmp, lab) = lab("bench");
        let mut devs = devices(&lab, 3);
        let folder = FolderId::random();
        let per = total / 3;
        let t = Instant::now();
        for (d, e) in devs.iter_mut().enumerate() {
            append_synthetic(e, d as u64, per, &folder);
            e.push_own_batches().unwrap();
        }
        eprintln!(
            "setup: {} batches signed and pushed in {:.1} s",
            per * 3,
            t.elapsed().as_secs_f64()
        );
        let c = &mut devs[2];
        let (_, took, calls) = measure(c, |e| e.pull_ledger().unwrap());
        report("pull_ledger, first (ingest all)", took, calls);
        let (_, took, calls) = measure(c, |e| e.pull_ledger().unwrap());
        report("pull_ledger, nothing new", took, calls);
        let (view, took, calls) = measure(c, |e| e.view().unwrap());
        report("view()", took, calls);
        eprintln!(
            "view: {} batches, {} chunks",
            view.batches,
            view.chunks.len()
        );
        let (_, took, calls) = measure(c, |e| e.view().unwrap());
        report("view(), again", took, calls);
        let (_, took, calls) = measure(c, |e| {
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            e.commit_batch().unwrap()
        });
        report("commit_batch (one event, push)", took, calls);
        let bytes: u64 = walkdir::WalkDir::new(lab.root.join("storage/ledger"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
            .sum();
        let objects = walkdir::WalkDir::new(lab.root.join("storage/ledger"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();
        eprintln!(
            "storage ledger/: {objects} objects, {:.1} MB",
            bytes as f64 / 1e6
        );
    }
}
