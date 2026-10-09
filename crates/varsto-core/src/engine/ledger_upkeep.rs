// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Keeping the ledger cheap as it grows. The mailbox reads only what is new:
//! a pull lists each known device's batches after the head this device
//! already holds, and a push lists its own batches from the newest one a
//! storage is known to hold (`pushed.json`), so neither lists the whole
//! `ledger/` prefix on every sync.

use super::*;

/// Sequence number of a batch object (`<seq 16 digits>.json`) under
/// `ledger/<device>/`; other names there are not batches.
pub(super) fn batch_seq(file: &str) -> Option<u64> {
    let digits = file.strip_suffix(".json")?;
    if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Listing start for the batches of `device` after `seq` (0: from the first).
fn start_after(device: &DeviceId, seq: u64) -> String {
    if seq == 0 {
        String::new()
    } else {
        SignedBatch::storage_key(device, seq)
    }
}

/// Sequence numbers of the batches of `device` on a storage after `seq`.
fn remote_seqs(backend: &dyn Storage, device: &DeviceId, seq: u64) -> Result<BTreeSet<u64>> {
    let prefix = format!("ledger/{device}/");
    Ok(backend
        .list_after(&prefix, &start_after(device, seq))?
        .iter()
        .filter_map(|k| k.strip_prefix(&prefix).and_then(batch_seq))
        .collect())
}

impl Engine {
    /// Push every own batch that a storage does not have yet; detect forks.
    pub(super) fn push_own_batches(&mut self) -> Result<()> {
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me);
        for (spec, backend) in self.metadata_storages(true)? {
            // List from the newest batch this storage is known to hold, so
            // that batch is seen again: a storage that lost it (or another
            // storage under a known name) is filled from the start.
            let mut done = self.ledger.pushed(spec.name()).min(head.seq);
            let mut present = remote_seqs(backend.as_ref(), &me, done.saturating_sub(1))?;
            if done > 0 && !present.contains(&done) {
                done = 0;
                present = remote_seqs(backend.as_ref(), &me, 0)?;
            }
            if let Some(&newest) = present.last() {
                if newest > head.seq {
                    bail!("ledger fork: storage {} holds batch {} of this device, newer than its own last batch {} (restored from an old copy?)", backend.name(), newest, head.seq);
                }
            }
            for seq in done.max(1)..=head.seq {
                let key = SignedBatch::storage_key(&me, seq);
                if present.contains(&seq) {
                    if seq == head.seq {
                        if let (Some(remote), Some(batch)) =
                            (backend.get(&key)?, self.ledger.get(&me, seq)?)
                        {
                            let remote: SignedBatch = serde_json::from_slice(&remote)?;
                            if remote.hash != batch.hash {
                                bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
                            }
                        }
                    }
                    continue;
                }
                let Some(batch) = self.ledger.get(&me, seq)? else {
                    continue;
                };
                let written = backend.put_if_absent(&key, &serde_json::to_vec(&batch)?)?;
                if !written {
                    bail!(
                        "ledger fork: batch {} of this device appeared on {} concurrently",
                        seq,
                        backend.name()
                    );
                }
            }
            self.ledger.set_pushed(spec.name(), head.seq)?;
        }
        Ok(())
    }

    /// Pull everyone's new batches from every hot storage: for each device
    /// with a known key, only the batches after the local head.
    pub(super) fn pull_ledger(&mut self) -> Result<Vec<DeviceId>> {
        self.pull_registry()?;
        self.sync_membership()?;
        let dir = self.key_directory()?;
        let me = self.vault.device_id.clone();
        let mut devices: Vec<DeviceId> = dir.keys().cloned().collect();
        devices.sort();
        let mut forks = BTreeSet::new();
        for (_, backend) in self.metadata_storages(false)? {
            for dev in &devices {
                let head = self.ledger.head(dev);
                if !self.batch_accepted(dev, head.seq + 1) {
                    // Revoked, and everything up to the cut-off is here.
                    continue;
                }
                // Our own identity is listed after our head too: anything
                // there was written by another copy of this device. A forked
                // device is read in full, as it always was.
                let after = if head.forked { 0 } else { head.seq };
                for seq in remote_seqs(backend.as_ref(), dev, after)? {
                    if !self.batch_accepted(dev, seq) {
                        // Signed by a revoked device after its cut-off.
                        continue;
                    }
                    if self.ledger.get(dev, seq)?.is_some() && !self.ledger.is_forked(dev) {
                        continue;
                    }
                    let Some(blob) = backend.get(&SignedBatch::storage_key(dev, seq))? else {
                        continue;
                    };
                    let signed: SignedBatch = serde_json::from_slice(&blob)?;
                    if &signed.device != dev || signed.seq != seq {
                        continue;
                    }
                    let pk = &dir[dev];
                    // A batch under a key this device lacks is kept unread.
                    let key = self.key_for_id(&signed.key_id);
                    if dev == &me && seq > self.ledger.head(&me).seq {
                        // Another copy of this device identity published ahead of us.
                        forks.insert(me.clone());
                        let _ = self.ledger.ingest_with(signed, pk, key.as_ref());
                        self.mark_forked(&me)?;
                        continue;
                    }
                    match self.ledger.ingest_with(signed, pk, key.as_ref())? {
                        Ingest::Fork => {
                            forks.insert(dev.clone());
                        }
                        Ingest::New | Ingest::Known => {}
                    }
                }
            }
        }
        let view = self.view()?;
        self.observe_clock(view.max_lamport)?;
        Ok(forks.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            "{what:<34} {:>9.1} ms  ledger: lists {:>4} (keys {:>6}) gets {:>6} | all: lists {:>4} (keys {:>6}) gets {:>6} puts {:>6} exists {:>5} deletes {:>5}",
            took.as_secs_f64() * 1000.0,
            c.ledger_lists,
            c.ledger_listed_keys,
            c.ledger_gets,
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
        let (_, took, calls) = measure(c, |e| {
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            e.commit_batch().unwrap()
        });
        report("commit_batch, again", took, calls);
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

    /// After the first pull, a pull with nothing new lists one short range
    /// per device and storage and downloads nothing; a commit lists only
    /// the newest own batches.
    #[test]
    fn mailbox_reads_only_what_is_new() {
        let (_tmp, lab) = lab("incremental");
        let mut devs = devices(&lab, 3);
        let folder = FolderId::random();
        for (d, e) in devs.iter_mut().enumerate() {
            append_synthetic(e, d as u64, 12, &folder);
            e.push_own_batches().unwrap();
        }
        let c = &mut devs[2];
        c.pull_ledger().unwrap();
        let (_, _, calls) = measure(c, |e| {
            let mut out = Vec::new();
            for (_, b) in e.metadata_storages(false).unwrap() {
                for dev in e.key_directory().unwrap().keys() {
                    out.push(remote_seqs(b.as_ref(), dev, e.ledger.head(dev).seq).unwrap());
                }
            }
            out
        });
        assert_eq!(calls.listed_keys, 0, "nothing new after the heads");
        let before = c.view().unwrap().batches;
        let (forks, _, calls) = measure(c, |e| e.pull_ledger().unwrap());
        assert!(forks.is_empty());
        assert_eq!(calls.ledger_gets, 0, "nothing new to download: {calls:?}");
        assert_eq!(calls.ledger_listed_keys, 0, "{calls:?}");
        assert_eq!(c.view().unwrap().batches, before);

        // A new batch of A is the only one B downloads.
        devs[1].pull_ledger().unwrap();
        devs[0].pending.push(Event::FolderAdded {
            folder: folder.clone(),
        });
        let (_, _, calls) = measure(&mut devs[0], |e| e.commit_batch().unwrap());
        assert_eq!(calls.puts, 1, "{calls:?}");
        assert!(calls.ledger_listed_keys <= 1, "{calls:?}");
        let ledger_gets = |e: &mut Engine| {
            let calls = Arc::new(StorageCalls::default());
            e.count_storage_calls(calls.clone());
            let before = e.view().unwrap().batches;
            e.pull_ledger().unwrap();
            e.storage_calls = None;
            (e.view().unwrap().batches - before, calls.snapshot())
        };
        let (new, calls) = ledger_gets(&mut devs[1]);
        assert_eq!(new, 1);
        assert_eq!(calls.ledger_gets, 1, "{calls:?}");
    }

    /// A storage that lost this device's batches (or a new storage under a
    /// known name) is filled again from the first batch.
    #[test]
    fn push_refills_a_storage_that_lost_batches() {
        let (_tmp, lab) = lab("refill");
        let mut devs = devices(&lab, 1);
        let folder = FolderId::random();
        let a = &mut devs[0];
        append_synthetic(a, 0, 5, &folder);
        a.push_own_batches().unwrap();
        let head = a.ledger.head(&a.vault.device_id).seq;
        let dir = lab
            .root
            .join("storage/ledger")
            .join(a.vault.device_id.as_str());
        fs::remove_dir_all(&dir).unwrap();
        a.push_own_batches().unwrap();
        let n = fs::read_dir(&dir).unwrap().count() as u64;
        assert_eq!(n, head);
    }

    /// A copy of this device restored from an old backup sees its newer
    /// batches after its own head and refuses to push.
    #[test]
    fn restored_copy_is_fenced_by_incremental_listing() {
        let (_tmp, lab) = lab("fence");
        let mut devs = devices(&lab, 2);
        let folder = FolderId::random();
        let home = devs[0].home.clone();
        let backup = lab.root.join("backup");
        copy_tree(&home, &backup);
        append_synthetic(&mut devs[0], 0, 3, &folder);
        devs[0].push_own_batches().unwrap();
        drop(devs);
        fs::remove_dir_all(&home).unwrap();
        copy_tree(&backup, &home);
        let mut restored = Engine::open(&home, PASS).unwrap();
        let forks = restored.pull_ledger().unwrap();
        assert_eq!(forks, vec![restored.vault.device_id.clone()]);
        assert!(restored.forked_self);
        let _ = folder;
    }

    fn copy_tree(from: &Path, to: &Path) {
        for e in walkdir::WalkDir::new(from)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let rel = e.path().strip_prefix(from).unwrap();
            let dst = to.join(rel);
            if e.file_type().is_dir() {
                fs::create_dir_all(&dst).unwrap();
            } else {
                fs::copy(e.path(), &dst).unwrap();
            }
        }
    }
}
