// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Gaps and freshness of the ledger (`docs/spec/alpha-0-format.md` section
//! 58): a storage that withholds one batch of a device cannot make the
//! batches after it count as if nothing were missing, a gap that another
//! device's acknowledgements reveal is reported once it outlasts a few
//! pulls, a damaged or planted batch on one storage does not stop the pull,
//! and a batch with an absurd Lamport time is refused.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::ids::{DeviceId, FolderId};
use varsto_core::ledger::Event;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir_spec(name: &str, path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn storage(&self) -> PathBuf {
        self.root.join("storage")
    }
    fn batch(&self, dev: &DeviceId, seq: u64) -> PathBuf {
        self.storage()
            .join("ledger")
            .join(dev.as_str())
            .join(format!("{seq:016}.json"))
    }
    /// Hide a batch from the storage (a storage withholding it).
    fn withhold(&self, dev: &DeviceId, seq: u64) {
        let aside = self.root.join(format!("withheld-{seq}"));
        fs::rename(self.batch(dev, seq), aside).unwrap();
    }
    fn release(&self, dev: &DeviceId, seq: u64) {
        let aside = self.root.join(format!("withheld-{seq}"));
        fs::rename(aside, self.batch(dev, seq)).unwrap();
    }
}

/// `n` devices of one vault on one storage, each knowing the others.
fn devices(n: usize) -> (Lab, Vec<Engine>) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let spec = dir_spec("box", &root.join("storage"));
    let (mut a, key) = Engine::init(&root.join("dev0"), "dev0", PASS).unwrap();
    a.add_storage(spec.clone()).unwrap();
    let mut out = vec![a];
    for i in 1..n {
        let name = format!("dev{i}");
        out.push(Engine::join(&root.join(&name), &name, PASS, &key, spec.clone()).unwrap());
    }
    for e in out.iter_mut() {
        e.sync(None).unwrap();
    }
    (Lab { _tmp: tmp, root }, out)
}

fn head_of(e: &mut Engine, dev: &DeviceId) -> u64 {
    e.ledger_status(false)
        .unwrap()
        .devices
        .iter()
        .find(|d| d.device == dev.as_str())
        .map(|d| d.head)
        .unwrap_or(0)
}

fn folder_event() -> (FolderId, Event) {
    let f = FolderId::random();
    (f.clone(), Event::FolderAdded { folder: f })
}

/// The storage withholds batch N of A and offers N + 1: B's head for A
/// stays at N - 1 and N + 1 waits; once N appears, both count.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_withheld_batch_holds_back_the_ones_after_it() {
    let (lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let (f1, e1) = folder_event();
    let (f2, e2) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    let n1 = devs[0].seal_batch_unchecked(None, vec![e2], None).unwrap();
    assert_eq!(n1, n + 1);
    lab.withhold(&a_id, n);
    let b = &mut devs[1];
    b.sync(None).unwrap();
    assert_eq!(head_of(b, &a_id), n - 1, "the head does not pass the gap");
    let view = b.view().unwrap();
    assert!(!view.folders.contains(&f1) && !view.folders.contains(&f2));
    let health = b.ledger_health();
    let behind = health
        .behind
        .iter()
        .find(|x| x.device == a_id.as_str())
        .expect("the gap is noticed");
    assert_eq!((behind.held, behind.seen), (n - 1, n + 1));

    lab.release(&a_id, n);
    b.sync(None).unwrap();
    assert_eq!(head_of(b, &a_id), n + 1);
    let view = b.view().unwrap();
    assert!(view.folders.contains(&f1) && view.folders.contains(&f2));
    assert!(b.ledger_health().behind.is_empty());
    assert_eq!(b.view().unwrap(), b.view_replayed().unwrap());
}

/// C says (in its signed `seen`) that it holds A's batches up to N + 1
/// while the storage hides N and N + 1 from B: B notices, asks again on
/// every pull, and after three pulls warns that a storage may be
/// withholding A's batches. The warning goes once the batches arrive.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn acknowledgements_reveal_withheld_batches() {
    let (lab, mut devs) = devices(3);
    let a_id = devs[0].device_id().clone();
    let (_, e1) = folder_event();
    let (_, e2) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    devs[0].seal_batch_unchecked(None, vec![e2], None).unwrap();
    devs[2].sync(None).unwrap();
    // C acknowledges what it holds in its next batch.
    devs[2].seal_batch_unchecked(None, vec![], None).unwrap();
    lab.withhold(&a_id, n);
    lab.withhold(&a_id, n + 1);
    let b = &mut devs[1];
    for pull in 1..=3u32 {
        b.sync(None).unwrap();
        let h = b.ledger_health();
        let behind = h
            .behind
            .iter()
            .find(|x| x.device == a_id.as_str())
            .expect("C's acknowledgement shows the gap");
        assert_eq!(
            (behind.held, behind.seen, behind.pulls),
            (n - 1, n + 1, pull)
        );
        let warned = h.warnings.iter().any(|w| w.contains("withholding"));
        assert_eq!(warned, pull >= 3, "pull {pull}: {:?}", h.warnings);
    }
    assert!(b.ledger_health().describe().contains("withholding"));
    let help = b.help_state(Default::default()).unwrap();
    assert!(
        help.attention
            .iter()
            .any(|a| a.id.starts_with("ledger-withheld:")),
        "{:?}",
        help.attention
    );
    lab.release(&a_id, n);
    lab.release(&a_id, n + 1);
    b.sync(None).unwrap();
    assert_eq!(head_of(b, &a_id), n + 1);
    let h = b.ledger_health();
    assert!(h.behind.is_empty() && h.warnings.is_empty(), "{h:?}");
}

/// A damaged or planted object in place of a batch on one storage does not
/// stop the pull: the batch comes from the other storage and the skipped
/// object is counted.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_malformed_batch_on_one_storage_does_not_stop_the_pull() {
    let (lab, mut devs) = devices(2);
    let second = lab.root.join("second");
    for e in devs.iter_mut() {
        e.add_storage(dir_spec("second", &second)).unwrap();
    }
    devs[0].sync(None).unwrap();
    let a_id = devs[0].device_id().clone();
    let (f, ev) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![ev], None).unwrap();
    fs::write(lab.batch(&a_id, n), b"{\"not\": \"a batch\"}").unwrap();
    let b = &mut devs[1];
    b.sync(None).expect("one bad object does not stop the pull");
    assert!(b.view().unwrap().folders.contains(&f));
    assert!(b.ledger_health().batches_malformed >= 1);
}

/// A batch whose Lamport time is beyond anything a device can have reached
/// is refused and not applied: it would win every later ordering.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_batch_with_an_absurd_lamport_time_is_refused() {
    let (_lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let (f, ev) = folder_event();
    let n = devs[0]
        .seal_batch_unchecked(None, vec![ev], Some(u64::MAX))
        .unwrap();
    let b = &mut devs[1];
    b.sync(None).unwrap();
    assert!(!b.view().unwrap().folders.contains(&f));
    assert_eq!(head_of(b, &a_id), n - 1);
    let st = b.status().unwrap();
    assert!(st.lamport < 1 << 41, "the clock jumped to {}", st.lamport);
    assert!(b.ledger_health().batches_refused >= 1);
}
