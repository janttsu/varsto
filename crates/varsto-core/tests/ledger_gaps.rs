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

// ---- ledger heads between peers (section 74) -------------------------------

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use varsto_core::ledger_heads::{HeadEntry, HeadStatement};
use varsto_core::p2p::{PeerAddr, Peers, Server, Snapshot};

/// A device serving its snapshot over loopback until dropped.
struct Serving {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Serving {
    fn start(e: &Engine) -> Serving {
        let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.addr;
        let snap: Arc<Mutex<Option<Arc<Snapshot>>>> =
            Arc::new(Mutex::new(Some(Arc::new(e.peer_snapshot().unwrap()))));
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = std::thread::spawn(move || server.run(snap, stop2));
        Serving {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `b` knows `a` as a peer on `serving`.
fn meet(b: &mut Engine, a: &Engine, serving: &Serving) {
    let peers = Peers::new(
        b.peer_key(),
        b.device_id().clone(),
        vec![PeerAddr {
            device: a.device_id().clone(),
            addr: serving.addr,
            name: "dev0".into(),
        }],
    );
    b.set_peers(Some(Arc::new(peers)));
}

/// A's newest batches are withheld from B by the storage; A tells B over
/// peer-to-peer how far it holds its own ledger. B notes the gap with the
/// source `peer`, warns after three pulls, and the statement moves nothing.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_peers_heads_reveal_batches_the_storage_withholds() {
    let (lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let (f1, e1) = folder_event();
    let (_, e2) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    devs[0].seal_batch_unchecked(None, vec![e2], None).unwrap();
    lab.withhold(&a_id, n);
    lab.withhold(&a_id, n + 1);
    let serving = Serving::start(&devs[0]);
    let (a, rest) = devs.split_first_mut().unwrap();
    let b = &mut rest[0];
    assert!(b.ledger_health().behind.is_empty());
    meet(b, a, &serving);
    for pull in 1..=3u32 {
        b.sync(None).unwrap();
        let h = b.ledger_health();
        let behind = h
            .behind
            .iter()
            .find(|x| x.device == a_id.as_str())
            .expect("the peer's statement shows the gap");
        assert_eq!(
            (
                behind.held,
                behind.seen,
                behind.pulls,
                behind.source.as_str()
            ),
            (n - 1, n + 1, pull, "peer")
        );
        let warned = h.warnings.iter().any(|w| w.contains("rolling back"));
        assert_eq!(warned, pull >= 3, "pull {pull}: {:?}", h.warnings);
    }
    // A statement only raises the question: nothing was ingested.
    assert_eq!(head_of(b, &a_id), n - 1);
    assert!(!b.view().unwrap().folders.contains(&f1));
    let h = b.ledger_health();
    assert!(h.is_ok(), "a peer cannot make this device refuse anything");
    assert!(h.describe().contains("a peer holds"), "{}", h.describe());
    let help = b.help_state(Default::default()).unwrap();
    assert!(
        help.attention
            .iter()
            .any(|x| x.id.starts_with("ledger-withheld:")),
        "{:?}",
        help.attention
    );
    // The statement is kept for the next run.
    assert!(b.home().join("ledger/heads-seen.json").is_file());

    lab.release(&a_id, n);
    lab.release(&a_id, n + 1);
    b.sync(None).unwrap();
    assert_eq!(head_of(b, &a_id), n + 1);
    let h = b.ledger_health();
    assert!(h.behind.is_empty() && h.warnings.is_empty(), "{h:?}");
}

/// The storage's ledger directory is replaced by an older copy; the device
/// that has not pulled the lost batches yet learns from a peer that they
/// existed.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_rolled_back_storage_is_caught_by_a_peer() {
    let (lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let ledger = lab.storage().join("ledger");
    let old = lab.root.join("ledger-old");
    copy_dir(&ledger, &old);
    let old_head = head_of(&mut devs[1], &a_id);
    let (_, e1) = folder_event();
    let (_, e2) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    devs[0].seal_batch_unchecked(None, vec![e2], None).unwrap();
    // The storage goes back to the copy taken before those batches.
    fs::remove_dir_all(&ledger).unwrap();
    fs::rename(&old, &ledger).unwrap();
    let serving = Serving::start(&devs[0]);
    let (a, rest) = devs.split_first_mut().unwrap();
    let b = &mut rest[0];
    meet(b, a, &serving);
    for _ in 0..3 {
        b.sync(None).unwrap();
    }
    assert_eq!(head_of(b, &a_id), old_head, "n = {n}");
    let h = b.ledger_health();
    assert!(
        h.warnings.iter().any(|w| w.contains("rolling back")),
        "{:?}",
        h.warnings
    );
    assert!(h.is_ok());
    let behind = h.behind.iter().find(|x| x.device == a_id.as_str()).unwrap();
    assert_eq!((behind.source.as_str(), behind.seen), ("peer", n + 1));
    assert!(behind.held < n);
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Statements that do not count: from a removed device, forged, edited,
/// this device's own, or not newer than the one kept.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn statements_from_removed_or_forged_senders_are_ignored() {
    let (_lab, mut devs) = devices(3);
    let a_id = devs[0].device_id().clone();
    let c_id = devs[2].device_id().clone();
    let (_, ev) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![ev], None).unwrap();
    let (_, ev) = folder_event();
    devs[2].seal_batch_unchecked(None, vec![ev], None).unwrap();
    let from_a = devs[0].head_statement().unwrap();
    let from_c = devs[2].head_statement().unwrap();
    assert!(from_a.entry(&a_id).unwrap().seq >= n);
    assert!(from_c.entry(&c_id).is_some());

    let b = &mut devs[1];
    b.sync(None).unwrap();
    // A forged or edited statement does not verify.
    let mut edited = from_a.clone();
    edited.heads[0].seq += 100;
    assert!(!b.accept_head_statement(edited));
    let mut renamed = from_c.clone();
    renamed.sender = a_id.clone();
    assert!(!b.accept_head_statement(renamed));
    let forged = HeadStatement::sign(
        b.vault_id(),
        &c_id,
        5,
        1,
        vec![HeadEntry {
            device: a_id.clone(),
            seq: 1000,
            hash: String::new(),
            checkpoint: 0,
        }],
        &varsto_core::crypto::SigningKey::generate(),
    );
    assert!(!b.accept_head_statement(forged));
    // This device's own statement is not a peer's.
    let own = b.head_statement().unwrap();
    assert!(!b.accept_head_statement(own));
    // A genuine one is kept once; an equal one is not.
    assert!(b.accept_head_statement(from_a.clone()));
    assert!(!b.accept_head_statement(from_a));
    // A removed device's statement is ignored, and what it said is gone.
    assert!(b.accept_head_statement(from_c.clone()));
    b.revoke_device("dev2", false).unwrap();
    assert!(!b.accept_head_statement(from_c));
    b.sync(None).unwrap();
    let h = b.ledger_health();
    assert!(
        h.behind.iter().all(|x| x.device != c_id.as_str()),
        "{:?}",
        h.behind
    );
}

/// Devices that only meet through the storage: A's rendezvous record
/// carries its own head, B reads the record and compares.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn a_rendezvous_record_carries_the_senders_own_head() {
    let (lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let (_, e1) = folder_event();
    let (_, e2) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    devs[0].seal_batch_unchecked(None, vec![e2], None).unwrap();
    let rec = devs[0].peer_record_template(4000);
    let head = rec.head.clone().expect("a full device signs its head");
    assert_eq!(head.heads.len(), 1);
    assert_eq!(head.heads[0].device, a_id);
    assert_eq!(head.heads[0].seq, n + 1);
    // A newer head is a change to publish; a new signature alone is not.
    let again = devs[0].peer_record_template(4000);
    assert!(again.same_as(&rec));
    devs[0].publish_peer_record(&rec).unwrap();
    lab.withhold(&a_id, n);
    lab.withhold(&a_id, n + 1);
    let b = &mut devs[1];
    assert_eq!(b.peer_record_list().unwrap().len(), 1);
    for _ in 0..3 {
        b.sync(None).unwrap();
    }
    let h = b.ledger_health();
    let behind = h.behind.iter().find(|x| x.device == a_id.as_str()).unwrap();
    assert_eq!((behind.seen, behind.source.as_str()), (n + 1, "peer"));
    assert!(h.warnings.iter().any(|w| w.contains("rolling back")));
}

/// `/p2p/changed` carries the sender's statement and is answered with the
/// receiver's, so one message exchanges both.
#[test]
#[ignore = "f3-switch: port in part B (ledger gaps)"]
fn the_changed_message_exchanges_statements() {
    let (_lab, mut devs) = devices(2);
    let a_id = devs[0].device_id().clone();
    let b_id = devs[1].device_id().clone();
    let (_, e1) = folder_event();
    let n = devs[0].seal_batch_unchecked(None, vec![e1], None).unwrap();
    let serving = Serving::start(&devs[0]);
    let (a, rest) = devs.split_first_mut().unwrap();
    let b = &mut rest[0];
    let peers = Peers::new(
        b.peer_key(),
        b_id.clone(),
        vec![PeerAddr {
            device: a_id.clone(),
            addr: serving.addr,
            name: "dev0".into(),
        }],
    );
    peers.notify_changed_with(b.head_statement().as_ref());
    assert!(varsto_core::p2p::take_change_heard());
    // A's answer and B's message were queued; each is checked at the
    // receiver's next pull.
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let kept_b = fs::read_to_string(b.home().join("ledger/heads-seen.json")).unwrap();
    assert!(kept_b.contains(a_id.as_str()), "{kept_b}");
    let kept_a = fs::read_to_string(a.home().join("ledger/heads-seen.json")).unwrap();
    assert!(kept_a.contains(b_id.as_str()), "{kept_a}");
    assert!(a.head_statement().unwrap().entry(&a_id).unwrap().seq >= n);
}
