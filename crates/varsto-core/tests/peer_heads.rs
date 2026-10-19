// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ledger heads between peers in storage format 3 (`format-3-design.md`
//! section 8, `alpha-0-format.md` section 77.8): a peer proves batches the
//! storage withholds (signed envelopes, and the writer's own peer record)
//! and hands them over; the rollback warning comes after two pulls for a
//! storage the writer confirmed; `/p2p/changed` carries head lists both
//! ways. Ported from the format-2 head statements of `ledger_gaps.rs`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::ids::DeviceId;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn storage(&self) -> PathBuf {
        self.root.join("storage")
    }
    fn batches(&self, dev: &DeviceId) -> PathBuf {
        self.storage().join("ledger").join(dev.as_str())
    }
    /// Hide `dev`'s batches after `after` from the storage (a storage that
    /// withholds them, or was rolled back to an older copy).
    fn withhold_after(&self, dev: &DeviceId, after: u64) -> usize {
        let aside = self.root.join("withheld");
        fs::create_dir_all(&aside).unwrap();
        let mut n = 0;
        for e in fs::read_dir(self.batches(dev)).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(seq) = name
                .strip_suffix("-0000.rec")
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if seq > after {
                fs::rename(e.path(), aside.join(&name)).unwrap();
                n += 1;
            }
        }
        n
    }
    fn release(&self, dev: &DeviceId) {
        let aside = self.root.join("withheld");
        for e in fs::read_dir(&aside).unwrap().flatten() {
            fs::rename(e.path(), self.batches(dev).join(e.file_name())).unwrap();
        }
    }
}

fn spec(path: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

/// A laptop and a desk of one vault on one storage, both synced.
fn two() -> (Lab, Engine, Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let lab = Lab { _tmp: tmp, root };
    let (mut a, key) = Engine::init(&lab.root.join("a"), "laptop", PASS).unwrap();
    a.add_storage(spec(&lab.storage())).unwrap();
    let mut b = Engine::join(
        &lab.root.join("b"),
        "desk",
        PASS,
        &key,
        spec(&lab.storage()),
    )
    .unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    (lab, a, b)
}

/// The newest batch of `of` that `e` holds.
fn head(e: &Engine, of: &Engine) -> u64 {
    let id = varsto_core::record::id16(of.device_id()).unwrap();
    e.head_list()
        .into_iter()
        .find(|h| h.device == id)
        .map(|h| h.seq)
        .unwrap_or(0)
}

/// The laptop writes new batches (folders added) and pushes them; the
/// storage then withholds them from the desk.
fn new_batches_withheld(lab: &Lab, a: &mut Engine, b: &Engine) -> (u64, u64) {
    let before = head(b, a);
    for name in ["photos", "music"] {
        a.add_folder(name, &lab.root.join(name)).unwrap();
    }
    a.sync(None).unwrap();
    let top = head(a, a);
    assert!(top > before, "{top} > {before}");
    assert!(lab.withhold_after(a.device_id(), before) > 0);
    (before, top)
}

#[test]
fn a_withheld_batch_is_proved_by_a_peer_and_handed_over() {
    let (lab, mut a, mut b) = two();
    let (before, top) = new_batches_withheld(&lab, &mut a, &b);
    b.sync(None).unwrap();
    assert_eq!(head(&b, &a), before, "the storage withholds them");

    // The laptop serves; its record carries its own head and what it
    // pushed where.
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    let dir = b.peer_directory().unwrap();
    let rec = dir
        .bodies()
        .find(|r| r.name == "laptop")
        .expect("the laptop's record");
    let own = varsto_core::record::id16(a.device_id()).unwrap();
    assert_eq!(
        rec.heads.iter().find(|h| h.device == own).map(|h| h.seq),
        Some(top)
    );
    assert!(rec.pushed.iter().any(|p| p.seq == top), "{:?}", rec.pushed);

    // The head exchange proves the batches and the laptop hands them over.
    let r = b.p2p_catch_up().unwrap();
    assert!(r.proofs >= 1, "{r:?}");
    assert_eq!(r.fetched as u64, top - before, "{r:?}");
    assert_eq!(r.refused, 0);
    assert_eq!(head(&b, &a), top);
    assert!(b.home().join("ledger/proofs.json").is_file());
    // The desk does not push the laptop's batches: only their writer does.
    assert!(!lab
        .batches(a.device_id())
        .join(format!("{top:016}-0000.rec"))
        .exists());
    // Nothing left to fetch the next time.
    let again = b.p2p_catch_up().unwrap();
    assert_eq!(again.fetched, 0, "{again:?}");
    drop(serving);
}

#[test]
fn rollback_warning_after_two_pulls_for_a_storage_the_writer_confirmed() {
    let (lab, mut a, mut b) = two();
    let (_before, top) = new_batches_withheld(&lab, &mut a, &b);
    // The desk learns the laptop's head from its peer record alone (no
    // connection is needed: the record is signed by the laptop).
    common::p2p::publish(&a, 9);
    b.refresh_devices().unwrap();
    b.p2p_catch_up().unwrap();
    let pull = varsto_core::util::now_utc() + 1;
    let first = b.p2p_judge_rollback(pull, None).unwrap();
    assert!(first.is_empty(), "one pull is not enough: {first:?}");
    assert_eq!(b.rollback_suspects().len(), 1);
    let second = b.p2p_judge_rollback(pull + 1, None).unwrap();
    assert_eq!(second.len(), 1, "{second:?}");
    let w = &second[0];
    assert!(
        w.text
            .starts_with("storage box may be withholding or rolled back"),
        "{}",
        w.text
    );
    assert!(w.text.contains("laptop"), "{}", w.text);
    assert_eq!(w.proved, top);
    assert!(w.notify);
    // Notified once a day, not at every pull.
    let third = b.p2p_judge_rollback(pull + 2, None).unwrap();
    assert!(!third[0].notify);

    // The storage shows the batches again: the warning goes.
    lab.release(a.device_id());
    assert!(b.p2p_judge_rollback(pull + 3, None).unwrap().is_empty());
    assert!(b.rollback_suspects().is_empty());

    // The laptop judges its own batches the same way: the storage shows
    // every one it pushed there.
    assert!(a.p2p_judge_rollback(pull + 4, None).unwrap().is_empty());
}

#[test]
fn the_changed_message_carries_head_lists_both_ways() {
    let (_lab, mut a, mut b) = two();
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    let _ = varsto_core::p2p::take_change_heard();
    let peers = b.p2p_peers_tcp().unwrap();
    let mine = b.head_list();
    let answers = peers.notify_changed(&mine);
    assert!(varsto_core::p2p::take_change_heard());
    // The laptop's answer carries its own list.
    assert_eq!(answers.len(), 1);
    assert_eq!(&answers[0].0, a.device_id());
    let own = varsto_core::record::id16(a.device_id()).unwrap();
    assert!(answers[0].1.heads.iter().any(|h| h.device == own));
    // The desk's list was heard, as its claim, from the desk.
    let heard = serving.responder.take_heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(&heard[0].from, b.device_id());
    assert_eq!(heard[0].heads, mine);
}

/// The storage withholds the laptop's new batches, and the laptop hands
/// them over itself: the desk now holds them, but the storage still shows
/// less than the laptop proved, so the next pulls flag it. (The judge used
/// to count a storage as showing at least the head held here.)
#[test]
fn a_storage_is_judged_by_its_own_listing_after_a_hand_over() {
    let (lab, mut a, mut b) = two();
    let (before, top) = new_batches_withheld(&lab, &mut a, &b);
    let serving = common::p2p::Serving::start(&mut a);
    common::p2p::connect(&mut a, &serving, &mut [&mut b]);
    let r = b.p2p_catch_up().unwrap();
    assert_eq!(r.fetched as u64, top - before, "{r:?}");
    assert_eq!(head(&b, &a), top);
    drop(serving);
    // The proof is older than the pulls that judge it.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    b.sync(None).unwrap();
    b.sync(None).unwrap();
    let suspects = b.rollback_suspects();
    let s = suspects
        .values()
        .next()
        .unwrap_or_else(|| panic!("the storage is not suspect: {suspects:?}"));
    assert!(s.pulls >= 2, "{s:?}");
    assert_eq!(s.shown, before, "{s:?}");
    assert_eq!(s.proved, top, "{s:?}");
    // The storage shows them again: cleared at the next pull.
    lab.release(a.device_id());
    b.sync(None).unwrap();
    assert!(
        b.rollback_suspects().is_empty(),
        "{:?}",
        b.rollback_suspects()
    );
}
