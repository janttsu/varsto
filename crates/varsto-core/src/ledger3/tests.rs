// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of the format-3 ledger: events, scopes, the pack-level view, the
//! store's chains, gaps, forks and checkpoints, and the settle queries.

use super::envelope::{self, kind, Header, LedgerRecord, SignedRecord};
use super::events::*;
use super::scope::{ledger_key_id, share_ledger_key_id, EventScope, KEY_REPLICA};
use super::view::*;
use super::*;
use crate::crypto::{SecretKey, SigningKey};
use std::collections::{BTreeSet, HashMap};

const VAULT: [u8; 16] = [7; 16];

fn signer(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i; 64]).unwrap()
}

fn dev_of(s: &SigningKey) -> DeviceBin {
    device_bin_for(&s.public())
}

fn pid(n: u8) -> PackId {
    [n; 32]
}

fn fid(n: u8) -> FolderBin {
    if n == 0 {
        NO_FOLDER
    } else {
        [n; 16]
    }
}

fn stored(storage: &str, pack: u8, folder: u8, map_seq: u64) -> Event {
    Event::PackStored(PackStored {
        storage: storage.into(),
        pack: pid(pack),
        class: 1,
        folder: fid(folder),
        map_seq,
    })
}

fn verified(storage: &str, pack: u8) -> Event {
    Event::PackVerified(PackOn {
        storage: storage.into(),
        pack: pid(pack),
    })
}

fn dropped(storage: &str, pack: u8) -> Event {
    Event::PackDropped(PackOn {
        storage: storage.into(),
        pack: pid(pack),
    })
}

fn published(kind: u8, folder: u8, seq: u64, base: u64, h: u8) -> Event {
    Event::RecordPublished(Announcement {
        kind,
        scope: fid(folder),
        seq,
        base,
        parts: 1,
        body_hash: [h; 32],
        size: 100,
    })
}

fn batch(device: DeviceBin, seq: u64, lamport: u64, events: &[Event]) -> Batch {
    Batch {
        device,
        seq,
        prev: [0; 32],
        lamport,
        created_utc: 1_000 + lamport as i64,
        seen: Vec::new(),
        events: events.iter().map(Event::to_raw).collect(),
    }
}

fn store(dir: &tempfile::TempDir, name: &str) -> LedgerStore {
    LedgerStore::open(&dir.path().join(name), VAULT).unwrap()
}

fn full_scope(_: &DeviceBin, id: &str) -> Option<EventScope> {
    EventScope::of_key_id(id)
}

// ---- events -------------------------------------------------------------

fn one_of_each() -> Vec<Event> {
    vec![
        Event::DeviceEnrolled(DeviceEnrolled {
            name: "laptop".into(),
        }),
        Event::FolderAdded(FolderAdded { folder: fid(1) }),
        stored("h1", 1, 1, 17),
        verified("h1", 1),
        dropped("h1", 1),
        published(kind::BLOCK_MAP, 1, 17, 12, 9),
        Event::StorageRetired(StorageRetired {
            storage: "old".into(),
        }),
        Event::SnapshotTaken(SnapshotTaken {
            backup: fid(2),
            seq: 3,
            taken_utc: 10,
            expires_utc: 20,
            files: 4,
            bytes: 5,
        }),
        Event::SnapshotExpired(SnapshotExpired {
            backup: fid(2),
            device: [3; 16],
            seq: 2,
        }),
        Event::BackupStopped(BackupStopped { backup: fid(2) }),
    ]
}

/// Every event code survives its encoding, inside a batch body, inside a
/// sealed and signed batch record; the codes are those of section 4.
#[test]
fn every_event_code_round_trips() {
    let events = one_of_each();
    let codes: Vec<u16> = events.iter().map(Event::code).collect();
    assert_eq!(codes, (1..=10).collect::<Vec<u16>>());
    for ev in &events {
        assert_eq!(ev.to_raw().decode(), Decoded::Event(ev.clone()), "{ev:?}");
    }
    let s = signer(1);
    let d = dev_of(&s);
    let b = Batch {
        seen: vec![([4; 16], 9)],
        ..batch(d, 1, 3, &events)
    };
    assert_eq!(Batch::from_postcard(&b.to_postcard().unwrap()).unwrap(), b);
    let key = SecretKey::random();
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let rec = own
        .append_own(
            &d,
            b.events.clone(),
            b.seen.clone(),
            3,
            &key,
            &ledger_key_id(0),
            NO_FOLDER,
            &s,
        )
        .unwrap();
    assert_eq!(rec.kind, kind::BATCH);
    let again = SignedRecord::decode(&rec.encode()).unwrap();
    assert_eq!(again, rec);
    let opened = store::check_batch(&again, &VAULT, &s.public(), Some(&key))
        .unwrap()
        .unwrap();
    let (decoded, unknown, malformed) = opened.decoded();
    assert_eq!((unknown, malformed), (0, 0));
    assert_eq!(
        decoded.into_iter().map(|(_, e)| e).collect::<Vec<_>>(),
        events
    );
    assert_eq!(
        checkpoint::batch_key(&d, 1),
        format!("ledger/{}/0000000000000001-0000.rec", hex::encode(d))
    );
}

/// A code this version does not know is skipped and counted; the rest of
/// its batch counts. A known code that does not parse or breaks a limit is
/// refused.
#[test]
fn unknown_code_is_skipped_and_counted() {
    let d = [1; 16];
    let mut b = batch(d, 1, 1, &[stored("h1", 1, 1, 1)]);
    b.events.insert(
        0,
        RawEvent {
            code: 99,
            payload: vec![1, 2, 3],
        },
    );
    b.events.push(RawEvent {
        code: code::PACK_VERIFIED,
        payload: vec![0xff],
    });
    // A storage name over 64 bytes and a size class that does not exist.
    b.events.push(stored(&"x".repeat(65), 2, 1, 1).to_raw());
    let mut bad = stored("h1", 3, 1, 1);
    if let Event::PackStored(p) = &mut bad {
        p.class = 6;
    }
    b.events.push(bad.to_raw());
    let mut v = LedgerView::default();
    v.apply(&b);
    assert_eq!(v.events_unknown, 1);
    assert_eq!(v.events_refused, 3);
    assert_eq!(v.holders(&pid(1)), vec!["h1"]);
    assert!(v.pack(&pid(2)).is_none() && v.pack(&pid(3)).is_none());
}

/// An action over `MAX_EVENTS` events seals further batches.
#[test]
fn large_actions_seal_further_batches() {
    let ev = verified("h1", 1).to_raw();
    let parts = split_events(vec![ev.clone(); MAX_EVENTS + 1]);
    assert_eq!(
        parts.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![MAX_EVENTS, 1]
    );
    assert_eq!(split_events(Vec::new()), vec![Vec::<RawEvent>::new()]);
    let big = RawEvent {
        code: 99,
        payload: vec![0; 6 << 20],
    };
    assert_eq!(split_events(vec![big.clone(), big.clone(), big]).len(), 2);

    let s = signer(2);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let mut lamport = 10;
    let recs = own
        .append_action(
            &d,
            vec![ev; MAX_EVENTS + 1],
            Vec::new(),
            || {
                lamport += 1;
                lamport
            },
            &key,
            &ledger_key_id(0),
            NO_FOLDER,
            &s,
        )
        .unwrap();
    assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert!(recs
        .iter()
        .all(|r| r.body.len() <= envelope::padded_body_len(MAX_BATCH_BODY)));
    // Bodies are padded to 64 KiB steps (1 MiB from 4 MiB).
    assert!(recs.iter().all(|r| r.body.len() % (64 << 10) == 0));
    assert_eq!(class_bytes(0), Some(256 << 10));
    assert_eq!(class_bytes(5), Some(256 << 20));
    assert_eq!(class_bytes(6), None);
    let b = Batch::from_postcard(&recs[1].open(&key, MAX_BATCH_PLAIN).unwrap()).unwrap();
    assert_eq!((b.lamport, b.prev), (12, recs[0].body_hash));
    let too_many = Batch {
        events: vec![
            RawEvent {
                code: 1,
                payload: vec![]
            };
            MAX_EVENTS + 1
        ],
        ..batch(d, 1, 1, &[])
    };
    assert!(too_many.to_postcard().is_err());
}

// ---- scopes -------------------------------------------------------------

/// A member may claim, verify and drop only its folder's packs (and drop
/// only packs it stored), and announce only manifests, maps and trash of
/// its folder; a replica only claims and verifies whole packs without a
/// folder; a viewer only verifies its folder's packs. Everything else is
/// refused and counted, whatever order the batches arrive in.
#[test]
fn scope_refusals_per_role() {
    let owner = [1; 16];
    let member = [2; 16];
    let replica = [3; 16];
    let viewer = [4; 16];
    let (f1, f2) = (fid(1), fid(2));
    let owner_b = batch(owner, 1, 1, &[stored("h1", 1, 1, 5), stored("h1", 3, 2, 6)]);
    let member_b = batch(
        member,
        1,
        2,
        &[
            // Its own pack of its folder: counts.
            stored("h1", 2, 2, 1),
            // Pack 1 is folder 1's (the owner said so): refused.
            stored("h2", 1, 2, 1),
            // Names another folder outright: refused.
            stored("h2", 1, 1, 1),
            verified("h1", 1),
            dropped("h1", 1),
            // Pack 3 is of its folder, but the member never stored it.
            dropped("h1", 3),
            verified("h1", 3),
            dropped("h1", 2),
            stored("h1", 2, 2, 1),
            published(kind::MANIFEST, 2, 1, 1, 1),
            published(kind::MANIFEST, 1, 1, 1, 1),
            published(kind::SNAPSHOT, 2, 1, 1, 1),
            Event::StorageRetired(StorageRetired {
                storage: "h1".into(),
            }),
            Event::FolderAdded(FolderAdded { folder: f2 }),
        ],
    );
    let replica_b = batch(
        replica,
        1,
        3,
        &[
            stored("replica:r", 1, 0, 0),
            stored("replica:r", 1, 1, 0),
            verified("replica:r", 1),
            published(kind::MANIFEST, 1, 1, 1, 1),
            dropped("h1", 1),
            Event::DeviceEnrolled(DeviceEnrolled { name: "r".into() }),
        ],
    );
    let viewer_b = batch(
        viewer,
        1,
        4,
        &[
            verified("h1", 3),
            verified("h1", 1),
            stored("h1", 3, 2, 1),
            dropped("h1", 3),
            published(kind::MANIFEST, 2, 1, 1, 1),
        ],
    );
    let all = [
        (owner_b, EventScope::Full),
        (member_b, EventScope::Member(f2)),
        (replica_b, EventScope::Replica),
        (viewer_b, EventScope::Viewer(f2)),
    ];
    let mut results = Vec::new();
    for order in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2]] {
        let mut v = LedgerView::default();
        for i in order {
            v.apply_scoped(&all[i].0, &all[i].1);
        }
        let v = v.finish([]);
        // Member: stored 2 (twice), drop of 2, manifest of folder 2 count.
        // Replica: its zero-folder claim, its verification, its name.
        // Viewer: its verification of pack 3.
        assert_eq!(v.events_refused, 9 + 3 + 4, "order {order:?}");
        assert_eq!(v.holders(&pid(1)), vec!["h1", "replica:r"]);
        assert!(
            !v.is_held(&pid(1), "h2"),
            "member's claim on another folder's pack"
        );
        let c = &v.copies(&pid(1))[0];
        assert_eq!(
            c.verified_by,
            Vec::<DeviceBin>::new(),
            "member's verification of folder 1"
        );
        assert_eq!(v.pack_folder(&pid(1)), Some(f1));
        assert_eq!(v.pack_writer(&pid(1)), Some(owner));
        assert_eq!(v.pack_folder(&pid(2)), Some(f2));
        assert_eq!(v.pack_writer(&pid(2)), Some(member));
        // The member's second claim of pack 2 is a later batch position
        // than its drop, but in the same batch: same Lamport, so the drop
        // wins (a place counts only when its claim is newer than its drop).
        assert!(v.dropped_from(&pid(2), "h1"));
        assert_eq!(v.copies(&pid(3))[0].verified_by, vec![member, viewer]);
        assert!(v.holders(&pid(3)) == vec!["h1"]);
        assert!(v.retired.is_empty() && !v.folders.contains(&f2));
        assert!(v.stream(kind::MANIFEST, &f2, &member).is_some());
        assert!(v.stream(kind::MANIFEST, &f1, &member).is_none());
        assert!(v.stream(kind::SNAPSHOT, &f2, &member).is_none());
        assert!(v.stream(kind::MANIFEST, &f1, &replica).is_none());
        assert!(v.stream(kind::MANIFEST, &f2, &viewer).is_none());
        assert_eq!(v.devices.get(&replica).map(String::as_str), Some("r"));
        assert!(v
            .copies(&pid(1))
            .iter()
            .any(|c| c.storage == "replica:r" && c.independently_verified));
        results.push(v.canonical());
    }
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(
        EventScope::of_key_id(&share_ledger_key_id(&f2, 3)),
        Some(EventScope::Member(f2))
    );
    assert_eq!(
        EventScope::of_key_id(&ledger_key_id(2)),
        Some(EventScope::Full)
    );
    assert_eq!(
        EventScope::of_key_id(KEY_REPLICA),
        Some(EventScope::Replica)
    );
    for bad in [
        "ledger",
        "ledger@",
        "ledger@x",
        "share-ledger:00@1",
        "share:ab@1",
    ] {
        assert_eq!(EventScope::of_key_id(bad), None, "{bad}");
    }
}

/// A member claim of a pack no full device named counts for the member's
/// folder; once a full device names another folder for it, it does not.
#[test]
fn member_claim_yields_to_a_full_devices_folder() {
    let (owner, member) = ([1; 16], [2; 16]);
    let m = batch(member, 1, 5, &[stored("h1", 1, 2, 1)]);
    let mut v = LedgerView::default();
    v.apply_scoped(&m, &EventScope::Member(fid(2)));
    let fin = v.finish([]);
    assert_eq!(fin.holders(&pid(1)), vec!["h1"]);
    assert_eq!(fin.pack_folder(&pid(1)), Some(fid(2)));
    v.apply(&batch(owner, 1, 1, &[stored("h2", 1, 1, 3)]));
    let fin = v.finish([]);
    assert_eq!(fin.holders(&pid(1)), vec!["h2"]);
    assert_eq!(fin.pack_folder(&pid(1)), Some(fid(1)));
    assert_eq!(fin.events_refused, 1);
}

// ---- the view -------------------------------------------------------------

/// A drop cancels the claims on that storage made before it (Lamport) and
/// not later ones; a verification after a drop does not bring the copy
/// back; a retirement cancels earlier claims on the storage.
#[test]
fn drop_cancels_earlier_claims_and_not_later_ones() {
    let (a, b, c) = ([1; 16], [2; 16], [3; 16]);
    let mut batches = vec![
        batch(a, 1, 3, &[stored("h1", 1, 1, 1), stored("h2", 1, 1, 1)]),
        batch(b, 1, 5, &[dropped("h1", 1)]),
        batch(c, 1, 6, &[verified("h1", 1)]),
    ];
    let check = |batches: &[Batch]| {
        let mut v = LedgerView::default();
        for x in batches {
            v.apply(x);
        }
        v.finish([])
    };
    let v = check(&batches);
    assert_eq!(v.holders(&pid(1)), vec!["h2"]);
    assert!(v.dropped_from(&pid(1), "h1"));
    batches.push(batch(c, 2, 7, &[stored("h1", 1, 1, 1)]));
    batches.reverse();
    let v = check(&batches);
    assert_eq!(v.holders(&pid(1)), vec!["h1", "h2"]);
    assert!(!v.dropped_from(&pid(1), "h1"));
    // The verification at 6 came after the drop: it counts for the copy
    // c claimed again at 7? c is a claimant, so not independently.
    let h1 = v
        .copies(&pid(1))
        .into_iter()
        .find(|c| c.storage == "h1")
        .unwrap();
    assert!(!h1.independently_verified);
    batches.push(batch(
        b,
        2,
        6,
        &[Event::StorageRetired(StorageRetired {
            storage: "h2".into(),
        })],
    ));
    let v = check(&batches);
    assert_eq!(v.holders(&pid(1)), vec!["h1"]);
    batches.push(batch(a, 2, 8, &[stored("h2", 1, 1, 1)]));
    assert_eq!(check(&batches).holders(&pid(1)), vec!["h1", "h2"]);
}

/// Folder, writer, class and map seq of a pack come from the claim with
/// the largest (Lamport, device, seq, position) stamp, whatever the order.
#[test]
fn pack_metadata_follows_the_newest_claim() {
    let (a, b) = ([1; 16], [2; 16]);
    let x = batch(a, 1, 4, &[stored("h1", 1, 1, 10)]);
    let mut y = batch(b, 1, 4, &[stored("h2", 1, 1, 20)]);
    let mut z = batch(a, 2, 2, &[stored("h3", 1, 1, 30)]);
    for order in [[0, 1, 2], [2, 1, 0], [1, 0, 2]] {
        let all = [&x, &y, &z];
        let mut v = LedgerView::default();
        for i in order {
            v.apply(all[i]);
        }
        assert_eq!(v.pack(&pid(1)).unwrap().map_seq, 20, "b wins the tie at 4");
        assert_eq!(v.pack_writer(&pid(1)), Some(b));
    }
    y.lamport = 1;
    z.lamport = 9;
    let mut v = LedgerView::default();
    v.apply(&z);
    v.apply(&y);
    v.apply(&x);
    assert_eq!(v.pack(&pid(1)).unwrap().map_seq, 30);
}

/// Streams keep the newest base and what follows; records below it are
/// dropped whatever the arrival order; two records under one seq mark the
/// stream forked.
#[test]
fn streams_keep_the_newest_base_and_its_deltas() {
    let d = [1; 16];
    let evs = [
        published(kind::MANIFEST, 1, 1, 1, 1),
        published(kind::MANIFEST, 1, 2, 1, 2),
        published(kind::MANIFEST, 1, 3, 3, 3),
        published(kind::MANIFEST, 1, 4, 3, 4),
        published(kind::MANIFEST, 1, 5, 3, 5),
    ];
    let mut views = Vec::new();
    for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3]] {
        let mut v = LedgerView::default();
        for i in order {
            v.apply(&batch(d, i as u64 + 1, 1, std::slice::from_ref(&evs[i])));
        }
        let s = v.stream(kind::MANIFEST, &fid(1), &d).unwrap();
        assert_eq!(s.base(), Some((3, [3; 32], 1)));
        assert_eq!(
            s.deltas().iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![4, 5]
        );
        assert!(v.announced(kind::MANIFEST, &fid(1), &d, 2).is_none());
        views.push(v.canonical());
    }
    assert!(views.windows(2).all(|w| w[0] == w[1]));
    let mut v = LedgerView::default();
    v.apply(&batch(d, 1, 1, &[published(kind::BLOCK_MAP, 1, 4, 3, 4)]));
    v.apply(&batch(d, 2, 1, &[published(kind::BLOCK_MAP, 1, 4, 3, 8)]));
    assert_eq!(v.forked_streams.len(), 1);
    // The larger hash is kept, whatever came first.
    let kept = v.announced(kind::BLOCK_MAP, &fid(1), &d, 4).unwrap();
    assert_eq!((kept.batch, kept.body_hash), (2, [8; 32]));
    // Snapshot streams keep every record (differentials name old bases).
    let mut v = LedgerView::default();
    v.apply(&batch(
        d,
        1,
        1,
        &[
            published(kind::SNAPSHOT, 2, 1, 1, 1),
            published(kind::SNAPSHOT, 2, 2, 2, 2),
        ],
    ));
    assert_eq!(
        v.stream(kind::SNAPSHOT, &fid(2), &d).unwrap().records.len(),
        2
    );
}

/// "Copies of a block" go through the map: storages holding a live pack
/// of an unmarked place; marked places only when nothing else exists.
#[test]
fn copies_of_a_block_come_from_map_places() {
    struct Marked(UnmarkedPlaces, BTreeSet<Place>);
    impl BlockMapView for Marked {
        fn places_of(&self, o: &ObjectBin) -> Vec<Place> {
            self.0.places_of(o)
        }
        fn is_marked(&self, p: &Place) -> bool {
            self.1.contains(p)
        }
    }
    let a = [1; 16];
    let mut v = LedgerView::default();
    v.apply(&batch(
        a,
        1,
        1,
        &[
            stored("h1", 1, 1, 1),
            stored("h2", 1, 1, 1),
            stored("c", 2, 1, 1),
            stored("h1", 3, 1, 1),
        ],
    ));
    v.apply(&batch(a, 2, 2, &[dropped("h1", 3)]));
    let v = v.finish([]);
    let obj = [9; 32];
    let p1 = Place {
        pack: pid(1),
        offset: 0,
        len: 100,
    };
    let p2 = Place {
        pack: pid(2),
        offset: 4096,
        len: 100,
    };
    let p3 = Place {
        pack: pid(3),
        offset: 0,
        len: 100,
    };
    let map = UnmarkedPlaces(HashMap::from([(obj, vec![p1, p2, p3])]));
    assert_eq!(
        v.block_copies(&obj, &map),
        BTreeSet::from(["c".to_string(), "h1".into(), "h2".into()])
    );
    let marked = Marked(map, BTreeSet::from([p1]));
    assert_eq!(
        v.block_copies(&obj, &marked),
        BTreeSet::from(["c".to_string()])
    );
    let places = v.block_places(&obj, &marked);
    assert_eq!(places.len(), 2, "pack 3 is held nowhere");
    assert_eq!((places[0].place, places[0].marked), (p2, false));
    assert_eq!((places[1].place, places[1].marked), (p1, true));
    assert_eq!(v.packs_on("h1").count(), 1);
}

/// 100 000 blocks in 1 500 packs give the same view as 1 500 packs of one
/// block each: the view knows packs, never blocks (test 5 of section 12).
#[test]
fn view_is_pack_level() {
    let size = |blocks_per_pack: u64| {
        let mut v = LedgerView::default();
        let mut events = Vec::new();
        for p in 0..1500u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&p.to_le_bytes());
            for s in ["h1", "h2"] {
                events.push(Event::PackStored(PackStored {
                    storage: s.into(),
                    pack: id,
                    class: 3,
                    folder: fid(1),
                    map_seq: 1,
                }));
            }
        }
        // The blocks are listed in the block map; the batch announces it.
        events.push(published(kind::BLOCK_MAP, 1, 1, 1, blocks_per_pack as u8));
        v.apply(&batch([1; 16], 1, 1, &events));
        postcard::to_allocvec(&v).unwrap().len()
    };
    let (many, one) = (size(67), size(1));
    assert!(many.abs_diff(one) * 10 <= one, "{many} vs {one}");
}

// ---- the store ------------------------------------------------------------

#[test]
fn append_chain_and_ingest() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let dir = tempfile::tempdir().unwrap();
    let mut a = store(&dir, "a");
    let enrol = Event::DeviceEnrolled(DeviceEnrolled { name: "a".into() }).to_raw();
    let b1 = a
        .append_own(&d, vec![enrol], vec![], 1, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let b2 = a
        .append_own(&d, vec![], vec![], 2, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let body2 = Batch::from_postcard(&b2.open(&key, MAX_BATCH_PLAIN).unwrap()).unwrap();
    assert_eq!(body2.prev, b1.body_hash);
    let mut b = store(&dir, "b");
    let pk = s.public();
    assert_eq!(b.ingest(b1.clone(), &pk, Some(&key)).unwrap(), Ingest::New);
    assert_eq!(
        b.ingest(b1.clone(), &pk, Some(&key)).unwrap(),
        Ingest::Known
    );
    assert_eq!(b.ingest(b2, &pk, Some(&key)).unwrap(), Ingest::New);
    assert_eq!(b.head(&d).seq, 2);
    let key_for = |k: &str| (k == id).then(|| key.clone());
    let v = b.view_scoped(key_for, |_, _| true, full_scope).unwrap();
    assert_eq!(v.devices.get(&d).unwrap(), "a");
    assert_eq!(v.batches, 2);
    // Another vault's batch, a moved or relabelled one are refused.
    let mut other = LedgerStore::open(&dir.path().join("other"), [8; 16]).unwrap();
    assert!(other.ingest(b1.clone(), &pk, Some(&key)).is_err());
    let mut moved = b1.clone();
    moved.seq = 3;
    assert!(b.ingest(moved, &pk, Some(&key)).is_err());
    let mut relabelled = b1.clone();
    relabelled.key_id = ledger_key_id(1);
    assert!(b.ingest(relabelled, &pk, None).is_err(), "key_id is signed");
    let mut rescoped = b1;
    rescoped.scope = fid(1);
    assert!(b.ingest(rescoped, &pk, None).is_err(), "scope is signed");
}

#[test]
fn fork_is_detected() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let dir = tempfile::tempdir().unwrap();
    let b1 = store(&dir, "a")
        .append_own(&d, vec![], vec![], 1, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let enrol = Event::DeviceEnrolled(DeviceEnrolled { name: "x".into() }).to_raw();
    let again = store(&dir, "restored")
        .append_own(&d, vec![enrol], vec![], 5, &key, &id, NO_FOLDER, &s)
        .unwrap();
    assert_ne!(b1.body_hash, again.body_hash);
    let mut obs = store(&dir, "observer");
    assert_eq!(
        obs.ingest(b1, &s.public(), Some(&key)).unwrap(),
        Ingest::New
    );
    assert_eq!(
        obs.ingest(again, &s.public(), Some(&key)).unwrap(),
        Ingest::Fork
    );
    assert!(obs.is_forked(&d));
    let v = obs
        .view_scoped(|_| Some(key.clone()), |_, _| true, full_scope)
        .unwrap();
    assert!(v.forked.contains(&d));
}

/// A batch whose predecessor is missing waits without moving the head;
/// the gap filled, it follows; one naming another predecessor is a fork;
/// one far ahead is refused; one under an unknown key is kept unread.
#[test]
fn gaps_wait_and_follow() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let recs: Vec<SignedRecord> = (1..=4)
        .map(|l| {
            own.append_own(&d, vec![], vec![], l, &key, &id, NO_FOLDER, &s)
                .unwrap()
        })
        .collect();
    let pk = s.public();
    let mut r = store(&dir, "reader");
    assert_eq!(
        r.ingest(recs[0].clone(), &pk, Some(&key)).unwrap(),
        Ingest::New
    );
    assert_eq!(
        r.ingest(recs[2].clone(), &pk, Some(&key)).unwrap(),
        Ingest::Pending
    );
    assert_eq!(
        r.ingest(recs[3].clone(), &pk, None).unwrap(),
        Ingest::Pending
    );
    assert_eq!(r.head(&d).seq, 1);
    assert_eq!(r.pending_seqs(&d), vec![3, 4]);
    assert_eq!(
        r.ingest(recs[1].clone(), &pk, Some(&key)).unwrap(),
        Ingest::New
    );
    assert_eq!(r.head(&d).seq, 4);
    assert!(r.pending_seqs(&d).is_empty());
    // A batch at the head plus MAX_AHEAD + 1 is not kept.
    let far = Batch {
        prev: [1; 32],
        ..batch(d, 4 + MAX_AHEAD + 1, 9, &[])
    };
    let h = Header {
        kind: kind::BATCH,
        vault: VAULT,
        scope: NO_FOLDER,
        device: d,
        seq: far.seq,
        part: 0,
        parts: 1,
        key_id: id.clone(),
    };
    let far = SignedRecord::seal(&h, &key, &far.to_postcard().unwrap(), &s).unwrap();
    assert_eq!(r.ingest(far, &pk, Some(&key)).unwrap(), Ingest::Refused);
    // Batch 6 naming a predecessor other than batch 5 is a fork once 5 is in.
    let mut alt = store(&dir, "alt");
    for rec in &recs {
        alt.ingest(rec.clone(), &pk, Some(&key)).unwrap();
    }
    let five = own
        .append_own(&d, vec![], vec![], 5, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let alt5 = alt
        .append_own(
            &d,
            vec![Event::FolderAdded(FolderAdded { folder: fid(1) }).to_raw()],
            vec![],
            5,
            &key,
            &id,
            NO_FOLDER,
            &s,
        )
        .unwrap();
    let alt6 = alt
        .append_own(&d, vec![], vec![], 6, &key, &id, NO_FOLDER, &s)
        .unwrap();
    assert_eq!(r.ingest(alt6, &pk, Some(&key)).unwrap(), Ingest::Pending);
    assert_eq!(r.ingest(five, &pk, Some(&key)).unwrap(), Ingest::New);
    assert!(r.is_forked(&d));
    assert_ne!(alt5.body_hash, recs[3].body_hash);
    // The Lamport limit.
    let mut lim = store(&dir, "lim");
    assert_eq!(
        lim.ingest_limited(recs[0].clone(), &pk, Some(&key), 0)
            .unwrap(),
        Ingest::Refused
    );
}

/// A checkpoint speaks for its signer only: claims, verifications, drops,
/// announcements, snapshots and acknowledgements it attributes to another
/// device are left out.
#[test]
fn checkpoint_cannot_speak_for_other_devices() {
    let s = signer(1);
    let x = dev_of(&s);
    let y = dev_of(&signer(2));
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let b1 = own
        .append_own(&x, vec![], vec![], 1, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let mut forged = LedgerView::default();
    forged.apply(&batch(x, 1, 1, &[stored("box", 1, 1, 4)]));
    let mut yb = batch(
        y,
        1,
        2,
        &[
            verified("box", 1),
            dropped("box2", 1),
            stored("box3", 1, 1, 9),
            published(kind::MANIFEST, 1, 9, 9, 1),
            Event::SnapshotTaken(SnapshotTaken {
                backup: fid(1),
                seq: 1,
                taken_utc: 1,
                expires_utc: 2,
                files: 1,
                bytes: 1,
            }),
        ],
    );
    yb.seen = vec![(x, 99)];
    forged.apply(&yb);
    assert_eq!(forged.pack_writer(&pid(1)), Some(y));
    let cp = Checkpoint {
        device: x,
        seq: 1,
        head_hash: b1.body_hash,
        created_utc: 0,
        view: forged,
    };
    let parts = cp.seal(&VAULT, &key, &id, &s).unwrap();
    parts[0].verify(&s.public()).unwrap();
    let mut reader = store(&dir, "reader");
    let opened = Checkpoint::open(&parts, &key).unwrap();
    assert_eq!(
        reader.ingest_checkpoint(&parts, &opened, None).unwrap(),
        Ingest::New
    );
    let v = reader
        .view_scoped(|k| (k == id).then(|| key.clone()), |_, _| true, full_scope)
        .unwrap();
    assert_eq!(
        v.holders(&pid(1)),
        vec!["box"],
        "x's own claim stays, y's on box3 goes"
    );
    let c = &v.copies(&pid(1))[0];
    assert!(c.verified_by.is_empty() && !c.independently_verified);
    assert!(!v.dropped_from(&pid(1), "box2"));
    assert_eq!(v.pack_writer(&pid(1)), None, "y's stamp is not x's to give");
    assert!(v.stream(kind::MANIFEST, &fid(1), &y).is_none());
    assert!(v.snapshots.keys().all(|(_, d, _)| d != &y));
    assert!(!v.acks.contains_key(&y));
}

/// A checkpoint far beyond the batches held is refused unless the batch it
/// ends at is beside it.
#[test]
fn checkpoint_far_ahead_is_refused() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let far = Checkpoint {
        device: d,
        seq: MAX_AHEAD + 5,
        head_hash: [5; 32],
        created_utc: 0,
        view: LedgerView::default(),
    };
    let parts = far.seal(&VAULT, &key, &id, &s).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut r = store(&dir, "r");
    assert_eq!(
        r.ingest_checkpoint(&parts, &far, None).unwrap(),
        Ingest::Refused
    );
    let last = Batch {
        prev: [4; 32],
        ..batch(d, MAX_AHEAD + 5, 7, &[])
    };
    let h = Header {
        kind: kind::BATCH,
        vault: VAULT,
        scope: NO_FOLDER,
        device: d,
        seq: last.seq,
        part: 0,
        parts: 1,
        key_id: id.clone(),
    };
    let last = SignedRecord::seal(&h, &key, &last.to_postcard().unwrap(), &s).unwrap();
    let real = Checkpoint {
        head_hash: last.body_hash,
        ..far
    };
    let parts = real.seal(&VAULT, &key, &id, &s).unwrap();
    assert_eq!(
        r.ingest_checkpoint(&parts, &real, Some(&last)).unwrap(),
        Ingest::New
    );
    assert_eq!(r.head(&d).seq, MAX_AHEAD + 5);
}

/// A reader starting from a checkpoint and the later batches sees what a
/// reader of every batch sees; covered batches are not kept; a checkpoint
/// or batch contradicting it is a fork. A checkpoint larger than one part
/// comes in parts.
#[test]
fn checkpoint_stands_in_for_its_batches() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let key_for = |k: &str| (k == id).then(|| key.clone());
    let keep = |_: &DeviceBin, _: u64| true;
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let mut rng = Rng(77);
    let mut recs = Vec::new();
    for l in 1..=30 {
        let evs: Vec<RawEvent> = (0..3)
            .map(|_| random_event(&mut rng, Role::Full).to_raw())
            .collect();
        recs.push(
            own.append_own(&d, evs, vec![], l, &key, &id, NO_FOLDER, &s)
                .unwrap(),
        );
    }
    let cp = own.make_checkpoint(&d, 20, key_for, &key, &id, &s).unwrap();
    let pk = s.public();
    let mut full = store(&dir, "full");
    for r in &recs {
        full.ingest(r.clone(), &pk, Some(&key)).unwrap();
    }
    let expected = full
        .view_scoped(key_for, keep, full_scope)
        .unwrap()
        .canonical();
    assert_eq!(
        own.view_scoped(key_for, keep, full_scope)
            .unwrap()
            .canonical(),
        expected
    );
    let opened = Checkpoint::open(&cp, &key).unwrap();
    let mut fresh = store(&dir, "fresh");
    assert_eq!(
        fresh.ingest_checkpoint(&cp, &opened, None).unwrap(),
        Ingest::New
    );
    assert_eq!(fresh.head(&d).seq, 20);
    assert_eq!(
        fresh.ingest(recs[4].clone(), &pk, Some(&key)).unwrap(),
        Ingest::Known
    );
    assert!(fresh.get(&d, 5).unwrap().is_none());
    for r in &recs[20..] {
        assert_eq!(
            fresh.ingest(r.clone(), &pk, Some(&key)).unwrap(),
            Ingest::New
        );
    }
    assert_eq!(
        fresh
            .view_scoped(key_for, keep, full_scope)
            .unwrap()
            .canonical(),
        expected
    );
    let mut cache = ViewCache::new("ctx".into());
    fresh
        .update_view_scoped(&mut cache, key_for, keep, full_scope)
        .unwrap();
    assert_eq!(fresh.finish(&cache.raw).canonical(), expected);
    assert_eq!(
        full.ingest_checkpoint(&cp, &opened, None).unwrap(),
        Ingest::New
    );
    assert_eq!(full.drop_through(&d, 20).unwrap(), 20);
    assert_eq!(full.all().unwrap().len(), 10);
    assert_eq!(
        full.view_scoped(key_for, keep, full_scope)
            .unwrap()
            .canonical(),
        expected
    );
    // A copy restored to 20 signs another 21.
    let mut restored = store(&dir, "restored");
    for r in &recs[..20] {
        restored.ingest(r.clone(), &pk, Some(&key)).unwrap();
    }
    let other21 = restored
        .append_own(&d, vec![], vec![], 99, &key, &id, NO_FOLDER, &s)
        .unwrap();
    let mut obs = store(&dir, "obs");
    obs.ingest_checkpoint(&cp, &opened, None).unwrap();
    assert_eq!(obs.ingest(other21, &pk, Some(&key)).unwrap(), Ingest::New);
    assert_eq!(
        obs.ingest(recs[21].clone(), &pk, Some(&key)).unwrap(),
        Ingest::Fork
    );
    let other_cp = restored
        .make_checkpoint(&d, 21, key_for, &key, &id, &s)
        .unwrap();
    let other_open = Checkpoint::open(&other_cp, &key).unwrap();
    assert_eq!(
        fresh
            .ingest_checkpoint(&other_cp, &other_open, None)
            .unwrap(),
        Ingest::Fork
    );
    // Parts: a body over one part's limit is cut and joined in order.
    let big: Vec<u8> = (0..(envelope::MAX_PART_BODY + 4096))
        .map(|i| (i * 7919 % 251) as u8)
        .collect();
    let mut rnd = vec![0u8; envelope::MAX_PART_BODY + 4096];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
    let h = Header {
        kind: kind::CHECKPOINT,
        vault: VAULT,
        scope: NO_FOLDER,
        device: d,
        seq: 1,
        part: 0,
        parts: 1,
        key_id: id.clone(),
    };
    let parts = envelope::seal_parts(&h, &key, &rnd, &s).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(envelope::open_parts(&parts, &key, 1 << 30).unwrap(), rnd);
    let swapped = vec![parts[1].clone(), parts[0].clone()];
    assert!(envelope::open_parts(&swapped, &key, 1 << 30).is_err());
    assert!(envelope::open_parts(&parts[..1], &key, 1 << 30).is_err());
    assert_eq!(envelope::seal_parts(&h, &key, &big, &s).unwrap().len(), 1);
}

// ---- settling ---------------------------------------------------------------

/// "Settled" (section 3): every current writer of the folder acknowledged
/// the marker's batch, members through their folder-scoped batches; the
/// answer does not depend on the order acknowledgements arrive in, and
/// members' acknowledgements never count for vault pruning.
#[test]
fn settle_needs_every_writer_in_any_order() {
    let (a, b, m) = ([1; 16], [2; 16], [3; 16]);
    let folder = fid(5);
    let writers = [a, b, m];
    let acks = [
        (b, EventScope::Full, 1, vec![(a, 4)]),
        (m, EventScope::Member(folder), 1, vec![(a, 7), (b, 3)]),
        (b, EventScope::Full, 2, vec![(a, 6)]),
        (m, EventScope::Member(fid(6)), 2, vec![(a, 9)]),
    ];
    let orders: [[usize; 4]; 4] = [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]];
    for order in orders {
        let mut v = LedgerView::default();
        let mut seen_m = false;
        let mut seen_b2 = false;
        for i in order {
            let (dev, scope, seq, seen) = &acks[i];
            v.apply_scoped(
                &Batch {
                    seen: seen.clone(),
                    ..batch(*dev, *seq, *seq, &[])
                },
                scope,
            );
            seen_m |= i == 1;
            seen_b2 |= i == 2;
            let want = seen_m && seen_b2;
            assert_eq!(
                v.settled(&folder, &writers, &a, 5),
                want,
                "{order:?} at {i}"
            );
        }
        assert!(v.settled(&folder, &writers, &a, 6));
        assert!(!v.settled(&folder, &writers, &a, 7), "b saw 6 only");
        assert_eq!(v.settle_waiting_for(&folder, &writers, &a, 7), vec![b]);
        assert_eq!(
            v.settle_waiting_for(&fid(6), &writers, &a, 8),
            vec![b],
            "m acked 9 for folder 6"
        );
        assert!(
            v.settled(&folder, &[b, m], &b, 3),
            "a writer never waits for itself"
        );
        assert!(
            !v.vault_acked_by_all(&[b, m], &a, 5),
            "a member's ack is not a vault ack"
        );
        assert!(v.vault_acked_by_all(&[b], &a, 6));
        assert_eq!(v.acked(&m, &a, None), 0);
        assert_eq!(v.acked(&m, &a, Some(&folder)), 7);
    }
    // A replica's `seen` counts nowhere.
    let mut v = LedgerView::default();
    v.apply_scoped(
        &Batch {
            seen: vec![(a, 9)],
            ..batch(m, 1, 1, &[])
        },
        &EventScope::Replica,
    );
    assert!(!v.settled(&folder, &[m], &a, 1));
}

// ---- order independence -----------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Full,
    Member,
    Replica,
}

const STORAGES: [&str; 3] = ["h1", "h2", "replica:r"];

fn random_event(rng: &mut Rng, role: Role) -> Event {
    let pack = 1 + rng.below(6) as u8;
    let storage = STORAGES[rng.below(3) as usize];
    let folder = 1 + rng.below(3) as u8;
    match (role, rng.below(12)) {
        (Role::Replica, 0..=5) => stored("replica:r", pack, 0, 0),
        (Role::Replica, 6..=9) => verified(storage, pack),
        (_, 0) => Event::DeviceEnrolled(DeviceEnrolled {
            name: format!("n{}", rng.below(4)),
        }),
        (_, 1) => Event::FolderAdded(FolderAdded {
            folder: fid(folder),
        }),
        (_, 2 | 3) => stored(
            storage,
            pack,
            if rng.below(5) == 0 { 0 } else { folder },
            rng.below(9),
        ),
        (_, 4) => verified(storage, pack),
        (_, 5) => dropped(storage, pack),
        (_, 6) => {
            let seq = 1 + rng.below(8);
            let base = if rng.below(3) == 0 {
                seq
            } else {
                1 + rng.below(seq)
            };
            let k = [kind::MANIFEST, kind::BLOCK_MAP, kind::TRASH, kind::SNAPSHOT]
                [rng.below(4) as usize];
            published(k, folder, seq, base, rng.below(3) as u8)
        }
        (_, 7) => Event::StorageRetired(StorageRetired {
            storage: storage.into(),
        }),
        (_, 8) => Event::SnapshotTaken(SnapshotTaken {
            backup: fid(folder),
            seq: rng.below(4),
            taken_utc: rng.below(100) as i64,
            expires_utc: rng.below(1000) as i64,
            files: rng.below(10),
            bytes: rng.below(1000),
        }),
        (_, 9) => Event::SnapshotExpired(SnapshotExpired {
            backup: fid(folder),
            device: [1 + rng.below(3) as u8; 16],
            seq: rng.below(4),
        }),
        (_, 10) => Event::BackupStopped(BackupStopped {
            backup: fid(folder),
        }),
        _ => verified(storage, pack),
    }
}

fn random_raw(rng: &mut Rng, role: Role) -> Vec<RawEvent> {
    (0..rng.below(5))
        .map(|_| match rng.below(20) {
            0 => RawEvent {
                code: 40 + rng.below(3) as u16,
                payload: vec![1],
            },
            1 => RawEvent {
                code: code::PACK_STORED,
                payload: vec![9, 9],
            },
            _ => random_event(rng, role).to_raw(),
        })
        .collect()
}

/// Batches applied to a view in any order, or split over two views that
/// are merged, give the same finished view.
#[test]
fn view_application_is_order_independent() {
    for round in 0..20u64 {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d ^ ((round + 1) * 0x9e37_79b9));
        let roles = [
            (Role::Full, EventScope::Full),
            (Role::Full, EventScope::Full),
            (Role::Member, EventScope::Member(fid(1))),
            (Role::Replica, EventScope::Replica),
        ];
        let mut all = Vec::new();
        for (i, (role, scope)) in roles.iter().enumerate() {
            for seq in 1..=(3 + rng.below(10)) {
                let mut b = Batch {
                    events: random_raw(&mut rng, *role),
                    ..batch([i as u8 + 1; 16], seq, rng.below(20), &[])
                };
                b.seen = vec![([1 + rng.below(4) as u8; 16], rng.below(9))];
                all.push((b, scope.clone()));
            }
        }
        let build = |order: &[usize]| {
            let mut v = LedgerView::default();
            for i in order {
                v.apply_scoped(&all[*i].0, &all[*i].1);
            }
            v
        };
        let mut order: Vec<usize> = (0..all.len()).collect();
        let first = build(&order).finish([]).canonical();
        for _ in 0..4 {
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            assert_eq!(build(&order).finish([]).canonical(), first, "round {round}");
            let cut = rng.below(order.len() as u64) as usize;
            let mut left = build(&order[..cut]);
            left.merge(&build(&order[cut..]));
            assert_eq!(
                left.finish([]).canonical(),
                first,
                "round {round} merged at {cut}"
            );
            let wire: LedgerView =
                postcard::from_bytes(&postcard::to_allocvec(&left).unwrap()).unwrap();
            assert_eq!(wire.finish([]).canonical(), first);
        }
    }
}

/// A cached view brought up to date at random moments, while batches of
/// full devices (some under a key the reader lacks, one with a cut-off and
/// a checkpoint possibly beyond it), a member and a replica arrive in
/// random order, always equals a full replay; also after its saved form.
#[test]
fn cached_view_equals_full_replay() {
    for round in 0..8u64 {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ ((round + 1) * 0x1234_5678_9abc));
        let key = SecretKey::random();
        let other = SecretKey::random();
        let share = SecretKey::random();
        let rkey = SecretKey::random();
        let dir = tempfile::tempdir().unwrap();
        let signers: Vec<SigningKey> = (0..5).map(|i| signer(i as u8 + 1)).collect();
        let ids: Vec<DeviceBin> = signers.iter().map(dev_of).collect();
        let f1 = fid(1);
        let (lk, ok, sk) = (
            ledger_key_id(0),
            ledger_key_id(1),
            share_ledger_key_id(&f1, 0),
        );
        let writer_key = |id: &str| -> Option<SecretKey> {
            match id {
                x if x == lk => Some(key.clone()),
                x if x == ok => Some(other.clone()),
                x if x == sk => Some(share.clone()),
                KEY_REPLICA => Some(rkey.clone()),
                _ => None,
            }
        };
        enum Item {
            Batch(usize, SignedRecord),
            Checkpoint(usize, Vec<SignedRecord>),
        }
        let mut pending = Vec::new();
        for (i, s) in signers.iter().enumerate() {
            let mut own = store(&dir, &format!("own{i}"));
            let role = match i {
                3 => Role::Member,
                4 => Role::Replica,
                _ => Role::Full,
            };
            let mut lamport = 0;
            let n = 5 + rng.below(20);
            for _ in 0..n {
                lamport += 1 + rng.below(3);
                let (k, id, scope) = match role {
                    Role::Member => (&share, sk.as_str(), f1),
                    Role::Replica => (&rkey, KEY_REPLICA, NO_FOLDER),
                    Role::Full if rng.below(6) == 0 => (&other, ok.as_str(), NO_FOLDER),
                    Role::Full => (&key, lk.as_str(), NO_FOLDER),
                };
                let seen = vec![(ids[rng.below(5) as usize], rng.below(20))];
                let rec = own
                    .append_own(
                        &ids[i],
                        random_raw(&mut rng, role),
                        seen,
                        lamport,
                        k,
                        id,
                        scope,
                        s,
                    )
                    .unwrap();
                pending.push(Item::Batch(i, rec));
            }
            if i == 0 || i == 2 {
                let at = 1 + rng.below(n);
                let cp = own
                    .make_checkpoint(&ids[i], at, writer_key, &key, &lk, s)
                    .unwrap();
                pending.push(Item::Checkpoint(i, cp));
            }
        }
        let cutoff = 3 + rng.below(10);
        // The reader holds the vault key of epoch 0, the member key and the
        // replica key, not epoch 1's.
        let key_for = |id: &str| if id == ok { None } else { writer_key(id) };
        let keep = |d: &DeviceBin, seq: u64| d != &ids[2] || seq <= cutoff;
        let scope = |d: &DeviceBin, id: &str| -> Option<EventScope> {
            let s = EventScope::of_key_id(id)?;
            let ok = match &s {
                EventScope::Full => ids[..3].contains(d),
                EventScope::Member(_) => d == &ids[3],
                EventScope::Replica => d == &ids[4],
                EventScope::Viewer(_) => false,
            };
            ok.then_some(s)
        };
        let mut reader = store(&dir, "reader");
        let mut cache = ViewCache::new("ctx".into());
        let (ck, aad) = (SecretKey::random(), b"view".to_vec());
        while !pending.is_empty() {
            match pending.remove(rng.below(pending.len() as u64) as usize) {
                Item::Batch(i, rec) => {
                    let k = key_for(&rec.key_id);
                    reader
                        .ingest(rec, &signers[i].public(), k.as_ref())
                        .unwrap();
                }
                Item::Checkpoint(i, parts) => {
                    for p in &parts {
                        p.verify(&signers[i].public()).unwrap();
                    }
                    let cp = Checkpoint::open(&parts, &key).unwrap();
                    assert_ne!(
                        reader.ingest_checkpoint(&parts, &cp, None).unwrap(),
                        Ingest::Fork
                    );
                    if i == 0 && rng.below(2) == 0 {
                        reader.drop_through(&ids[0], cp.seq).unwrap();
                    }
                }
            }
            if rng.below(3) == 0 {
                reader
                    .update_view_scoped(&mut cache, key_for, keep, scope)
                    .unwrap();
                let full = reader.view_scoped(key_for, keep, scope).unwrap();
                assert_eq!(
                    reader.finish(&cache.raw).canonical(),
                    full.canonical(),
                    "round {round}"
                );
            }
            if rng.below(8) == 0 {
                cache = ViewCache::open(&cache.seal(&ck, &aad).unwrap(), &ck, &aad).unwrap();
            }
        }
        reader
            .update_view_scoped(&mut cache, key_for, keep, scope)
            .unwrap();
        let full = reader.view_scoped(key_for, keep, scope).unwrap();
        assert_eq!(
            reader.finish(&cache.raw).canonical(),
            full.canonical(),
            "round {round}"
        );
        assert!(full.batches > 0);
        assert!(reader.cache_fits(&cache));
    }
}

/// The local heads can be rebuilt from the files held.
#[test]
fn rescan_rebuilds_heads() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    for l in 1..=5 {
        own.append_own(&d, vec![], vec![], l, &key, &id, NO_FOLDER, &s)
            .unwrap();
    }
    own.make_checkpoint(&d, 3, |_| Some(key.clone()), &key, &id, &s)
        .unwrap();
    let before = own.head(&d);
    std::fs::remove_file(dir.path().join("own").join("heads.json")).unwrap();
    std::fs::write(
        dir.path()
            .join("own")
            .join(hex::encode(d))
            .join("0000000000000009-0000.rec"),
        b"junk",
    )
    .unwrap();
    let mut again = store(&dir, "own");
    assert!(again.heads_absent());
    let r = again.rescan().unwrap();
    assert_eq!(
        (r.devices, r.batches, r.checkpoints, r.damaged.len()),
        (1, 5, 1, 1)
    );
    let after = again.head(&d);
    assert_eq!((after.seq, after.hash), (before.seq, before.hash));
    assert_eq!(after.base.map(|b| b.seq), Some(3));
}

// ---- the record envelope and folder roles (work package 12) ----------------

/// Folder roles for the tests: (device, folder) -> role changes by Lamport
/// time (`true`: owner or editor from then on).
struct Roles(Vec<(DeviceBin, FolderBin, u64, bool)>);

impl scope::FolderRoles for Roles {
    fn writes_at(&self, device: &DeviceBin, folder: &FolderBin, lamport: u64) -> Option<bool> {
        if !self.0.iter().any(|(_, f, _, _)| f == folder) {
            return None;
        }
        Some(
            self.0
                .iter()
                .filter(|(d, f, at, _)| d == device && f == folder && *at <= lamport)
                .max_by_key(|(_, _, at, _)| *at)
                .is_some_and(|(_, _, _, w)| *w),
        )
    }
}

/// A full device's batch counts for the vault, but its claims naming a
/// folder and its announcements of a folder's manifests, maps and trash
/// count only while it is an owner or editor there (section 9): a viewer
/// and a device without a grant (K3 only) copy whole packs, verify and
/// drop, and nothing they claim for the folder counts; an editor demoted
/// later keeps what it wrote before. A folder the roles do not know is not
/// judged.
#[test]
fn full_devices_folder_events_follow_their_folder_roles() {
    let (editor, viewer, k3_only, demoted) = ([1; 16], [2; 16], [3; 16], [4; 16]);
    let (f, unknown) = (fid(1), fid(9));
    let roles = Roles(vec![
        (editor, f, 0, true),
        (viewer, f, 0, false),
        (demoted, f, 0, true),
        (demoted, f, 50, false),
    ]);
    let batches = [
        batch(
            editor,
            1,
            10,
            &[stored("h1", 1, 1, 1), published(kind::MANIFEST, 1, 1, 1, 1)],
        ),
        batch(
            viewer,
            1,
            11,
            &[
                stored("h1", 2, 1, 1),
                published(kind::MANIFEST, 1, 1, 1, 2),
                published(kind::BLOCK_MAP, 1, 1, 1, 2),
                verified("h1", 1),
                // A whole-pack copy: zero folder.
                stored("h2", 1, 0, 0),
            ],
        ),
        batch(
            k3_only,
            1,
            12,
            &[
                stored("h3", 3, 1, 1),
                published(kind::TRASH, 1, 1, 1, 3),
                stored("h3", 1, 0, 0),
                dropped("h1", 1),
            ],
        ),
        batch(demoted, 1, 20, &[stored("h1", 4, 1, 1)]),
        batch(demoted, 2, 60, &[stored("h1", 5, 1, 2)]),
        batch(viewer, 2, 70, &[stored("h1", 6, 9, 1)]),
    ];
    let mut v = LedgerView::default();
    for b in &batches {
        v.apply_scoped_with(b, &EventScope::Full, &roles);
    }
    let v = v.finish(Vec::<DeviceBin>::new());
    // The editor's claim and announcement count.
    assert_eq!(v.pack_folder(&pid(1)), Some(f));
    assert!(v.announced(kind::MANIFEST, &f, &editor, 1).is_some());
    // The viewer's and the K3-only device's claims for the folder do not.
    assert!(v.pack(&pid(2)).is_none());
    assert!(v.pack(&pid(3)).is_none());
    assert!(v.stream(kind::MANIFEST, &f, &viewer).is_none());
    assert!(v.stream(kind::BLOCK_MAP, &f, &viewer).is_none());
    assert!(v.stream(kind::TRASH, &f, &k3_only).is_none());
    // Their copies, verifications and drops do.
    assert_eq!(v.holders(&pid(1)), vec!["h2", "h3"]);
    assert!(v.dropped_from(&pid(1), "h1"));
    // Before its demotion the editor's claim counts, after it not.
    assert_eq!(v.pack_folder(&pid(4)), Some(f));
    assert!(v.pack(&pid(5)).is_none());
    // A folder the roles do not know: not judged.
    assert_eq!(v.pack_folder(&pid(6)), Some(unknown));
    assert_eq!(v.events_refused, 6);
    // Without roles every full device's event counts, as before.
    let mut all = LedgerView::default();
    for b in &batches {
        all.apply(b);
    }
    assert!(all.finish(Vec::<DeviceBin>::new()).pack(&pid(5)).is_some());
}

/// Batches are `record::SignedRecord`s: the signature and the body's
/// associated data bind storage format 3 (not the build's format), the
/// acceptance rule of every record checks the name it was read under, and
/// a relabelled key id is refused.
#[test]
fn batches_are_signed_records_bound_to_format_3() {
    let s = signer(1);
    let d = dev_of(&s);
    let key = SecretKey::random();
    let dir = tempfile::tempdir().unwrap();
    let mut own = store(&dir, "own");
    let rec = own
        .append_own(
            &d,
            vec![stored("h1", 1, 1, 1).to_raw()],
            Vec::new(),
            1,
            &key,
            &ledger_key_id(0),
            NO_FOLDER,
            &s,
        )
        .unwrap();
    assert_eq!(rec.format, 3);
    rec.verify(&s.public()).unwrap();
    let aad = |format: u16| {
        crate::crypto::aad_for_format(
            format,
            "batch",
            &[
                &rec.vault,
                &rec.scope,
                &rec.device,
                &rec.seq.to_le_bytes(),
                &rec.part.to_le_bytes(),
                &rec.parts.to_le_bytes(),
                rec.key_id.as_bytes(),
            ],
        )
    };
    assert!(crate::crypto::decrypt(&key, &aad(3), &rec.body).is_ok());
    assert!(crate::crypto::decrypt(&key, &aad(2), &rec.body).is_err());
    let mut other = store(&dir, "other");
    // Read under another seq's name: refused by the acceptance rule.
    let wrong = checkpoint::batch_key(&d, 2);
    assert!(other
        .ingest_named(&wrong, rec.clone(), &s.public(), Some(&key), u64::MAX)
        .is_err());
    // A relabelled key id breaks the signature.
    let mut relabelled = rec.clone();
    relabelled.key_id = ledger_key_id(1);
    assert!(other.ingest(relabelled, &s.public(), Some(&key)).is_err());
    // Another device's key: refused.
    assert!(other
        .ingest(rec.clone(), &signer(2).public(), Some(&key))
        .is_err());
    let right = checkpoint::batch_key(&d, 1);
    assert_eq!(
        other
            .ingest_named(&right, rec, &s.public(), Some(&key), u64::MAX)
            .unwrap(),
        Ingest::New
    );
}
