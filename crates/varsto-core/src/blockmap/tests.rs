// SPDX-License-Identifier: PolyForm-Shield-1.0.0
use super::*;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ledger3::events::{Event, PackOn};
use crate::ledger3::{Batch, DeviceBin, LedgerView, ObjectBin, PackId, Place};
use crate::record::{
    Acceptor, Announced, DeviceSigner, Id16, Junk, KeyId, Kind, Outcome, RecordKeys,
    RecordPublished, RecordStore, RecordTrust, RecordWriter, RecordsRefused, Refusal, SealedRecord,
    StreamRef,
};
use crate::storage::{LocalDirStorage, Storage};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Instant;

const VAULT: Id16 = [0x11; 16];
const FOLDER: [u8; 16] = [0x22; 16];
const OTHER_FOLDER: [u8; 16] = [0x33; 16];

struct Keys(SecretKey);

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        matches!(key_id, KeyId::Meta { folder, .. } if *folder == FOLDER).then(|| self.0.clone())
    }
}

/// Trust from a ledger view: every listed device may write, announcements
/// come from the view.
struct ViewTrust<'a> {
    view: &'a LedgerView,
    keys: &'a HashMap<Id16, Vec<u8>>,
}

impl RecordTrust for ViewTrust<'_> {
    fn signer_key(&self, device: &Id16, _: Kind, _: &Id16) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(self.keys.get(device)?).ok()
    }
    fn may_write(&self, device: &Id16, _: Kind, _: &Id16, _: &KeyId) -> bool {
        self.keys.contains_key(device)
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        self.view
            .announced(kind.code(), scope, device, seq)
            .map(|a| Announced {
                parts: a.parts,
                body_hash: a.body_hash,
                base: a.base,
            })
    }
}

struct Dev {
    id: DeviceBin,
    sk: SigningKey,
    writer: MapWriter,
    batch_seq: u64,
    table: MapTable,
}

/// Devices writing map records to one metadata storage, and the batches
/// they sealed (applied to `view` as they are made).
struct World {
    dir: tempfile::TempDir,
    meta: LocalDirStorage,
    k10: Keys,
    keys: HashMap<Id16, Vec<u8>>,
    view: LedgerView,
    lamport: u64,
    devs: Vec<Dev>,
    batches: Vec<Batch>,
}

fn folder_pack(view: &LedgerView) -> impl Fn(&PackId) -> bool + '_ {
    |p| view.pack_folder(p).is_none_or(|f| f == FOLDER)
}

impl World {
    fn new(n: u8) -> World {
        let dir = tempfile::tempdir().unwrap();
        let meta = LocalDirStorage::new("meta".into(), dir.path().join("meta")).unwrap();
        let mut keys = HashMap::new();
        let mut devs = Vec::new();
        for i in 0..n {
            let sk = SigningKey::generate();
            let id = [0xa0 + i; 16];
            keys.insert(id, sk.public().to_bytes());
            let table = MapTable::open(
                &table_path(&dir.path().join(format!("dev{i}")), &FOLDER),
                FOLDER,
            )
            .unwrap();
            devs.push(Dev {
                id,
                sk,
                writer: MapWriter::from_view(FOLDER, id, 0, &LedgerView::default(), 0),
                batch_seq: 0,
                table,
            });
        }
        World {
            dir,
            meta,
            k10: Keys(SecretKey([9; 32])),
            keys,
            view: LedgerView::default(),
            lamport: 0,
            devs,
            batches: Vec::new(),
        }
    }

    fn id(&self, d: usize) -> DeviceBin {
        self.devs[d].id
    }

    fn batch(&mut self, d: usize, events: Vec<Event>, seen: Vec<(DeviceBin, u64)>) -> u64 {
        self.lamport += 1;
        let dev = &mut self.devs[d];
        dev.batch_seq += 1;
        let b = Batch {
            device: dev.id,
            seq: dev.batch_seq,
            prev: [0; 32],
            lamport: self.lamport,
            created_utc: 1_000,
            seen,
            events: events.iter().map(Event::to_raw).collect(),
        };
        self.view.apply(&b);
        self.batches.push(b);
        self.devs[d].batch_seq
    }

    /// Device `d` writes a map record for `packs` (after `marks` adds its
    /// marks), seals the batch and applies the record to its own table.
    fn publish(
        &mut self,
        d: usize,
        packs: &[WrittenPack],
        marks: impl FnOnce(&mut MapWriter),
    ) -> MapPublish {
        self.lamport += 1;
        let lamport = self.lamport;
        let World {
            meta,
            k10,
            view,
            devs,
            ..
        } = self;
        let dev = &mut devs[d];
        marks(&mut dev.writer);
        let signer = DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &*k10,
        };
        let p = dev
            .writer
            .publish(
                &rw,
                &[&*meta as &dyn Storage],
                packs,
                lamport,
                Some(&dev.table),
                view,
            )
            .unwrap();
        let events = p.events.clone();
        self.batch(d, events, Vec::new());
        let World { view, devs, .. } = self;
        p.apply_to(&mut devs[d].table, &folder_pack(view)).unwrap();
        p
    }

    fn drop_pack(&mut self, d: usize, pack: &PackId, storages: &[&str]) {
        let ev = storages
            .iter()
            .map(|s| {
                Event::PackDropped(PackOn {
                    storage: s.to_string(),
                    pack: *pack,
                })
            })
            .collect();
        self.batch(d, ev, Vec::new());
    }

    fn reader_table(&self, name: &str) -> MapTable {
        MapTable::open(&table_path(&self.dir.path().join(name), &FOLDER), FOLDER).unwrap()
    }

    fn pull_with(&self, table: &mut MapTable, view: &LedgerView) -> ApplyReport {
        let trust = ViewTrust {
            view,
            keys: &self.keys,
        };
        let store = RecordStore {
            storage: &self.meta,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &self.k10,
                trust: &trust,
            },
        };
        let mut refused = RecordsRefused::default();
        let r = pull(table, &store, view, &mut refused).unwrap();
        assert_eq!(refused.total(), 0, "{refused:?}");
        r
    }

    fn pull(&self, table: &mut MapTable) -> ApplyReport {
        self.pull_with(table, &self.view)
    }
}

fn rnd32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

/// A pack of `n` synthetic members on `storages`.
fn synth_pack(rng: &mut StdRng, storages: &[&str], n: u32) -> WrittenPack {
    WrittenPack {
        id: rnd32(rng),
        class: 1,
        storages: storages.iter().map(|s| s.to_string()).collect(),
        members: (0..n)
            .map(|i| WrittenMember {
                object: rnd32(rng),
                chunk: rnd32(rng),
                offset: i * 1000,
                len: 1000,
                plain_len: 900,
                epoch: 0,
            })
            .collect(),
    }
}

fn place_of(p: &WrittenPack, i: usize) -> (ObjectBin, Place) {
    let m = &p.members[i];
    (
        m.object,
        Place {
            pack: p.id,
            offset: m.offset,
            len: m.len,
        },
    )
}

type RowKey = (ObjectBin, Place, [u8; 32], u32, u8, DeviceBin, u32, u8);
type MarkKey = (PackId, u32, ObjectBin, u8, DeviceBin, u64, u64);

fn contents(t: &MapTable) -> (BTreeSet<RowKey>, BTreeSet<MarkKey>) {
    let rows = t
        .scan()
        .map(|r| {
            let r = r.unwrap();
            (
                r.object,
                r.place,
                r.chunk,
                r.epoch,
                r.flags,
                r.writer,
                r.plain_len,
                r.class,
            )
        })
        .collect();
    let marks = t
        .scan_marks()
        .map(|m| {
            let m = m.unwrap();
            (
                m.pack,
                m.offset,
                m.object,
                m.kind.code(),
                m.marker,
                m.lamport,
                m.map_seq,
            )
        })
        .collect();
    (rows, marks)
}

/// Three writers with bases, deltas, marks and a dropped pack.
fn scenario() -> (World, Vec<WrittenPack>) {
    let mut rng = StdRng::seed_from_u64(7);
    let mut w = World::new(3);
    let mut all = Vec::new();
    for round in 0..4 {
        for d in 0..3 {
            let packs = vec![
                synth_pack(&mut rng, &["h1", "h2"], 3 + round),
                synth_pack(&mut rng, &["c"], 2),
            ];
            let earlier: Vec<WrittenPack> = all.clone();
            w.publish(d, &packs, |mw| {
                // Mark a place another device wrote, then revive one.
                if let Some(p) = earlier.get(round as usize * 2 + d) {
                    mw.mark_dead(&[place_of(p, 0)]);
                    if round > 1 {
                        mw.mark_undead(&[place_of(p, 0)]);
                    }
                }
            });
            all.extend(packs);
        }
        if round == 1 {
            // C's first pack goes everywhere: its next base leaves it out.
            let p = all[4].clone();
            w.drop_pack(2, &p.id, &["h1", "h2"]);
        }
    }
    (w, all)
}

// ---- records ----------------------------------------------------------------

fn big_body(rng: &mut StdRng, entries: usize) -> BlockMap {
    let per_pack = 1024usize;
    let packs: Vec<PackRef> = (0..entries.div_ceil(per_pack))
        .map(|_| PackRef {
            id: rnd32(rng),
            class: 4,
        })
        .collect();
    let entries = (0..entries)
        .map(|i| MapEntry {
            object: rnd32(rng),
            chunk: rnd32(rng),
            pack: (i / per_pack) as u32,
            offset: ((i % per_pack) * 65_536) as u32,
            len: 65_536,
            plain_len: 65_000,
            epoch: 0,
            flags: 0,
        })
        .collect();
    BlockMap {
        folder: FOLDER,
        device: [0xa0; 16],
        seq: 1,
        lamport: 1,
        base: 1,
        prev: [0; 32],
        packs,
        entries,
        marks: Vec::new(),
    }
}

/// Seal `body` as device 0 of `w` without the writer's own checks, and
/// announce it in a batch.
fn seal_raw(w: &mut World, body: &BlockMap) -> SealedRecord {
    let dev = &w.devs[0];
    let signer = DeviceSigner {
        device: dev.id,
        key: &dev.sk,
    };
    let rw = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &w.k10,
    };
    let stream = StreamRef::new(Kind::BlockMap, body.folder, dev.id);
    let key = KeyId::Meta {
        folder: FOLDER,
        epoch: 0,
    };
    let sealed = rw.seal(&stream, body.seq, body.base, &key, body).unwrap();
    let a = &sealed.published;
    w.batch(
        0,
        vec![Event::RecordPublished(crate::ledger3::Announcement {
            kind: a.kind,
            scope: a.scope,
            seq: a.seq,
            base: a.base,
            parts: a.parts,
            body_hash: a.body_hash,
            size: a.size,
        })],
        Vec::new(),
    );
    sealed
}

fn accept(w: &World, sealed: &SealedRecord) -> Outcome<BlockMap> {
    let trust = ViewTrust {
        view: &w.view,
        keys: &w.keys,
    };
    Acceptor {
        vault: VAULT,
        keys: &w.k10,
        trust: &trust,
    }
    .accept::<BlockMap>(&sealed.parts)
}

fn expect_bad_body(o: Outcome<BlockMap>) -> String {
    match o {
        Outcome::Refused(r) => match r.reason {
            Refusal::Junk(Junk::BadBody(e)) => e,
            other => panic!("refused for another reason: {other:?}"),
        },
        Outcome::Accepted(_) => panic!("accepted"),
        Outcome::Waiting(_) => panic!("waiting"),
    }
}

/// A base of 1 M entries seals into several parts of at most 32 MiB of
/// body, is accepted, decodes to the same body, and builds a table.
#[test]
fn a_record_of_a_million_entries_round_trips() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut w = World::new(1);
    let body = big_body(&mut rng, 1 << 20);
    let t = Instant::now();
    let sealed = seal_raw(&mut w, &body);
    let seal_time = t.elapsed();
    let parts = sealed.parts.len();
    let size: usize = sealed.parts.iter().map(|(_, b)| b.len()).sum();
    assert!(parts >= 2, "{parts} parts");
    assert_eq!(usize::from(sealed.published.parts), parts);
    for (name, bytes) in &sealed.parts {
        assert!(bytes.len() as u64 <= crate::record::MAX_PART_READ, "{name}");
        let env = crate::record::SignedRecord::decode(bytes).unwrap();
        assert!(env.body.len() <= crate::record::MAX_PART_BODY);
    }
    let t = Instant::now();
    let got = match accept(&w, &sealed) {
        Outcome::Accepted(r) => r.body,
        other => panic!("{other:?}"),
    };
    let open_time = t.elapsed();
    assert!(got == body, "the body round trips");
    let mut table = w.reader_table("big");
    let t = Instant::now();
    table
        .apply(
            vec![MapUpdate {
                device: body.device,
                records: vec![(got, sealed.published.body_hash)],
            }],
            &|_| true,
        )
        .unwrap();
    let build_time = t.elapsed();
    let file = std::fs::metadata(table.path()).unwrap().len();
    let t = Instant::now();
    for e in body.entries.iter().step_by(1009) {
        assert_eq!(table.rows_of(&e.object).unwrap().len(), 1);
        assert_eq!(table.rows_of_chunk(&e.chunk).unwrap().len(), 1);
    }
    let lookups = body.entries.len().div_ceil(1009);
    let lookup_time = t.elapsed();
    eprintln!(
        "1M-entry block map: {parts} parts, {size} bytes sealed ({:.1} B/entry); \
         seal {seal_time:?}, accept+open {open_time:?}; table {file} bytes, build {build_time:?}; \
         {lookups} object+chunk lookups {lookup_time:?}",
        size as f64 / body.entries.len() as f64
    );
    // Optimised builds take well under a second for each step; unoptimised
    // test builds spend most of their time in serde's per-byte calls.
    let limit = if cfg!(debug_assertions) { 90 } else { 5 };
    for (what, t) in [
        ("seal", seal_time),
        ("accept", open_time),
        ("table", build_time),
    ] {
        assert!(t.as_secs() < limit, "{what} took {t:?}");
    }
}

#[test]
fn limits_are_checked_on_acceptance() {
    let mut w = World::new(1);
    let mut rng = StdRng::seed_from_u64(2);
    // An entry past the end of its pack's class.
    let mut body = big_body(&mut rng, 4);
    body.packs[0].class = 0;
    body.entries[3].offset = (256 << 10) - 100;
    body.entries[3].len = 200;
    let sealed = seal_raw(&mut w, &body);
    let e = expect_bad_body(accept(&w, &sealed));
    assert!(e.contains("passes the end of pack"), "{e}");
    // More marks than one part may hold (identical marks compress into one
    // part).
    let mut body = big_body(&mut rng, 1);
    body.seq = 2;
    body.base = 2;
    body.marks = vec![
        Mark {
            object: [1; 32],
            pack: [2; 32],
            offset: 0,
            kind: 1,
        };
        MAX_MARKS_PER_PART + 1
    ];
    let sealed = seal_raw(&mut w, &body);
    assert_eq!(sealed.published.parts, 1);
    let e = expect_bad_body(accept(&w, &sealed));
    assert!(e.contains("marks in 1 parts"), "{e}");
    // A body that names another seq, device or folder than its envelope.
    let mut body = big_body(&mut rng, 1);
    body.seq = 3;
    body.base = 3;
    body.device = [0xee; 16];
    let sealed = seal_raw_as(&mut w, &body, 3);
    let e = expect_bad_body(accept(&w, &sealed));
    assert!(e.contains("another device"), "{e}");
    // Bad class, pack index, flags, mark kind, base.
    let ok = big_body(&mut rng, 2);
    assert!(ok.check_limits(1).is_ok());
    type Change = Box<dyn Fn(&mut BlockMap)>;
    let cases: Vec<(&str, Change)> = vec![
        ("class", Box::new(|b: &mut BlockMap| b.packs[0].class = 6)),
        (
            "names pack",
            Box::new(|b: &mut BlockMap| b.entries[0].pack = 9),
        ),
        ("flags", Box::new(|b: &mut BlockMap| b.entries[0].flags = 2)),
        (
            "mark kind",
            Box::new(|b: &mut BlockMap| {
                b.marks.push(Mark {
                    object: [0; 32],
                    pack: [0; 32],
                    offset: 0,
                    kind: 4,
                })
            }),
        ),
        ("base", Box::new(|b: &mut BlockMap| b.base = 2)),
        ("bytes", Box::new(|b: &mut BlockMap| b.entries[0].len = 10)),
    ];
    for (want, f) in cases {
        let mut b = ok.clone();
        f(&mut b);
        let e = b.check_limits(1).unwrap_err();
        assert!(e.contains(want), "{want}: {e}");
    }
}

/// `seal_raw` for a body whose device differs from the sealing device.
fn seal_raw_as(w: &mut World, body: &BlockMap, seq: u64) -> SealedRecord {
    let mut b = body.clone();
    b.seq = seq;
    seal_raw(w, &b)
}

#[test]
fn too_many_entries_or_packs_are_refused() {
    let e = MapEntry {
        object: [1; 32],
        chunk: [2; 32],
        pack: 0,
        offset: 0,
        len: 100,
        plain_len: 50,
        epoch: 0,
        flags: 0,
    };
    let mut body = BlockMap {
        folder: FOLDER,
        device: [0xa0; 16],
        seq: 1,
        lamport: 1,
        base: 1,
        prev: [0; 32],
        packs: vec![PackRef {
            id: [3; 32],
            class: 4,
        }],
        entries: vec![e; MAX_ENTRIES_PER_PART + 1],
        marks: Vec::new(),
    };
    let err = body.check_limits(1).unwrap_err();
    assert!(err.contains("entries in 1 parts"), "{err}");
    assert!(body.check_limits(2).is_ok());
    body.entries.truncate(MAX_ENTRIES_PER_PART);
    assert!(body.check_limits(1).is_ok());
    body.entries.truncate(1);
    body.packs = vec![
        PackRef {
            id: [3; 32],
            class: 4
        };
        MAX_PACKS + 1
    ];
    let err = body.check_limits(1).unwrap_err();
    assert!(err.contains("packs"), "{err}");
}

/// The body parser never panics on junk and round-trips what it makes.
#[test]
fn body_parser_survives_random_input() {
    let mut rng = StdRng::seed_from_u64(3);
    let mut base = big_body(&mut rng, 5);
    base.marks.push(Mark {
        object: [4; 32],
        pack: base.packs[0].id,
        offset: 0,
        kind: 2,
    });
    let good = postcard::to_stdvec(&base).unwrap();
    assert_eq!(postcard::from_bytes::<BlockMap>(&good).unwrap(), base);
    for _ in 0..20_000 {
        let mut b = good.clone();
        match rng.gen_range(0..4) {
            0 => {
                for _ in 0..rng.gen_range(1..8) {
                    let i = rng.gen_range(0..b.len());
                    b[i] = rng.gen();
                }
            }
            1 => b.truncate(rng.gen_range(0..b.len())),
            2 => {
                let i = rng.gen_range(0..b.len());
                b.insert(i, rng.gen());
            }
            _ => {
                b = vec![0u8; rng.gen_range(0..200)];
                rng.fill_bytes(&mut b);
            }
        }
        if let Ok(m) = postcard::from_bytes::<BlockMap>(&b) {
            let _ = m.check_limits(1);
            let _ = m.check_limits(u16::MAX);
        }
        // Through the record framing (zstd) too.
        let z = zstd::bulk::compress(&b, 1).unwrap();
        if let Ok(m) = crate::record::envelope::decode_body::<BlockMap>(&z) {
            let _ = m.check_limits(1);
        }
        let mut junk = vec![0u8; rng.gen_range(0..64)];
        rng.fill_bytes(&mut junk);
        let _ = crate::record::envelope::decode_body::<BlockMap>(&junk);
    }
    // Random valid bodies round trip.
    for _ in 0..200 {
        let n = rng.gen_range(0..40);
        let mut b = big_body(&mut rng, n);
        b.lamport = rng.gen();
        for _ in 0..rng.gen_range(0..5) {
            b.marks.push(Mark {
                object: rnd32(&mut rng),
                pack: rnd32(&mut rng),
                offset: rng.gen(),
                kind: rng.gen_range(1..4),
            });
        }
        let enc = postcard::to_stdvec(&b).unwrap();
        assert_eq!(postcard::from_bytes::<BlockMap>(&enc).unwrap(), b);
    }
}

// ---- writer ----------------------------------------------------------------

fn fake_sealed(seq: u64, base: u64, size: u64) -> SealedRecord {
    SealedRecord {
        parts: Vec::new(),
        published: RecordPublished {
            kind: Kind::BlockMap.code(),
            scope: FOLDER,
            seq,
            base,
            parts: 1,
            body_hash: [seq as u8; 32],
            size,
        },
    }
}

#[test]
fn a_base_follows_1024_deltas_or_a_quarter_of_the_base() {
    let view = LedgerView::default();
    let mut w = MapWriter::from_view(FOLDER, [1; 16], 0, &view, 0);
    assert!(w.base_due(), "the first record is a base");
    assert_eq!(w.next_seq(), 1);
    let body = |seq: u64, base: u64| BlockMap {
        folder: FOLDER,
        device: [1; 16],
        seq,
        base,
        ..Default::default()
    };
    w.commit(&body(1, 1), &fake_sealed(1, 1, 1_000_000));
    for seq in 2..=5 {
        assert!(!w.base_due(), "delta {seq}");
        w.commit(&body(seq, 1), &fake_sealed(seq, 1, 65_536));
    }
    // 4 x 64 KiB = 262 144 >= 1 000 000 / 4.
    assert!(w.base_due());
    w.commit(&body(6, 6), &fake_sealed(6, 6, u64::MAX / 8));
    for seq in 7..7 + BASE_AFTER_DELTAS {
        assert!(!w.base_due());
        w.commit(&body(seq, 6), &fake_sealed(seq, 6, 65_536));
    }
    assert!(w.base_due(), "after 1024 deltas");
    assert_eq!(w.next_seq(), 7 + BASE_AFTER_DELTAS);
}

/// The counter comes back from the view; a seq taken on the storage by a
/// record no batch announced makes the next record a base after it.
#[test]
fn the_writer_resumes_from_the_view_and_skips_orphans() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut w = World::new(1);
    w.publish(0, &[synth_pack(&mut rng, &["h1"], 2)], |_| {});
    w.publish(0, &[synth_pack(&mut rng, &["h1"], 2)], |_| {});
    let id = w.id(0);
    let resumed = MapWriter::from_view(FOLDER, id, 0, &w.view, 2);
    assert_eq!(resumed.next_seq(), 3);
    // A crash after writing record 3 and before its batch.
    let orphan = synth_pack(&mut rng, &["h1"], 1);
    {
        let World {
            meta,
            k10,
            view,
            devs,
            ..
        } = &mut w;
        let dev = &mut devs[0];
        let signer = DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &*k10,
        };
        let body = dev
            .writer
            .body(&[orphan], 99, Some(&dev.table), view)
            .unwrap();
        let sealed = dev.writer.seal(&rw, &body).unwrap();
        RecordWriter::publish(meta, &sealed).unwrap();
    }
    // A fresh writer that knows only the view finds seq 3 taken.
    w.devs[0].writer = MapWriter::from_view(FOLDER, id, 0, &w.view, 0);
    let p = w.publish(0, &[synth_pack(&mut rng, &["h1"], 1)], |_| {});
    assert_eq!(p.body.seq, 4);
    assert!(p.body.is_base(), "a base after the orphan");
    let mut t = w.reader_table("r");
    w.pull(&mut t);
    assert_eq!(t.marker(&id).unwrap().applied, 4);
    // The base lists every live place: 2 + 2 + 1 (the orphan's is not).
    assert_eq!(t.rows(), 5);
}

// ---- table -------------------------------------------------------------------

#[test]
fn three_writers_in_any_arrival_order_give_the_same_rows() {
    let (w, _) = scenario();
    let mut full = w.reader_table("full");
    w.pull(&mut full);
    let want = contents(&full);
    assert!(want.0.len() > 30 && !want.1.is_empty());
    for seed in 0..12 {
        let mut rng = StdRng::seed_from_u64(100 + seed);
        let mut order: Vec<usize> = (0..w.batches.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.gen_range(0..=i));
        }
        let mut view = LedgerView::default();
        let mut t = w.reader_table(&format!("r{seed}"));
        t.run_rows = 1 + rng.gen_range(0..5);
        for i in order {
            view.apply(&w.batches[i]);
            if rng.gen_bool(0.5) {
                w.pull_with(&mut t, &view);
            }
        }
        w.pull_with(&mut t, &view);
        assert_eq!(contents(&t), want, "seed {seed}");
    }
}

#[test]
fn incremental_updates_and_a_rebuild_agree() {
    let (w, all) = scenario();
    // Pull after every batch, in order.
    let mut inc = w.reader_table("inc");
    inc.run_rows = 2;
    let mut view = LedgerView::default();
    let mut applied = 0;
    for b in &w.batches {
        view.apply(b);
        applied += w.pull_with(&mut inc, &view).records;
    }
    assert!(applied >= 12);
    let mut rebuilt = w.reader_table("rebuilt");
    let r = w.pull(&mut rebuilt);
    assert!(
        r.records < applied,
        "a rebuild reads bases and their deltas only"
    );
    assert_eq!(contents(&inc), contents(&rebuilt));
    // Device C's dropped pack left its base.
    let dropped = &all[4];
    assert!(rebuilt
        .rows_of(&dropped.members[0].object)
        .unwrap()
        .is_empty());
    // Reopening gives the same table.
    let again = w.reader_table("rebuilt");
    assert_eq!(contents(&again), contents(&rebuilt));
    assert_eq!(again.streams(), rebuilt.streams());
    // Nothing new: nothing is read.
    let mut again = again;
    assert_eq!(w.pull(&mut again).records, 0);
}

#[test]
fn a_crash_while_writing_the_table_leaves_a_usable_one() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut w = World::new(2);
    w.publish(0, &[synth_pack(&mut rng, &["h1"], 4)], |_| {});
    let mut t = w.reader_table("r");
    w.pull(&mut t);
    let before = contents(&t);
    w.publish(1, &[synth_pack(&mut rng, &["h1"], 4)], |_| {});
    t.crash_after_rows = Some(3);
    let trust = ViewTrust {
        view: &w.view,
        keys: &w.keys,
    };
    let store = RecordStore {
        storage: &w.meta,
        acceptor: Acceptor {
            vault: VAULT,
            keys: &w.k10,
            trust: &trust,
        },
    };
    assert!(pull(&mut t, &store, &w.view, &mut RecordsRefused::default()).is_err());
    // A real crash leaves the half-written file behind.
    std::fs::write(format!("{}.tmp", t.path().display()), b"half a table").unwrap();
    let mut t = w.reader_table("r");
    assert!(!t.was_corrupt());
    assert_eq!(contents(&t), before, "the old table is untouched");
    w.pull(&mut t);
    assert_eq!(t.rows(), 8);
    // A corrupt table opens empty and is rebuilt from the records.
    let path = t.path().to_path_buf();
    drop(t);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0x40;
    std::fs::write(&path, &bytes).unwrap();
    let mut t = w.reader_table("r");
    assert!(t.was_corrupt());
    assert_eq!(t.rows(), 0);
    w.pull(&mut t);
    assert_eq!(t.rows(), 8);
    assert!(!w.reader_table("r").was_corrupt());
}

#[test]
fn a_mark_outside_the_folders_packs_is_refused_and_counted() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut w = World::new(2);
    let p = synth_pack(&mut rng, &["h1"], 2);
    w.publish(0, std::slice::from_ref(&p), |_| {});
    // A pack of another folder, claimed in the view.
    let foreign = synth_pack(&mut rng, &["h1"], 1);
    w.batch(
        1,
        vec![Event::PackStored(crate::ledger3::events::PackStored {
            storage: "h1".into(),
            pack: foreign.id,
            class: 1,
            folder: OTHER_FOLDER,
            map_seq: 1,
        })],
        Vec::new(),
    );
    let unknown = synth_pack(&mut rng, &["h1"], 1);
    w.publish(1, &[], |mw| {
        mw.mark_dead(&[
            place_of(&p, 0),
            place_of(&foreign, 0),
            place_of(&unknown, 0),
        ]);
    });
    let mut t = w.reader_table("r");
    let r = w.pull(&mut t);
    // The unknown pack's claim may still arrive: that mark is kept.
    assert_eq!((r.marks, r.marks_refused), (2, 1));
    w.view.count_marks_refused(r.marks_refused);
    assert_eq!(w.view.marks_refused, 1);
    assert_eq!(
        t.is_marked(&place_of(&p, 0).1).unwrap(),
        Some(MarkKind::Dead)
    );
    assert_eq!(t.is_marked(&place_of(&foreign, 0).1).unwrap(), None);
    assert_eq!(
        t.is_marked(&place_of(&unknown, 0).1).unwrap(),
        Some(MarkKind::Dead)
    );
}

// ---- dedup and settling -----------------------------------------------------------

#[test]
fn dedup_writes_a_block_only_where_it_is_missing() {
    let mut rng = StdRng::seed_from_u64(8);
    let mut w = World::new(1);
    let p = synth_pack(&mut rng, &["h1"], 2);
    w.publish(0, std::slice::from_ref(&p), |_| {});
    let t = &w.devs[0].table;
    let m = p.members[0];
    let targets = vec!["h1".to_string(), "h2".to_string()];
    let d = needs_write(t, &w.view, &m.chunk, 0, &targets).unwrap();
    assert_eq!(d.object, Some(m.object));
    assert_eq!(d.missing, vec!["h2".to_string()]);
    assert!(!d.skip());
    // A newer epoch keeps the object of the older one.
    let d1 = needs_write(t, &w.view, &m.chunk, 3, &targets).unwrap();
    assert_eq!((d1.object, d1.epoch), (Some(m.object), 0));
    // An unknown chunk goes everywhere.
    let none = needs_write(t, &w.view, &[0x55; 32], 0, &targets).unwrap();
    assert_eq!((none.object, none.missing.len()), (None, 2));
    // Written to h2 only now: nothing more to write.
    let mut q = synth_pack(&mut rng, &["h2"], 0);
    q.members.push(m);
    w.publish(0, &[q], |_| {});
    let t = &w.devs[0].table;
    assert!(needs_write(t, &w.view, &m.chunk, 0, &targets)
        .unwrap()
        .skip());
    assert_eq!(
        w.view.block_copies(&m.object, t),
        BTreeSet::from(["h1".to_string(), "h2".into()])
    );
}

#[test]
fn a_dead_marked_place_is_not_reused() {
    let mut rng = StdRng::seed_from_u64(9);
    let mut w = World::new(2);
    let p = synth_pack(&mut rng, &["h1", "h2"], 2);
    w.publish(0, std::slice::from_ref(&p), |_| {});
    let m = p.members[0];
    let targets = vec!["h1".to_string(), "h2".to_string()];
    let mut t = w.reader_table("r");
    w.pull(&mut t);
    assert!(needs_write(&t, &w.view, &m.chunk, 0, &targets)
        .unwrap()
        .skip());
    // Device 1 marks it dead: written again, not revived by reuse.
    w.publish(1, &[], |mw| mw.mark_dead(&[place_of(&p, 0)]));
    w.pull(&mut t);
    let d = needs_write(&t, &w.view, &m.chunk, 0, &targets).unwrap();
    assert_eq!((d.object, d.missing.len()), (None, 2));
    assert!(w.view.block_copies(&m.object, &t).is_empty());
    let places = w.view.block_places(&m.object, &t);
    assert_eq!(places.len(), 1);
    assert!(places[0].marked, "still read as a last resort");
    assert_eq!(
        t.place_of_chunk(&m.chunk, 0).unwrap().unwrap().object,
        m.object
    );
    // Device 0 finds a reference and revives it (a newer stamp).
    w.publish(0, &[], |mw| mw.mark_undead(&[place_of(&p, 0)]));
    w.pull(&mut t);
    assert_eq!(
        t.is_marked(&place_of(&p, 0).1).unwrap(),
        Some(MarkKind::Undead)
    );
    assert!(needs_write(&t, &w.view, &m.chunk, 0, &targets)
        .unwrap()
        .skip());
    // A lost mark stays whatever comes after it.
    w.publish(1, &[], |mw| mw.mark_lost(&[place_of(&p, 0)]));
    w.publish(0, &[], |mw| mw.mark_undead(&[place_of(&p, 0)]));
    w.pull(&mut t);
    assert_eq!(
        t.is_marked(&place_of(&p, 0).1).unwrap(),
        Some(MarkKind::Lost)
    );
    assert_eq!(
        needs_write(&t, &w.view, &m.chunk, 0, &targets)
            .unwrap()
            .missing
            .len(),
        2
    );
}

#[test]
fn a_place_is_collectable_only_when_settled_unreferenced_and_not_revived() {
    let mut rng = StdRng::seed_from_u64(10);
    let mut w = World::new(2);
    let p = synth_pack(&mut rng, &["h1"], 1);
    w.publish(0, std::slice::from_ref(&p), |_| {});
    let (a, b) = (w.id(0), w.id(1));
    let writers = [a, b];
    w.publish(1, &[], |mw| mw.mark_dead(&[place_of(&p, 0)]));
    let marker_batch = w.devs[1].batch_seq;
    let mut t = w.reader_table("r");
    w.pull(&mut t);
    let place = place_of(&p, 0).1;
    let unreferenced = |_: &ObjectBin| false;
    assert!(!collectable(&t, &w.view, &FOLDER, &writers, &place, unreferenced).unwrap());
    // A acknowledges the marker's batch: settled.
    w.batch(0, Vec::new(), vec![(b, marker_batch)]);
    assert!(collectable(&t, &w.view, &FOLDER, &writers, &place, unreferenced).unwrap());
    assert!(
        !collectable(
            &t,
            &w.view,
            &FOLDER,
            &writers,
            &place,
            referenced_until_wired
        )
        .unwrap(),
        "nothing is collectable until references are wired"
    );
    // A third writer that has not acknowledged holds it back.
    let c = [0xcc; 16];
    assert!(!collectable(&t, &w.view, &FOLDER, &[a, b, c], &place, unreferenced).unwrap());
    // An undead mark with a newer stamp revives it.
    w.publish(0, &[], |mw| mw.mark_undead(&[place_of(&p, 0)]));
    w.pull(&mut t);
    assert!(!collectable(&t, &w.view, &FOLDER, &writers, &place, unreferenced).unwrap());
}

// ---- finding a block end to end ------------------------------------------------------

#[test]
fn a_block_is_found_and_read_through_the_map() {
    use crate::packs::{chunk_key, PackContext, PackStore, HOT_TARGET};
    let mut rng = StdRng::seed_from_u64(11);
    let mut w = World::new(1);
    let folder_id = crate::ids::Id::from_bytes(&FOLDER);
    let vault_id = crate::ids::Id::from_bytes(&VAULT);
    let fk = crate::vault::FolderKeys::from_folder_key(&folder_id, SecretKey([7; 32])).unwrap();
    let mut plains: Vec<Vec<u8>> = vec![vec![1; 1000], vec![0; 5], vec![0; 300 << 10]];
    rng.fill_bytes(&mut plains[2]);
    let mut info: HashMap<ObjectBin, ([u8; 32], u32, u32)> = HashMap::new();
    let mut objects: Vec<(String, Vec<u8>)> = Vec::new();
    for plain in &plains {
        let chunk = crate::crypto::keyed_hash(&fk.hash, plain);
        let obj = crate::chunk_seal::seal_chunk(
            &fk,
            &vault_id,
            &crate::ids::Id::from_bytes(&chunk),
            0,
            plain,
        )
        .unwrap();
        let name = crate::crypto::hash(&obj);
        info.insert(name, (chunk, plain.len() as u32, 0));
        objects.push((hex::encode(name), obj));
    }
    let members: Vec<(String, &[u8])> = objects
        .iter()
        .map(|(o, b)| (o.clone(), b.as_slice()))
        .collect();
    // Packs written by the pack layer to two local-directory storages.
    let ctx = Arc::new(PackContext::default());
    let mut new = Vec::new();
    let mut dirs = HashMap::new();
    for name in ["h1", "h2"] {
        let root = w.dir.path().join(name);
        dirs.insert(name.to_string(), root.clone());
        let ps = PackStore::new(
            Box::new(LocalDirStorage::new(name.into(), root).unwrap()),
            &ctx,
            HOT_TARGET,
        );
        assert!(ps.put_pack(&members).unwrap().iter().all(|b| *b));
        new.push((name.to_string(), ps.take_new_packs()));
    }
    let written = written_packs(&new, &|o| info.get(o).copied()).unwrap();
    assert_eq!(written.len(), 2, "one pack per storage");
    assert!(
        written.iter().all(|p| p.class == 1),
        "300 KiB of members: the 1 MiB class"
    );
    w.publish(0, &written, |_| {});

    // A device that never wrote: table from the records, places from it.
    let mut t = w.reader_table("reader");
    w.pull(&mut t);
    assert_eq!(t.rows(), 6);
    let open = |name: &str| -> Option<Arc<dyn Storage>> {
        let root = dirs.get(name)?;
        Some(Arc::new(
            LocalDirStorage::new(name.into(), root.clone()).unwrap(),
        ))
    };
    for ((o, obj), plain) in objects.iter().zip(&plains) {
        let mut name = [0u8; 32];
        hex::decode_to_slice(o, &mut name).unwrap();
        assert_eq!(
            w.view.block_copies(&name, &t),
            BTreeSet::from(["h1".to_string(), "h2".into()])
        );
        let found = find_block(&t, &w.view, &name, &open).unwrap().unwrap();
        assert_eq!(&found.bytes, obj);
        assert!(!found.marked);
        assert_eq!(&open_block(&fk, &vault_id, &found).unwrap(), plain);
    }
    // h1 loses its pack (dropped in the view): h2 serves.
    let on_h1 = written.iter().find(|p| p.storages == ["h1"]).unwrap();
    w.drop_pack(0, &on_h1.id, &["h1"]);
    let (o, obj) = &objects[2];
    let mut name = [0u8; 32];
    hex::decode_to_slice(o, &mut name).unwrap();
    let found = find_block(&t, &w.view, &name, &open).unwrap().unwrap();
    assert_eq!((found.storage.as_str(), &found.bytes), ("h2", obj));

    // The pack layer reads blocks from the table's places.
    let shared = Arc::new(RwLock::new(w.reader_table("reader")));
    let ctx2 = Arc::new(PackContext::default());
    ctx2.add_place_source(shared);
    let ps = PackStore::new(
        Box::new(LocalDirStorage::new("h2".into(), dirs["h2"].clone()).unwrap()),
        &ctx2,
        HOT_TARGET,
    );
    for (o, obj) in &objects {
        assert_eq!(ps.get(&chunk_key(o)).unwrap().as_ref(), Some(obj));
    }
    let empty = PackStore::new(
        Box::new(LocalDirStorage::new("h2".into(), dirs["h2"].clone()).unwrap()),
        &Arc::new(PackContext::default()),
        HOT_TARGET,
    );
    assert_eq!(
        empty.get(&chunk_key(&objects[0].0)).unwrap(),
        None,
        "no places, no block"
    );
}
