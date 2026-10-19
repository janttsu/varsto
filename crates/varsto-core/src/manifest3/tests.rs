// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of format-3 manifests: the body and its limits, base + delta
//! reconstruction against full snapshots, forks, the merge rules, `held`,
//! references, listing and pruning.

use super::merge::{compare, conflict_path};
use super::record::Header;
use super::*;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::fsmeta::{FileMeta, Owner};
use crate::ledger3::events::{Batch, Event};
use crate::ledger3::{Announcement, EventScope, LedgerView};
use crate::manifest::{self, Order};
use crate::record::{
    Acceptor, Announced, DeviceSigner, KeyId, Kind, RecordKeys, RecordPublished, RecordStore,
    RecordTrust, RecordWriter, RecordsRefused,
};
use crate::storage::Storage;
use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

const VAULT: Id16 = [0x11; 16];
const FOLDER: Id16 = [0x22; 16];

// ---- a small world ------------------------------------------------------

#[derive(Default)]
struct Mem {
    name: String,
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl Mem {
    fn named(n: &str) -> Mem {
        Mem {
            name: n.into(),
            ..Default::default()
        }
    }
    fn names(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }
}

impl Storage for Mem {
    fn name(&self) -> &str {
        &self.name
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let mut m = self.objects.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.to_string(), data.to_vec());
        Ok(true)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.objects.lock().unwrap().contains_key(key))
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}

struct Keys(SecretKey);

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        (key_id == &meta_key()).then(|| self.0.clone())
    }
}

fn meta_key() -> KeyId {
    KeyId::Meta {
        folder: FOLDER,
        epoch: 0,
    }
}

/// Device keys, and announcements from a format-3 ledger view.
struct Trust {
    keys: HashMap<Id16, VerifyingKey>,
    view: RefCell<LedgerView>,
}

impl RecordTrust for Trust {
    fn signer_key(&self, device: &Id16, _kind: Kind, _scope: &Id16) -> Option<VerifyingKey> {
        self.keys.get(device).cloned()
    }
    fn may_write(&self, _device: &Id16, _kind: Kind, _scope: &Id16, _key_id: &KeyId) -> bool {
        true
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        announcement(&self.view.borrow(), device, kind, scope, seq)
    }
}

struct Dev {
    id: Id16,
    sk: SigningKey,
    batch: u64,
    writer: ManifestWriter,
    view: BTreeMap<String, FileEntry>,
}

struct World {
    hot: Mem,
    cold: Mem,
    keys: Keys,
    trust: Trust,
    devs: Vec<Dev>,
}

impl World {
    fn new(n: u8) -> World {
        let devs: Vec<Dev> = (1..=n)
            .map(|i| {
                let id = [i; 16];
                Dev {
                    id,
                    sk: SigningKey::from_bytes(&[i; 64]).unwrap(),
                    batch: 0,
                    writer: ManifestWriter::new(FOLDER, id),
                    view: BTreeMap::new(),
                }
            })
            .collect();
        World {
            hot: Mem::named("hot"),
            cold: Mem::named("cold"),
            keys: Keys(SecretKey::random()),
            trust: Trust {
                keys: devs.iter().map(|d| (d.id, d.sk.public())).collect(),
                view: RefCell::new(LedgerView::default()),
            },
            devs,
        }
    }

    fn id(&self, i: usize) -> Id16 {
        self.devs[i].id
    }

    fn rule(&mut self, i: usize, rule: BaseRule) {
        self.devs[i].writer.rule = rule;
    }

    fn seal(&self, i: usize) -> Option<Pending> {
        let d = &self.devs[i];
        let signer = DeviceSigner {
            device: d.id,
            key: &d.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &self.keys,
        };
        d.writer
            .seal(&rw, &meta_key(), &d.view, d.writer.seq + 1, 0)
            .unwrap()
    }

    /// Publish device `i`'s view (if changed): parts on both storages, then
    /// a batch announcing it. The batch seq that announced it.
    fn publish(&mut self, i: usize) -> Option<(Pending, u64)> {
        let p = self.seal(i)?;
        RecordWriter::publish(&self.hot, &p.sealed).unwrap();
        RecordWriter::publish(&self.cold, &p.sealed).unwrap();
        let b = self.announce(i, &p.sealed.published);
        self.devs[i].writer.commit(p.clone());
        Some((p, b))
    }

    fn announce(&mut self, i: usize, p: &RecordPublished) -> u64 {
        self.batch(
            i,
            vec![Event::RecordPublished(Announcement {
                kind: p.kind,
                scope: p.scope,
                seq: p.seq,
                base: p.base,
                parts: p.parts,
                body_hash: p.body_hash,
                size: p.size,
            })],
            Vec::new(),
            EventScope::Full,
        )
    }

    fn batch(
        &mut self,
        i: usize,
        events: Vec<Event>,
        seen: Vec<(Id16, u64)>,
        scope: EventScope,
    ) -> u64 {
        let d = &mut self.devs[i];
        d.batch += 1;
        let b = Batch {
            device: d.id,
            seq: d.batch,
            prev: [0; 32],
            lamport: d.batch,
            created_utc: 0,
            seen,
            events: events.iter().map(Event::to_raw).collect(),
        };
        self.trust.view.borrow_mut().apply_scoped(&b, &scope);
        d.batch
    }

    /// Device `reader` says it holds `of`'s batches up to `upto`.
    fn ack(&mut self, reader: usize, of: usize, upto: u64, scope: EventScope) {
        let of = self.id(of);
        self.batch(reader, Vec::new(), vec![(of, upto)], scope);
    }

    fn store<'a>(&'a self, storage: &'a dyn Storage) -> RecordStore<'a> {
        RecordStore {
            storage,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &self.keys,
                trust: &self.trust,
            },
        }
    }

    fn pull(&self, fm: &mut FolderManifests, me: &Id16) -> PullReport {
        let mut counter = RecordsRefused::default();
        let view = self.trust.view.borrow();
        fm.pull(&self.store(&self.hot), &view, me, &mut counter)
            .unwrap()
    }
}

// ---- entries --------------------------------------------------------------

fn h32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0; 32];
    rng.fill_bytes(&mut b);
    b
}

fn live(rng: &mut StdRng, path: &str, by: Id16, version: BTreeMap<Id16, u64>) -> FileEntry {
    let chunks: Vec<Chunk3> = (0..rng.gen_range(0..4))
        .map(|_| Chunk3 {
            chunk: h32(rng),
            object: h32(rng),
            size: rng.gen_range(1..5000),
            epoch: rng.gen_range(0..2),
        })
        .collect();
    let clock = version.get(&by).copied().unwrap_or(0);
    FileEntry {
        path: path.into(),
        version,
        deleted: false,
        size: chunks.iter().map(|c| c.size).sum(),
        mtime: rng.gen(),
        content_hash: Some(h32(rng)),
        chunks,
        modified_by: by,
        modified_clock: clock,
        meta: None,
        chunking: 2,
        held: rng.gen(),
    }
}

fn gone(mut e: FileEntry) -> FileEntry {
    e.deleted = true;
    e.chunks.clear();
    e.size = 0;
    e.content_hash = None;
    e.held = false;
    e
}

fn rich_meta() -> FileMeta {
    FileMeta {
        v: 1,
        mode: Some(0o640),
        symlink: None,
        xattrs: Some(BTreeMap::from([("user.tag".into(), "aGVsbG8=".into())])),
        owner: Some(Owner {
            uid: 1000,
            gid: 100,
            user: Some("alice".into()),
            group: None,
        }),
    }
}

fn header(seq: u64, base: u64, prev: [u8; 32]) -> Header {
    Header {
        folder: FOLDER,
        device: [1; 16],
        seq,
        lamport: seq,
        created_utc: 0,
        base,
        prev,
    }
}

// ---- record: round trip and limits ---------------------------------------

#[test]
fn a_body_round_trips_through_a_sealed_record() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut w = World::new(2);
    let a = w.id(0);
    for i in 0..50 {
        let mut e = live(
            &mut rng,
            &format!("docs/f{i}.txt"),
            a,
            BTreeMap::from([(a, i + 1)]),
        );
        if i % 7 == 0 {
            e.meta = Some(rich_meta());
        }
        if i % 11 == 0 {
            e = gone(e);
        }
        w.devs[0].view.insert(e.path.clone(), e);
    }
    let (p, _) = w.publish(0).unwrap();
    assert!(p.is_base);
    assert_eq!(p.sealed.parts.len(), 1);
    assert_eq!(
        p.sealed.parts[0].0,
        format!(
            "manifests/{}/{}/0000000000000001-0000.rec",
            hex::encode(FOLDER),
            hex::encode(a)
        )
    );
    let mut fm = FolderManifests::new(FOLDER);
    let r = w.pull(&mut fm, &w.id(1));
    assert_eq!(r.applied, 1);
    assert_eq!(fm.views[&a].files, w.devs[0].view);
}

#[test]
fn file_states_convert_both_ways() {
    let mut rng = StdRng::seed_from_u64(2);
    let a = [9; 16];
    let mut e = live(
        &mut rng,
        "a/b.txt",
        a,
        BTreeMap::from([(a, 3), ([8; 16], 1)]),
    );
    e.meta = Some(rich_meta());
    e.held = false;
    let st = e.to_state();
    assert_eq!(FileEntry::from_state(&st, false).unwrap(), e);
    let mut bad = st.clone();
    bad.chunks.push(crate::manifest::ChunkRef {
        chunk: crate::ids::Id::from_bytes(&[1; 16]),
        object: crate::ids::Id::from_bytes(&[2; 32]),
        size: 1,
        epoch: 0,
    });
    assert!(
        FileEntry::from_state(&bad, false).is_err(),
        "16-byte chunk id"
    );
}

#[test]
fn bodies_outside_the_limits_are_refused() {
    let mut rng = StdRng::seed_from_u64(3);
    let a = [1; 16];
    let e = live(&mut rng, "ok.txt", a, BTreeMap::from([(a, 1)]));
    let good = ManifestBody::new(header(2, 1, [5; 32]), [&e], ["old.txt"]);
    assert!(good.validate().is_ok());
    let refused = |b: &ManifestBody| b.validate().unwrap_err();

    let mut long = e.clone();
    long.path = "a/".repeat(MAX_PATH / 2 + 1);
    assert!(refused(&ManifestBody::new(header(1, 1, [0; 32]), [&long], [])).contains("path"));

    let mut b = good.clone();
    b.files[0].path = vec![0xff, 0xfe];
    assert!(refused(&b).contains("UTF-8"));

    let mut b = good.clone();
    b.files[0].modified_by = 7;
    assert!(refused(&b).contains("out of range"));

    let mut b = good.clone();
    let first = b.files[0].version[0];
    b.files[0].version.push(first);
    assert!(refused(&b).contains("twice"));

    let b = ManifestBody::new(header(2, 1, [5; 32]), [&e, &e], []);
    assert!(refused(&b).contains("twice"));
    let b = ManifestBody::new(header(2, 1, [5; 32]), [&e], ["ok.txt"]);
    assert!(refused(&b).contains("twice"));

    // A base removes nothing; seq 1 has no predecessor; base <= seq.
    assert!(refused(&ManifestBody::new(header(2, 2, [5; 32]), [&e], ["x"])).contains("base"));
    assert!(refused(&ManifestBody::new(header(1, 1, [5; 32]), [&e], [])).contains("predecessor"));
    assert!(refused(&ManifestBody::new(header(2, 3, [5; 32]), [&e], [])).contains("base"));

    let mut b = good.clone();
    b.files[0].size += 1;
    assert!(refused(&b).contains("chunks hold"));
    let mut b = good.clone();
    b.files[0].path = b"../escape".to_vec();
    assert!(b.validate().is_err());
    let mut b = good.clone();
    b.devices.push([0; 16]);
    assert!(refused(&b).contains("sorted"));

    let mut b = good.clone();
    b.removed = vec![Vec::new(); MAX_ENTRIES];
    assert!(refused(&b).contains("entries"));

    let mut many = e.clone();
    many.chunks = vec![
        e.chunks.first().copied().unwrap_or(Chunk3 {
            chunk: [1; 32],
            object: [2; 32],
            size: 1,
            epoch: 0,
        });
        MAX_CHUNKS_PER_ENTRY + 1
    ];
    many.size = many.chunks.iter().map(|c| c.size).sum();
    assert!(refused(&ManifestBody::new(header(1, 1, [0; 32]), [&many], [])).contains("chunks"));
}

#[test]
fn the_envelope_and_the_body_must_agree() {
    use crate::record::RecordBody;
    let mut rng = StdRng::seed_from_u64(4);
    let a = [1; 16];
    let e = live(&mut rng, "ok.txt", a, BTreeMap::from([(a, 1)]));
    let body = ManifestBody::new(header(1, 1, [0; 32]), [&e], []);
    let meta = |scope: Id16, device: Id16, seq: u64| crate::record::RecordMeta {
        kind: Kind::Manifest,
        vault: VAULT,
        scope,
        device,
        seq,
        parts: 1,
        key_id: meta_key(),
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    assert!(body.check(&meta(FOLDER, a, 1)).is_ok());
    assert!(body.check(&meta([3; 16], a, 1)).is_err());
    assert!(body.check(&meta(FOLDER, [2; 16], 1)).is_err());
    assert!(body.check(&meta(FOLDER, a, 2)).is_err());
}

/// The body parser never panics on mutated or random input, and whatever
/// it accepts passes or fails `validate` cleanly.
#[test]
fn the_body_parser_survives_mutations() {
    let mut rng = StdRng::seed_from_u64(5);
    let a = [1; 16];
    let files: Vec<FileEntry> = (0..20)
        .map(|i| {
            let mut e = live(
                &mut rng,
                &format!("d/{i}"),
                a,
                BTreeMap::from([(a, i), ([2; 16], 1)]),
            );
            e.meta = (i % 3 == 0).then(rich_meta);
            e
        })
        .collect();
    let body = ManifestBody::new(header(3, 2, [7; 32]), files.iter(), ["x", "y"]);
    let plain = postcard::to_stdvec(&body).unwrap();
    let mut parsed = 0;
    for round in 0..4000 {
        let mut m = plain.clone();
        match round % 4 {
            0 => {
                for _ in 0..rng.gen_range(1..8) {
                    let i = rng.gen_range(0..m.len());
                    m[i] ^= rng.gen_range(1..=255u8);
                }
            }
            1 => m.truncate(rng.gen_range(0..m.len())),
            2 => {
                let i = rng.gen_range(0..m.len());
                let n = rng.gen_range(1..16);
                let ins: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
                m.splice(i..i, ins);
            }
            _ => {
                m = vec![0u8; rng.gen_range(0..400)];
                rng.fill_bytes(&mut m);
            }
        }
        if let Ok(b) = postcard::from_bytes::<ManifestBody>(&m) {
            parsed += 1;
            let _ = b.validate();
        }
        let z = zstd::bulk::compress(&m, 3).unwrap();
        if let Ok(b) = crate::record::envelope::decode_body::<ManifestBody>(&z) {
            let _ = b.validate();
        }
    }
    assert!(parsed > 0, "some mutations still parse");
}

// ---- base and delta -------------------------------------------------------

#[test]
fn the_base_rule() {
    let r = BaseRule::default();
    // Small folders: the 64th record after a base is a base.
    assert!(!r.is_base(63, 64 << 10, 62 * (64 << 10)));
    assert!(r.is_base(64, 64 << 10, 63 * (64 << 10)));
    // A large base: small deltas wait for the size condition, or 1024.
    let big = 350_000_000;
    assert!(!r.is_base(64, big, 63 * (64 << 10)));
    let n = (big / 16).div_ceil(64 << 10) + 1;
    assert!(!r.is_base(n - 1, big, (n - 2) * (64 << 10)));
    assert!(r.is_base(n, big, (n - 1) * (64 << 10)));
    assert!(r.is_base(1024, u64::MAX, 0));
    // Deltas that rewrite most entries: a base after 64.
    assert!(r.is_base(64, big, 63 * big));
}

#[test]
fn a_base_follows_63_deltas() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut w = World::new(2);
    let a = w.id(0);
    let mut bases = Vec::new();
    for i in 0..200u64 {
        let e = live(
            &mut rng,
            &format!("f{}", i % 10),
            a,
            BTreeMap::from([(a, i + 1)]),
        );
        w.devs[0].view.insert(e.path.clone(), e);
        let (p, _) = w.publish(0).unwrap();
        if p.is_base {
            bases.push(p.sealed.published.seq);
        }
    }
    assert_eq!(bases, vec![1, 65, 129, 193]);
    // Nothing changed: nothing is published.
    assert!(w.seal(0).is_none());
}

/// Reconstruction is exact: after each of 1000 random operations, a reader
/// that saw every record, and readers that join at random points, hold
/// exactly the writer's full view (the reference snapshot).
#[test]
fn base_and_deltas_equal_full_snapshots() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut w = World::new(3);
    w.rule(
        0,
        BaseRule {
            min_deltas: 16,
            size_divisor: 16,
            max_deltas: 1024,
        },
    );
    let a = w.id(0);
    let b = w.id(1);
    let mut follower = FolderManifests::new(FOLDER);
    let mut clock = 0u64;
    let (mut bases, mut deltas, mut joins) = (0, 0, 0);
    for op in 0..1000 {
        let view = &mut w.devs[0].view;
        let paths: Vec<String> = view.keys().cloned().collect();
        clock += 1;
        match rng.gen_range(0..100) {
            0..=29 => {
                let p = format!(
                    "dir{}/file{}.bin",
                    rng.gen_range(0..8),
                    rng.gen_range(0..300)
                );
                let e = live(&mut rng, &p, a, BTreeMap::from([(a, clock)]));
                view.insert(p, e);
            }
            30..=59 if !paths.is_empty() => {
                let p = &paths[rng.gen_range(0..paths.len())];
                let mut vv = view[p].version.clone();
                vv.insert(a, clock);
                let e = live(&mut rng, p, a, vv);
                view.insert(p.clone(), e);
            }
            60..=74 if !paths.is_empty() => {
                let p = &paths[rng.gen_range(0..paths.len())];
                let mut e = gone(view[p].clone());
                e.version.insert(a, clock);
                e.modified_clock = clock;
                view.insert(p.clone(), e);
            }
            75..=84 if !paths.is_empty() => {
                let p = &paths[rng.gen_range(0..paths.len())];
                let e = view.get_mut(p).unwrap();
                e.held = !e.held && !e.deleted;
            }
            85..=89 if !paths.is_empty() => {
                let p = &paths[rng.gen_range(0..paths.len())];
                view.remove(p);
            }
            90..=91 => {
                // A mass metadata change: every entry.
                for e in view.values_mut() {
                    e.mtime = rng.gen();
                }
            }
            _ => {}
        }
        if rng.gen_range(0..3) == 0 && op != 999 {
            continue;
        }
        if let Some((p, _)) = w.publish(0) {
            if p.is_base {
                bases += 1;
            } else {
                deltas += 1;
            }
        }
        w.pull(&mut follower, &b);
        assert_eq!(
            follower.views.get(&a).map(|v| &v.files),
            (w.devs[0].writer.seq > 0).then_some(&w.devs[0].view),
            "follower after op {op}"
        );
        if rng.gen_range(0..40) == 0 {
            joins += 1;
            let mut fresh = FolderManifests::new(FOLDER);
            w.pull(&mut fresh, &b);
            assert_eq!(
                fresh.views[&a].files, w.devs[0].view,
                "joiner after op {op}"
            );
            assert_eq!(fresh.views[&a].seq, w.devs[0].writer.seq);
        }
    }
    assert!(
        bases >= 5 && deltas >= 300 && joins >= 5,
        "{bases} {deltas} {joins}"
    );
}

#[test]
fn a_delta_with_a_wrong_prev_forks_the_stream() {
    let mut rng = StdRng::seed_from_u64(8);
    let mut w = World::new(2);
    let a = w.id(0);
    let b = w.id(1);
    let e = live(&mut rng, "x", a, BTreeMap::from([(a, 1)]));
    w.devs[0].view.insert("x".into(), e.clone());
    w.publish(0).unwrap();
    let mut fm = FolderManifests::new(FOLDER);
    w.pull(&mut fm, &b);
    assert_eq!(fm.applied(&a), 1);

    // Seq 2, a delta naming a predecessor that is not record 1.
    let e2 = live(&mut rng, "y", a, BTreeMap::from([(a, 2)]));
    let body = ManifestBody::new(
        Header {
            folder: FOLDER,
            device: a,
            seq: 2,
            lamport: 2,
            created_utc: 0,
            base: 1,
            prev: [0xee; 32],
        },
        [&e2],
        [],
    );
    let sealed = {
        let signer = DeviceSigner {
            device: a,
            key: &w.devs[0].sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &w.keys,
        };
        rw.seal(&stream(FOLDER, a), 2, 1, &meta_key(), &body)
            .unwrap()
    };
    RecordWriter::publish(&w.hot, &sealed).unwrap();
    w.announce(0, &sealed.published);
    let r = w.pull(&mut fm, &b);
    assert_eq!(r.forked, vec![a]);
    assert!(r
        .refused
        .iter()
        .any(|x| x.reason == crate::record::Refusal::Forked));
    assert_eq!(fm.applied(&a), 1, "the view stays as last accepted");
    assert!(
        fm.wanted(&w.trust.view.borrow(), &b).is_empty(),
        "not read again"
    );
    fm.clear_fork(&a);
    assert_eq!(fm.wanted(&w.trust.view.borrow(), &b).len(), 1);

    // The view's own check: a delta of another base forks too.
    let mut v = WriterView::new(a);
    let base = ManifestBody::new(
        Header {
            device: a,
            ..header(1, 1, [0; 32])
        },
        [&e],
        [],
    );
    v.apply(&base, [1; 32]).unwrap();
    let other_base = ManifestBody::new(
        Header {
            device: a,
            ..header(2, 1, [2; 32])
        },
        [&e2],
        [],
    );
    assert_eq!(
        v.apply(&other_base, [3; 32]),
        Err(ApplyError::Forked { seq: 2 })
    );
    let gap = ManifestBody::new(
        Header {
            device: a,
            ..header(3, 1, [1; 32])
        },
        [&e2],
        [],
    );
    assert_eq!(
        v.apply(&gap, [3; 32]),
        Err(ApplyError::Gap { have: 1, got: 3 })
    );
    assert!(matches!(
        v.apply(&base, [1; 32]),
        Err(ApplyError::Stale { .. })
    ));
}

#[test]
fn a_record_that_differs_from_its_announcement_forks() {
    let mut rng = StdRng::seed_from_u64(9);
    let mut w = World::new(2);
    let a = w.id(0);
    let b = w.id(1);
    let e = live(&mut rng, "x", a, BTreeMap::from([(a, 1)]));
    w.devs[0].view.insert("x".into(), e);
    let p = w.seal(0).unwrap();
    RecordWriter::publish(&w.hot, &p.sealed).unwrap();
    let mut wrong = p.sealed.published.clone();
    wrong.body_hash = [0xab; 32];
    w.announce(0, &wrong);
    let mut fm = FolderManifests::new(FOLDER);
    let r = w.pull(&mut fm, &b);
    assert_eq!(r.forked, vec![a]);
    assert!(fm.views.is_empty());
}

#[test]
fn a_writer_that_loses_a_seq_writes_a_base_next() {
    let mut rng = StdRng::seed_from_u64(10);
    let mut w = World::new(2);
    let a = w.id(0);
    let b = w.id(1);
    for i in 0..3u64 {
        let e = live(&mut rng, &format!("f{i}"), a, BTreeMap::from([(a, i + 1)]));
        w.devs[0].view.insert(e.path.clone(), e);
        w.publish(0).unwrap();
    }
    // Seq 4 is sealed but never published or announced.
    let e = live(&mut rng, "lost", a, BTreeMap::from([(a, 9)]));
    w.devs[0].view.insert("lost".into(), e);
    let p = w.seal(0).unwrap();
    assert!(!p.is_base);
    w.devs[0].writer.abandon(p);
    let (p, _) = w.publish(0).unwrap();
    assert!(p.is_base);
    assert_eq!(p.sealed.published.seq, 5);
    let mut fm = FolderManifests::new(FOLDER);
    w.pull(&mut fm, &b);
    assert_eq!(fm.views[&a].files, w.devs[0].view);
    assert_eq!(fm.applied(&a), 5);
}

// ---- listing ---------------------------------------------------------------

#[test]
fn a_pull_lists_only_streams_announced_past_what_was_applied() {
    let mut rng = StdRng::seed_from_u64(11);
    let mut w = World::new(3);
    w.rule(
        0,
        BaseRule {
            min_deltas: 3,
            size_divisor: 16,
            max_deltas: 1024,
        },
    );
    let (a, b, c) = (w.id(0), w.id(1), w.id(2));
    let mut fm = FolderManifests::new(FOLDER);
    assert!(fm.wanted(&w.trust.view.borrow(), &b).is_empty());
    let mut put = |w: &mut World, i: usize, n: u64| {
        let id = w.id(i);
        let e = live(&mut rng, &format!("f{n}"), id, BTreeMap::from([(id, n)]));
        w.devs[i].view.insert(e.path.clone(), e);
        w.publish(i).unwrap()
    };
    put(&mut w, 0, 1);
    put(&mut w, 2, 1);
    put(&mut w, 1, 1); // own stream: never wanted
    let wanted = fm.wanted(&w.trust.view.borrow(), &b);
    assert_eq!(
        wanted
            .iter()
            .map(|x| (x.device, x.after))
            .collect::<Vec<_>>(),
        vec![(a, 0), (c, 0)]
    );
    w.pull(&mut fm, &b);
    assert!(
        fm.wanted(&w.trust.view.borrow(), &b).is_empty(),
        "nothing new"
    );
    put(&mut w, 0, 2);
    let wanted = fm.wanted(&w.trust.view.borrow(), &b);
    assert_eq!(wanted.len(), 1);
    assert_eq!(
        (wanted[0].device, wanted[0].after, wanted[0].rebuild),
        (a, 1, false)
    );
    // A newer base than what was applied: rebuilt from it.
    put(&mut w, 0, 3);
    let (p, _) = put(&mut w, 0, 4);
    assert!(p.is_base);
    let wanted = fm.wanted(&w.trust.view.borrow(), &b);
    assert_eq!((wanted[0].after, wanted[0].rebuild), (3, true));
    let r = w.pull(&mut fm, &b);
    assert_eq!(r.applied, 1, "only the base");
    assert_eq!(fm.views[&a].files, w.devs[0].view);
    assert!(r.changed[&a].contains("f2") && r.changed[&a].contains("f4"));
}

// ---- merge -------------------------------------------------------------------

fn st(dev: u8, clock: u64, hash: u8, vv: &[(u8, u64)]) -> FileEntry {
    FileEntry {
        path: "a.txt".into(),
        version: vv.iter().map(|(d, c)| ([*d; 16], *c)).collect(),
        deleted: false,
        size: 0,
        mtime: 0,
        content_hash: (hash != 0).then_some([hash; 32]),
        chunks: vec![],
        modified_by: [dev; 16],
        modified_clock: clock,
        meta: None,
        chunking: 0,
        held: false,
    }
}

#[test]
fn version_vector_orders() {
    let a = st(1, 1, 1, &[(1, 1)]);
    let b = st(2, 2, 2, &[(1, 1), (2, 2)]);
    assert_eq!(merge_entry(Some(&a), &b), Merge3::TakeRemote);
    assert_eq!(merge_entry(Some(&b), &a), Merge3::KeepLocal);
    assert_eq!(merge_entry(None, &a), Merge3::TakeRemote);
    assert_eq!(resolve([&a, &b]).unwrap().winner, b);
    assert_eq!(compare(&a.version, &b.version), Order::RemoteNewer);
}

#[test]
fn concurrent_edits_conflict_deterministically() {
    let a = st(1, 5, 1, &[(1, 5)]);
    let b = st(2, 7, 2, &[(2, 7)]);
    let (
        Merge3::Conflict {
            winner: w1,
            loser: l1,
        },
        Merge3::Conflict {
            winner: w2,
            loser: l2,
        },
    ) = (merge_entry(Some(&a), &b), merge_entry(Some(&b), &a))
    else {
        panic!()
    };
    assert_eq!(w1, w2);
    assert_eq!(l1, l2);
    assert_eq!(w1.content_hash, Some([2; 32]));
    assert_eq!(w1.version.len(), 2);
    let r = resolve([&a, &b]).unwrap();
    assert_eq!(r.winner, w1);
    assert_eq!(r.losers, vec![l1.clone().unwrap()]);
    assert_eq!(
        conflict_path("docs/report.txt", l1.as_ref().unwrap()),
        "docs/report.conflict-01010101-5.txt"
    );
    // The same naming as format 2.
    let fs = l1.unwrap().to_state();
    assert_eq!(
        manifest::conflict_path("docs/report.txt", &fs),
        "docs/report.conflict-01010101-5.txt"
    );
}

#[test]
fn concurrent_metadata_changes_need_no_conflict_copy() {
    let meta = |mode| {
        Some(FileMeta {
            v: 1,
            mode: Some(mode),
            ..Default::default()
        })
    };
    let mut a = st(1, 5, 9, &[(1, 5)]);
    a.meta = meta(0o644);
    let mut b = st(2, 7, 9, &[(2, 7)]);
    b.meta = meta(0o755);
    for (l, r) in [(&a, &b), (&b, &a)] {
        let Merge3::Conflict { winner, loser } = merge_entry(Some(l), r) else {
            panic!()
        };
        assert!(loser.is_none());
        assert_eq!(
            winner.meta,
            meta(0o755),
            "the later change wins on both sides"
        );
        assert_eq!(winner.version.len(), 2);
        let res = resolve([l, r]).unwrap();
        assert_eq!(res.winner, winner);
        assert!(res.losers.is_empty());
    }
    assert!(!a.same_as(&b));
}

#[test]
fn delete_loses_against_concurrent_edit() {
    let del = gone(st(1, 5, 0, &[(1, 5)]));
    let edit = st(2, 3, 2, &[(2, 3)]);
    let Merge3::Conflict { winner, loser } = merge_entry(Some(&del), &edit) else {
        panic!()
    };
    assert!(!winner.deleted);
    assert!(loser.is_none());
    let r = resolve([&del, &edit]).unwrap();
    assert!(!r.winner.deleted && r.losers.is_empty());
}

/// Devices editing, deleting and syncing the paths of one folder. Every
/// state it makes is one honest devices could publish: a (device, clock)
/// names one change, so two states with equal version vectors are equal.
struct Sim {
    clocks: Vec<u64>,
    views: Vec<BTreeMap<String, FileEntry>>,
    paths: u32,
}

impl Sim {
    fn new(devices: usize, paths: u32) -> Sim {
        Sim {
            clocks: vec![0; devices],
            views: vec![BTreeMap::new(); devices],
            paths,
        }
    }

    fn dev(i: usize) -> Id16 {
        [i as u8 + 1; 16]
    }

    /// One random step; the device and path it touched.
    fn step(&mut self, rng: &mut StdRng) -> (usize, String) {
        let n = self.views.len();
        let i = rng.gen_range(0..n);
        let p = format!("p{}", rng.gen_range(0..self.paths));
        let d = Sim::dev(i);
        let old = self.views[i].get(&p).cloned();
        match rng.gen_range(0..10) {
            0..=3 => {
                self.clocks[i] += 1;
                let c = self.clocks[i];
                let mut vv = old.map(|o| o.version).unwrap_or_default();
                vv.insert(d, c);
                let h: u8 = rng.gen_range(1..4);
                let mut e = st(d[0], c, h, &[]);
                e.version = vv;
                e.path = p.clone();
                e.chunks = vec![Chunk3 {
                    chunk: [h; 32],
                    object: [h; 32],
                    size: 1,
                    epoch: 0,
                }];
                e.size = 1;
                e.held = rng.gen_bool(0.6);
                if rng.gen_bool(0.25) {
                    e.meta = Some(FileMeta {
                        v: 1,
                        mode: Some(rng.gen_range(0..3) * 0o111),
                        ..Default::default()
                    });
                }
                self.views[i].insert(p.clone(), e);
            }
            4 => {
                if let Some(o) = old.filter(|o| !o.deleted) {
                    self.clocks[i] += 1;
                    let c = self.clocks[i];
                    let mut e = gone(o);
                    e.version.insert(d, c);
                    e.modified_by = d;
                    e.modified_clock = c;
                    self.views[i].insert(p.clone(), e);
                }
            }
            5 => {
                self.views[i].remove(&p);
            }
            _ => {
                let j = (i + rng.gen_range(1..n)) % n;
                let theirs = self.views[j].get(&p).cloned();
                if let Some(r) = resolve(old.iter().chain(theirs.iter())) {
                    let mut w = r.winner;
                    w.held = old.as_ref().is_some_and(|o| {
                        o.held && o.content_hash == w.content_hash && o.chunks == w.chunks
                    }) && !w.deleted;
                    self.views[i].insert(p.clone(), w);
                }
            }
        }
        (i, p)
    }

    fn states(&self, p: &str) -> Vec<FileEntry> {
        self.views
            .iter()
            .filter_map(|v| v.get(p).cloned())
            .collect()
    }
}

fn content(e: &FileEntry) -> (bool, Option<[u8; 32]>) {
    (e.deleted, e.content_hash)
}

/// `resolve` agrees with the pairwise rule of format 2 on two states, and
/// depends only on the set of states (any order, repeats, a winner added
/// back).
#[test]
fn merge_properties() {
    let mut rng = StdRng::seed_from_u64(12);
    let (mut pairs, mut conflicts) = (0, 0);
    for _ in 0..60 {
        let mut sim = Sim::new(4, 1);
        for _ in 0..100 {
            sim.step(&mut rng);
            let (Some(a), Some(b)) = (sim.views[0].get("p0"), sim.views[1].get("p0")) else {
                continue;
            };
            pairs += 1;
            let r = resolve([a, b]).unwrap();
            match merge_entry(Some(a), b) {
                Merge3::KeepLocal => {
                    assert_ne!(compare(&a.version, &b.version), Order::RemoteNewer);
                    assert_eq!(content(&r.winner), content(a));
                }
                Merge3::TakeRemote => assert_eq!(content(&r.winner), content(b)),
                Merge3::Conflict { winner, loser } => {
                    conflicts += 1;
                    assert_eq!(r.winner.version, winner.version);
                    assert_eq!(content(&r.winner), content(&winner), "{a:?} {b:?}");
                    assert_eq!(r.losers.len(), usize::from(loser.is_some()), "{a:?} {b:?}");
                    if let Some(l) = loser {
                        assert_eq!(content(&r.losers[0]), content(&l));
                    }
                }
            }
            let mut states = sim.states("p0");
            let r = resolve(&states).unwrap();
            for _ in 0..3 {
                // Commutative.
                for i in (1..states.len()).rev() {
                    states.swap(i, rng.gen_range(0..=i));
                }
                assert_eq!(resolve(&states).unwrap(), r);
            }
            // Repeats change nothing.
            let mut twice = states.clone();
            twice.extend(states.iter().cloned());
            assert_eq!(resolve(&twice).unwrap(), r);
            // Idempotent: the winner dominates what it came from.
            let mut with = states.clone();
            with.push(r.winner.clone());
            let again = resolve(&with).unwrap();
            assert_eq!(again.winner, r.winner);
            assert!(again.losers.is_empty());
            for s in &states {
                assert_ne!(compare(&r.winner.version, &s.version), Order::RemoteNewer);
            }
        }
    }
    assert!(
        pairs > 1000 && conflicts > 50,
        "{pairs} pairs, {conflicts} conflicts"
    );
}

fn without_held(m: &Merged) -> BTreeMap<String, FileEntry> {
    m.files
        .iter()
        .map(|(p, e)| {
            let mut e = e.clone();
            e.held = false;
            (p.clone(), e)
        })
        .collect()
}

#[test]
fn merging_views_is_commutative_idempotent_and_incremental() {
    let mut rng = StdRng::seed_from_u64(13);
    let mut copies = 0;
    for _ in 0..200 {
        let mut sim = Sim::new(3, 12);
        for _ in 0..rng.gen_range(5..120) {
            sim.step(&mut rng);
        }
        let [own, x, y] = [&sim.views[0], &sim.views[1], &sim.views[2]];
        let m = merge_views(own, &[x, y]);
        copies += m.conflicts.len();
        assert_eq!(merge_views(own, &[y, x]), m);
        // Another writer's point of view: the same files, its own `held`.
        let from_x = merge_views(x, &[own, y]);
        assert_eq!(without_held(&from_x), without_held(&m));
        assert_eq!(from_x.conflicts, m.conflicts);
        // Merging the merged view again changes nothing and copies nothing.
        let again = merge_views(&m.files, &[x, y]);
        assert_eq!(again.files, m.files);
        assert!(again.conflicts.is_empty());
        // `held` only for what the own entry holds.
        for (p, e) in &m.files {
            if e.held {
                let o = &own[p];
                assert!(o.held && o.chunks == e.chunks && o.content_hash == e.content_hash);
            }
        }
    }
    assert!(copies > 20, "{copies} conflict copies");
    // Incremental: refreshing the paths that changed equals merging again.
    let mut sim = Sim::new(3, 12);
    let mut m = Merged::default();
    for _ in 0..2000 {
        let (_, p) = sim.step(&mut rng);
        let [own, x, y] = [&sim.views[0], &sim.views[1], &sim.views[2]];
        m.refresh(own, &[x, y], [p.as_str()]);
        assert_eq!(m, merge_views(own, &[x, y]));
    }
}

// ---- held, holders, references ---------------------------------------------

fn view_of(dev: Id16, seq: u64, files: Vec<FileEntry>) -> WriterView {
    WriterView {
        device: dev,
        seq,
        base: seq,
        files: files.into_iter().map(|f| (f.path.clone(), f)).collect(),
        ..Default::default()
    }
}

#[test]
fn held_flags_give_the_holders_of_each_object() {
    let mut rng = StdRng::seed_from_u64(14);
    let (a, b, c, d) = ([1; 16], [2; 16], [3; 16], [4; 16]);
    let mut f = live(&mut rng, "f", a, BTreeMap::from([(a, 1)]));
    while f.chunks.len() < 2 {
        f = live(&mut rng, "f", a, BTreeMap::from([(a, 1)]));
    }
    let g = live(&mut rng, "g", b, BTreeMap::from([(b, 1)]));
    let held = |e: &FileEntry, h: bool| FileEntry {
        held: h,
        ..e.clone()
    };
    let mut fm = FolderManifests::new(FOLDER);
    fm.insert_view(view_of(a, 1, vec![held(&f, true), held(&g, false)]));
    fm.insert_view(view_of(b, 1, vec![held(&f, false), held(&g, true)]));
    fm.insert_view(view_of(c, 1, vec![held(&f, true)]));
    // A deleted entry holds nothing, whatever its flag says.
    let mut dead = held(&g, true);
    dead.deleted = true;
    fm.insert_view(view_of(d, 1, vec![dead]));
    let idx = fm.held_index();
    let o = f.chunks[0].object;
    assert_eq!(idx.holders(&o), &[a, c]);
    assert!(idx.held_by(&o, &a) && !idx.held_by(&o, &b));
    assert!(idx.held_elsewhere(&o, &a));
    assert!(!idx.held_elsewhere(&g.chunks.first().map(|c| c.object).unwrap_or([0; 32]), &b));
    assert!(idx.held_by_all(&o, [&a, &c]));
    assert!(!idx.held_by_all(&o, [&a, &b]));
    assert!(idx.holders(&[0x77; 32]).is_empty());
    assert!(idx.uses(&d) && !idx.uses(&[9; 16]));
    let bytes = idx.bytes_by_device();
    assert_eq!(bytes[&a].0, f.size);
    assert_eq!(bytes[&a].1, f.chunks.len() as u64);
    assert_eq!(bytes.get(&b).map(|x| x.0).unwrap_or(0), g.size);
    assert!(!bytes.contains_key(&d));
    assert_eq!(idx.held_objects(&c).count(), f.chunks.len());
}

#[test]
fn references_are_the_current_files_of_every_writer() {
    let mut rng = StdRng::seed_from_u64(15);
    let (a, b) = ([1; 16], [2; 16]);
    let f = live(&mut rng, "f", a, BTreeMap::from([(a, 1)]));
    let mut old = live(&mut rng, "old", a, BTreeMap::from([(a, 1)]));
    while old.chunks.is_empty() {
        old = live(&mut rng, "old", a, BTreeMap::from([(a, 1)]));
    }
    let deleted_obj = old.chunks[0].object;
    let mut tomb = old.clone();
    tomb.deleted = true; // its chunks are not references
    let g = live(&mut rng, "g", b, BTreeMap::from([(b, 1)]));
    let mut fm = FolderManifests::new(FOLDER);
    fm.insert_view(view_of(a, 1, vec![f.clone(), tomb]));
    fm.insert_view(view_of(b, 1, vec![g.clone(), f.clone()]));
    let set = fm.reference_set();
    let expect: std::collections::HashSet<[u8; 32]> =
        f.objects().chain(g.objects()).copied().collect();
    assert_eq!(set, expect);
    for o in &expect {
        assert!(fm.is_referenced(o));
    }
    assert!(!fm.is_referenced(&deleted_obj));
    fm.remove_writer(&b);
    assert!(g
        .objects()
        .all(|o| !fm.is_referenced(o) || f.objects().any(|x| x == o)));
}

// ---- pruning ---------------------------------------------------------------

#[test]
fn pruning_waits_for_every_reader() {
    let mut rng = StdRng::seed_from_u64(16);
    let mut w = World::new(3);
    w.rule(
        0,
        BaseRule {
            min_deltas: 3,
            size_divisor: 16,
            max_deltas: 1024,
        },
    );
    let (a, b, m) = (w.id(0), w.id(1), w.id(2));
    let readers = [a, b, m];
    let mut base_batch = 0;
    for i in 0..5u64 {
        let e = live(&mut rng, &format!("f{i}"), a, BTreeMap::from([(a, i + 1)]));
        w.devs[0].view.insert(e.path.clone(), e);
        let (p, batch) = w.publish(0).unwrap();
        if p.is_base {
            base_batch = batch;
        }
    }
    // Records 1 (base), 2, 3, then the base 4 and delta 5.
    let stream_names = |s: &Mem| {
        s.names()
            .into_iter()
            .filter(|n| n.starts_with("manifests/"))
            .count()
    };
    assert_eq!(stream_names(&w.hot), 5);
    assert_eq!(base_batch, 4);
    let floor = |w: &World| prune_floor(&w.trust.view.borrow(), &FOLDER, &a, &readers);
    assert_eq!(floor(&w), None);
    assert_eq!(
        readers_waiting(&w.trust.view.borrow(), &FOLDER, &a, &readers),
        vec![b, m]
    );
    // The full device acknowledges in its vault batch.
    w.ack(1, 0, base_batch, EventScope::Full);
    assert_eq!(floor(&w), None, "the member has not");
    assert_eq!(
        readers_waiting(&w.trust.view.borrow(), &FOLDER, &a, &readers),
        vec![m]
    );
    // An acknowledgement of an older batch does not count.
    w.ack(2, 0, base_batch - 1, EventScope::Member(FOLDER));
    assert_eq!(floor(&w), None);
    // The member acknowledges in its folder-scoped batch.
    w.ack(2, 0, base_batch, EventScope::Member(FOLDER));
    assert_eq!(floor(&w), Some(4));

    let mut state = PruneState::default();
    // A storage that does not hold the base is left alone.
    let empty = Mem::named("other");
    assert_eq!(
        prune_stream(&empty, false, &FOLDER, &a, 4, &mut state).unwrap(),
        0
    );
    assert_eq!(
        prune_stream(&w.cold, true, &FOLDER, &a, 4, &mut state).unwrap(),
        0
    );
    assert_eq!(
        prune_stream(&w.hot, false, &FOLDER, &a, 4, &mut state).unwrap(),
        3
    );
    assert_eq!(
        prune_stream(&w.hot, false, &FOLDER, &a, 4, &mut state).unwrap(),
        0
    );
    assert_eq!(stream_names(&w.hot), 2);
    assert_eq!(stream_names(&w.cold), 5, "cold storages are never pruned");
    assert_eq!(state.pruned_below["hot"], 4);
    // A reader that joins now reads the base and its delta.
    let mut fresh = FolderManifests::new(FOLDER);
    w.pull(&mut fresh, &b);
    assert_eq!(fresh.views[&a].files, w.devs[0].view);
}

// ---- scale -------------------------------------------------------------------

/// The design's worst case: a base of 1 M files (700 k small, 280 k of
/// 1-32 MiB, 20 k large: ~4.3 M blocks) with realistic paths. Run with
/// `cargo test --release -p varsto-core --lib
/// manifest3::tests::a_million_file_base -- --ignored --nocapture`.
#[test]
#[ignore]
fn a_million_file_base() {
    use std::time::Instant;
    let mut rng = StdRng::seed_from_u64(17);
    let devs: Vec<Id16> = (1..=4).map(|i| [i; 16]).collect();
    let words = [
        "Photos",
        "Documents",
        "Projects",
        "Music",
        "Archive",
        "2023",
        "2024",
        "2025",
        "invoices",
        "src",
        "assets",
        "notes",
        "Camera",
        "holiday",
        "reports",
        "drafts",
    ];
    let exts = [
        "jpg", "pdf", "txt", "rs", "png", "mp3", "docx", "json", "mov",
    ];
    let t = Instant::now();
    let mut files: Vec<FileEntry> = Vec::with_capacity(1_000_000);
    let mut chunks_total = 0usize;
    for i in 0..1_000_000u64 {
        let depth = rng.gen_range(2..5);
        let mut path = String::new();
        for _ in 0..depth {
            path.push_str(words[rng.gen_range(0..words.len())]);
            path.push('/');
        }
        path.push_str(&format!(
            "{}_{:06}.{}",
            words[rng.gen_range(0..words.len())].to_lowercase(),
            i,
            exts[rng.gen_range(0..exts.len())]
        ));
        let (n, avg) = match i % 50 {
            0 => (rng.gen_range(10..140), 5 << 20),
            1..=14 => (rng.gen_range(2..15), 1 << 20),
            _ => (1, 150_000),
        };
        chunks_total += n;
        let chunks: Vec<Chunk3> = (0..n)
            .map(|_| Chunk3 {
                chunk: h32(&mut rng),
                object: h32(&mut rng),
                size: rng.gen_range(avg / 2..avg * 3 / 2),
                epoch: 0,
            })
            .collect();
        let by = devs[rng.gen_range(0..4)];
        let mut vv = BTreeMap::from([(by, rng.gen_range(1..100_000))]);
        if rng.gen_bool(0.3) {
            vv.insert(devs[rng.gen_range(0..4)], rng.gen_range(1..100_000));
        }
        files.push(FileEntry {
            size: chunks.iter().map(|c| c.size).sum(),
            path,
            modified_clock: vv[&by],
            version: vv,
            deleted: false,
            mtime: 1_700_000_000_000_000_000 + rng.gen_range(0..100_000_000_000_000_000),
            content_hash: Some(h32(&mut rng)),
            chunks,
            modified_by: by,
            meta: Some(FileMeta {
                v: 1,
                mode: Some(0o644),
                ..Default::default()
            }),
            chunking: 2,
            held: true,
        });
    }
    eprintln!(
        "generated 1 M entries, {chunks_total} blocks in {:?}",
        t.elapsed()
    );
    let t = Instant::now();
    let body = ManifestBody::new(
        Header {
            device: devs[0],
            ..header(1, 1, [0; 32])
        },
        files.iter(),
        [],
    );
    let plain = postcard::to_stdvec(&body).unwrap();
    eprintln!("postcard: {} bytes in {:?}", plain.len(), t.elapsed());
    let t = Instant::now();
    let z = zstd::bulk::compress(&plain, 3).unwrap();
    eprintln!("zstd 3: {} bytes in {:?}", z.len(), t.elapsed());
    let t = Instant::now();
    let w = World::new(1);
    let signer = DeviceSigner {
        device: devs[0],
        key: &w.devs[0].sk,
    };
    let rw = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &w.keys,
    };
    let sealed = rw
        .seal_compressed(&stream(FOLDER, devs[0]), 1, 1, &meta_key(), &z)
        .unwrap();
    eprintln!(
        "sealed: {} parts, {} bytes stored in {:?}",
        sealed.parts.len(),
        sealed.published.size,
        t.elapsed()
    );
    let t = Instant::now();
    let back: ManifestBody = crate::record::envelope::decode_body(&z).unwrap();
    eprintln!("decode: {:?}", t.elapsed());
    let t = Instant::now();
    let (entries, _) = back.validate().unwrap();
    eprintln!("validate + resolve: {:?}", t.elapsed());
    let t = Instant::now();
    let mut v = WriterView::new(devs[0]);
    v.apply(&back, sealed.published.body_hash).unwrap();
    eprintln!("apply as a base (validates again): {:?}", t.elapsed());
    assert_eq!(entries.len(), 1_000_000);
    let t = Instant::now();
    let mut fm = FolderManifests::new(FOLDER);
    fm.insert_view(v);
    let idx = fm.held_index();
    eprintln!("held index of {} objects: {:?}", idx.len(), t.elapsed());
}
