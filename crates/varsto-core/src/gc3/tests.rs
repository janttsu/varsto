// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Section 3's marks, collection, verification, repair and pruning end to
//! end: devices with their own map tables, map writers and manifests,
//! sharing local-directory storages (two hot, one cold with a minimum
//! duration) and one ledger view that every sealed batch is applied to.
//! What a device has *pulled* (map records, manifests) and what it
//! *acknowledges* (`seen`) are its own, so the orders the design argues
//! about can be played out.

use super::*;
use crate::blockmap::{self, table_path, MapRow, MapTable, MapWriter, MarkKind, WrittenPack};
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ledger3::events::{Announcement, Event, PackOn};
use crate::ledger3::{Batch, DeviceBin, EventScope, LedgerView, ObjectBin, PackId, Place};
use crate::manifest3::{Chunk3, FileEntry, FolderManifests, ManifestWriter, PruneState};
use crate::membership3::{DeviceRecord, DeviceRegistry, FolderRegistry, FolderState, Role, Trust};
use crate::record::{
    Acceptor, Announced, DeviceSigner, Id16, KeyId, Kind, RecordKeys, RecordStore, RecordTrust,
    RecordWriter, RecordsRefused,
};
use crate::storage::{LocalDirStorage, Storage};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const VAULT: Id16 = [0x11; 16];
const FOLDER: Id16 = [0x22; 16];
const DAY: i64 = 86_400;
const T0: i64 = 1_800_000_000;
const H1: &str = "h1";
const H2: &str = "h2";
const C: &str = "c";

struct Keys(SecretKey);

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        matches!(key_id, KeyId::Meta { folder, .. } if *folder == FOLDER).then(|| self.0.clone())
    }
}

/// The real trust of membership3 (device records, folder roles), with
/// announcements from the ledger view as the engine adds them.
struct TestTrust<'a> {
    inner: Trust<'a>,
    view: &'a LedgerView,
    /// Accept every signed record (a careless reader): to show that
    /// collection still ignores marks of non-writers.
    permissive: bool,
}

impl RecordTrust for TestTrust<'_> {
    fn signer_key(&self, device: &Id16, kind: Kind, scope: &Id16) -> Option<VerifyingKey> {
        self.inner.signer_key(device, kind, scope)
    }
    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool {
        self.permissive || self.inner.may_write(device, kind, scope, key_id)
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        crate::manifest3::announcement(self.view, device, kind, scope, seq)
    }
}

/// Seals into a list; the world applies the batches afterwards.
struct Sink {
    lamport: u64,
    batches: Vec<Vec<Event>>,
    fail: bool,
}

impl Commit for Sink {
    fn tick(&mut self) -> u64 {
        self.lamport += 1;
        self.lamport
    }
    fn commit(&mut self, events: Vec<Event>) -> anyhow::Result<()> {
        if self.fail {
            anyhow::bail!("the storage refused the batch");
        }
        self.batches.push(events);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Owner,
    Editor,
    Viewer,
    /// Joined with the vault words, no grant.
    K3Only,
    /// Another person's device, editor of the folder.
    MemberEditor,
}

struct Dev {
    id: DeviceBin,
    sk: SigningKey,
    class: Class,
    map: MapWriter,
    table: MapTable,
    manifests: FolderManifests,
    mw: ManifestWriter,
    files: BTreeMap<String, FileEntry>,
    batch_seq: u64,
    /// The newest batch of each device it has pulled: its `seen`.
    known: BTreeMap<DeviceBin, u64>,
}

impl Dev {
    fn role(&self) -> Option<Role> {
        match self.class {
            Class::Owner => Some(Role::Owner),
            Class::Editor | Class::MemberEditor => Some(Role::Editor),
            Class::Viewer => Some(Role::Viewer),
            Class::K3Only => None,
        }
    }
    fn standing(&self) -> Standing {
        Standing {
            device: self.id,
            role: self.role(),
            member: self.class == Class::MemberEditor,
            holds_k10: self.class != Class::K3Only,
        }
    }
}

struct World {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    set: StorageSet,
    meta: Arc<LocalDirStorage>,
    keys: Keys,
    devices: DeviceRegistry,
    folders: FolderRegistry,
    revoked: BTreeSet<Id16>,
    view: LedgerView,
    lamport: u64,
    now: i64,
    devs: Vec<Dev>,
    heads: BTreeMap<DeviceBin, u64>,
    rng: StdRng,
}

fn hot() -> Vec<String> {
    vec![H1.into(), H2.into()]
}
fn cold() -> Vec<String> {
    vec![C.into()]
}

impl World {
    fn new(classes: &[Class]) -> World {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut set = StorageSet::default();
        let h1 = Arc::new(LocalDirStorage::new(H1.into(), root.join(H1)).unwrap());
        set.add(h1.clone(), StorageInfo::HOT);
        set.add(
            Arc::new(LocalDirStorage::new(H2.into(), root.join(H2)).unwrap()),
            StorageInfo::HOT,
        );
        set.add(
            Arc::new(LocalDirStorage::new(C.into(), root.join(C)).unwrap()),
            StorageInfo {
                class: StorageClass::Cold,
                minimum_secs: Some(90 * DAY),
            },
        );
        let mut devices = DeviceRegistry::default();
        let mut entries = BTreeMap::new();
        let mut devs = Vec::new();
        for (i, class) in classes.iter().enumerate() {
            let sk = SigningKey::generate();
            let id = crate::membership3::device_id(&sk.public());
            devices.insert(
                DeviceRecord {
                    device: id,
                    name: format!("dev{i}"),
                    sign_pub: sk.public().to_bytes(),
                    kem_pub: Vec::new(),
                    stamp: Default::default(),
                },
                0,
            );
            let d = Dev {
                id,
                sk,
                class: *class,
                map: MapWriter::from_view(FOLDER, id, 0, &LedgerView::default(), 0),
                table: MapTable::open(&table_path(&root.join(format!("dev{i}")), &FOLDER), FOLDER)
                    .unwrap(),
                manifests: FolderManifests::new(FOLDER),
                mw: ManifestWriter::new(FOLDER, id),
                files: BTreeMap::new(),
                batch_seq: 0,
                known: BTreeMap::new(),
            };
            if let Some(r) = d.role() {
                entries.insert(id, (Some(r), Default::default()));
            }
            devs.push(d);
        }
        let mut folders = FolderRegistry::default();
        folders.folders.insert(
            FOLDER,
            FolderState {
                id: FOLDER,
                name: "photos".into(),
                settings: BTreeMap::new(),
                creator: devs[0].id,
                history: entries
                    .iter()
                    .map(|(d, (r, s))| (*d, vec![(*s, *r)]))
                    .collect(),
                entries,
                entries_refused: 0,
                max_lamport: 0,
                members: BTreeMap::new(),
            },
        );
        World {
            _dir: dir,
            root,
            set,
            meta: h1,
            keys: Keys(SecretKey([9; 32])),
            devices,
            folders,
            revoked: BTreeSet::new(),
            view: LedgerView::default(),
            lamport: 0,
            now: T0,
            devs,
            heads: BTreeMap::new(),
            rng: StdRng::seed_from_u64(7),
        }
    }

    fn id(&self, d: usize) -> DeviceBin {
        self.devs[d].id
    }

    fn writers(&self) -> Vec<DeviceBin> {
        folder_writers(&self.folders, &FOLDER, 0, &self.revoked)
    }

    fn readers(&self) -> Vec<DeviceBin> {
        folder_readers(&self.folders, &FOLDER, 0, &self.revoked)
    }

    fn storage(&self, name: &str) -> Arc<dyn Storage> {
        self.set.open(name).unwrap()
    }

    /// Device `d` seals a batch of `events`, acknowledging what it pulled.
    fn batch(&mut self, d: usize, events: Vec<Event>) -> u64 {
        self.lamport += 1;
        let dev = &mut self.devs[d];
        dev.batch_seq += 1;
        let b = Batch {
            device: dev.id,
            seq: dev.batch_seq,
            prev: [0; 32],
            lamport: self.lamport,
            created_utc: self.now,
            seen: dev.known.iter().map(|(k, v)| (*k, *v)).collect(),
            events: events.iter().map(Event::to_raw).collect(),
        };
        let scope = match dev.class {
            Class::MemberEditor => EventScope::Member(FOLDER),
            _ => EventScope::Full,
        };
        self.view.apply_scoped(&b, &scope);
        self.heads.insert(dev.id, dev.batch_seq);
        dev.batch_seq
    }

    fn finish(&mut self, d: usize, sink: Sink) -> Vec<u64> {
        self.lamport = self.lamport.max(sink.lamport);
        sink.batches
            .into_iter()
            .map(|evs| self.batch(d, evs))
            .collect()
    }

    fn sink(&self) -> Sink {
        Sink {
            lamport: self.lamport,
            batches: Vec::new(),
            fail: false,
        }
    }

    /// Device `d` pulls the ledger: its next batches acknowledge it.
    fn pull_ledger(&mut self, d: usize) {
        let me = self.id(d);
        self.devs[d].known = self
            .heads
            .iter()
            .filter(|(k, _)| **k != me)
            .map(|(k, v)| (*k, *v))
            .collect();
    }

    /// Device `d` pulls map records and manifests (not the ledger).
    fn pull_records(&mut self, d: usize) -> RecordsRefused {
        self.pull_records_with(d, false)
    }

    fn pull_records_with(&mut self, d: usize, permissive: bool) -> RecordsRefused {
        let World {
            devs,
            view,
            devices,
            revoked,
            folders,
            keys,
            meta,
            ..
        } = self;
        let trust = TestTrust {
            inner: Trust {
                devices,
                revoked,
                folders: Some(folders),
                members: None,
            },
            view,
            permissive,
        };
        let store = RecordStore {
            storage: &**meta,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &*keys,
                trust: &trust,
            },
        };
        let mut refused = RecordsRefused::default();
        let dev = &mut devs[d];
        let r = blockmap::pull(&mut dev.table, &store, view, &mut refused).unwrap();
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        let mr = dev
            .manifests
            .pull(&store, view, &[0; 16], &mut refused)
            .unwrap();
        assert!(mr.refused.is_empty(), "{:?}", mr.refused);
        refused
    }

    /// Pull everything and acknowledge it in a batch.
    fn sync(&mut self, d: usize) {
        self.pull_records(d);
        self.pull_ledger(d);
        self.batch(d, Vec::new());
    }

    fn block(&mut self, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        self.rng.fill_bytes(&mut b);
        b
    }

    /// Publish device `d`'s manifest of its current files; returns the
    /// `record_published` event.
    fn manifest_event(&mut self, d: usize) -> Option<Event> {
        self.lamport += 1;
        let lamport = self.lamport;
        let now = self.now;
        let World {
            devs, keys, meta, ..
        } = self;
        let dev = &mut devs[d];
        let signer = DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &*keys,
        };
        let p = dev
            .mw
            .seal(
                &rw,
                &KeyId::Meta {
                    folder: FOLDER,
                    epoch: 0,
                },
                &dev.files,
                lamport,
                now,
            )
            .unwrap()?;
        RecordWriter::publish(&**meta, &p.sealed).unwrap();
        let a = p.sealed.published.clone();
        dev.mw.commit(p);
        Some(Event::RecordPublished(Announcement {
            kind: a.kind,
            scope: a.scope,
            seq: a.seq,
            base: a.base,
            parts: a.parts,
            body_hash: a.body_hash,
            size: a.size,
        }))
    }

    /// Device `d` adds files (path, blocks) and pushes them to every target
    /// set: blocks the map shows live on a target are not written again
    /// (`blockmap::needs_write`), the others go into new packs; one map
    /// delta, the manifest, one batch.
    fn push(
        &mut self,
        d: usize,
        files: &[(&str, &[Vec<u8>])],
        sets: &[Vec<String>],
    ) -> Vec<WrittenPack> {
        let mut to_write: BTreeMap<Vec<String>, Vec<(MapRow, Vec<u8>)>> = BTreeMap::new();
        for (path, blocks) in files {
            let mut chunks = Vec::new();
            for b in blocks.iter() {
                let object = crate::crypto::hash(b);
                let chunk = crate::crypto::hash(&[b"chunk".as_slice(), b].concat());
                chunks.push(Chunk3 {
                    chunk,
                    object,
                    size: b.len() as u64 - 41,
                    epoch: 0,
                });
                for set in sets {
                    let dd = blockmap::needs_write(&self.devs[d].table, &self.view, &chunk, 0, set)
                        .unwrap();
                    if dd.skip() {
                        continue;
                    }
                    let row = MapRow {
                        object,
                        chunk,
                        place: Place {
                            pack: [0; 32],
                            offset: 0,
                            len: b.len() as u32,
                        },
                        class: 0,
                        plain_len: b.len() as u32 - 41,
                        epoch: 0,
                        flags: 0,
                        writer: self.id(d),
                    };
                    to_write
                        .entry(dd.missing)
                        .or_default()
                        .push((row, b.clone()));
                }
            }
            let dev = &mut self.devs[d];
            let n = dev.files.get(*path).map_or(1, |f| f.modified_clock + 1);
            dev.files.insert(
                path.to_string(),
                FileEntry {
                    path: path.to_string(),
                    version: BTreeMap::from([(dev.id, n)]),
                    deleted: false,
                    size: blocks.iter().map(|b| b.len() as u64 - 41).sum(),
                    mtime: 0,
                    content_hash: Some(crate::crypto::hash(path.as_bytes())),
                    chunks,
                    modified_by: dev.id,
                    modified_clock: n,
                    meta: None,
                    chunking: 2,
                    held: true,
                },
            );
        }
        let mut written = Vec::new();
        for (to, items) in &to_write {
            let target = if to.iter().any(|s| s == C) {
                crate::packs::COLD_TARGET
            } else {
                crate::packs::HOT_TARGET
            };
            let refs: Vec<(MapRow, &[u8])> = items.iter().map(|(r, b)| (*r, &b[..])).collect();
            written.extend(super::collect::write_packs(&refs, to, target, &self.set).unwrap());
        }
        let mut events = Vec::new();
        if !written.is_empty() {
            self.lamport += 1;
            let lamport = self.lamport;
            let World {
                devs,
                keys,
                meta,
                view,
                ..
            } = self;
            let dev = &mut devs[d];
            let signer = DeviceSigner {
                device: dev.id,
                key: &dev.sk,
            };
            let rw = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &*keys,
            };
            let p = dev
                .map
                .publish(
                    &rw,
                    &[&**meta as &dyn Storage],
                    &written,
                    lamport,
                    Some(&dev.table),
                    view,
                )
                .unwrap();
            p.apply_to(&mut dev.table, &|_| true).unwrap();
            events.extend(p.events);
        }
        events.extend(self.manifest_event(d));
        self.batch(d, events);
        self.pull_records(d);
        written
    }

    /// Device `d` deletes a file (its manifest names no block of it).
    fn delete(&mut self, d: usize, path: &str) {
        let f = self.devs[d].files.get_mut(path).unwrap();
        f.deleted = true;
        f.chunks.clear();
        f.content_hash = None;
        f.modified_clock += 1;
        let ev = self.manifest_event(d).into_iter().collect();
        self.batch(d, ev);
        self.pull_records(d);
    }

    fn mark(&mut self, d: usize) -> MarkReport {
        let writers = self.writers();
        let mut sink = self.sink();
        let r = {
            let World {
                devs,
                keys,
                meta,
                view,
                ..
            } = &mut *self;
            let dev = &mut devs[d];
            let signer = DeviceSigner {
                device: dev.id,
                key: &dev.sk,
            };
            let rw = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &*keys,
            };
            let metas = [&**meta as &dyn Storage];
            let out = MapOut {
                writer: &rw,
                meta: &metas,
            };
            let standing = dev.standing();
            mark_round(
                &standing,
                &mut dev.map,
                &mut dev.table,
                view,
                &out,
                &dev.manifests,
                &writers,
                &mut sink,
            )
            .unwrap()
        };
        self.finish(d, sink);
        r
    }

    fn collect_with(&mut self, d: usize, opts: GcOptions) -> GcReport {
        let writers = self.writers();
        let mut sink = self.sink();
        let r = {
            let World {
                devs,
                keys,
                meta,
                view,
                set,
                ..
            } = &mut *self;
            let dev = &mut devs[d];
            let signer = DeviceSigner {
                device: dev.id,
                key: &dev.sk,
            };
            let rw = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &*keys,
            };
            let metas = [&**meta as &dyn Storage];
            let out = MapOut {
                writer: &rw,
                meta: &metas,
            };
            let standing = dev.standing();
            collect(
                &standing,
                &mut dev.map,
                &mut dev.table,
                view,
                &out,
                &*set,
                &dev.manifests,
                &writers,
                &mut sink,
                &opts,
            )
            .unwrap()
        };
        self.finish(d, sink);
        r
    }

    fn collect(&mut self, d: usize) -> GcReport {
        let opts = GcOptions {
            now_utc: self.now,
            ..GcOptions::default()
        };
        self.collect_with(d, opts)
    }

    fn has_pack(&self, storage: &str, pack: &PackId) -> bool {
        self.storage(storage)
            .exists(&crate::packs::pack_key(&hex::encode(pack)))
            .unwrap()
    }

    /// A device that joins now: a fresh table pulled from the storages.
    fn fresh_reader(&mut self, name: &str) -> MapTable {
        let mut t = MapTable::open(&table_path(&self.root.join(name), &FOLDER), FOLDER).unwrap();
        let trust = TestTrust {
            inner: Trust {
                devices: &self.devices,
                revoked: &self.revoked,
                folders: Some(&self.folders),
                members: None,
            },
            view: &self.view,
            permissive: false,
        };
        let store = RecordStore {
            storage: &*self.meta,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &self.keys,
                trust: &trust,
            },
        };
        let mut refused = RecordsRefused::default();
        blockmap::pull(&mut t, &store, &self.view, &mut refused).unwrap();
        assert_eq!(refused.total(), 0, "{refused:?}");
        t
    }

    /// Read a block through a table's places (checked against its name).
    fn read(&self, table: &MapTable, block: &[u8]) -> Option<Vec<u8>> {
        let object = crate::crypto::hash(block);
        let set = &self.set;
        blockmap::find_block(table, &self.view, &object, &|n| set.open(n))
            .unwrap()
            .map(|f| f.bytes)
    }

    /// Flip one byte of a pack on a local storage.
    fn flip(&self, storage: &str, pack: &PackId, at: usize) {
        let p = self
            .root
            .join(storage)
            .join(crate::packs::pack_key(&hex::encode(pack)));
        let mut b = std::fs::read(&p).unwrap();
        b[at] ^= 0x40;
        std::fs::write(&p, b).unwrap();
    }
}

fn pack_on<'a>(packs: &'a [WrittenPack], storage: &str) -> &'a WrittenPack {
    packs
        .iter()
        .find(|p| p.storages.iter().any(|s| s == storage))
        .unwrap()
}

fn photo(w: &mut World) -> Vec<Vec<u8>> {
    (0..3).map(|_| w.block(200 << 10)).collect()
}

// ---- the worked example of section 3 ---------------------------------------

#[test]
fn worked_example_a_pushes_deletes_b_marks_a_acks_b_collects() {
    let (a, b) = (0, 1);
    let mut w = World::new(&[Class::Owner, Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot(), cold()]);
    assert_eq!(packs.len(), 2, "P for the hot set, Q for the cold one");
    let p = pack_on(&packs, H1).id;
    let q = pack_on(&packs, C).id;
    assert_eq!(w.view.holders(&p), vec![H1, H2]);
    assert_eq!(w.view.holders(&q), vec![C]);

    // B pulls: six places, and a2 reads from P.
    w.sync(b);
    assert_eq!(w.devs[b].table.rows(), 6);
    assert_eq!(
        w.read(&w.devs[b].table, &blocks[1]),
        Some(blocks[1].clone())
    );
    w.sync(a);

    // A deletes the photo; B finds the blocks unreferenced and marks them.
    w.delete(a, "photo.jpg");
    w.pull_records(b);
    let m = w.mark(b);
    assert_eq!((m.dead, m.undead), (6, 0), "{m:?}");

    // Not settled yet: A has not acknowledged B's batch.
    let r = w.collect(b);
    assert_eq!(r.packs_dropped, 0);
    assert_eq!(r.plan_waiting.get(&w.id(a)), Some(&6), "{r:?}");
    assert!(w.has_pack(H1, &p) && w.has_pack(C, &q));

    // A acknowledges B/77 in A/251; B's settle check passes.
    w.sync(a);
    w.pull_records(b);
    let r = w.collect(b);
    assert_eq!(r.packs_dropped, 1, "{r:?}");
    assert_eq!(r.drops, 2, "pack_dropped on H1 and H2");
    assert!(w.view.holders(&p).is_empty());
    assert!(!w.has_pack(H1, &p) && !w.has_pack(H2, &p));
    // Q waits for C's minimum duration.
    assert_eq!(r.drops_later.len(), 1);
    assert_eq!(r.drops_later[0].1, C);
    assert!(w.has_pack(C, &q));

    w.now += 89 * DAY;
    assert_eq!(w.collect(b).packs_dropped, 0);
    assert!(w.has_pack(C, &q));
    w.now += 2 * DAY;
    let r = w.collect(b);
    assert_eq!(r.packs_dropped, 1, "{r:?}");
    assert!(!w.has_pack(C, &q));
    assert!(w.view.holders(&q).is_empty());
}

#[test]
fn worked_example_d_re_adds_the_photo_before_pulling_the_mark() {
    let (a, b, d) = (0, 1, 2);
    let mut w = World::new(&[Class::Owner, Class::Owner, Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot(), cold()]);
    let p = pack_on(&packs, H1).id;
    let q = pack_on(&packs, C).id;
    for x in [b, d, a] {
        w.sync(x);
    }
    w.delete(a, "photo.jpg");
    w.pull_records(b);
    assert_eq!(w.mark(b).dead, 6);
    let mark_batch = w.devs[b].batch_seq;

    // D re-adds the same photo before pulling B's mark: its push skips
    // every block (live places in its table) and announces its manifest
    // in a batch that does not acknowledge B's.
    let written = w.push(d, &[("copy.jpg", &blocks)], &[hot(), cold()]);
    assert!(written.is_empty(), "D skipped writing the blocks");
    assert!(w.view.acked(&w.id(d), &w.id(b), None) < mark_batch);
    w.sync(a);

    // B has not read D's manifest yet: nothing is collected.
    let r = w.collect(b);
    assert_eq!(r.packs_dropped, 0);
    assert_eq!(r.behind, vec![w.id(d)], "{r:?}");

    // D acknowledges B's batch only now (D/31); B reads D's manifest from
    // D/30 and finds the reference.
    w.sync(d);
    assert!(w.view.acked(&w.id(d), &w.id(b), None) >= mark_batch);
    // Settled now, but B must read what D announced before D/31 first.
    let r = w.collect(b);
    assert_eq!(r.drops, 0, "{r:?}");
    assert_eq!(r.behind, vec![w.id(d)]);
    w.pull_records(b);
    w.now += 365 * DAY;
    let r = w.collect(b);
    assert_eq!(
        (r.packs_dropped, r.packs_rewritten, r.drops),
        (0, 0, 0),
        "{r:?}"
    );
    let m = w.mark(b);
    assert_eq!((m.dead, m.undead), (0, 6), "{m:?}");
    assert_eq!(w.collect(b).drops, 0);
    for s in [H1, H2] {
        assert!(w.has_pack(s, &p));
    }
    assert!(w.has_pack(C, &q));
    // Every reader finds the blocks live again.
    let fresh = w.fresh_reader("late");
    for blk in &blocks {
        assert_eq!(w.read(&fresh, blk).as_ref(), Some(blk));
        let o = crate::crypto::hash(blk);
        for pl in fresh.places_of(&o).unwrap() {
            assert_eq!(fresh.is_marked(&pl).unwrap(), Some(MarkKind::Undead));
        }
    }
}

// ---- who may mark ------------------------------------------------------------

/// Device `d` publishes dead marks on `places` regardless of its role (a
/// hostile device does not run `mark_round`'s check).
fn hostile_marks(w: &mut World, d: usize, places: &[(ObjectBin, Place)], scope: EventScope) {
    w.lamport += 1;
    let lamport = w.lamport;
    let World {
        devs,
        keys,
        meta,
        view,
        ..
    } = &mut *w;
    let dev = &mut devs[d];
    let signer = DeviceSigner {
        device: dev.id,
        key: &dev.sk,
    };
    let rw = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &*keys,
    };
    dev.map.mark_dead(places);
    let p = dev
        .map
        .publish(
            &rw,
            &[&**meta as &dyn Storage],
            &[],
            lamport,
            Some(&dev.table),
            view,
        )
        .unwrap();
    w.lamport += 1;
    let dev = &mut w.devs[d];
    dev.batch_seq += 1;
    let b = Batch {
        device: dev.id,
        seq: dev.batch_seq,
        prev: [0; 32],
        lamport: w.lamport,
        created_utc: w.now,
        seen: Vec::new(),
        events: p.events.iter().map(Event::to_raw).collect(),
    };
    w.view.apply_scoped(&b, &scope);
    w.heads.insert(dev.id, dev.batch_seq);
}

#[test]
fn a_hostile_mark_from_a_viewer_k3_only_device_or_replica_deletes_nothing() {
    let (a, v, k, r) = (0, 1, 2, 3);
    let mut w = World::new(&[Class::Owner, Class::Viewer, Class::K3Only, Class::K3Only]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    let p = packs[0].id;
    for x in [v, k, r] {
        w.sync(x);
    }
    let places: Vec<(ObjectBin, Place)> = packs[0]
        .members
        .iter()
        .map(|m| {
            (
                m.object,
                Place {
                    pack: p,
                    offset: m.offset,
                    len: m.len,
                },
            )
        })
        .collect();

    // Their own marking round refuses.
    assert!(w.mark(v).refused);
    assert!(w.mark(k).refused);
    assert!(w.collect(v).refused);

    hostile_marks(&mut w, v, &places, EventScope::Full);
    hostile_marks(&mut w, k, &places, EventScope::Full);
    // A replica's batch cannot announce a map record at all.
    let refused_before = w.view.events_refused;
    hostile_marks(&mut w, r, &places, EventScope::Replica);
    assert!(w.view.events_refused > refused_before);

    // The owner's reader refuses the viewer's and the K3-only device's map
    // records; the replica's has no announcement and waits for ever.
    let refused = w.pull_records(a);
    assert_eq!(refused.get(Kind::BlockMap), 2, "{refused:?}");
    assert_eq!(w.devs[a].table.mark_count(), 0);

    // Even with the photo deleted and a reader that took the records in,
    // marks of non-writers count for nothing.
    w.delete(a, "photo.jpg");
    let careless = World::pull_into_fresh_permissive(&mut w, "careless");
    let writers = w.writers();
    let plan = plan(
        &careless,
        &w.view,
        &writers,
        &w.devs[a].manifests,
        &w.set,
        &GcOptions::default(),
    )
    .unwrap();
    assert!(careless.mark_count() >= 6);
    assert!(
        plan.drops.is_empty() && plan.rewrites.is_empty(),
        "{plan:?}"
    );
    assert!(plan.marks_ignored >= 6, "{plan:?}");
    let rep = w.collect(a);
    assert_eq!(rep.drops, 0);
    assert!(w.has_pack(H1, &p) && w.has_pack(H2, &p));
}

impl World {
    fn pull_into_fresh_permissive(w: &mut World, name: &str) -> MapTable {
        let mut t = MapTable::open(&table_path(&w.root.join(name), &FOLDER), FOLDER).unwrap();
        let trust = TestTrust {
            inner: Trust {
                devices: &w.devices,
                revoked: &w.revoked,
                folders: Some(&w.folders),
                members: None,
            },
            view: &w.view,
            permissive: true,
        };
        let store = RecordStore {
            storage: &*w.meta,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &w.keys,
                trust: &trust,
            },
        };
        let mut refused = RecordsRefused::default();
        blockmap::pull(&mut t, &store, &w.view, &mut refused).unwrap();
        t
    }
}

#[test]
fn a_member_that_never_acknowledges_blocks_collection_and_is_named() {
    let (a, m) = (0, 1);
    let mut w = World::new(&[Class::Owner, Class::MemberEditor]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    w.sync(m);
    w.sync(a);
    w.delete(a, "photo.jpg");
    assert_eq!(w.mark(a).dead, 3);
    // Members do not collect.
    assert!(w.collect(m).refused);
    for _ in 0..3 {
        w.now += 30 * DAY;
        let r = w.collect(a);
        assert_eq!(r.drops, 0);
        assert_eq!(r.plan_waiting, BTreeMap::from([(w.id(m), 3)]), "{r:?}");
    }
    assert!(w.has_pack(H1, &packs[0].id));
    // Its folder-scoped batch acknowledges the mark: collection goes on.
    w.sync(m);
    let r = w.collect(a);
    assert_eq!(r.packs_dropped, 1, "{r:?}");
    assert!(!w.has_pack(H1, &packs[0].id));
}

// ---- rewrite, compaction, orphans ---------------------------------------------

#[test]
fn a_hot_pack_more_than_half_dead_is_rewritten_and_a_later_reader_finds_the_rest() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let gone: Vec<Vec<u8>> = (0..3).map(|_| w.block(100 << 10)).collect();
    let kept = vec![w.block(100 << 10)];
    let packs = w.push(a, &[("gone.bin", &gone), ("kept.bin", &kept)], &[hot()]);
    assert_eq!(packs.len(), 1);
    let old = packs[0].id;
    w.delete(a, "gone.bin");
    assert_eq!(w.mark(a).dead, 3);
    let r = w.collect(a);
    assert_eq!(
        (r.packs_rewritten, r.blocks_moved, r.packs_written),
        (1, 1, 1),
        "{r:?}"
    );
    assert!(!w.has_pack(H1, &old) && !w.has_pack(H2, &old));
    assert!(w.view.holders(&old).is_empty());
    let fresh = w.fresh_reader("later");
    assert_eq!(w.read(&fresh, &kept[0]).as_ref(), Some(&kept[0]));
    let place = fresh.places_of(&crate::crypto::hash(&kept[0])).unwrap();
    assert!(place
        .iter()
        .any(|p| p.pack != old && w.view.holders(&p.pack) == vec![H1, H2]));
    for g in &gone {
        assert_eq!(w.read(&fresh, g), None);
    }
}

#[test]
fn a_cold_pack_is_never_rewritten() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let gone: Vec<Vec<u8>> = (0..3).map(|_| w.block(100 << 10)).collect();
    let kept = vec![w.block(100 << 10)];
    let packs = w.push(a, &[("gone.bin", &gone), ("kept.bin", &kept)], &[cold()]);
    w.delete(a, "gone.bin");
    w.mark(a);
    w.now += 400 * DAY;
    let r = w.collect(a);
    assert_eq!((r.packs_rewritten, r.drops), (0, 0), "{r:?}");
    assert!(w.has_pack(C, &packs[0].id));
}

#[test]
fn compaction_merges_small_hot_packs() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let mut all = Vec::new();
    let mut olds = Vec::new();
    for i in 0..5 {
        let b = vec![w.block(220 << 10)];
        let p = w.push(a, &[(format!("f{i}").as_str(), &b)], &[hot()]);
        assert_eq!(p[0].class, 0, "a 256 KiB pack");
        olds.push(p[0].id);
        all.push(b[0].clone());
    }
    let opts = GcOptions {
        now_utc: w.now,
        compact_bytes: 1 << 20,
        ..GcOptions::default()
    };
    let r = w.collect_with(a, opts);
    assert_eq!(
        (r.packs_compacted, r.packs_written, r.blocks_moved),
        (5, 1, 5),
        "{r:?}"
    );
    for o in &olds {
        assert!(!w.has_pack(H1, o) && !w.has_pack(H2, o));
    }
    let fresh = w.fresh_reader("later");
    for b in &all {
        assert_eq!(w.read(&fresh, b).as_ref(), Some(b));
    }
    // With the design's 64 MiB, 1.1 MiB of small packs stay as they are.
    let r = w.collect(a);
    assert_eq!(r.packs_compacted, 0);
}

#[test]
fn a_failed_batch_deletes_nothing() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    w.delete(a, "photo.jpg");
    w.mark(a);
    let writers = w.writers();
    let mut sink = w.sink();
    sink.fail = true;
    let World {
        devs,
        keys,
        meta,
        view,
        set,
        ..
    } = &mut w;
    let dev = &mut devs[a];
    let signer = DeviceSigner {
        device: dev.id,
        key: &dev.sk,
    };
    let rw = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &*keys,
    };
    let metas = [&**meta as &dyn Storage];
    let out = MapOut {
        writer: &rw,
        meta: &metas,
    };
    let standing = dev.standing();
    let res = collect(
        &standing,
        &mut dev.map,
        &mut dev.table,
        view,
        &out,
        &*set,
        &dev.manifests,
        &writers,
        &mut sink,
        &GcOptions::default(),
    );
    assert!(res.is_err());
    assert!(w.has_pack(H1, &packs[0].id) && w.has_pack(H2, &packs[0].id));
}

#[test]
fn an_orphan_pack_goes_after_seven_days_and_a_dropped_leftover_at_once() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    // A crash before the batch: a pack nobody claims.
    let refs: Vec<(MapRow, Vec<u8>)> = {
        let b = w.block(50 << 10);
        vec![(
            MapRow {
                object: crate::crypto::hash(&b),
                chunk: [1; 32],
                place: Place {
                    pack: [0; 32],
                    offset: 0,
                    len: b.len() as u32,
                },
                class: 0,
                plain_len: 10,
                epoch: 0,
                flags: 0,
                writer: w.id(a),
            },
            b,
        )]
    };
    let r2: Vec<(MapRow, &[u8])> = refs.iter().map(|(r, b)| (*r, &b[..])).collect();
    let orphan =
        super::collect::write_packs(&r2, &[H1.to_string()], crate::packs::HOT_TARGET, &w.set)
            .unwrap()[0]
            .id;
    // A drop sealed but the delete never happened.
    let kept = packs[0].id;
    w.batch(
        a,
        vec![Event::PackDropped(PackOn {
            storage: H2.into(),
            pack: kept,
        })],
    );
    let standing = w.devs[a].standing();
    let mut state = OrphanState::default();
    let names = w.set.names();
    let run = |w: &World, state: &mut OrphanState| {
        let opts = GcOptions {
            now_utc: w.now,
            ..GcOptions::default()
        };
        collect_orphans(
            &standing,
            &w.set,
            &names,
            &w.view,
            &[&w.devs[a].table],
            state,
            &opts,
        )
        .unwrap()
    };
    let r = run(&w, &mut state);
    assert_eq!(
        (r.orphans_deleted, r.leftovers_deleted, r.orphans_waiting),
        (0, 1, 1),
        "{r:?}"
    );
    assert!(!w.has_pack(H2, &kept) && w.has_pack(H1, &kept));
    w.now += 6 * DAY;
    assert_eq!(run(&w, &mut state).orphans_deleted, 0);
    assert!(w.has_pack(H1, &orphan));
    w.now += DAY;
    assert_eq!(run(&w, &mut state).orphans_deleted, 1);
    assert!(!w.has_pack(H1, &orphan));
    assert!(w.has_pack(H1, &kept), "a claimed pack stays");
}

// ---- verification and repair -------------------------------------------------

#[test]
fn verification_finds_a_flipped_byte_and_repair_takes_the_member_from_another_storage() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    let p = &packs[0];
    let m1 = p.members[1];
    w.flip(H1, &p.id, m1.offset as usize + 7);

    let good = verify_pack(&*w.storage(H2), &p.id, p.class).unwrap();
    assert_eq!(good.check, PackCheck::Good);
    assert!(matches!(good.event, Some(Event::PackVerified(_))));
    let bad = verify_pack(&*w.storage(H1), &p.id, p.class).unwrap();
    assert_eq!(bad.check, PackCheck::Mismatch);
    assert!(bad.event.is_none());

    let mut sink = w.sink();
    let rep = {
        let World {
            devs,
            keys,
            meta,
            view,
            set,
            ..
        } = &mut w;
        let dev = &mut devs[a];
        let signer = DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &*keys,
        };
        let metas = [&**meta as &dyn Storage];
        let out = MapOut {
            writer: &rw,
            meta: &metas,
        };
        let standing = dev.standing();
        let snapshot = MapTable::open(dev.table.path(), FOLDER).unwrap();
        let fetch = other_places(&snapshot, view, &*set, p.id);
        repair_pack(
            &standing,
            &mut dev.map,
            &mut dev.table,
            view,
            &out,
            &*set,
            H1,
            &p.id,
            bad.damaged.as_deref().unwrap(),
            &fetch,
            &mut sink,
        )
        .unwrap()
    };
    w.finish(a, sink);
    assert_eq!(rep.good, 2);
    assert_eq!(rep.from_same_place, vec![m1.object]);
    assert!(rep.lost.is_empty() && rep.from_elsewhere.is_empty());
    assert_eq!(rep.new_packs.len(), 1);
    assert_eq!(w.view.holders(&p.id), vec![H2]);
    assert!(!w.has_pack(H1, &p.id));
    assert_eq!(w.view.holders(&rep.new_packs[0]), vec![H1]);
    let fresh = w.fresh_reader("later");
    for b in &blocks {
        assert_eq!(w.read(&fresh, b).as_ref(), Some(b));
    }
    // No lost mark: H2's copy of the place is good.
    assert_eq!(fresh.mark_count(), 0);
    // Verification of the new pack passes.
    let class = w.view.pack(&rep.new_packs[0]).unwrap().class;
    assert_eq!(
        verify_pack(&*w.storage(H1), &rep.new_packs[0], class)
            .unwrap()
            .check,
        PackCheck::Good
    );
}

fn repair_on(
    w: &mut World,
    d: usize,
    storage: &str,
    pack: &PackId,
    fetch: &dyn Fn(&MapRow) -> Option<Vec<u8>>,
) -> RepairReport {
    let class = w.view.pack(pack).unwrap().class;
    let bad = verify_pack(&*w.storage(storage), pack, class).unwrap();
    assert_eq!(bad.check, PackCheck::Mismatch);
    let mut sink = w.sink();
    let rep = {
        let World {
            devs,
            keys,
            meta,
            view,
            set,
            ..
        } = &mut *w;
        let dev = &mut devs[d];
        let signer = DeviceSigner {
            device: dev.id,
            key: &dev.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &*keys,
        };
        let metas = [&**meta as &dyn Storage];
        let out = MapOut {
            writer: &rw,
            meta: &metas,
        };
        let standing = dev.standing();
        repair_pack(
            &standing,
            &mut dev.map,
            &mut dev.table,
            view,
            &out,
            &*set,
            storage,
            pack,
            bad.damaged.as_deref().unwrap(),
            fetch,
            &mut sink,
        )
        .unwrap()
    };
    w.finish(d, sink);
    rep
}

#[test]
fn a_member_with_no_good_copy_is_marked_lost_and_reported() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let blocks = photo(&mut w);
    // Only on the cold storage: repair writes there anyway.
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[cold()]);
    let p = packs[0].clone();
    w.flip(C, &p.id, p.members[2].offset as usize + 1);
    let rep = repair_on(&mut w, a, C, &p.id, &|_| None);
    assert_eq!(rep.good, 2);
    assert_eq!(rep.lost, vec![p.members[2].object]);
    assert_eq!(rep.new_packs.len(), 1);
    assert!(!w.has_pack(C, &p.id));
    let fresh = w.fresh_reader("later");
    let lost_place = Place {
        pack: p.id,
        offset: p.members[2].offset,
        len: p.members[2].len,
    };
    assert_eq!(fresh.is_marked(&lost_place).unwrap(), Some(MarkKind::Lost));
    assert_eq!(w.read(&fresh, &blocks[2]), None, "the file is damaged");
    assert_eq!(w.read(&fresh, &blocks[0]).as_ref(), Some(&blocks[0]));
}

#[test]
fn a_corrupt_member_is_taken_from_the_local_file_when_no_storage_has_it() {
    let a = 0;
    let mut w = World::new(&[Class::Owner]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[vec![H1.to_string()]]);
    let p = packs[0].clone();
    w.flip(H1, &p.id, p.members[0].offset as usize + 3);
    let local = blocks.clone();
    let rep = repair_on(&mut w, a, H1, &p.id, &move |row: &MapRow| {
        local
            .iter()
            .find(|b| crate::crypto::hash(b) == row.object)
            .cloned()
    });
    assert_eq!(rep.from_elsewhere, vec![p.members[0].object]);
    assert!(rep.lost.is_empty());
    let fresh = w.fresh_reader("later");
    for b in &blocks {
        assert_eq!(w.read(&fresh, b).as_ref(), Some(b));
    }
}

#[test]
fn a_k3_only_device_verifies_and_copies_packs_without_keys() {
    let (a, k) = (0, 1);
    let mut w = World::new(&[Class::Owner, Class::K3Only]);
    let blocks = photo(&mut w);
    let packs = w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    let p = packs[0].id;
    w.sync(k);
    // Everything K uses: the storages and the pack-level view.
    let class = w.view.pack(&p).unwrap().class;
    let v = verify_pack(&*w.storage(H1), &p, class).unwrap();
    assert_eq!(v.check, PackCheck::Good);
    w.batch(k, v.event.into_iter().collect());
    let copies = w.view.copies(&p);
    let h1 = copies.iter().find(|c| c.storage == H1).unwrap();
    assert!(h1.verified_by.contains(&w.id(k)) && h1.independently_verified);

    // The pack is lost on H2 (the object deleted by the storage): K copies
    // it whole from H1 under the same id.
    w.storage(H2)
        .delete(&crate::packs::pack_key(&hex::encode(p)))
        .unwrap();
    assert_eq!(
        verify_pack(&*w.storage(H2), &p, class).unwrap().check,
        PackCheck::Missing
    );
    let ev = copy_missing_pack(&w.view, &p, H2, &w.set, false)
        .unwrap()
        .unwrap();
    let Event::PackStored(ps) = &ev else { panic!() };
    assert_eq!((ps.pack, ps.storage.as_str(), ps.folder), (p, H2, FOLDER));
    w.batch(k, vec![ev]);
    assert_eq!(
        verify_pack(&*w.storage(H2), &p, class).unwrap().check,
        PackCheck::Good
    );
    // K may not repair (it writes no maps).
    let st = w.devs[k].standing();
    assert!(!st.may_repair() && !st.may_collect() && !st.may_mark());
}

// ---- pruning -----------------------------------------------------------------

#[test]
fn map_pruning_waits_for_every_reader() {
    let (a, b, v) = (0, 1, 2);
    let mut w = World::new(&[Class::Owner, Class::Editor, Class::Viewer]);
    for i in 0..3 {
        let blk = vec![w.block(10 << 10)];
        w.push(a, &[(format!("f{i}").as_str(), &blk)], &[hot()]);
    }
    let me = w.id(a);
    let st = w.view.stream(Kind::BlockMap.code(), &FOLDER, &me).unwrap();
    let base = st.base().unwrap().0;
    assert!(
        base > 1,
        "a later base: {:?}",
        st.records.keys().collect::<Vec<_>>()
    );
    // A copy of the records on the cold storage: never pruned.
    let prefix = format!("maps/{}/{}/", hex::encode(FOLDER), hex::encode(me));
    let names = w.meta.list(&prefix).unwrap();
    for n in &names {
        w.storage(C)
            .put_if_absent(n, &w.meta.get(n).unwrap().unwrap())
            .unwrap();
    }
    let readers = w.readers();
    assert_eq!(readers.len(), 3);
    let mut state = PruneState::default();
    let cold_s = w.storage(C);
    let meta = w.meta.clone();
    let stores: [(&dyn Storage, bool); 2] = [(&*meta, false), (&*cold_s, true)];
    let r = prune_map(&stores, &w.view, &FOLDER, &me, &readers, &mut state).unwrap();
    assert_eq!(r.deleted, 0);
    assert_eq!(r.waiting.len(), 2);
    w.sync(b);
    let r = prune_map(&stores, &w.view, &FOLDER, &me, &readers, &mut state).unwrap();
    assert_eq!((r.deleted, r.waiting.clone()), (0, vec![w.id(v)]));
    w.sync(v);
    let r = prune_map(&stores, &w.view, &FOLDER, &me, &readers, &mut state).unwrap();
    assert!(r.deleted > 0 && r.waiting.is_empty(), "{r:?}");
    let left = w.meta.list(&prefix).unwrap();
    assert!(left
        .iter()
        .all(|n| crate::record::RecordName::parse_as(Kind::BlockMap, n)
            .is_some_and(|x| x.seq >= base)));
    assert_eq!(
        w.storage(C).list(&prefix).unwrap(),
        names,
        "cold is never pruned"
    );
    // A reader that joins now reads the base and its deltas.
    let fresh = w.fresh_reader("late");
    assert_eq!(fresh.rows(), 3);
}

// ---- the race (design test 7), random schedules --------------------------------

#[test]
fn no_referenced_block_is_ever_collected_in_random_schedules() {
    let mut drops = 0;
    for seed in 0..10u64 {
        drops += random_schedule(seed);
    }
    assert!(drops > 0, "the schedules collected something");
}

fn random_schedule(seed: u64) -> u64 {
    let mut drops = 0;
    let mut rng = StdRng::seed_from_u64(seed);
    let n = 4;
    let mut w = World::new(&[Class::Owner, Class::Owner, Class::Editor, Class::Owner]);
    w.rng = StdRng::seed_from_u64(seed + 100);
    // A small pool of contents, re-added and deleted by random devices.
    let pool: Vec<Vec<Vec<u8>>> = (0..4)
        .map(|_| (0..2).map(|_| w.block(20 << 10)).collect())
        .collect();
    for step in 0..60 {
        let d = rng.gen_range(0..n);
        match rng.gen_range(0..7) {
            0 => {
                let c = rng.gen_range(0..pool.len());
                let path = format!("p{c}-{d}");
                w.push(d, &[(path.as_str(), &pool[c])], &[hot()]);
            }
            1 => {
                let live: Vec<String> = w.devs[d]
                    .files
                    .iter()
                    .filter(|(_, f)| !f.deleted)
                    .map(|(p, _)| p.clone())
                    .collect();
                if !live.is_empty() {
                    let p = live[rng.gen_range(0..live.len())].clone();
                    w.delete(d, &p);
                }
            }
            2 => {
                w.pull_records(d);
            }
            3 => {
                // An acknowledgement always follows a pull of the records
                // it acknowledges (the engine applies both in one pull).
                w.sync(d);
            }
            4 => {
                w.mark(d);
            }
            _ => {
                w.now += DAY;
                // Only collection deletes: check after each run.
                let r = w.collect(d);
                drops += r.drops;
                if r.drops > 0 {
                    assert_referenced_readable(&mut w, seed, step);
                }
            }
        }
    }
    // Everyone syncs: every unreferenced block goes within three rounds.
    for _ in 0..3 {
        for d in 0..n {
            w.sync(d);
        }
        for d in 0..n {
            w.mark(d);
        }
        for d in 0..n {
            w.sync(d);
        }
        for d in 0..n {
            drops += w.collect(d).drops;
        }
        assert_referenced_readable(&mut w, seed, 999);
    }
    // What is left of unreferenced blocks is collectable dead space (in
    // packs not dead enough to rewrite).
    for d in 0..n {
        w.sync(d);
    }
    let referenced = referenced_now(&w);
    let writers = w.writers();
    let p = plan(
        &w.devs[0].table,
        &w.view,
        &writers,
        &w.devs[0].manifests,
        &w.set,
        &GcOptions {
            now_utc: w.now,
            ..GcOptions::default()
        },
    )
    .unwrap();
    assert!(
        p.behind.is_empty() && p.waiting.is_empty(),
        "seed {seed}: {p:?}"
    );
    for st in p.packs.values() {
        for (row, v) in &st.members {
            if !referenced.contains(&row.object) {
                assert_eq!(*v, PlaceVerdict::Collectable, "seed {seed}");
            } else {
                assert_ne!(*v, PlaceVerdict::Collectable, "seed {seed}");
            }
        }
    }
    drops
}

/// Objects some device's current files name (the truth, not anyone's view).
fn referenced_now(w: &World) -> BTreeSet<ObjectBin> {
    w.devs
        .iter()
        .flat_map(|d| d.files.values())
        .flat_map(|f| f.objects().copied().collect::<Vec<_>>())
        .collect()
}

fn assert_referenced_readable(w: &mut World, seed: u64, step: usize) {
    let referenced = referenced_now(w);
    let fresh = w.fresh_reader(&format!("check{seed}-{step}"));
    for o in referenced {
        let set = &w.set;
        let found = blockmap::find_block(&fresh, &w.view, &o, &|n| set.open(n)).unwrap();
        assert!(
            found.is_some(),
            "seed {seed} step {step}: a referenced block is gone"
        );
    }
    let _ = std::fs::remove_dir_all(w.root.join(format!("check{seed}-{step}")));
}

#[test]
fn standing_follows_roles() {
    let w = World::new(&[
        Class::Owner,
        Class::Editor,
        Class::Viewer,
        Class::K3Only,
        Class::MemberEditor,
    ]);
    let s: Vec<Standing> = w.devs.iter().map(Dev::standing).collect();
    assert!(s[0].may_collect() && s[1].may_collect());
    assert!(!s[2].may_mark() && !s[3].may_mark());
    assert!(s[4].may_mark() && !s[4].may_collect());
    let writers = w.writers();
    assert_eq!(writers.len(), 3);
    assert!(!writers.contains(&w.id(2)) && !writers.contains(&w.id(3)));
    assert_eq!(w.readers().len(), 4);
}

#[test]
fn wp7_references_count_like_the_manifests_and_wait_for_unread_writers() {
    let (a, b) = (0, 1);
    let mut w = World::new(&[Class::Owner, Class::Owner]);
    let blocks = photo(&mut w);
    w.push(a, &[("photo.jpg", &blocks)], &[hot()]);
    let writers = w.writers();
    let o = crate::crypto::hash(&blocks[0]);
    {
        let refs = crate::trash3::Refs {
            manifests: Some(&w.devs[b].manifests),
            trash: None,
            snapshots: None,
            now: w.now,
        };
        let fr = FolderReferences::new(&refs);
        assert!(!fr.is_referenced(&o), "B has not read A's manifest");
        assert_eq!(fr.behind(&w.view, &FOLDER, &writers), vec![w.id(a)]);
    }
    w.pull_records(b);
    let refs = crate::trash3::Refs {
        manifests: Some(&w.devs[b].manifests),
        trash: None,
        snapshots: None,
        now: w.now,
    };
    let fr = FolderReferences::new(&refs);
    assert!(fr.is_referenced(&o));
    assert!(fr.behind(&w.view, &FOLDER, &writers).is_empty());
}
