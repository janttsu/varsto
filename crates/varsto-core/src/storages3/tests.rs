// SPDX-License-Identifier: PolyForm-Shield-1.0.0
use super::*;
use crate::blockmap::{
    find_block, table_path, BlockMap, MapEntry, MapTable, MapUpdate, Mark, PackRef, WrittenMember,
    WrittenPack,
};
use crate::crypto::{hash, SecretKey};
use crate::ledger3::events::{class_bytes, Event, PackOn, PackStored};
use crate::ledger3::{Batch, DeviceBin, EventScope, FolderBin, LedgerView, ObjectBin, PackId};
use crate::manifest::ChunkRef;
use crate::packs::{self, pack_key};
use crate::policy::{self, Policy, PolicyState};
use crate::pool::{
    set_fake_space, DiskSpace, PoolIdentity, PoolStorage, DATA_DIR, DEFAULT_VERIFY_AFTER_DAYS,
};
use crate::storage::{LocalDirStorage, Storage, StorageSpec};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

const FOLDER: FolderBin = [0x22; 16];
const ME: DeviceBin = [0xa1; 16];
const OTHER: DeviceBin = [0xb2; 16];
const GIB: u64 = 1 << 30;

/// A pack made for a test: its bytes, id and members.
#[derive(Clone)]
struct TestPack {
    id: PackId,
    class: u8,
    bytes: Vec<u8>,
    /// (data, member) per member in order.
    members: Vec<(Vec<u8>, WrittenMember)>,
}

impl TestPack {
    fn written(&self, storages: &[&str]) -> WrittenPack {
        WrittenPack {
            id: self.id,
            class: self.class,
            storages: storages.iter().map(|s| s.to_string()).collect(),
            members: self.members.iter().map(|(_, m)| *m).collect(),
        }
    }
    fn object(&self, i: usize) -> ObjectBin {
        self.members[i].1.object
    }
}

struct Env {
    dir: tempfile::TempDir,
    view: LedgerView,
    table: MapTable,
    lamport: u64,
    batch_seq: HashMap<DeviceBin, u64>,
    /// device -> (last seq, base seq, last hash)
    maps: HashMap<DeviceBin, (u64, u64, [u8; 32])>,
    stores: BTreeMap<String, Arc<LocalDirStorage>>,
    salt: u8,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let table =
            MapTable::open(&table_path(&dir.path().join("state"), &FOLDER), FOLDER).unwrap();
        Env {
            dir,
            view: LedgerView::default(),
            table,
            lamport: 0,
            batch_seq: HashMap::new(),
            maps: HashMap::new(),
            stores: BTreeMap::new(),
            salt: 0,
        }
    }

    fn store(&mut self, name: &str) -> Arc<LocalDirStorage> {
        let root = self.dir.path().join("stores").join(name);
        let s = Arc::new(LocalDirStorage::new(name.to_string(), root).unwrap());
        self.stores.insert(name.to_string(), s.clone());
        s
    }

    fn batch(&mut self, dev: DeviceBin, events: Vec<Event>, scope: &EventScope) {
        self.lamport += 1;
        let seq = self.batch_seq.entry(dev).or_insert(0);
        *seq += 1;
        let b = Batch {
            device: dev,
            seq: *seq,
            prev: [0; 32],
            lamport: self.lamport,
            created_utc: 1_000 + self.lamport as i64,
            seen: Vec::new(),
            events: events.iter().map(Event::to_raw).collect(),
        };
        self.view.apply_scoped(&b, scope);
    }

    fn apply(&mut self, dev: DeviceBin, events: Vec<Event>) {
        self.batch(dev, events, &EventScope::Full);
    }

    /// A pack of members with `sizes` bytes of distinct random data.
    fn make_pack(&mut self, sizes: &[usize]) -> TestPack {
        let data: Vec<Vec<u8>> = sizes
            .iter()
            .map(|n| {
                self.salt = self.salt.wrapping_add(1);
                let mut d = vec![0u8; *n];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut d);
                d[0] = self.salt;
                d
            })
            .collect();
        self.pack_of(data)
    }

    fn pack_of(&self, data: Vec<Vec<u8>>) -> TestPack {
        let named: Vec<(String, &[u8])> = data
            .iter()
            .map(|d| (hex::encode(hash(d)), d.as_slice()))
            .collect();
        let (id_hex, bytes, locs) = packs::build(&named, packs::HOT_TARGET);
        let mut id = [0u8; 32];
        hex::decode_to_slice(&id_hex, &mut id).unwrap();
        let class = crate::blockmap::class_of_len(bytes.len() as u64).unwrap();
        let members = data
            .into_iter()
            .zip(locs)
            .map(|(d, (_, loc))| {
                let object = hash(&d);
                let m = WrittenMember {
                    object,
                    chunk: hash(&[d.as_slice(), b"chunk"].concat()),
                    offset: loc.offset as u32,
                    len: loc.len as u32,
                    plain_len: (loc.len as u32).saturating_sub(41),
                    epoch: 0,
                };
                (d, m)
            })
            .collect();
        TestPack {
            id,
            class,
            bytes,
            members,
        }
    }

    fn write(&self, store: &dyn Storage, p: &TestPack) {
        assert!(store
            .put_if_absent(&pack_key(&hex::encode(p.id)), &p.bytes)
            .unwrap());
    }

    /// `dev` claims the pack on `storage` as its writer (folder, map seq).
    fn claim(&mut self, dev: DeviceBin, storage: &str, p: &TestPack, map_seq: u64) {
        self.apply(
            dev,
            vec![Event::PackStored(PackStored {
                storage: storage.to_string(),
                pack: p.id,
                class: p.class,
                folder: FOLDER,
                map_seq,
            })],
        );
    }

    fn verify(&mut self, dev: DeviceBin, storage: &str, p: &TestPack) {
        self.apply(
            dev,
            vec![Event::PackVerified(PackOn {
                storage: storage.to_string(),
                pack: p.id,
            })],
        );
    }

    /// Write a map record of `dev` for these packs and marks, and apply it
    /// to the table (the first record of a device is a base, later ones
    /// deltas). Returns its seq.
    fn publish_map(&mut self, dev: DeviceBin, packs: &[WrittenPack], marks: Vec<Mark>) -> u64 {
        let (last, base, prev) = self.maps.get(&dev).copied().unwrap_or((0, 0, [0; 32]));
        let seq = last + 1;
        let base_seq = if base == 0 { seq } else { base };
        let mut refs = Vec::new();
        let mut entries = Vec::new();
        for (i, p) in packs.iter().enumerate() {
            refs.push(PackRef {
                id: p.id,
                class: p.class,
            });
            for m in &p.members {
                entries.push(MapEntry {
                    object: m.object,
                    chunk: m.chunk,
                    pack: i as u32,
                    offset: m.offset,
                    len: m.len,
                    plain_len: m.plain_len,
                    epoch: m.epoch,
                    flags: 0,
                });
            }
        }
        let body = BlockMap {
            folder: FOLDER,
            device: dev,
            seq,
            lamport: self.lamport + seq,
            base: base_seq,
            prev: if seq == 1 { [0; 32] } else { prev },
            packs: refs,
            entries,
            marks,
        };
        let h = hash(&[dev.as_slice(), &seq.to_le_bytes()].concat());
        let r = self
            .table
            .apply(
                vec![MapUpdate {
                    device: dev,
                    records: vec![(body, h)],
                }],
                &|_| true,
            )
            .unwrap();
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        self.maps.insert(dev, (seq, base_seq, h));
        seq
    }

    /// The batch of a mover after a run: claims for the new packs (as
    /// `MapWriter::events` makes them) and the run's own events.
    fn finish_run(&mut self, dev: DeviceBin, run: &MoveRun) {
        let seq = self.publish_map(dev, &run.new_packs, Vec::new());
        let mut events = Vec::new();
        for p in &run.new_packs {
            for s in &p.storages {
                events.push(Event::PackStored(PackStored {
                    storage: s.clone(),
                    pack: p.id,
                    class: p.class,
                    folder: FOLDER,
                    map_seq: seq,
                }));
            }
        }
        events.extend(run.events.clone());
        self.apply(dev, events);
    }

    fn copies(&self, object: &ObjectBin) -> BTreeSet<String> {
        block_copies(&self.view, &self.table, object)
    }

    fn lookup(&self) -> impl Fn(&str) -> Option<Arc<dyn Storage>> + '_ {
        |n| self.stores.get(n).map(|s| s.clone() as Arc<dyn Storage>)
    }

    /// A pack written to `storages` and claimed there with its map record.
    fn publish_pack(&mut self, sizes: &[usize], storages: &[&str]) -> TestPack {
        let p = self.make_pack(sizes);
        let seq = self.publish_map(ME, &[p.written(storages)], Vec::new());
        for s in storages {
            let store = self.stores[*s].clone();
            self.write(&*store, &p);
            self.claim(ME, s, &p, seq);
        }
        p
    }
}

fn pool_spec(name: &str, scan: &Path, copies: u32) -> StorageSpec {
    StorageSpec::Pool {
        name: name.into(),
        place: "home".into(),
        reserve_percent: 5,
        min_reserve_bytes: 1,
        disks: vec![],
        scan_roots: vec![scan.to_path_buf()],
        copies,
        verify_after_days: DEFAULT_VERIFY_AFTER_DAYS,
    }
}

fn identity() -> PoolIdentity {
    PoolIdentity {
        pool_id: "p".into(),
        vault_tag: "t".into(),
        marker_key: SecretKey::from_bytes(&[7u8; 32]).unwrap(),
    }
}

fn fake_space(mount: &Path) {
    set_fake_space(
        mount,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
}

fn hex_id(id: &PackId) -> String {
    hex::encode(id)
}

// ---- replicas ----------------------------------------------------------------

#[test]
fn replica_copies_packs_and_claims_them_without_keys() {
    let mut env = Env::new();
    let src = env.store("source");
    let tgt = env.store("replica-disk");
    let good = env.make_pack(&[1000, 2000]);
    env.write(&*src, &good);
    // Records are copied as they are, never opened.
    src.put_if_absent("maps/f/d/0000000000000001-0000.rec", b"opaque record")
        .unwrap();
    src.put_if_absent(
        "manifests/f/d/0000000000000001-0000.rec",
        b"opaque manifest",
    )
    .unwrap();
    // A pack whose bytes do not hash to its id, a pack that is no size
    // class, format-2 leftovers and a name under packs/ that is no pack.
    let flipped = env.make_pack(&[500]);
    let wrong_id = hex_id(&hash(b"another name"));
    src.put_if_absent(&pack_key(&wrong_id), &flipped.bytes)
        .unwrap();
    let odd = vec![7u8; 1234];
    src.put_if_absent(&pack_key(&hex::encode(hash(&odd))), &odd)
        .unwrap();
    src.put_if_absent("chunks/ab/abcdef", b"x").unwrap();
    src.put_if_absent("packs/ab/not-a-pack", b"x").unwrap();

    let round = replicate(&*src, &*tgt, "replica:r", &|_| false).unwrap();
    let r = &round.report;
    assert_eq!(r.packs_copied, 1, "{r:?}");
    assert_eq!(r.records_copied, 2, "{r:?}");
    assert_eq!(
        (r.packs_corrupt, r.packs_refused, r.skipped_junk),
        (1, 1, 2)
    );
    assert_eq!(r.packs_claimed, 1);
    assert_eq!(
        tgt.get(&pack_key(&hex_id(&good.id))).unwrap().unwrap(),
        good.bytes
    );
    assert!(tgt.exists("maps/f/d/0000000000000001-0000.rec").unwrap());
    assert!(!tgt.exists(&pack_key(&wrong_id)).unwrap());
    assert!(!tgt.exists("chunks/ab/abcdef").unwrap());
    // Claim and verification, zero folder, no map record.
    assert_eq!(
        round.events,
        vec![
            Event::PackStored(PackStored {
                storage: "replica:r".into(),
                pack: good.id,
                class: good.class,
                folder: [0; 16],
                map_seq: 0,
            }),
            Event::PackVerified(PackOn {
                storage: "replica:r".into(),
                pack: good.id,
            }),
        ]
    );
    check_replica_events(&round.events).unwrap();
    // The ledger counts the replica as a copy, verified by itself.
    env.batch(OTHER, round.events.clone(), &EventScope::Replica);
    assert_eq!(env.view.events_refused, 0);
    assert_eq!(env.view.holders(&good.id), vec!["replica:r"]);
    assert!(env.view.copies(&good.id)[0].independently_verified);
    // A second round has nothing to do; an unclaimed pack that is on the
    // target already (a crash before the batch) is claimed without a copy.
    let again = replicate(&*src, &*tgt, "replica:r", &|id| *id == good.id).unwrap();
    assert!(again.events.is_empty(), "{again:?}");
    let late = replicate(&*src, &*tgt, "replica:r", &|_| false).unwrap();
    assert_eq!(late.report.packs_copied, 0);
    assert_eq!(late.report.packs_claimed, 1);
    assert_eq!(late.events.len(), 2);
}

#[test]
fn a_replica_never_writes_maps_marks_or_claims_a_folder() {
    let mut env = Env::new();
    let p = env.make_pack(&[800]);
    let named = |folder: [u8; 16], map_seq: u64| {
        Event::PackStored(PackStored {
            storage: "replica:r".into(),
            pack: p.id,
            class: p.class,
            folder,
            map_seq,
        })
    };
    // The guard refuses what the ledger would ignore anyway.
    assert!(check_replica_events(&[named(FOLDER, 0)]).is_err());
    assert!(check_replica_events(&[named([0; 16], 3)]).is_err());
    assert!(check_replica_events(&[Event::PackDropped(PackOn {
        storage: "replica:r".into(),
        pack: p.id
    })])
    .is_err());
    assert!(check_replica_events(&[Event::RecordPublished(
        crate::ledger3::events::Announcement {
            kind: crate::ledger3::envelope::kind::BLOCK_MAP,
            scope: FOLDER,
            seq: 1,
            base: 1,
            parts: 1,
            body_hash: [1; 32],
            size: 10,
        }
    )])
    .is_err());
    // A replica batch that tries anyway changes nothing in the view.
    env.batch(
        OTHER,
        vec![
            named(FOLDER, 0),
            named([0; 16], 3),
            Event::PackDropped(PackOn {
                storage: "replica:r".into(),
                pack: p.id,
            }),
        ],
        &EventScope::Replica,
    );
    assert_eq!(env.view.events_refused, 3);
    assert!(env.view.holders(&p.id).is_empty());
}

// ---- pools ---------------------------------------------------------------------

#[test]
fn a_pool_disk_lists_packs_from_the_ledger_and_tidies_unknown_ones() {
    let mut env = Env::new();
    let tmp = tempfile::tempdir().unwrap();
    let mounts = tmp.path().join("mounts");
    let a = mounts.join("a");
    fs::create_dir_all(&a).unwrap();
    fake_space(&a);
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let pool = PoolStorage::open(&pool_spec("shelf", &mounts, 1), &home, identity()).unwrap();
    let disk = pool.add_disk_at(&a, "A", "").unwrap();

    // P1 only here, P2 here but dropped by the ledger, P4 also on s3.
    let (p1, p2, p4) = (
        env.make_pack(&[900]),
        env.make_pack(&[900]),
        env.make_pack(&[900]),
    );
    for p in [&p1, &p2, &p4] {
        assert!(pool
            .put_if_absent(&pack_key(&hex_id(&p.id)), &p.bytes)
            .unwrap());
        env.claim(ME, "shelf", p, 1);
    }
    env.claim(ME, "s3", &p4, 1);
    env.apply(
        ME,
        vec![Event::PackDropped(PackOn {
            storage: "shelf".into(),
            pack: p2.id,
        })],
    );
    // Files another device put on the disk: P5 the ledger names (adopted),
    // P3 no claim names (removed).
    let (p3, p5) = (env.make_pack(&[900]), env.make_pack(&[900]));
    env.claim(OTHER, "shelf", &p5, 1);
    for p in [&p3, &p5] {
        let path = a.join(DATA_DIR).join(pack_key(&hex_id(&p.id)));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &p.bytes).unwrap();
    }

    // Only a pack a live claim names is referenced; with a ledger that
    // could not be brought up to date, only a pack it dropped is not.
    let name = |p: &TestPack| hex_id(&p.id);
    let strict = pack_referenced(&env.view, "shelf", true);
    assert!(strict(&name(&p1)) && strict(&name(&p5)) && strict(&name(&p4)));
    assert!(!strict(&name(&p2)) && !strict(&name(&p3)) && !strict("not hex"));
    let lenient = pack_referenced(&env.view, "shelf", false);
    assert!(lenient(&name(&p3)) && !lenient(&name(&p2)));

    let (tidy, events) = tidy_disk_packs(&pool, &disk.id, &env.view, true).unwrap();
    assert_eq!((tidy.unneeded_removed, tidy.adopted), (1, 1), "{tidy:?}");
    assert!(events.is_empty());
    assert!(!a.join(DATA_DIR).join(pack_key(&hex_id(&p3.id))).exists());
    assert!(a.join(DATA_DIR).join(pack_key(&hex_id(&p5.id))).exists());

    // The "next disk to dock" counting works on pack copies.
    let sets = book_sets(&env.view, "shelf", &[(p3.id, p3.class)], None);
    assert_eq!(
        sets.wanted,
        [&p1, &p4, &p5].iter().map(|p| hex_id(&p.id)).collect()
    );
    assert_eq!(sets.elsewhere, [hex_id(&p4.id)].into());
    assert_eq!(sets.first_copy_bytes, class_bytes(p3.class).unwrap());
    let rows = pool.statuses_with(Some(&sets.input(None, None)));
    let row = rows.iter().find(|d| d.label == "A").unwrap();
    assert_eq!(row.objects, 4); // P1, P2, P4, P5
    assert_eq!(row.unneeded_objects, Some(1)); // P2: dropped by the ledger
    assert_eq!(row.only_copy_objects, Some(2)); // P1 and P5: no other copy
    assert_eq!(row.lacking_bytes, Some(class_bytes(p3.class).unwrap()));

    // A disk check hashes every pack against its id.
    let path = a.join(DATA_DIR).join(pack_key(&hex_id(&p1.id)));
    let mut bytes = fs::read(&path).unwrap();
    bytes[10] ^= 1;
    fs::write(&path, bytes).unwrap();
    let (out, events) = check_disk_packs(&pool, &disk.id, &env.view, &mut |_, _| {}).unwrap();
    assert_eq!(out.bad, vec![pack_key(&hex_id(&p1.id))]);
    assert!(events.contains(&Event::PackDropped(PackOn {
        storage: "shelf".into(),
        pack: p1.id
    })));
    for p in [&p4, &p5] {
        assert!(events.contains(&Event::PackVerified(PackOn {
            storage: "shelf".into(),
            pack: p.id
        })));
    }
    assert!(!events.contains(&Event::PackVerified(PackOn {
        storage: "shelf".into(),
        pack: p1.id
    })));
}

#[test]
fn a_staged_move_across_two_disks_counts_a_group_rule_by_places() {
    let mut env = Env::new();
    let src = env.store("src");
    let tmp = tempfile::tempdir().unwrap();
    let mounts = tmp.path().join("mounts");
    let (a, b) = (mounts.join("a"), mounts.join("b"));
    let away = tmp.path().join("away");
    for d in [&a, &b, &away] {
        fs::create_dir_all(d).unwrap();
    }
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let spec = pool_spec("shelf", &mounts, 2);
    for m in [&a, &b] {
        fake_space(m);
    }
    {
        let p = PoolStorage::open(&spec, &home, identity()).unwrap();
        p.add_disk_at(&a, "A", "").unwrap();
        p.add_disk_at(&b, "B", "offsite").unwrap();
    }
    let p = env.publish_pack(&[3000, 4000], &["src"]);

    // Disk B is away: the pack lands on A alone, one place of two.
    fs::rename(&b, away.join("b")).unwrap();
    let pool = PoolStorage::open(&spec, &home, identity()).unwrap();
    let plan = plan_move(&env.view, &env.table, &FOLDER, "src", "shelf", &|_| true).unwrap();
    assert_eq!(plan.actions.len(), 1);
    assert!(matches!(
        &plan.actions[0],
        PackAction::Whole { copy: true, .. }
    ));
    let from = Endpoint {
        name: "src",
        storage: &*src,
        cold: false,
        pool: None,
    };
    let to = Endpoint {
        name: "shelf",
        storage: &pool,
        cold: false,
        pool: Some(&pool),
    };
    let run = run_move(&plan, &from, &to, &MoveOptions::default());
    assert_eq!(run.report.packs_copied, 1, "{:?}", run.report);
    assert_eq!(run.report.waiting_place_packs, 1);
    assert!(run.dropped.is_empty());
    assert!(!run
        .events
        .iter()
        .any(|e| matches!(e, Event::PackDropped(_))));
    assert_eq!(pool.places_of(&pack_key(&hex_id(&p.id))).len(), 1);
    env.finish_run(ME, &run);
    assert!(env.view.is_held(&p.id, "shelf") && env.view.is_held(&p.id, "src"));
    drop(pool);

    // B is back: the pack is on the pool already, the rule adds the second
    // place, and only then does the source let go of the pack.
    fs::rename(away.join("b"), &b).unwrap();
    fake_space(&b);
    let pool = PoolStorage::open(&spec, &home, identity()).unwrap();
    let plan = plan_move(&env.view, &env.table, &FOLDER, "src", "shelf", &|_| true).unwrap();
    assert!(matches!(
        &plan.actions[0],
        PackAction::Whole {
            copy: false,
            on_destination: true,
            ..
        }
    ));
    let to = Endpoint {
        name: "shelf",
        storage: &pool,
        cold: false,
        pool: Some(&pool),
    };
    let run = run_move(&plan, &from, &to, &MoveOptions::default());
    assert_eq!(run.dropped, vec![p.id], "{:?}", run.report);
    assert_eq!(run.report.disks_used, vec!["B".to_string()]);
    assert_eq!(pool.places_of(&pack_key(&hex_id(&p.id))).len(), 2);
    env.finish_run(ME, &run);
    run.delete_dropped(&*src).unwrap();
    assert!(!src.exists(&pack_key(&hex_id(&p.id))).unwrap());
    for i in 0..2 {
        assert_eq!(env.copies(&p.object(i)), ["shelf".to_string()].into());
    }
    // Both disks hold the pack and a disk check of either counts.
    let copies = pool_pack_copies(&pool, &p.id);
    assert_eq!(copies.len(), 2);
}

// ---- copies of a block, policies ----------------------------------------------

fn chunk_ref(object: &ObjectBin, size: u64) -> ChunkRef {
    ChunkRef {
        chunk: crate::ids::ChunkId::from_bytes(&hash(object)),
        object: crate::ids::ObjectName::from_bytes(object),
        size,
        epoch: 0,
    }
}

fn place_of(name: &str) -> Standing {
    match name {
        "usb" => Standing::Carrier,
        "s3" | "b2" => Standing::Place("cloud".into()),
        _ => Standing::Place("home".into()),
    }
}

#[test]
fn a_policy_with_two_copies_is_met_by_a_pack_on_two_storages_and_broken_by_a_dead_member() {
    let mut env = Env::new();
    for s in ["nas", "s3", "b2"] {
        env.store(s);
    }
    let two = Policy {
        min_copies: 2,
        ..Default::default()
    };
    // R holds w and z on nas and s3; z also has a place in Q, on b2 alone.
    let r = env.publish_pack(&[1500, 1500], &["nas", "s3"]);
    // Q holds a second copy of z's bytes (same object name).
    let z = r.members[1].0.clone();
    let q = env.pack_of(vec![z.clone()]);
    let b2 = env.stores["b2"].clone();
    env.write(&*b2, &q);
    let seq = env.publish_map(ME, &[q.written(&["b2"])], Vec::new());
    env.claim(ME, "b2", &q, seq);
    let (w_obj, z_obj) = (r.object(0), r.object(1));
    assert_eq!(z_obj, q.object(0));

    let env_for = CopyEnv::new(&place_of);
    let eval = |env: &Env, objects: &[ObjectBin]| {
        let chunks: Vec<ChunkRef> = objects.iter().map(|o| chunk_ref(o, 1500)).collect();
        let (facts, unreadable) = file_facts(&env.view, &env.table, &chunks, &env_for).unwrap();
        policy::evaluate("f", &two, &facts, &unreadable, &[], 2_000_000_000)
    };
    // The pack on two storages satisfies "2 copies" for each member.
    assert_eq!(
        env.copies(&w_obj),
        ["nas".to_string(), "s3".to_string()].into()
    );
    assert_eq!(
        env.copies(&z_obj),
        ["b2".to_string(), "nas".to_string(), "s3".to_string()].into()
    );
    assert_eq!(eval(&env, &[w_obj, z_obj]).state, PolicyState::Ok);
    let fc = file_copies(
        &env.view,
        &env.table,
        &[chunk_ref(&w_obj, 1), chunk_ref(&z_obj, 1)],
    )
    .unwrap();
    assert_eq!(fc.fewest, 2);
    assert_eq!(
        fc.on_every_block,
        ["nas".to_string(), "s3".to_string()].into()
    );

    // z's place in R is marked dead (by another device): z keeps only the
    // copy in Q, w is unaffected.
    env.publish_map(
        OTHER,
        &[],
        vec![Mark {
            object: z_obj,
            pack: r.id,
            offset: r.members[1].1.offset,
            kind: 1,
        }],
    );
    assert_eq!(env.copies(&z_obj), ["b2".to_string()].into());
    assert_eq!(
        env.copies(&w_obj),
        ["nas".to_string(), "s3".to_string()].into()
    );
    let rep = eval(&env, &[w_obj]);
    assert_eq!(rep.state, PolicyState::Ok);
    let rep = eval(&env, &[w_obj, z_obj]);
    assert_eq!(rep.state, PolicyState::Violated, "{rep:?}");
    assert_eq!(rep.chunks_short_of_copies, 1);
    assert_eq!(
        file_copies(&env.view, &env.table, &[chunk_ref(&z_obj, 1)])
            .unwrap()
            .fewest,
        1
    );
    // A block with no live place at all has no copy, and says so.
    env.publish_map(
        OTHER,
        &[],
        vec![Mark {
            object: z_obj,
            pack: q.id,
            offset: q.members[0].1.offset,
            kind: 3,
        }],
    );
    let fc = file_copies(&env.view, &env.table, &[chunk_ref(&z_obj, 1)]).unwrap();
    assert_eq!((fc.fewest, fc.without_copy), (0, 1));
}

#[test]
fn facts_carry_places_verification_age_and_leave_out_carriers() {
    let mut env = Env::new();
    for s in ["nas", "s3", "usb"] {
        env.store(s);
    }
    let p = env.publish_pack(&[900], &["nas", "s3", "usb"]);
    let obj = p.object(0);
    // Verified by the writer: not independent. Verified by another device:
    // it counts, with its time.
    env.verify(ME, "nas", &p);
    env.verify(OTHER, "s3", &p);
    let f = block_facts(&env.view, &env.table, &obj, &CopyEnv::new(&place_of));
    let names: Vec<&str> = f.facts.copies.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(names, vec!["nas", "s3"]); // the transferrer is no copy
    assert!(!f.facts.copies[0].2);
    assert!(f.facts.copies[1].2 && f.facts.copies[1].3 > 0);
    assert!(f.facts.stored_utc > 0);
    // Raw copy sets include every storage, carriers too.
    assert_eq!(env.copies(&obj).len(), 3);
}

// ---- moves ----------------------------------------------------------------------

#[test]
fn moving_a_folder_to_another_storage_keeps_every_block_readable_through_the_map() {
    let mut env = Env::new();
    let hot = env.store("hot");
    let other = env.store("other");
    // docs: P1 whole; photos: P2 whole; P3 mixes a4 (docs) and b3 (photos).
    let p1 = env.publish_pack(&[3000, 5000, 4000], &["hot"]);
    let p2 = env.publish_pack(&[2000, 2500], &["hot"]);
    let p3 = env.publish_pack(&[6000, 7000], &["hot"]);
    let docs: HashSet<ObjectBin> = [p1.object(0), p1.object(1), p1.object(2), p3.object(0)].into();
    let photos = [p2.object(0), p2.object(1), p3.object(1)];

    let plan = plan_move(&env.view, &env.table, &FOLDER, "hot", "other", &|o| {
        docs.contains(o)
    })
    .unwrap();
    assert_eq!(plan.blocks, 4);
    assert_eq!(plan.packs_untouched, 1);
    assert_eq!(plan.actions.len(), 2);
    for a in &plan.actions {
        match a {
            PackAction::Whole { pack, copy, .. } => assert!(*pack == p1.id && *copy),
            PackAction::Rebuild {
                pack,
                moving,
                staying,
                ..
            } => {
                assert_eq!(*pack, p3.id);
                assert_eq!(moving.len(), 1);
                assert_eq!(staying.len(), 1);
            }
        }
    }
    assert_eq!(objects_moving(&plan), docs.iter().copied().collect());

    let from = Endpoint {
        name: "hot",
        storage: &*hot,
        cold: false,
        pool: None,
    };
    let to = Endpoint {
        name: "other",
        storage: &*other,
        cold: false,
        pool: None,
    };
    let run = run_move(&plan, &from, &to, &MoveOptions::default());
    let rep = &run.report;
    assert_eq!(rep.packs_copied, 1, "{rep:?}");
    assert_eq!(rep.packs_built, 2); // a4 on `other`, b3 on `hot`
    assert_eq!(rep.packs_dropped, 2);
    assert_eq!(rep.blocks_moved, 4);
    assert!(rep.corrupt.is_empty() && rep.unavailable.is_empty());
    // Nothing is deleted before the caller's batch is pushed.
    assert!(hot.exists(&pack_key(&hex_id(&p1.id))).unwrap());
    // The new places went through a map delta and a batch, then the old
    // packs go.
    env.finish_run(ME, &run);
    assert_eq!(run.delete_dropped(&*hot).unwrap(), 2);
    assert!(!hot.exists(&pack_key(&hex_id(&p1.id))).unwrap());
    assert!(!hot.exists(&pack_key(&hex_id(&p3.id))).unwrap());
    assert!(hot.exists(&pack_key(&hex_id(&p2.id))).unwrap());

    // Every block reads through the map from where it is now.
    let lookup = env.lookup();
    for (pack, i) in [
        (&p1, 0),
        (&p1, 1),
        (&p1, 2),
        (&p3, 0),
        (&p2, 0),
        (&p2, 1),
        (&p3, 1),
    ] {
        let (data, m) = &pack.members[i];
        let found = find_block(&env.table, &env.view, &m.object, &lookup)
            .unwrap()
            .unwrap_or_else(|| panic!("block {i} of {} unreadable", hex_id(&pack.id)));
        assert_eq!(&found.bytes, data);
        assert!(!found.marked);
    }
    for o in &docs {
        assert_eq!(
            env.copies(o),
            ["other".to_string()].into(),
            "docs are moved"
        );
    }
    for o in &photos {
        assert_eq!(env.copies(o), ["hot".to_string()].into(), "photos stay");
    }
    // The source keeps the untouched pack and the remainder of the mixed
    // one; the destination has the whole pack and the rebuilt members.
    assert_eq!(hot.list("packs/").unwrap().len(), 2);
    assert_eq!(other.list("packs/").unwrap().len(), 2);
    // Planning again finds nothing left to move.
    let again = plan_move(&env.view, &env.table, &FOLDER, "hot", "other", &|o| {
        docs.contains(o)
    })
    .unwrap();
    assert!(again.actions.is_empty(), "{again:?}");
    assert_eq!(storage_usage(&env.view, "hot").packs, 2);
    assert_eq!(storage_usage(&env.view, "other").packs, 2);
}

#[test]
fn a_move_that_keeps_the_source_or_meets_a_bad_pack_drops_nothing() {
    let mut env = Env::new();
    let hot = env.store("hot");
    let other = env.store("other");
    let p1 = env.publish_pack(&[3000, 4000], &["hot"]);
    let p2 = env.publish_pack(&[3500], &["hot"]);
    // P2's bytes are damaged on the source.
    let path = env
        .dir
        .path()
        .join("stores/hot")
        .join(pack_key(&hex_id(&p2.id)));
    let mut b = fs::read(&path).unwrap();
    b[5] ^= 0xff;
    fs::write(&path, b).unwrap();
    let plan = plan_move(&env.view, &env.table, &FOLDER, "hot", "other", &|_| true).unwrap();
    assert_eq!(plan.actions.len(), 2);
    let from = Endpoint {
        name: "hot",
        storage: &*hot,
        cold: false,
        pool: None,
    };
    let to = Endpoint {
        name: "other",
        storage: &*other,
        cold: false,
        pool: None,
    };
    let run = run_move(&plan, &from, &to, &MoveOptions::default());
    assert_eq!(run.report.corrupt, vec![p2.id]);
    assert_eq!(run.dropped, vec![p1.id]);
    assert!(!other.exists(&pack_key(&hex_id(&p2.id))).unwrap());
    // keep_source: copied and checked, never dropped.
    let opts = MoveOptions {
        keep_source: true,
        ..Default::default()
    };
    let kept = run_move(&plan, &from, &to, &opts);
    assert!(kept.dropped.is_empty());
    assert!(!kept
        .events
        .iter()
        .any(|e| matches!(e, Event::PackDropped(_))));
    assert_eq!(kept.report.packs_dropped, 0);
    // An interrupted move: the ledger shows P1 dropped from the source but
    // its bytes are still there; the next run finds and deletes them.
    env.apply(
        ME,
        run.events
            .iter()
            .filter(|e| matches!(e, Event::PackDropped(_)))
            .cloned()
            .collect(),
    );
    assert_eq!(leftovers(&env.view, "hot", &*hot).unwrap(), vec![p1.id]);
    // A run may be limited; the report says more is left.
    let one = MoveOptions {
        max_packs: 1,
        ..Default::default()
    };
    let limited = run_move(&plan, &from, &to, &one);
    assert!(limited.report.stopped_early);
}

#[test]
fn a_pool_disk_without_room_for_a_whole_pack_takes_its_members_in_smaller_packs() {
    let mut env = Env::new();
    let src = env.store("src");
    let tmp = tempfile::tempdir().unwrap();
    let mounts = tmp.path().join("mounts");
    let a = mounts.join("a");
    fs::create_dir_all(&a).unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    fake_space(&a);
    let pool = PoolStorage::open(&pool_spec("shelf", &mounts, 1), &home, identity()).unwrap();
    pool.add_disk_at(&a, "A", "").unwrap();
    // Two members of ~700 KiB in a 4 MiB pack ...
    let p = env.publish_pack(&[700_000, 700_000], &["src"]);
    assert_eq!(class_bytes(p.class), Some(4 << 20));
    // ... and a disk with room for 1.3 MB only (room = free - reserve).
    set_fake_space(
        &a,
        Some(DiskSpace {
            free: 1_300_000,
            total: 2_000_000,
        }),
    );
    let plan = plan_move(&env.view, &env.table, &FOLDER, "src", "shelf", &|_| true).unwrap();
    let from = Endpoint {
        name: "src",
        storage: &*src,
        cold: false,
        pool: None,
    };
    let to = Endpoint {
        name: "shelf",
        storage: &pool,
        cold: false,
        pool: Some(&pool),
    };
    // Without splitting the pack waits for room, with the least room that
    // would help.
    let waits = run_move(&plan, &from, &to, &MoveOptions::default());
    assert_eq!(waits.report.waiting_room_packs, 1, "{:?}", waits.report);
    assert!(waits.dropped.is_empty());
    // With splitting its members go in packs of their own.
    let opts = MoveOptions {
        split_on_no_room: true,
        ..Default::default()
    };
    let run = run_move(&plan, &from, &to, &opts);
    assert_eq!(run.report.packs_built, 2, "{:?}", run.report);
    assert_eq!(run.dropped, vec![p.id]);
    env.finish_run(ME, &run);
    for i in 0..2 {
        assert_eq!(env.copies(&p.object(i)), ["shelf".to_string()].into());
    }
}

// ---- drains and quotas ----------------------------------------------------------

fn needs(targets: &[&str], rules: Option<Policy>) -> HashMap<FolderBin, DrainNeeds> {
    [(
        FOLDER,
        DrainNeeds {
            name: "docs".into(),
            rules,
            targets: targets.iter().map(|s| s.to_string()).collect(),
            referenced: None,
        },
    )]
    .into()
}

fn place_name(s: &str) -> String {
    match place_of(s) {
        Standing::Place(p) => p,
        Standing::Carrier => "carrier".into(),
    }
}

#[test]
fn a_drain_refuses_while_a_place_is_the_only_live_one_and_copies_packs_whole() {
    let mut env = Env::new();
    for s in ["nas", "s3", "b2"] {
        env.store(s);
    }
    let p = env.publish_pack(&[1000, 1000], &["nas"]);
    let tables: HashMap<FolderBin, &MapTable> = [(FOLDER, &env.table)].into();

    // Nowhere to put the only copy: the drain refuses.
    let plan = drain_plan(
        &env.view,
        "nas",
        &tables,
        &needs(&[], None),
        &place_name,
        &[],
    )
    .unwrap();
    assert_eq!(plan.packs_blocked, 1);
    assert!(plan.refusal().unwrap().contains("no other copy"));
    assert!(plan.items[0].copy_to.is_empty());

    // With a storage that takes the folder, the pack is copied whole first.
    let plan = drain_plan(
        &env.view,
        "nas",
        &tables,
        &needs(&["s3"], None),
        &place_name,
        &[],
    )
    .unwrap();
    assert_eq!(plan.refusal(), None);
    assert_eq!(plan.items[0].copy_to, vec!["s3".to_string()]);
    assert_eq!(
        (plan.packs_to_copy, plan.bytes_to_copy),
        (1, class_bytes(p.class).unwrap())
    );
    let nas = env.stores["nas"].clone();
    let s3 = env.stores["s3"].clone();
    let src = Endpoint {
        name: "nas",
        storage: &*nas,
        cold: false,
        pool: None,
    };
    let dsts = [Endpoint {
        name: "s3",
        storage: &*s3,
        cold: true,
        pool: None,
    }];
    let run = run_drain(&env.view, &plan, &src, &dsts, &MoveOptions::default());
    assert_eq!(run.dropped, vec![p.id], "{:?}", run.report);
    env.apply(ME, run.events.clone());
    run.delete_dropped(&*nas).unwrap();
    assert!(s3.exists(&pack_key(&hex_id(&p.id))).unwrap());
    assert!(!nas.exists(&pack_key(&hex_id(&p.id))).unwrap());
    assert_eq!(env.copies(&p.object(0)), ["s3".to_string()].into());
    assert_eq!(storage_usage(&env.view, "nas"), Usage::default());
    assert_eq!(
        storage_usage(&env.view, "s3"),
        Usage {
            bytes: class_bytes(p.class).unwrap(),
            packs: 1
        }
    );
}

#[test]
fn a_drain_counts_the_copy_rules_by_the_places_a_block_keeps() {
    let mut env = Env::new();
    for s in ["nas", "s3", "b2"] {
        env.store(s);
    }
    let two = Policy {
        min_copies: 2,
        ..Default::default()
    };
    let cloud = Policy {
        min_per_place: [("cloud".to_string(), 1)].into(),
        ..Default::default()
    };
    // The block is on nas and s3 (two copies, one in the cloud).
    let p = env.publish_pack(&[1000], &["nas", "s3"]);
    let tables: HashMap<FolderBin, &MapTable> = [(FOLDER, &env.table)].into();
    // Draining s3 with "2 copies" needs another storage.
    let plan = drain_plan(
        &env.view,
        "s3",
        &tables,
        &needs(&[], Some(two.clone())),
        &place_name,
        &[],
    )
    .unwrap();
    assert!(
        plan.refusal().unwrap().contains("needs 2 copies"),
        "{plan:?}"
    );
    let plan = drain_plan(
        &env.view,
        "s3",
        &tables,
        &needs(&["b2", "nas"], Some(two)),
        &place_name,
        &[],
    )
    .unwrap();
    assert_eq!(plan.items[0].copy_to, vec!["b2".to_string()]); // nas holds it
                                                               // Draining s3 with "one in the cloud": a cloud storage must take it;
                                                               // nas (home) does not do.
    let plan = drain_plan(
        &env.view,
        "s3",
        &tables,
        &needs(&["nas"], Some(cloud.clone())),
        &place_name,
        &[],
    )
    .unwrap();
    assert!(plan.refusal().unwrap().contains("cloud"), "{plan:?}");
    let plan = drain_plan(
        &env.view,
        "s3",
        &tables,
        &needs(&["nas", "b2"], Some(cloud)),
        &place_name,
        &[],
    )
    .unwrap();
    assert_eq!(plan.items[0].copy_to, vec!["b2".to_string()]);
    // A block with another live place on a kept storage needs no copy; a
    // pack nothing uses is only dropped.
    let z = p.members[0].0.clone();
    let q = env.pack_of(vec![z]);
    let b2 = env.stores["b2"].clone();
    env.write(&*b2, &q);
    let seq = env.publish_map(ME, &[q.written(&["b2"])], Vec::new());
    env.claim(ME, "b2", &q, seq);
    let tables: HashMap<FolderBin, &MapTable> = [(FOLDER, &env.table)].into();
    let plan = drain_plan(
        &env.view,
        "nas",
        &tables,
        &needs(&[], None),
        &place_name,
        &[],
    )
    .unwrap();
    assert_eq!(plan.refusal(), None);
    assert!(plan.items[0].copy_to.is_empty());
    assert_eq!(plan.packs_to_drop, 1);
    let mut n = needs(&[], None);
    n.get_mut(&FOLDER).unwrap().referenced = Some(HashSet::new());
    let tables: HashMap<FolderBin, &MapTable> = [(FOLDER, &env.table)].into();
    let plan = drain_plan(&env.view, "b2", &tables, &n, &place_name, &[]).unwrap();
    assert_eq!((plan.packs_to_drop, plan.packs_blocked), (1, 0));
}

#[test]
fn quota_usage_counts_pack_classes_held() {
    let mut env = Env::new();
    for s in ["nas", "s3"] {
        env.store(s);
    }
    let small = env.publish_pack(&[1000], &["nas"]);
    let big = env.publish_pack(&[600_000], &["nas", "s3"]);
    assert_ne!(small.class, big.class);
    let u = storage_usage(&env.view, "nas");
    assert_eq!(u.packs, 2);
    assert_eq!(
        u.bytes,
        class_bytes(small.class).unwrap() + class_bytes(big.class).unwrap()
    );
    env.apply(
        ME,
        vec![Event::PackDropped(PackOn {
            storage: "nas".into(),
            pack: small.id,
        })],
    );
    assert_eq!(storage_usage(&env.view, "nas").packs, 1);
}

// ---- transferrers -----------------------------------------------------------------

#[test]
fn a_transferrer_takes_what_no_other_device_has_and_empties_when_delivered() {
    let mut env = Env::new();
    env.store("usb");
    let p = env.publish_pack(&[1000, 1000], &["usb"]);
    let (m1, m2) = (p.object(0), p.object(1));
    let held: std::cell::RefCell<HashMap<ObjectBin, Vec<DeviceBin>>> =
        std::cell::RefCell::new(HashMap::new());
    let holders = |o: &ObjectBin| held.borrow().get(o).cloned().unwrap_or_default();
    let to_other: &[DeviceBin] = &[OTHER];
    let to_nobody: &[DeviceBin] = &[];
    // Only this device holds the blocks: a carrier without destinations
    // takes them; with a destination that lacks them it takes them too.
    assert!(carrier_wants(&holders, &m1, &ME, None));
    assert!(carrier_wants(&holders, &m1, &ME, Some(to_other)));
    assert!(!carrier_wants(&holders, &m1, &ME, Some(to_nobody)));
    held.borrow_mut().insert(m1, vec![ME, OTHER]);
    held.borrow_mut().insert(m2, vec![ME]);
    assert!(!carrier_wants(&holders, &m1, &ME, None));
    assert!(!carrier_wants(&holders, &m1, &ME, Some(to_other)));
    assert!(carrier_wants(&holders, &m2, &ME, Some(to_other)));
    let carriers = vec![
        ("usb".to_string(), Some(vec![OTHER])),
        ("any".to_string(), None),
    ];
    // m2 is held by this device alone: the open transferrer takes it as well.
    assert_eq!(
        carrier_targets(&holders, &m2, &ME, &carriers),
        vec!["usb".to_string(), "any".to_string()]
    );
    assert_eq!(
        carrier_targets(&holders, &m1, &ME, &carriers),
        Vec::<String>::new()
    );
    // Emptied pack by pack once every live member is delivered.
    let gone = |dests: Option<&[DeviceBin]>| {
        delivered_packs(&env.view, &env.table, &FOLDER, "usb", &holders, &ME, dests).unwrap()
    };
    assert!(gone(Some(to_other)).is_empty()); // m2 is not at OTHER yet
    held.borrow_mut().insert(m2, vec![ME, OTHER]);
    assert_eq!(gone(Some(to_other)), vec![p.id]);
    assert_eq!(gone(None), vec![p.id]);
    let ev = drop_events("usb", &gone(None));
    assert_eq!(
        ev,
        vec![Event::PackDropped(PackOn {
            storage: "usb".into(),
            pack: p.id
        })]
    );
    // Destinations that use the folder: only those count.
    let configured: BTreeMap<String, Vec<DeviceBin>> = [
        ("usb".to_string(), vec![OTHER, [9; 16]]),
        ("any".to_string(), vec![]),
    ]
    .into();
    let d = carrier_destinations(&configured, &|d| *d == OTHER);
    assert_eq!(d["usb"], vec![OTHER]);
    assert!(!d.contains_key("any"));
}

#[test]
fn transferrers_read_the_held_flags_of_the_manifests() {
    use crate::manifest3::{Chunk3, FileEntry, FolderManifests, WriterView};
    let mut env = Env::new();
    env.store("usb");
    let p = env.publish_pack(&[1000, 1000], &["usb"]);
    let chunk = |i: usize| Chunk3 {
        chunk: p.members[i].1.chunk,
        object: p.object(i),
        size: 900,
        epoch: 0,
    };
    let entry = |path: &str, i: usize, held: bool| FileEntry {
        path: path.into(),
        version: BTreeMap::new(),
        deleted: false,
        size: 900,
        mtime: 0,
        content_hash: Some([i as u8; 32]),
        chunks: vec![chunk(i)],
        modified_by: ME,
        modified_clock: 1,
        meta: None,
        chunking: 2,
        held,
    };
    let view_of = |dev: DeviceBin, files: Vec<FileEntry>| WriterView {
        device: dev,
        seq: 1,
        base: 1,
        files: files.into_iter().map(|f| (f.path.clone(), f)).collect(),
        ..Default::default()
    };
    let mut fm = FolderManifests::new(FOLDER);
    // This device holds both files; OTHER holds the first only.
    fm.insert_view(view_of(ME, vec![entry("a", 0, true), entry("b", 1, true)]));
    fm.insert_view(view_of(
        OTHER,
        vec![entry("a", 0, true), entry("b", 1, false)],
    ));
    let held = fm.held_index();
    let dest: &[DeviceBin] = &[OTHER];
    assert!(!carrier_wants(&held, &p.object(0), &ME, None));
    assert!(carrier_wants(&held, &p.object(1), &ME, Some(dest)));
    assert!(gone_from_usb(&env, &held, Some(dest)).is_empty());
    // OTHER receives the second file too: the transferrer is emptied.
    fm.insert_view(view_of(
        OTHER,
        vec![entry("a", 0, true), entry("b", 1, true)],
    ));
    let held = fm.held_index();
    assert_eq!(gone_from_usb(&env, &held, Some(dest)), vec![p.id]);
    // Destinations are those that use the folder.
    let configured: BTreeMap<String, Vec<DeviceBin>> =
        [("usb".to_string(), vec![OTHER, [9; 16]])].into();
    assert_eq!(
        carrier_destinations_held(&configured, &held)["usb"],
        vec![OTHER]
    );
    // The references drains and garbage collection start from.
    let refs = fm.reference_set();
    assert!(refs.contains(&p.object(0)) && refs.contains(&p.object(1)));
}

fn gone_from_usb(
    env: &Env,
    held: &crate::manifest3::HeldIndex,
    dests: Option<&[DeviceBin]>,
) -> Vec<PackId> {
    delivered_packs(&env.view, &env.table, &FOLDER, "usb", held, &ME, dests).unwrap()
}
