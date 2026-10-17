// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of format-3 snapshots: the body and its limits, reconstruction
//! from a base, expiry in any order, retained bases, references, the
//! writer's base rule and parser fuzzing.

use super::reader::{deletable, delete_records, expiry_due};
use super::record::SnapHeader;
use super::*;
use crate::ledger3::events::{Event, SnapshotExpired, SnapshotTaken};
use crate::ledger3::EventScope;
use crate::manifest3::{Chunk3, FileEntry};
use crate::record::{Kind, RecordsRefused};
use crate::trash3::testkit::{meta_key, World, BACKUP};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::BTreeMap;

const DAY: i64 = 86_400;
type Listing = BTreeMap<String, FileEntry>;

fn h32(rng: &mut StdRng) -> Hash32 {
    let mut b = [0; 32];
    rng.fill_bytes(&mut b);
    b
}

/// A live file with fresh blocks.
fn file(rng: &mut StdRng, path: &str, by: Id16) -> FileEntry {
    let chunks: Vec<Chunk3> = (0..rng.gen_range(1..4))
        .map(|_| Chunk3 {
            chunk: h32(rng),
            object: h32(rng),
            size: rng.gen_range(1..5000),
            epoch: 0,
        })
        .collect();
    FileEntry {
        path: path.into(),
        version: BTreeMap::from([(by, rng.gen_range(1..9))]),
        deleted: false,
        size: chunks.iter().map(|c| c.size).sum(),
        mtime: rng.gen(),
        content_hash: Some(h32(rng)),
        chunks,
        modified_by: by,
        modified_clock: 1,
        meta: None,
        chunking: 2,
        held: false,
    }
}

fn listing(rng: &mut StdRng, n: usize, by: Id16) -> Listing {
    (0..n)
        .map(|i| {
            let p = format!("dir/f{i:03}.txt");
            (p.clone(), file(rng, &p, by))
        })
        .collect()
}

fn objects(l: &Listing) -> Vec<Hash32> {
    l.values().flat_map(|e| e.objects().copied()).collect()
}

/// Take a snapshot as device `i` (sealing, publishing, announcing it with
/// `snapshot_taken`) and return it.
fn take(
    w: &mut World,
    sw: &mut SnapshotWriter,
    i: usize,
    cur: &Listing,
    taken: i64,
    expires: i64,
) -> Pending {
    let p = w.with_writer(i, |rw| {
        sw.seal(rw, &meta_key(BACKUP), cur, sw.seq + 1, taken, expires)
            .unwrap()
    });
    let ev = Event::SnapshotTaken(SnapshotTaken {
        backup: BACKUP,
        seq: p.sealed.published.seq,
        taken_utc: taken,
        expires_utc: expires,
        files: cur.len() as u64,
        bytes: cur.values().map(|e| e.size).sum(),
    });
    w.publish_sealed(i, &p.sealed, vec![ev]);
    sw.commit(p.clone());
    p
}

fn expire(w: &mut World, i: usize, device: Id16, seq: u64) {
    w.batch(
        i,
        vec![Event::SnapshotExpired(SnapshotExpired {
            backup: BACKUP,
            device,
            seq,
        })],
        Vec::new(),
        EventScope::Full,
    );
}

fn pull(w: &World, bs: &mut BackupSnapshots, now: i64) -> reader::PullReport {
    let mut counter = RecordsRefused::default();
    let view = w.trust.view.borrow();
    bs.pull(&w.store(&w.hot), &view, now, &mut counter).unwrap()
}

// ---- record -----------------------------------------------------------------

#[test]
fn a_snapshot_round_trips_through_a_sealed_record() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut w = World::new(2);
    let a = w.id(0);
    let cur = listing(&mut rng, 30, a);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let p = take(&mut w, &mut sw, 0, &cur, 1000, 1000 + 90 * DAY);
    assert!(p.is_base);
    assert_eq!(
        p.sealed.parts[0].0,
        format!(
            "snapshots/{}/{}/0000000000000001-0000.rec",
            hex::encode(BACKUP),
            hex::encode(a)
        )
    );
    let mut bs = BackupSnapshots::new(BACKUP);
    let r = pull(&w, &mut bs, 2000);
    assert_eq!(r.loaded, 1);
    assert_eq!(bs.reconstruct(&a, 1).unwrap(), cur);
    let list = bs.list(&w.trust.view.borrow(), 2000);
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].taken_utc, list[0].expires_utc, list[0].files),
        (1000, 1000 + 90 * DAY, 30)
    );
    // Nothing new: nothing wanted.
    assert!(bs.wanted(&w.trust.view.borrow(), 2000).is_empty());
}

#[test]
fn bodies_outside_the_limits_are_refused() {
    let mut rng = StdRng::seed_from_u64(2);
    let a = [1; 16];
    let e = file(&mut rng, "ok.txt", a);
    let h = |seq, base| SnapHeader {
        backup: BACKUP,
        device: a,
        seq,
        lamport: seq,
        taken_utc: 10,
        expires_utc: 20,
        base,
    };
    let good = SnapshotBody::new(h(2, 1), [&e], ["gone.txt"]);
    assert!(good.validate().is_ok());
    let refused = |b: &SnapshotBody| b.validate().unwrap_err();

    // A base removes nothing.
    assert!(refused(&SnapshotBody::new(h(1, 1), [&e], ["x"])).contains("base removes"));
    // Seq and base.
    assert!(refused(&SnapshotBody::new(h(0, 0), [&e], [])).contains("seq"));
    assert!(refused(&SnapshotBody::new(h(2, 3), [&e], [])).contains("base"));
    assert!(refused(&SnapshotBody::new(h(2, 0), [&e], [])).contains("base"));
    // Expires before it was taken.
    let mut b = good.clone();
    b.expires_utc = 5;
    assert!(refused(&b).contains("expires"));
    // `held` is never set, and deleted files are not listed.
    let mut b = good.clone();
    b.files[0].held = true;
    assert!(refused(&b).contains("held"));
    let mut gone = e.clone();
    gone.deleted = true;
    gone.chunks.clear();
    gone.size = 0;
    gone.content_hash = None;
    assert!(refused(&SnapshotBody::new(h(1, 1), [&gone], [])).contains("deleted"));
    // Entries and paths.
    assert!(refused(&SnapshotBody::new(h(1, 1), [&e, &e], [])).contains("twice"));
    let mut bad = e.clone();
    bad.size += 1;
    assert!(refused(&SnapshotBody::new(h(1, 1), [&bad], [])).contains("bytes"));
    let mut b = good.clone();
    b.files[0].path = vec![0xff, 0xfe];
    assert!(refused(&b).contains("UTF-8"));
    let mut b = good.clone();
    b.files[0].modified_by = 9;
    assert!(refused(&b).contains("out of range"));

    use crate::record::{KeyId, RecordBody, RecordMeta};
    let meta = |scope, device, seq| RecordMeta {
        kind: Kind::Snapshot,
        vault: [0; 16],
        scope,
        device,
        seq,
        parts: 1,
        key_id: KeyId::Meta {
            folder: BACKUP,
            epoch: 0,
        },
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    assert!(good.check(&meta(BACKUP, a, 2)).is_ok());
    assert!(good.check(&meta([9; 16], a, 2)).is_err());
    assert!(good.check(&meta(BACKUP, [2; 16], 2)).is_err());
    assert!(good.check(&meta(BACKUP, a, 3)).is_err());
    // A snapshot never names a predecessor.
    assert_eq!(good.prev(), None);
    assert_eq!(good.base(), Some(1));
}

// ---- the writer's base rule ------------------------------------------------------

#[test]
fn a_new_base_when_32_snapshots_name_the_base_or_the_differential_is_large() {
    let mut rng = StdRng::seed_from_u64(3);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 400, a);
    let mut bases = Vec::new();
    for i in 0..70u64 {
        // One file changes: a tiny differential.
        let p = format!("dir/f{:03}.txt", i % 400);
        cur.insert(p.clone(), file(&mut rng, &p, a));
        let t = take(
            &mut w,
            &mut sw,
            0,
            &cur,
            100 * i as i64,
            100 * i as i64 + DAY,
        );
        if t.is_base {
            bases.push(t.sealed.published.seq);
        }
    }
    // The base and 31 differentials, then a new base.
    assert_eq!(bases, vec![1, 33, 65]);

    // Rewriting most of the listing is no differential: a base at once.
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut w = World::new(1);
    let mut cur = listing(&mut rng, 400, a);
    assert!(take(&mut w, &mut sw, 0, &cur, 0, DAY).is_base);
    cur.insert("dir/f000.txt".into(), file(&mut rng, "dir/f000.txt", a));
    assert!(!take(&mut w, &mut sw, 0, &cur, 1, DAY).is_base);
    cur = listing(&mut rng, 400, a);
    assert!(
        take(&mut w, &mut sw, 0, &cur, 2, DAY).is_base,
        "everything changed"
    );
    // A restart does not know the base's listing: a base.
    let mut again = SnapshotWriter::new(BACKUP, a);
    again.resume(3);
    let t = take(&mut w, &mut again, 0, &cur, 3, DAY);
    assert!(t.is_base && t.sealed.published.seq == 4);
    // A lost seq is skipped; differentials do not chain, so no base is needed.
    let p = w.with_writer(0, |rw| {
        again.seal(rw, &meta_key(BACKUP), &cur, 9, 4, DAY).unwrap()
    });
    assert!(!p.is_base);
    again.abandon(p);
    assert_eq!(again.seq, 5);
    // Refuses deleted or held entries.
    let mut bad = cur.clone();
    bad.get_mut("dir/f001.txt").unwrap().held = true;
    let r = w.with_writer(0, |rw| again.seal(rw, &meta_key(BACKUP), &bad, 1, 0, 1));
    assert!(r.is_err());
}

// ---- reconstruction -----------------------------------------------------------------

#[test]
fn every_snapshot_reconstructs_from_its_base() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut w = World::new(2);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 60, a);
    let mut truth: Vec<Listing> = Vec::new();
    for i in 0..20u64 {
        // A few changes, additions and removals between snapshots.
        for _ in 0..rng.gen_range(0..4) {
            let p = format!("dir/f{:03}.txt", rng.gen_range(0..80));
            match rng.gen_range(0..3) {
                0 => {
                    cur.remove(&p);
                }
                _ => {
                    cur.insert(p.clone(), file(&mut rng, &p, a));
                }
            }
        }
        take(&mut w, &mut sw, 0, &cur, 10 * i as i64, 10 * i as i64 + DAY);
        truth.push(cur.clone());
    }
    let mut bs = BackupSnapshots::new(BACKUP);
    let r = pull(&w, &mut bs, 1000);
    assert_eq!(r.loaded, 20);
    assert_eq!(r.missing_base, 0);
    for (i, t) in truth.iter().enumerate() {
        assert_eq!(
            &bs.reconstruct(&a, i as u64 + 1).unwrap(),
            t,
            "snapshot {}",
            i + 1
        );
    }
    assert!(bs.reconstruct(&a, 99).is_err());
}

#[test]
fn a_restore_reads_one_snapshot_and_its_base_only() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 40, a);
    for i in 0..4u64 {
        cur.insert(
            format!("dir/f{i:03}.txt"),
            file(&mut rng, &format!("dir/f{i:03}.txt"), a),
        );
        take(&mut w, &mut sw, 0, &cur, i as i64, DAY);
    }
    // The storage lost snapshots 2 and 3: snapshot 4 still restores.
    delete_records(&w.hot, &BACKUP, &a, &[2, 3]).unwrap();
    let mut bs = BackupSnapshots::new(BACKUP);
    // Only snapshot 4 is of interest (the others are expired in the ledger).
    expire(&mut w, 0, a, 2);
    expire(&mut w, 0, a, 3);
    let r = pull(&w, &mut bs, 100);
    assert_eq!(r.loaded, 2, "snapshot 4 and its base, nothing else");
    assert!(!bs.is_loaded(&a, 2) && !bs.is_loaded(&a, 3));
    assert_eq!(bs.reconstruct(&a, 4).unwrap(), cur);
}

#[test]
fn a_differential_without_its_base_waits() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 40, a);
    take(&mut w, &mut sw, 0, &cur, 0, DAY);
    cur.insert("dir/f000.txt".into(), file(&mut rng, "dir/f000.txt", a));
    take(&mut w, &mut sw, 0, &cur, 1, DAY);
    // The base is withheld by the storage.
    let base_names: Vec<String> = w
        .hot
        .names()
        .into_iter()
        .filter(|n| n.contains("0000000000000001-"))
        .collect();
    for n in &base_names {
        crate::storage::Storage::delete(&w.hot, n).unwrap();
    }
    let mut bs = BackupSnapshots::new(BACKUP);
    let r = pull(&w, &mut bs, 10);
    assert_eq!(r.loaded, 0);
    assert!(bs.is_empty());
    assert!(bs.reconstruct(&a, 2).is_err());
}

// ---- expiry -----------------------------------------------------------------------------

#[test]
fn expiring_a_base_does_not_break_a_differential_until_that_expires() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut w = World::new(2);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 40, a);
    let mut truth = Vec::new();
    for i in 0..3u64 {
        cur.insert(
            format!("dir/f{i:03}.txt"),
            file(&mut rng, &format!("dir/f{i:03}.txt"), a),
        );
        take(&mut w, &mut sw, 0, &cur, i as i64, 1_000_000);
        truth.push(cur.clone());
    }
    let now = 100;
    let del = |w: &World| deletable(&w.trust.view.borrow(), &BACKUP, &a, now);
    assert!(del(&w).is_empty());

    // The base expires first: its record stays.
    expire(&mut w, 0, a, 1);
    assert!(
        del(&w).is_empty(),
        "snapshots 2 and 3 are built on snapshot 1"
    );
    let mut bs = BackupSnapshots::new(BACKUP);
    pull(&w, &mut bs, now);
    let view = w.trust.view.borrow().clone();
    assert_eq!(bs.retained_bases(&view, now), vec![(a, 1)]);
    let seqs: Vec<u64> = bs.list(&view, now).iter().map(|s| s.seq).collect();
    assert_eq!(seqs, vec![3, 2], "the base is hidden from listings");
    assert_eq!(bs.reconstruct(&a, 3).unwrap(), truth[2]);
    assert_eq!(bs.reconstruct(&a, 2).unwrap(), truth[1]);

    // One differential expires: the other still needs the base.
    expire(&mut w, 0, a, 2);
    assert_eq!(del(&w), vec![2]);
    delete_records(&w.hot, &BACKUP, &a, &[2]).unwrap();
    let mut fresh = BackupSnapshots::new(BACKUP);
    pull(&w, &mut fresh, now);
    assert_eq!(fresh.reconstruct(&a, 3).unwrap(), truth[2]);

    // The last differential expires: the base goes with it.
    expire(&mut w, 0, a, 3);
    assert_eq!(del(&w), vec![1, 2, 3]);
    assert_eq!(delete_records(&w.hot, &BACKUP, &a, &[1, 2, 3]).unwrap(), 2);
    let mut empty = BackupSnapshots::new(BACKUP);
    assert_eq!(pull(&w, &mut empty, now).loaded, 0);
    assert!(empty.wanted(&w.trust.view.borrow(), now).is_empty());
    assert_eq!(
        w.hot
            .names()
            .iter()
            .filter(|n| n.starts_with("snapshots/"))
            .count(),
        0
    );
    assert_eq!(
        w.cold
            .names()
            .iter()
            .filter(|n| n.starts_with("snapshots/"))
            .count(),
        3,
        "other storages are the caller's"
    );
}

#[test]
fn expiring_in_any_order_never_breaks_the_others() {
    for seed in 0..12u64 {
        let mut rng = StdRng::seed_from_u64(200 + seed);
        let mut w = World::new(1);
        let a = w.id(0);
        let mut sw = SnapshotWriter::new(BACKUP, a);
        sw.rule.max_on_base = 3; // several bases in 8 snapshots
        let mut cur = listing(&mut rng, 30, a);
        let mut truth = BTreeMap::new();
        let n = 8u64;
        for i in 0..n {
            let p = format!("dir/f{:03}.txt", rng.gen_range(0..40));
            if rng.gen_bool(0.3) {
                cur.remove(&p);
            } else {
                cur.insert(p.clone(), file(&mut rng, &p, a));
            }
            take(&mut w, &mut sw, 0, &cur, i as i64, 1_000_000);
            truth.insert(i + 1, cur.clone());
        }
        let mut order: Vec<u64> = (1..=n).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.gen_range(0..=i));
        }
        let mut alive: Vec<u64> = (1..=n).collect();
        for s in order {
            expire(&mut w, 0, a, s);
            alive.retain(|x| *x != s);
            let gone = deletable(&w.trust.view.borrow(), &BACKUP, &a, 10);
            delete_records(&w.hot, &BACKUP, &a, &gone).unwrap();
            let mut bs = BackupSnapshots::new(BACKUP);
            pull(&w, &mut bs, 10);
            for k in &alive {
                assert_eq!(
                    bs.reconstruct(&a, *k).unwrap(),
                    truth[k],
                    "seed {seed}: snapshot {k} after expiring {s}"
                );
            }
            // Expired snapshots are not listed, whatever is retained.
            let listed: Vec<u64> = {
                let mut v: Vec<u64> = bs
                    .list(&w.trust.view.borrow(), 10)
                    .iter()
                    .map(|i| i.seq)
                    .collect();
                v.sort_unstable();
                v
            };
            assert_eq!(listed, alive, "seed {seed}");
        }
        assert_eq!(
            w.hot
                .names()
                .iter()
                .filter(|n| n.starts_with("snapshots/"))
                .count(),
            0,
            "seed {seed}: everything went with the last snapshot"
        );
    }
}

#[test]
fn a_snapshot_expires_by_its_time_without_a_mark_and_the_owner_owes_the_mark() {
    let mut rng = StdRng::seed_from_u64(8);
    let mut w = World::new(2);
    let (a, b) = (w.id(0), w.id(1));
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let cur = listing(&mut rng, 10, a);
    take(&mut w, &mut sw, 0, &cur, 0, 500);
    let mut cur2 = cur.clone();
    cur2.remove("dir/f000.txt");
    take(&mut w, &mut sw, 0, &cur2, 100, 900);
    let view = w.trust.view.borrow().clone();
    assert!(expiry_due(&view, &BACKUP, &a, 499).is_empty());
    assert_eq!(
        expiry_due(&view, &BACKUP, &a, 500),
        vec![SnapshotExpired {
            backup: BACKUP,
            device: a,
            seq: 1
        }]
    );
    assert_eq!(expiry_due(&view, &BACKUP, &a, 900).len(), 2);
    assert!(
        expiry_due(&view, &BACKUP, &b, 900).is_empty(),
        "only the owner's own"
    );
    // Past 500 snapshot 1 is not listed and not wanted by a new reader,
    // except as the base of snapshot 2.
    let mut bs = BackupSnapshots::new(BACKUP);
    assert_eq!(pull(&w, &mut bs, 600).loaded, 2);
    let list = bs.list(&view, 600);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].seq, 2);
    assert_eq!(bs.retained_bases(&view, 600), vec![(a, 1)]);
    assert!(bs.list(&view, 1000).is_empty());
    // Past 900 the ledger would also show both deletable.
    assert_eq!(deletable(&view, &BACKUP, &a, 1000), vec![1, 2]);
    assert_eq!(bs.forget_expired(&view, 1000), 2);
    assert!(bs.is_empty());
}

// ---- references -----------------------------------------------------------------------------

#[test]
fn references_include_unexpired_snapshots_and_exclude_expired_ones() {
    let mut rng = StdRng::seed_from_u64(9);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut sw = SnapshotWriter::new(BACKUP, a);
    let mut cur = listing(&mut rng, 50, a);
    let base_listing = cur.clone();
    take(&mut w, &mut sw, 0, &cur, 0, 100 * DAY); // 1: base
                                                  // 2: one file replaced, one removed.
    let replaced = "dir/f001.txt".to_string();
    let removed = "dir/f002.txt".to_string();
    cur.insert(replaced.clone(), file(&mut rng, &replaced, a));
    cur.remove(&removed);
    let listing2 = cur.clone();
    take(&mut w, &mut sw, 0, &cur, 1, 50 * DAY); // 2: differential
                                                 // 3: another file replaced.
    let replaced3 = "dir/f003.txt".to_string();
    cur.insert(replaced3.clone(), file(&mut rng, &replaced3, a));
    let listing3 = cur.clone();
    take(&mut w, &mut sw, 0, &cur, 2, 10 * DAY); // 3: differential
    let mut bs = BackupSnapshots::new(BACKUP);
    pull(&w, &mut bs, 5);
    let refs_at =
        |bs: &BackupSnapshots, w: &World, now| bs.reference_set(&w.trust.view.borrow(), now);
    let objs = |e: &FileEntry| e.objects().copied().collect::<Vec<_>>();

    // Everything unexpired: every file of every listing.
    let all = refs_at(&bs, &w, 5);
    for l in [&base_listing, &listing2, &listing3] {
        assert!(objects(l).iter().all(|o| all.contains(o)));
    }

    // Snapshot 3 ends (time): the file it replaced is still in the others.
    let r = refs_at(&bs, &w, 10 * DAY + 1);
    assert!(objects(&listing2).iter().all(|o| r.contains(o)));
    assert!(objects(&base_listing).iter().all(|o| r.contains(o)));
    assert!(
        objs(&listing3[&replaced3]).iter().all(|o| !r.contains(o)),
        "only snapshot 3 had it"
    );

    // The base expires (marked) while snapshot 2 lives: snapshot 2 needs
    // what it inherits, but not what it replaced or removed.
    expire(&mut w, 0, a, 1);
    let r = refs_at(&bs, &w, 10 * DAY + 1);
    assert!(objects(&listing2).iter().all(|o| r.contains(o)));
    assert!(objs(&base_listing[&replaced])
        .iter()
        .all(|o| !r.contains(o)));
    assert!(objs(&base_listing[&removed]).iter().all(|o| !r.contains(o)));
    assert!(objs(&base_listing["dir/f010.txt"])
        .iter()
        .all(|o| r.contains(o)));

    // Snapshot 2 ends too: nothing is referenced.
    let r = refs_at(&bs, &w, 50 * DAY + 1);
    assert!(r.is_empty());

    // With differentials 2 and 3 alive and the base expired, a base entry
    // that only one of them overrides is still needed by the other.
    let r = refs_at(&bs, &w, 5);
    assert!(
        objs(&base_listing[&replaced3])
            .iter()
            .all(|o| r.contains(o)),
        "snapshot 2 does not override f003"
    );
    assert!(
        objs(&base_listing[&replaced])
            .iter()
            .all(|o| !r.contains(o)),
        "both 2 and 3 override f001"
    );
}

// ---- fuzzing the parser ----------------------------------------------------------------------

#[test]
fn the_body_parser_survives_mutations() {
    let mut rng = StdRng::seed_from_u64(10);
    let a = [1; 16];
    let files: Vec<FileEntry> = (0..20)
        .map(|i| file(&mut rng, &format!("d/{i}"), a))
        .collect();
    let body = SnapshotBody::new(
        SnapHeader {
            backup: BACKUP,
            device: a,
            seq: 3,
            lamport: 3,
            taken_utc: 1,
            expires_utc: 2,
            base: 2,
        },
        files.iter(),
        ["x", "y"],
    );
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
                let ins: Vec<u8> = (0..rng.gen_range(1..16)).map(|_| rng.gen()).collect();
                m.splice(i..i, ins);
            }
            _ => {
                m = vec![0u8; rng.gen_range(0..400)];
                rng.fill_bytes(&mut m);
            }
        }
        if let Ok(b) = postcard::from_bytes::<SnapshotBody>(&m) {
            parsed += 1;
            let _ = b.validate();
            // Whatever parses can be offered to a reader without a panic.
            let mut bs = BackupSnapshots::new(BACKUP);
            let _ = bs.add(&b);
        }
        let z = zstd::bulk::compress(&m, 3).unwrap();
        if let Ok(b) = crate::record::envelope::decode_body::<SnapshotBody>(&z) {
            let _ = b.validate();
        }
    }
    assert!(parsed > 0, "some mutations still parse");
}
