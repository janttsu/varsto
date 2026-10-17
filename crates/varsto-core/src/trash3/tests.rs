// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of format-3 trash, history and settings: the body and its limits,
//! base + delta reconstruction against a full-state reference over random
//! sequences, the merge rules, expiry, references, pruning and parser
//! fuzzing.

use super::testkit::{meta_key, World, FOLDER};
use super::*;
use crate::ledger3::EventScope;
use crate::manifest3::{BaseRule, Chunk3, PruneState};
use crate::record::{Kind, RecordWriter, RecordsRefused};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};

const DAY: i64 = 86_400;

fn h32(rng: &mut StdRng) -> Hash32 {
    let mut b = [0; 32];
    rng.fill_bytes(&mut b);
    b
}

fn chunks(rng: &mut StdRng) -> Vec<Chunk3> {
    (0..rng.gen_range(0..4))
        .map(|_| Chunk3 {
            chunk: h32(rng),
            object: h32(rng),
            size: rng.gen_range(1..5000),
            epoch: rng.gen_range(0..2),
        })
        .collect()
}

/// An entry written by `device` for `path` at `clock`, deleted at `utc`.
fn entry(rng: &mut StdRng, device: Id16, path: &str, clock: u64, utc: i64) -> Entry {
    let chunks = chunks(rng);
    Entry::new(
        &FOLDER,
        path,
        chunks.iter().map(|c| c.size).sum(),
        rng.gen(),
        h32(rng),
        chunks,
        utc,
        device,
        clock,
        Some(device),
    )
}

fn removal(id: Id16, restored: bool, lamport: u64, utc: i64, deleted_utc: i64) -> Removal {
    Removal {
        id,
        utc,
        restored,
        deleted_utc,
        lamport,
    }
}

fn body(device: Id16, seq: u64, base: u64) -> TrashBody {
    TrashBody {
        folder: FOLDER,
        device,
        seq,
        lamport: 100,
        created_utc: 0,
        base,
        prev: if seq == 1 { [0; 32] } else { [5; 32] },
        entries: Vec::new(),
        removals: Vec::new(),
        versions: Vec::new(),
        forget: Vec::new(),
    }
}

fn snapshot(entries: &[&Entry], removals: &[&Removal], versions: &[&Entry]) -> TrashSnapshot {
    TrashSnapshot {
        entries: entries.iter().map(|e| (e.id, (*e).clone())).collect(),
        removals: removals.iter().map(|r| (r.id, (*r).clone())).collect(),
        versions: versions.iter().map(|e| (e.id, (*e).clone())).collect(),
    }
}

fn pull(w: &World, ft: &mut FolderTrash, me: &Id16) -> crate::manifest3::PullReport {
    let mut counter = RecordsRefused::default();
    let view = w.trust.view.borrow();
    ft.pull(&w.store(&w.hot), &view, me, &mut counter).unwrap()
}

fn publish(
    w: &mut World,
    tw: &mut TrashWriter,
    i: usize,
    cur: &TrashSnapshot,
    lamport: u64,
) -> Option<(Pending, u64)> {
    let p = w.with_writer(i, |rw| {
        tw.seal(rw, &meta_key(FOLDER), cur, lamport, 0).unwrap()
    })?;
    let b = w.publish_sealed(i, &p.sealed, Vec::new());
    tw.commit(p.clone());
    Some((p, b))
}

// ---- record: round trip and limits ----------------------------------------

#[test]
fn a_body_round_trips_through_a_sealed_record() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut w = World::new(2);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    let mut cur = TrashSnapshot::default();
    for i in 0..40u64 {
        let e = entry(
            &mut rng,
            a,
            &format!("docs/f{i}.txt"),
            i + 1,
            1000 + i as i64,
        );
        if i % 3 == 0 {
            cur.versions.insert(e.id, e.clone());
        }
        if i % 5 == 0 {
            let r = removal(e.id, i % 2 == 0, i, 2000, 1000);
            cur.removals.insert(r.id, r);
        }
        cur.entries.insert(e.id, e);
    }
    let (p, _) = publish(&mut w, &mut tw, 0, &cur, 100).unwrap();
    assert!(p.is_base);
    assert_eq!(p.sealed.parts.len(), 1);
    assert_eq!(
        p.sealed.parts[0].0,
        format!(
            "trash/{}/{}/0000000000000001-0000.rec",
            hex::encode(FOLDER),
            hex::encode(a)
        )
    );
    let mut ft = FolderTrash::new(FOLDER);
    let r = pull(&w, &mut ft, &w.id(1));
    assert_eq!(r.applied, 1);
    assert_eq!(ft.devices[&a].state, cur);
    // Nothing changed: nothing to publish, nothing to pull.
    assert!(publish(&mut w, &mut tw, 0, &cur, 101).is_none());
    assert!(ft.wanted(&w.trust.view.borrow(), &w.id(1)).is_empty());
}

#[test]
fn entries_recompute_their_ids_and_pass_the_manifest_checks() {
    let mut rng = StdRng::seed_from_u64(2);
    let a = [1; 16];
    let good = entry(&mut rng, a, "a/b.txt", 3, 10);
    assert!(good.validate(&FOLDER, &a).is_ok());
    // The same entry in a stream of another writer.
    assert!(good
        .validate(&FOLDER, &[2; 16])
        .unwrap_err()
        .contains("deletion"));
    // A moved entry (another folder, path or clock) no longer recomputes.
    assert!(good
        .validate(&[9; 16], &a)
        .unwrap_err()
        .contains("recompute"));
    let mut e = good.clone();
    e.path = "other.txt".into();
    assert!(e.validate(&FOLDER, &a).unwrap_err().contains("recompute"));
    let mut e = good.clone();
    e.clock += 1;
    assert!(e.validate(&FOLDER, &a).unwrap_err().contains("recompute"));
    // Paths and sizes.
    let bad_path = Entry::new(&FOLDER, "../x", 0, 0, [0; 32], vec![], 0, a, 1, None);
    assert!(bad_path.validate(&FOLDER, &a).is_err());
    let long = Entry::new(
        &FOLDER,
        &"a/".repeat(3000),
        0,
        0,
        [0; 32],
        vec![],
        0,
        a,
        1,
        None,
    );
    assert!(long.validate(&FOLDER, &a).unwrap_err().contains("path"));
    let mut e = good.clone();
    e.size += 1;
    assert!(e.validate(&FOLDER, &a).unwrap_err().contains("bytes"));
    let mut e = entry(&mut rng, a, "z", 4, 0);
    e.chunks.push(Chunk3 {
        chunk: [0; 32],
        object: [0; 32],
        size: 0,
        epoch: 0,
    });
    assert!(e.validate(&FOLDER, &a).unwrap_err().contains("chunk"));
}

#[test]
fn bodies_outside_the_limits_are_refused() {
    let mut rng = StdRng::seed_from_u64(3);
    let a = [1; 16];
    let e = entry(&mut rng, a, "ok.txt", 1, 5);
    let mut good = body(a, 2, 1);
    good.entries.push(e.clone());
    good.versions.push(entry(&mut rng, a, "v.txt", 2, 6));
    good.removals.push(removal([7; 16], true, 3, 5, 4));
    good.forget.push([8; 16]);
    assert!(good.validate().is_ok());
    let refused = |b: &TrashBody| b.validate().unwrap_err();

    let mut b = good.clone();
    b.seq = 0;
    assert!(refused(&b).contains("seq"));
    let mut b = good.clone();
    b.base = 3;
    assert!(refused(&b).contains("base"));
    let mut b = good.clone();
    b.base = 0;
    assert!(refused(&b).contains("base"));
    let mut b = body(a, 1, 1);
    b.prev = [1; 32];
    assert!(refused(&b).contains("predecessor"));
    let mut b = good.clone();
    b.base = 2;
    assert!(refused(&b).contains("forgets"), "a base forgets nothing");
    let mut b = good.clone();
    b.entries.push(e.clone());
    assert!(refused(&b).contains("twice"));
    let mut b = good.clone();
    b.versions.push(b.versions[0].clone());
    assert!(refused(&b).contains("twice"));
    let mut b = good.clone();
    b.removals.push(b.removals[0].clone());
    assert!(refused(&b).contains("twice"));
    let mut b = good.clone();
    b.forget.push(b.forget[0]);
    assert!(refused(&b).contains("twice"));
    let mut b = good.clone();
    b.removals[0].lamport = 101;
    assert!(refused(&b).contains("future"));
    // An entry of another writer.
    let mut b = good.clone();
    b.entries[0] = entry(&mut rng, [2; 16], "x", 1, 0);
    assert!(refused(&b).contains("deletion"));

    // The record's own check: scope, device and seq must be the envelope's.
    use crate::record::{KeyId, RecordBody, RecordMeta};
    let meta = |scope, device, seq| RecordMeta {
        kind: Kind::Trash,
        vault: [0; 16],
        scope,
        device,
        seq,
        parts: 1,
        key_id: KeyId::Meta {
            folder: FOLDER,
            epoch: 0,
        },
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    assert!(good.check(&meta(FOLDER, a, 2)).is_ok());
    assert!(good.check(&meta([9; 16], a, 2)).is_err());
    assert!(good.check(&meta(FOLDER, [2; 16], 2)).is_err());
    assert!(good.check(&meta(FOLDER, a, 3)).is_err());
}

#[test]
fn a_foreign_entry_in_a_sealed_record_is_refused_on_read() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut w = World::new(2);
    let (a, b) = (w.id(0), w.id(1));
    // Device a seals b's deletion into its own stream.
    let mut cur = TrashSnapshot::default();
    let foreign = entry(&mut rng, b, "x.txt", 1, 0);
    cur.entries.insert(foreign.id, foreign);
    let tw = TrashWriter::new(FOLDER, a);
    // The writer does not check (the reader does): seal and publish.
    let p = w.with_writer(0, |rw| {
        tw.seal(rw, &meta_key(FOLDER), &cur, 1, 0).unwrap().unwrap()
    });
    w.publish_sealed(0, &p.sealed, Vec::new());
    let mut ft = FolderTrash::new(FOLDER);
    let mut counter = RecordsRefused::default();
    let view = w.trust.view.borrow();
    let r = ft.pull(&w.store(&w.hot), &view, &b, &mut counter).unwrap();
    assert_eq!(r.applied, 0);
    assert_eq!(r.refused.len(), 1);
    assert_eq!(counter.get(Kind::Trash), 1);
    assert!(ft.devices.is_empty());
}

// ---- base and delta ---------------------------------------------------------

#[test]
fn the_default_base_rule_is_the_manifests() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    assert_eq!(tw.rule, BaseRule::default());
    let mut cur = TrashSnapshot::default();
    let mut bases = Vec::new();
    for i in 0..140u64 {
        let e = entry(&mut rng, a, &format!("f{i}"), i + 1, 10);
        cur.entries.insert(e.id, e);
        let (p, _) = publish(&mut w, &mut tw, 0, &cur, i + 1).unwrap();
        if p.is_base {
            bases.push(p.sealed.published.seq);
        }
    }
    // Every record is padded to 64 KiB, so the size condition holds as soon
    // as the 64-delta condition does: bases at 1, 65 and 129 (base + 63
    // deltas, then a base, test 12 of the design).
    assert_eq!(bases, vec![1, 65, 129]);
}

#[test]
fn the_size_condition_and_the_forced_base() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    // A huge divisor: the deltas never hold enough bytes; only the forced
    // base at 6 records ends the chain.
    tw.rule = BaseRule {
        min_deltas: 2,
        size_divisor: 0,
        max_deltas: 6,
    };
    let mut cur = TrashSnapshot::default();
    let mut bases = Vec::new();
    for i in 0..14u64 {
        let e = entry(&mut rng, a, &format!("f{i}"), i + 1, 10);
        cur.entries.insert(e.id, e);
        let (p, _) = publish(&mut w, &mut tw, 0, &cur, i + 1).unwrap();
        if p.is_base {
            bases.push(p.sealed.published.seq);
        }
    }
    assert_eq!(bases, vec![1, 7, 13]);
    // A divisor of 1: the first record past the minimum is a base.
    let mut tw = TrashWriter::new(FOLDER, [9; 16]);
    tw.rule = BaseRule {
        min_deltas: 3,
        size_divisor: 1,
        max_deltas: 1024,
    };
    assert!(tw.rule.is_base(3, 100, 100));
    assert!(!tw.rule.is_base(2, 100, 100));
    assert!(!tw.rule.is_base(3, 100, 99));
}

#[test]
fn a_lost_seq_makes_the_next_record_a_base() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    let mut cur = TrashSnapshot::default();
    let e = entry(&mut rng, a, "one", 1, 10);
    cur.entries.insert(e.id, e);
    publish(&mut w, &mut tw, 0, &cur, 1).unwrap();
    let e = entry(&mut rng, a, "two", 2, 10);
    cur.entries.insert(e.id, e);
    let p = w.with_writer(0, |rw| {
        tw.seal(rw, &meta_key(FOLDER), &cur, 2, 0).unwrap().unwrap()
    });
    assert!(!p.is_base);
    tw.abandon(p);
    let (p, _) = publish(&mut w, &mut tw, 0, &cur, 3).unwrap();
    assert!(p.is_base);
    assert_eq!(p.sealed.published.seq, 3);
    // A restart finds seq 3 on the storages and starts a base after it.
    let mut again = TrashWriter::new(FOLDER, a);
    again.resume(3);
    let e = entry(&mut rng, a, "three", 3, 10);
    cur.entries.insert(e.id, e);
    let (p, _) = publish(&mut w, &mut again, 0, &cur, 4).unwrap();
    assert!(p.is_base && p.sealed.published.seq == 4);
}

#[test]
fn forgetting_one_list_keeps_the_id_in_the_others() {
    let mut rng = StdRng::seed_from_u64(8);
    let a = [1; 16];
    let e = entry(&mut rng, a, "x", 1, 0);
    let r = removal(e.id, false, 4, 5, 0);
    let before = snapshot(&[&e], &[&r], &[&e]);
    // The entry and the version go, the removal stays.
    let after = snapshot(&[], &[&r], &[]);
    let d = before.diff_to(&after);
    assert_eq!(d.forget, vec![e.id]);
    assert_eq!(d.removals, vec![r.clone()], "listed again after the forget");
    let mut b = body(a, 2, 1);
    b.entries = d.entries;
    b.removals = d.removals;
    b.versions = d.versions;
    b.forget = d.forget;
    let mut applied = before.clone();
    applied.apply_delta(&b);
    assert_eq!(applied, after);
    // And the other way round.
    let after = snapshot(&[&e], &[], &[&e]);
    let d = before.diff_to(&after);
    let mut b = body(a, 2, 1);
    b.entries = d.entries;
    b.removals = d.removals;
    b.versions = d.versions;
    b.forget = d.forget;
    let mut applied = before;
    applied.apply_delta(&b);
    assert_eq!(applied, after);
}

// ---- random sequences against a full-state reference --------------------------

/// The full-state reference of the merge: every item of every device's
/// whole record, no base or delta anywhere.
fn reference_sets(
    states: &[(Id16, &TrashSnapshot)],
    now: i64,
    settings: &Settings,
) -> (
    BTreeSet<Id16>,
    BTreeSet<Id16>,
    BTreeSet<Id16>,
    BTreeSet<Id16>,
) {
    let days = i64::from(settings.trash_days_for(&FOLDER));
    let mut visible = BTreeSet::new();
    let mut gone = BTreeSet::new();
    let mut restored = BTreeSet::new();
    let mut seen: BTreeMap<Id16, &Entry> = BTreeMap::new();
    let mut removals: Vec<(Id16, (u64, bool, Id16), bool)> = Vec::new();
    for (dev, s) in states {
        for e in s.entries.values() {
            seen.entry(e.id).or_insert(e);
        }
        for r in s.removals.values() {
            removals.push((r.id, (r.lamport, !r.restored, *dev), r.restored));
        }
    }
    for (id, e) in seen {
        let winner = removals
            .iter()
            .filter(|(i, _, _)| *i == id)
            .max_by_key(|(_, k, _)| *k);
        match winner {
            Some((_, _, true)) => restored.insert(id),
            Some((_, _, false)) => gone.insert(id),
            None if now >= e.deleted_utc + days * DAY => gone.insert(id),
            None => visible.insert(id),
        };
    }
    // The history: each path's versions thinned by the shared function.
    let mut by_path: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    let mut all_versions: BTreeMap<Id16, &Entry> = BTreeMap::new();
    for (_, s) in states {
        for e in s.versions.values() {
            all_versions.entry(e.id).or_insert(e);
        }
    }
    for e in all_versions.values() {
        by_path.entry(&e.path).or_default().push(e);
    }
    let mut kept = BTreeSet::new();
    for (_, list) in by_path {
        let ids: Vec<String> = list.iter().map(|e| hex::encode(e.id)).collect();
        let keys: Vec<(i64, u64, &str)> = list
            .iter()
            .zip(&ids)
            .map(|(e, i)| (e.deleted_utc, e.clock, i.as_str()))
            .collect();
        let k = crate::engine::history_kept(&keys, now, settings.history_keep_days(&FOLDER));
        for (e, k) in list.iter().zip(k) {
            if k {
                kept.insert(e.id);
            }
        }
    }
    (visible, gone, restored, kept)
}

#[test]
fn base_plus_delta_equals_the_full_state_over_random_sequences() {
    for seed in 0..3u64 {
        let mut rng = StdRng::seed_from_u64(100 + seed);
        let mut w = World::new(3);
        let ids: Vec<Id16> = (0..3).map(|i| w.id(i)).collect();
        let mut writers: Vec<TrashWriter> =
            ids.iter().map(|d| TrashWriter::new(FOLDER, *d)).collect();
        for tw in &mut writers {
            tw.rule = BaseRule {
                min_deltas: 3,
                size_divisor: 16,
                max_deltas: 9,
            };
        }
        let mut cur: Vec<TrashSnapshot> = vec![TrashSnapshot::default(); 3];
        let mut clock = [0u64; 3];
        let mut lamport = 0u64;
        let reader = [9u8; 16];
        let mut persistent = FolderTrash::new(FOLDER);
        for step in 0..180 {
            let d = rng.gen_range(0..3);
            lamport += 1;
            match rng.gen_range(0..10) {
                0..=2 => {
                    clock[d] += 1;
                    let path = format!("p{}", rng.gen_range(0..6));
                    let e = entry(&mut rng, ids[d], &path, clock[d], step * 100);
                    cur[d].entries.insert(e.id, e);
                }
                3 | 4 => {
                    clock[d] += 1;
                    let path = format!("p{}", rng.gen_range(0..6));
                    let e = entry(&mut rng, ids[d], &path, clock[d], step * 100);
                    cur[d].versions.insert(e.id, e);
                }
                5 | 6 => {
                    // A restore or a purge of any entry anyone lists.
                    let all: Vec<Id16> =
                        cur.iter().flat_map(|s| s.entries.keys().copied()).collect();
                    if !all.is_empty() {
                        let id = all[rng.gen_range(0..all.len())];
                        cur[d]
                            .removals
                            .insert(id, removal(id, rng.gen(), lamport, step * 100, 0));
                    }
                }
                _ => {
                    // The writer forgets something (entry, removal or version).
                    let s = &mut cur[d];
                    match rng.gen_range(0..3) {
                        0 => {
                            if let Some(k) = s.entries.keys().next().copied() {
                                s.entries.remove(&k);
                            }
                        }
                        1 => {
                            if let Some(k) = s.removals.keys().next().copied() {
                                s.removals.remove(&k);
                            }
                        }
                        _ => {
                            if let Some(k) = s.versions.keys().next().copied() {
                                s.versions.remove(&k);
                            }
                        }
                    }
                }
            }
            if rng.gen_bool(0.6) {
                let st = cur[d].clone();
                publish(&mut w, &mut writers[d], d, &st, lamport);
            }
            if rng.gen_bool(0.1) {
                pull(&w, &mut persistent, &reader);
                // A reader that joins now converges to the same state.
                let mut fresh = FolderTrash::new(FOLDER);
                pull(&w, &mut fresh, &reader);
                for i in 0..3 {
                    assert_eq!(
                        persistent.devices.get(&ids[i]).map(|v| (&v.state, v.seq)),
                        fresh.devices.get(&ids[i]).map(|v| (&v.state, v.seq)),
                        "seed {seed} step {step}"
                    );
                    assert_eq!(
                        persistent.devices.get(&ids[i]).map(|v| &v.state),
                        (writers[i].seq > 0).then_some(&writers[i].published),
                        "seed {seed} step {step} device {i}"
                    );
                }
            }
        }
        for i in 0..3 {
            let st = cur[i].clone();
            publish(&mut w, &mut writers[i], i, &st, lamport + 1);
        }
        pull(&w, &mut persistent, &reader);
        let states: Vec<(Id16, &TrashSnapshot)> = (0..3)
            .filter(|i| writers[*i].seq > 0)
            .map(|i| (ids[i], &cur[i]))
            .collect();
        for i in 0..3 {
            if writers[i].seq > 0 {
                assert_eq!(persistent.devices[&ids[i]].state, cur[i], "seed {seed}");
            }
        }
        // The merge of the reconstructed records equals the merge of the
        // full states, at several times and with other days.
        let custom = Settings {
            trash_days: 3,
            history_days: 20,
            ..Settings::default()
        };
        for settings in [Settings::default(), custom] {
            for now in [0, 5_000, 12 * DAY, 40 * DAY, 400 * DAY] {
                let sets = persistent.sets(now, &settings, &Trust::default());
                let (v, g, r, k) = reference_sets(&states, now, &settings);
                let ids_of = |l: &[Entry]| l.iter().map(|e| e.id).collect::<BTreeSet<_>>();
                assert_eq!(ids_of(&sets.visible), v, "seed {seed} now {now}");
                assert_eq!(ids_of(&sets.gone), g, "seed {seed} now {now}");
                assert_eq!(ids_of(&sets.restored), r, "seed {seed} now {now}");
                assert_eq!(ids_of(&sets.versions), k, "seed {seed} now {now}");
            }
        }
    }
}

#[test]
fn a_reader_that_joins_at_any_point_converges() {
    let mut rng = StdRng::seed_from_u64(9);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    tw.rule = BaseRule {
        min_deltas: 2,
        size_divisor: 0,
        max_deltas: 4,
    };
    let mut cur = TrashSnapshot::default();
    let mut readers: Vec<FolderTrash> = Vec::new();
    for i in 0..13u64 {
        let e = entry(&mut rng, a, &format!("f{i}"), i + 1, 5);
        cur.entries.insert(e.id, e);
        if i % 4 == 3 {
            // Forget an old one every few records.
            let k = *cur.entries.keys().next().unwrap();
            cur.entries.remove(&k);
        }
        publish(&mut w, &mut tw, 0, &cur, i + 1).unwrap();
        let mut r = FolderTrash::new(FOLDER);
        pull(&w, &mut r, &[9; 16]);
        readers.push(r);
        assert_eq!(readers.last().unwrap().devices[&a].state, cur);
    }
    for r in &readers {
        assert_eq!(
            r.devices[&a].seq,
            readers.last().unwrap().devices[&a]
                .seq
                .min(r.devices[&a].seq)
        );
    }
    // A reader that fell behind skips to the newest base.
    let mut lag = readers[2].clone();
    let want = lag.wanted(&w.trust.view.borrow(), &[9; 16]);
    assert_eq!(want.len(), 1);
    pull(&w, &mut lag, &[9; 16]);
    assert_eq!(lag.devices[&a].state, cur);
}

// ---- merge, expiry, references ----------------------------------------------

fn pulled(w: &World, tw: &[(Id16, TrashSnapshot)]) -> FolderTrash {
    // Publish nothing here; helper for tests that set up the world first.
    let _ = tw;
    let mut ft = FolderTrash::new(FOLDER);
    pull(w, &mut ft, &[9; 16]);
    ft
}

#[test]
fn entries_expire_by_the_trash_days_of_the_vault_and_the_folder() {
    let mut rng = StdRng::seed_from_u64(10);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    let e = entry(&mut rng, a, "gone.txt", 1, 1_000);
    let mut cur = TrashSnapshot::default();
    cur.entries.insert(e.id, e.clone());
    publish(&mut w, &mut tw, 0, &cur, 1).unwrap();
    let ft = pulled(&w, &[]);
    let trust = Trust::default();
    let sets = |now, s: &Settings| ft.sets(now, s, &trust);
    let d30 = Settings::default();
    assert_eq!(sets(1_000 + 30 * DAY - 1, &d30).visible.len(), 1);
    assert_eq!(sets(1_000 + 30 * DAY, &d30).visible.len(), 0);
    assert_eq!(sets(1_000 + 30 * DAY, &d30).gone.len(), 1);
    // The vault's days.
    let d5 = Settings {
        trash_days: 5,
        ..Settings::default()
    };
    assert_eq!(sets(1_000 + 5 * DAY - 1, &d5).visible.len(), 1);
    assert_eq!(sets(1_000 + 5 * DAY, &d5).gone.len(), 1);
    // The folder's own days win over the vault's.
    let mut own = d30.clone();
    own.folder_trash_days.insert(FOLDER, 90);
    assert_eq!(sets(1_000 + 60 * DAY, &own).visible.len(), 1);
    let mut other = d30.clone();
    other.folder_trash_days.insert([4; 16], 1);
    assert_eq!(
        sets(1_000 + 2 * DAY, &other).visible.len(),
        1,
        "another folder's days"
    );
}

#[test]
fn history_versions_are_thinned_and_expire_by_the_history_days() {
    let mut rng = StdRng::seed_from_u64(11);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    let mut cur = TrashSnapshot::default();
    let t0 = 10_000_000i64;
    // Ten versions of one path, a minute apart.
    for i in 0..10u64 {
        let e = entry(&mut rng, a, "doc.txt", i + 1, t0 + 60 * i as i64);
        cur.versions.insert(e.id, e);
    }
    publish(&mut w, &mut tw, 0, &cur, 1).unwrap();
    let ft = pulled(&w, &[]);
    let trust = Trust::default();
    let s = Settings::default();
    // Within an hour every version is kept.
    assert_eq!(ft.sets(t0 + 600, &s, &trust).versions.len(), 10);
    // Two hours on, one per clock hour: the newest of the bucket.
    let thinned = ft.sets(t0 + 2 * 3600 + 700, &s, &trust).versions;
    assert!(thinned.len() < 10 && !thinned.is_empty());
    // Past the history days nothing is kept.
    assert!(ft.sets(t0 + 91 * DAY, &s, &trust).versions.is_empty());
    let short = Settings {
        history_days: 2,
        ..Settings::default()
    };
    assert!(ft.sets(t0 + 3 * DAY, &short, &trust).versions.is_empty());
    // A vault with the history off keeps the versions already there on
    // the default schedule.
    let off = Settings {
        history_days: 0,
        ..Settings::default()
    };
    assert_eq!(off.history_days_for(&FOLDER), None);
    assert_eq!(ft.sets(t0 + 600, &off, &trust).versions.len(), 10);
    assert!(ft.sets(t0 + 91 * DAY, &off, &trust).versions.is_empty());
    // A version this device let go is never kept again.
    let mut ft2 = ft.clone();
    let any = *cur.versions.keys().next().unwrap();
    ft2.let_go.insert(any);
    assert_eq!(ft2.sets(t0 + 600, &s, &trust).versions.len(), 9);
    assert_eq!(ft2.sets(t0 + 600, &s, &trust).versions_gone.len(), 1);
}

#[test]
fn restore_against_purge_is_decided_by_lamport_time() {
    let mut rng = StdRng::seed_from_u64(12);
    let (a, b, c) = ([1; 16], [2; 16], [3; 16]);
    let e = entry(&mut rng, a, "x.txt", 1, 100);
    let mut sa = TrashSnapshot::default();
    sa.entries.insert(e.id, e.clone());
    let kind_of = |sets: &TrashSets| {
        if !sets.visible.is_empty() {
            "visible"
        } else if !sets.restored.is_empty() {
            "restored"
        } else {
            "purged"
        }
    };
    let run = |w: &mut World, rb: Removal, rc: Removal| {
        let mut sb = TrashSnapshot::default();
        sb.removals.insert(rb.id, rb);
        let mut sc = TrashSnapshot::default();
        sc.removals.insert(rc.id, rc);
        let mut twb = TrashWriter::new(FOLDER, b);
        let mut twc = TrashWriter::new(FOLDER, c);
        publish(w, &mut twb, 1, &sb, 50).unwrap();
        publish(w, &mut twc, 2, &sc, 50).unwrap();
        let ft = pulled(w, &[]);
        kind_of(&ft.sets(200, &Settings::default(), &Trust::default()))
    };
    // B restores at 7, C purges at 9: the purge is the later decision.
    let mut w1 = World::new(3);
    let mut tw1 = TrashWriter::new(FOLDER, a);
    publish(&mut w1, &mut tw1, 0, &sa, 1).unwrap();
    assert_eq!(
        run(
            &mut w1,
            removal(e.id, true, 7, 150, 100),
            removal(e.id, false, 9, 150, 100)
        ),
        "purged"
    );
    // The other way round: the restore is later.
    let mut w2 = World::new(3);
    let mut tw2 = TrashWriter::new(FOLDER, a);
    publish(&mut w2, &mut tw2, 0, &sa, 1).unwrap();
    assert_eq!(
        run(
            &mut w2,
            removal(e.id, true, 9, 150, 100),
            removal(e.id, false, 7, 150, 100)
        ),
        "restored"
    );
    // Concurrent (equal Lamport time): the purge wins.
    let mut w3 = World::new(3);
    let mut tw3 = TrashWriter::new(FOLDER, a);
    publish(&mut w3, &mut tw3, 0, &sa, 1).unwrap();
    assert_eq!(
        run(
            &mut w3,
            removal(e.id, true, 8, 150, 100),
            removal(e.id, false, 8, 150, 100)
        ),
        "purged"
    );
}

#[test]
fn removals_of_members_do_not_count_and_revoked_devices_are_ignored() {
    let mut rng = StdRng::seed_from_u64(13);
    let mut w = World::new(3);
    let (a, b, c) = (w.id(0), w.id(1), w.id(2));
    let e = entry(&mut rng, a, "x.txt", 1, 100);
    let mut sa = TrashSnapshot::default();
    sa.entries.insert(e.id, e.clone());
    let mut twa = TrashWriter::new(FOLDER, a);
    publish(&mut w, &mut twa, 0, &sa, 1).unwrap();
    let mut sb = TrashSnapshot::default();
    sb.removals.insert(e.id, removal(e.id, false, 5, 150, 100));
    let mut twb = TrashWriter::new(FOLDER, b);
    publish(&mut w, &mut twb, 1, &sb, 5).unwrap();
    // C is a revoked device that also wrote a deletion.
    let e2 = entry(&mut rng, c, "y.txt", 1, 100);
    let mut sc = TrashSnapshot::default();
    sc.entries.insert(e2.id, e2);
    let mut twc = TrashWriter::new(FOLDER, c);
    publish(&mut w, &mut twc, 2, &sc, 1).unwrap();
    let ft = pulled(&w, &[]);
    let s = Settings::default();
    let plain = ft.sets(200, &s, &Trust::default());
    assert_eq!(plain.gone.len(), 1);
    assert_eq!(plain.visible.len(), 1);
    // B is a member of a shared folder: its removal does not count on the
    // owner's devices, its deletions would.
    let t = Trust {
        no_removals: BTreeSet::from([b]),
        ..Trust::default()
    };
    let s1 = ft.sets(200, &s, &t);
    assert_eq!(s1.visible.len(), 2);
    assert!(s1.gone.is_empty());
    // C revoked: nothing of it counts.
    let t = Trust {
        ignore: BTreeSet::from([c]),
        ..Trust::default()
    };
    let s2 = ft.sets(200, &s, &t);
    assert_eq!((s2.visible.len(), s2.gone.len()), (0, 1));
}

#[test]
fn references_include_unexpired_trash_and_history_and_exclude_the_rest() {
    let mut rng = StdRng::seed_from_u64(14);
    let mut w = World::new(1);
    let a = w.id(0);
    let mut tw = TrashWriter::new(FOLDER, a);
    let t0 = 1_000_000i64;
    let live = entry(&mut rng, a, "live.txt", 1, t0);
    let old = entry(&mut rng, a, "old.txt", 2, t0 - 40 * DAY);
    let purged = entry(&mut rng, a, "purged.txt", 3, t0);
    let restored = entry(&mut rng, a, "restored.txt", 4, t0);
    let ver_new = entry(&mut rng, a, "v.txt", 5, t0 - 60);
    let ver_old = entry(&mut rng, a, "v.txt", 6, t0 - 100 * DAY);
    let mut cur = TrashSnapshot::default();
    for e in [&live, &old, &purged, &restored] {
        cur.entries.insert(e.id, e.clone());
    }
    cur.versions.insert(ver_new.id, ver_new.clone());
    cur.versions.insert(ver_old.id, ver_old.clone());
    cur.removals
        .insert(purged.id, removal(purged.id, false, 3, t0, t0));
    cur.removals
        .insert(restored.id, removal(restored.id, true, 4, t0, t0));
    publish(&mut w, &mut tw, 0, &cur, 10).unwrap();
    let ft = pulled(&w, &[]);
    let refs = ft.reference_set(t0 + 10, &Settings::default(), &Trust::default());
    let objs = |e: &Entry| e.objects().copied().collect::<Vec<_>>();
    for o in objs(&live).iter().chain(&objs(&ver_new)) {
        assert!(
            refs.contains(o),
            "unexpired trash and history are referenced"
        );
    }
    for o in objs(&old)
        .iter()
        .chain(&objs(&purged))
        .chain(&objs(&restored))
        .chain(&objs(&ver_old))
    {
        assert!(
            !refs.contains(o),
            "expired, purged, restored and aged-out are not"
        );
    }
    // Time passes: the live entry expires too.
    let later = ft.reference_set(t0 + 31 * DAY, &Settings::default(), &Trust::default());
    assert!(objs(&live).iter().all(|o| !later.contains(o)));
    assert!(objs(&ver_new).iter().all(|o| later.contains(o)));
}

// ---- forgetting (the 7 days past expiry rule) -----------------------------------

#[test]
fn the_record_forgets_seven_days_past_the_expiry() {
    let mut rng = StdRng::seed_from_u64(15);
    let a = [1; 16];
    let t0 = 1_000i64;
    let e = entry(&mut rng, a, "x", 1, t0);
    let r = removal(e.id, false, 2, t0 + 5, t0);
    let v = entry(&mut rng, a, "y", 2, t0);
    let own = snapshot(&[&e], &[&r], &[&v]);
    let s = Settings::default();
    let keep = 30 * DAY + KEEP_LISTED_SECS;
    let at =
        |now, gone: &BTreeMap<Id16, i64>| FolderTrash::forgetting(&own, now, &s, &FOLDER, gone);
    let none = BTreeMap::new();
    assert_eq!(at(t0 + keep - 1, &none), own);
    let after = at(t0 + keep, &none);
    assert!(after.entries.is_empty() && after.removals.is_empty());
    assert_eq!(
        after.versions.len(),
        1,
        "a version waits until it was let go"
    );
    // A version let go is forgotten seven days after it was first seen go.
    let gone = BTreeMap::from([(v.id, 500)]);
    assert_eq!(at(500 + KEEP_LISTED_SECS - 1, &gone).versions.len(), 1);
    assert!(at(500 + KEEP_LISTED_SECS, &gone).versions.is_empty());
}

// ---- pruning ----------------------------------------------------------------------

#[test]
fn pruning_waits_for_every_reader() {
    let mut rng = StdRng::seed_from_u64(16);
    let mut w = World::new(3);
    let mut tw = TrashWriter::new(FOLDER, w.id(0));
    tw.rule = BaseRule {
        min_deltas: 3,
        size_divisor: 16,
        max_deltas: 1024,
    };
    let (a, b, m) = (w.id(0), w.id(1), w.id(2));
    let readers = [a, b, m];
    let mut cur = TrashSnapshot::default();
    let mut base_batch = 0;
    for i in 0..5u64 {
        let e = entry(&mut rng, a, &format!("f{i}"), i + 1, 10);
        cur.entries.insert(e.id, e);
        let (p, batch) = publish(&mut w, &mut tw, 0, &cur, i + 1).unwrap();
        if p.is_base {
            base_batch = batch;
        }
    }
    let count =
        |s: &super::testkit::Mem| s.names().iter().filter(|n| n.starts_with("trash/")).count();
    assert_eq!(count(&w.hot), 5);
    assert_eq!(base_batch, 4);
    let floor = |w: &World| prune_floor(&w.trust.view.borrow(), &FOLDER, &a, &readers);
    assert_eq!(floor(&w), None);
    assert_eq!(
        readers_waiting(&w.trust.view.borrow(), &FOLDER, &a, &readers),
        vec![b, m]
    );
    w.ack(1, 0, base_batch, EventScope::Full);
    assert_eq!(floor(&w), None, "the member has not");
    w.ack(2, 0, base_batch - 1, EventScope::Member(FOLDER));
    assert_eq!(floor(&w), None, "an older acknowledgement does not count");
    w.ack(2, 0, base_batch, EventScope::Member(FOLDER));
    assert_eq!(floor(&w), Some(4));

    let mut state = PruneState::default();
    let empty = super::testkit::Mem::named("other");
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
    assert_eq!(count(&w.hot), 2);
    assert_eq!(count(&w.cold), 5, "cold storages are never pruned");
    // A reader that joins now reads the base and its delta.
    let mut fresh = FolderTrash::new(FOLDER);
    pull(&w, &mut fresh, &b);
    assert_eq!(fresh.devices[&a].state, cur);
}

// ---- settings -------------------------------------------------------------------------

#[test]
fn settings_round_trip_and_the_newest_record_wins() {
    let w = World::new(2);
    let (a, b) = (w.id(0), w.id(1));
    let key = crate::record::KeyId::Registry(0);
    let mut sa = SettingsBody::defaults(a, 1);
    sa.updated_utc = 100;
    sa.trash_days = 10;
    sa.history_days = 0;
    sa.trash_storage = Some("cold-1".into());
    sa.storage_id = Some("id-1".into());
    sa.folder_trash_days = vec![([1; 16], 5), ([2; 16], 7)];
    sa.folder_history_days = vec![([3; 16], 0)];
    let mut sb = SettingsBody::defaults(b, 1);
    sb.updated_utc = 200;
    sb.trash_days = 20;
    for (i, body) in [(0, &sa), (1, &sb)] {
        let p = w.with_writer(i, |rw| {
            rw.seal(&settings_stream(w.id(i)), 1, 1, &key, body)
                .unwrap()
        });
        RecordWriter::publish(&w.hot, &p).unwrap();
    }
    let mut counter = RecordsRefused::default();
    let got = Settings::read(&w.store(&w.hot), &[a, b], &mut counter).unwrap();
    assert_eq!(got.trash_days, 20, "b wrote last");
    let got_a = Settings::read(&w.store(&w.hot), &[a], &mut counter).unwrap();
    assert_eq!(Settings::from(&sa), got_a);
    assert_eq!(got_a.trash_days_for(&[1; 16]), 5);
    assert_eq!(got_a.trash_days_for(&[9; 16]), 10);
    assert_eq!(got_a.history_days_for(&[3; 16]), None);
    assert_eq!(got_a.history_days_for(&[9; 16]), None, "the vault is off");
    assert_eq!(got_a.history_keep_days(&[9; 16]), DEFAULT_HISTORY_DAYS);
    // No record: the defaults.
    let none = Settings::read(&w.store(&w.cold), &[a, b], &mut counter).unwrap();
    assert_eq!(none, Settings::default());
    assert_eq!(none.trash_days_for(&FOLDER), 30);
    assert_eq!(none.history_days_for(&FOLDER), Some(90));
    // A newer record of the same device wins.
    let mut sa2 = sa.clone();
    sa2.seq = 2;
    sa2.updated_utc = 300;
    sa2.trash_days = 99;
    let p = w.with_writer(0, |rw| {
        rw.seal(&settings_stream(a), 2, 2, &key, &sa2).unwrap()
    });
    RecordWriter::publish(&w.hot, &p).unwrap();
    let got = Settings::read(&w.store(&w.hot), &[a, b], &mut counter).unwrap();
    assert_eq!(got.trash_days, 99);
    assert_eq!(counter.total(), 0);
}

#[test]
fn settings_outside_the_limits_are_refused() {
    let a = [1; 16];
    let good = SettingsBody::defaults(a, 1);
    assert!(good.validate().is_ok());
    let bad = |f: &dyn Fn(&mut SettingsBody)| {
        let mut b = good.clone();
        f(&mut b);
        b.validate().unwrap_err()
    };
    assert!(bad(&|b| b.seq = 0).contains("seq"));
    assert!(bad(&|b| b.trash_days = 0).contains("trash days"));
    assert!(bad(&|b| b.trash_days = 3651).contains("trash days"));
    assert!(bad(&|b| b.history_days = 3651).contains("history days"));
    assert!(bad(&|b| b.folder_trash_days = vec![([2; 16], 1), ([1; 16], 1)]).contains("sorted"));
    assert!(bad(&|b| b.folder_trash_days = vec![([1; 16], 1), ([1; 16], 1)]).contains("sorted"));
    assert!(bad(&|b| b.folder_trash_days = vec![([1; 16], 0)]).contains("0 trash"));
    assert!(bad(&|b| b.folder_history_days = vec![([1; 16], 4000)]).contains("longest"));
    assert!(bad(&|b| b.trash_storage = Some("x".repeat(2000))).contains("storage"));
    // Check against the envelope: vault-wide scope, the writer, the seq.
    use crate::record::{KeyId, RecordBody, RecordMeta};
    let meta = |scope, device, seq| RecordMeta {
        kind: Kind::Settings,
        vault: [0; 16],
        scope,
        device,
        seq,
        parts: 1,
        key_id: KeyId::Registry(0),
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    assert!(good.check(&meta([0; 16], a, 1)).is_ok());
    assert!(good.check(&meta(FOLDER, a, 1)).is_err());
    assert!(good.check(&meta([0; 16], [2; 16], 1)).is_err());
    assert!(good.check(&meta([0; 16], a, 2)).is_err());
}

// ---- fuzzing the parsers ----------------------------------------------------------------

fn mutate(rng: &mut StdRng, plain: &[u8], round: usize) -> Vec<u8> {
    let mut m = plain.to_vec();
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
    m
}

/// The trash and settings parsers never panic on mutated or random input,
/// and whatever they accept passes or fails `validate` cleanly.
#[test]
fn the_body_parsers_survive_mutations() {
    let mut rng = StdRng::seed_from_u64(17);
    let a = [1; 16];
    let mut b = body(a, 3, 2);
    for i in 0..12u64 {
        b.entries
            .push(entry(&mut rng, a, &format!("d/{i}"), i + 1, 5));
        b.versions
            .push(entry(&mut rng, a, &format!("v/{i}"), 100 + i, 6));
        b.removals.push(removal([i as u8; 16], i % 2 == 0, i, 7, 5));
        b.forget.push([200 + i as u8; 16]);
    }
    let trash_plain = postcard::to_stdvec(&b).unwrap();
    let mut sb = SettingsBody::defaults(a, 2);
    sb.trash_storage = Some("s".into());
    sb.folder_trash_days = vec![([1; 16], 3), ([2; 16], 4)];
    let settings_plain = postcard::to_stdvec(&sb).unwrap();
    let (mut parsed_t, mut parsed_s) = (0, 0);
    for round in 0..4000 {
        let m = mutate(&mut rng, &trash_plain, round);
        if let Ok(b) = postcard::from_bytes::<TrashBody>(&m) {
            parsed_t += 1;
            let _ = b.validate();
        }
        let z = zstd::bulk::compress(&m, 3).unwrap();
        if let Ok(b) = crate::record::envelope::decode_body::<TrashBody>(&z) {
            let _ = b.validate();
        }
        let m = mutate(&mut rng, &settings_plain, round);
        if let Ok(b) = postcard::from_bytes::<SettingsBody>(&m) {
            parsed_s += 1;
            let _ = b.validate();
        }
        let z = zstd::bulk::compress(&m, 3).unwrap();
        if let Ok(b) = crate::record::envelope::decode_body::<SettingsBody>(&z) {
            let _ = b.validate();
        }
    }
    assert!(parsed_t > 0 && parsed_s > 0, "some mutations still parse");
}

/// A reader never panics on a stream of random deltas and bases either:
/// every outcome is Ok, Stale, Gap, Forked or Bad.
#[test]
fn applying_random_records_never_panics() {
    let mut rng = StdRng::seed_from_u64(18);
    let a = [1; 16];
    let mut dt = DeviceTrash::new(a);
    for _ in 0..500 {
        let seq = rng.gen_range(0..8);
        let base = rng.gen_range(0..9);
        let mut b = body(a, seq, base);
        b.prev = if rng.gen() { dt.hash } else { [3; 32] };
        for i in 0..rng.gen_range(0..3) {
            let clock = rng.gen_range(0..4);
            b.entries
                .push(entry(&mut rng, a, &format!("p{i}"), clock, 1));
        }
        if rng.gen_bool(0.3) {
            b.forget.push([rng.gen_range(0..4); 16]);
        }
        let _ = dt.apply(&b, h32(&mut rng));
    }
}

// ---- combined references --------------------------------------------------------------------

#[test]
fn the_combined_predicate_is_the_union() {
    use crate::manifest3::{FileEntry, FolderManifests, ManifestWriter};
    let mut rng = StdRng::seed_from_u64(19);
    let mut w = World::new(2);
    let a = w.id(0);
    // A manifest with one current file.
    let chunk = Chunk3 {
        chunk: h32(&mut rng),
        object: h32(&mut rng),
        size: 10,
        epoch: 0,
    };
    let file = FileEntry {
        path: "cur.txt".into(),
        version: BTreeMap::from([(a, 1)]),
        deleted: false,
        size: 10,
        mtime: 0,
        content_hash: Some(h32(&mut rng)),
        chunks: vec![chunk],
        modified_by: a,
        modified_clock: 1,
        meta: None,
        chunking: 2,
        held: true,
    };
    let mw = ManifestWriter::new(FOLDER, a);
    let view: BTreeMap<String, FileEntry> = BTreeMap::from([(file.path.clone(), file.clone())]);
    let p = w.with_writer(0, |rw| {
        mw.seal(rw, &meta_key(FOLDER), &view, 1, 0)
            .unwrap()
            .unwrap()
    });
    w.publish_sealed(0, &p.sealed, Vec::new());
    // A trash entry and a history version.
    let t0 = 5_000_000i64;
    let trashed = entry(&mut rng, a, "trashed.txt", 2, t0);
    let version = entry(&mut rng, a, "ver.txt", 3, t0);
    let expired = entry(&mut rng, a, "expired.txt", 4, t0 - 50 * DAY);
    let mut cur = TrashSnapshot::default();
    cur.entries.insert(trashed.id, trashed.clone());
    cur.entries.insert(expired.id, expired.clone());
    cur.versions.insert(version.id, version.clone());
    let mut tw = TrashWriter::new(FOLDER, a);
    publish(&mut w, &mut tw, 0, &cur, 2).unwrap();

    let me = [9; 16];
    let mut fm = FolderManifests::new(FOLDER);
    {
        let mut counter = RecordsRefused::default();
        let v = w.trust.view.borrow();
        fm.pull(&w.store(&w.hot), &v, &me, &mut counter).unwrap();
    }
    let ft = pulled(&w, &[]);
    let settings = Settings::default();
    let trust = Trust::default();
    let refs = Refs {
        manifests: Some(&fm),
        trash: Some((&ft, &settings, &trust)),
        snapshots: None,
        now: t0 + 60,
    };
    let is_ref = all(&refs);
    assert!(is_ref(&chunk.object), "a current file");
    for e in [&trashed, &version] {
        assert!(e.objects().all(&is_ref), "unexpired trash and history");
    }
    assert!(expired.objects().all(|o| !is_ref(o)), "an expired entry");
    assert!(!is_ref(&[0xee; 32]));
    // Without the trash part only the manifests count.
    let only = Refs {
        trash: None,
        ..refs
    };
    let is_ref = all(&only);
    assert!(is_ref(&chunk.object));
    assert!(trashed.objects().all(|o| !is_ref(o)));
    // Time moves on: the trash entry expires, the manifest's file stays.
    let later = Refs {
        now: t0 + 31 * DAY,
        trash: Some((&ft, &settings, &trust)),
        ..only
    };
    let is_ref = all(&later);
    assert!(is_ref(&chunk.object));
    assert!(trashed.objects().all(|o| !is_ref(o)));
    assert!(version.objects().all(&is_ref), "the version has 90 days");
}
