// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The checks of a format-3 `fsck`.

use super::records::{RecordRef, RecordState};
use super::report::*;
use super::{
    find_class_len, list_packs, probe_len, Fsck3Input, Fsck3Options, LenProbe, PackCheck,
    PackVerdict, StorageDesc, ORPHAN_DAYS,
};
use crate::ledger3::events::class_bytes;
use crate::ledger3::{Hash32, LedgerView, PackId};
use crate::parverify::{lane_plan, run_ordered, Job, LanePlan, Parallelism};
use crate::record::Kind;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Most entries a list in the report keeps per folder; the rest is only
/// counted by the problem total ("at least").
const LIST_CAP: usize = 1000;

fn push_capped(v: &mut Vec<String>, s: String) {
    if v.len() < LIST_CAP {
        v.push(s);
    }
}

fn short(id: &[u8]) -> String {
    hex::encode(id)[..12.min(id.len() * 2)].to_string()
}

struct Copy<'a> {
    pack: PackId,
    desc: &'a StorageDesc<'a>,
    lane: usize,
    class_len: u64,
}

/// Compare the ledger view with the storages, the maps and the manifests.
pub fn fsck(input: &Fsck3Input, opts: &Fsck3Options) -> Result<Fsck3Report> {
    let view = input.view;
    let mut rep = Fsck3Report {
        verify: opts.verify,
        ..Default::default()
    };
    let by_name: BTreeMap<&str, (usize, &StorageDesc)> = input
        .storages
        .iter()
        .enumerate()
        .map(|(i, s)| (s.name.as_str(), (i, s)))
        .collect();

    // 1. What each storage holds under packs/.
    let mut listed: BTreeMap<&str, BTreeMap<PackId, String>> = BTreeMap::new();
    for s in input.storages {
        match list_packs(s.storage) {
            Ok(l) => {
                listed.insert(s.name.as_str(), l);
            }
            Err(e) => rep.storage_errors.push(StorageError {
                storage: s.name.clone(),
                detail: format!("cannot list packs: {e:#}"),
            }),
        }
    }

    // 2. Every claimed copy exists at its class length.
    let mut bad: HashSet<(PackId, String)> = HashSet::new();
    let mut unchecked: BTreeSet<String> = BTreeSet::new();
    let mut to_verify: Vec<Copy> = Vec::new();
    let mut ids: Vec<PackId> = view.packs.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        let rec = &view.packs[&id];
        let copies = view.copies(&id);
        if copies.is_empty() {
            continue;
        }
        rep.packs += 1;
        let hexid = hex::encode(id);
        for c in copies {
            rep.copies_claimed += 1;
            let Some(&(lane, desc)) = by_name.get(c.storage.as_str()) else {
                unchecked.insert(c.storage.clone());
                continue;
            };
            let Some(list) = listed.get(c.storage.as_str()) else {
                continue; // the listing failed: said in storage_errors
            };
            let issue = |detail: String| PackIssue {
                pack: hexid.clone(),
                storage: c.storage.clone(),
                detail,
            };
            let Some(class_len) = class_bytes(rec.class) else {
                rep.wrong_length.push(issue(format!(
                    "the ledger gives it class {}, which is no size class",
                    rec.class
                )));
                continue;
            };
            if rec.class > desc.max_class() {
                rep.wrong_length.push(issue(format!(
                    "class {} ({} bytes) is not allowed on a hot storage",
                    rec.class, class_len
                )));
            }
            if !list.contains_key(&id) {
                rep.missing_copies
                    .push(issue("claimed by the ledger, not on the storage".into()));
                bad.insert((id, c.storage.clone()));
                continue;
            }
            rep.copies_present += 1;
            match probe_len(desc.storage, &id, class_len) {
                Ok(LenProbe::Exact) => to_verify.push(Copy {
                    pack: id,
                    desc,
                    lane,
                    class_len,
                }),
                Ok(LenProbe::Longer) => {
                    rep.wrong_length
                        .push(issue(format!("longer than its class ({class_len} bytes)")));
                    bad.insert((id, c.storage.clone()));
                }
                Ok(LenProbe::Shorter) => {
                    rep.wrong_length
                        .push(issue(format!("shorter than its class ({class_len} bytes)")));
                    bad.insert((id, c.storage.clone()));
                }
                Ok(LenProbe::Missing) => {
                    rep.missing_copies
                        .push(issue("listed, but gone when read".into()));
                    bad.insert((id, c.storage.clone()));
                }
                Err(e) => rep.storage_errors.push(StorageError {
                    storage: c.storage.clone(),
                    detail: format!("pack {}: {e:#}", short(&id)),
                }),
            }
        }
    }

    // 3. Whole-pack verification through WP5's callback, in the lanes of
    // section 39.
    if opts.verify {
        let Some(verify) = input.verify_pack else {
            bail!("verification was asked for, but no verify_pack callback was given");
        };
        let lanes: Vec<LanePlan> = input
            .storages
            .iter()
            .map(|s| lane_plan(s.media, Parallelism::Auto))
            .collect();
        let jobs: Vec<Job<usize>> = to_verify
            .iter()
            .enumerate()
            .map(|(i, c)| Job {
                item: i,
                lane: c.lane,
                size: c.class_len,
            })
            .collect();
        run_ordered(
            &jobs,
            &lanes,
            |&i| {
                let c = &to_verify[i];
                verify(&PackCheck {
                    storage: &c.desc.name,
                    backend: c.desc.storage,
                    pack: c.pack,
                    class_len: c.class_len,
                })
            },
            |_, verdict| verdict,
            |_, &i, verdict| {
                let c = &to_verify[i];
                let issue = |detail: String| PackIssue {
                    pack: hex::encode(c.pack),
                    storage: c.desc.name.clone(),
                    detail,
                };
                match verdict {
                    PackVerdict::Ok => rep.copies_verified_now += 1,
                    PackVerdict::Corrupt(d) => {
                        rep.corrupt_copies.push(issue(d));
                        bad.insert((c.pack, c.desc.name.clone()));
                    }
                    PackVerdict::Missing => {
                        rep.missing_copies.push(issue("gone when read".into()));
                        bad.insert((c.pack, c.desc.name.clone()));
                    }
                    PackVerdict::Unreadable(d) => rep.verify_errors.push(issue(d)),
                }
                true
            },
        );
    }

    // 4. Maps: every place lies inside a known pack and class.
    let mut mapped: HashSet<PackId> = HashSet::new();
    for f in input.folders {
        let mut mf = MapFindings {
            folder: hex::encode(f.id),
            ..Default::default()
        };
        let mut pack_index: HashMap<PackId, u32> = HashMap::new();
        let mut unknown: HashSet<PackId> = HashSet::new();
        // (pack number, offset, length, first 8 bytes of the object)
        let mut spans: Vec<(u32, u32, u32, u64)> = Vec::new();
        for row in f.map.scan() {
            let row = row?;
            mf.places += 1;
            let pack = row.place.pack;
            let n = pack_index.len() as u32;
            let pi = *pack_index.entry(pack).or_insert(n);
            mapped.insert(pack);
            let name = format!("{}:{}+{}", short(&pack), row.place.offset, row.place.len);
            // The pack ends at the shorter of what the map and the ledger say.
            let limit = view
                .pack(&pack)
                .and_then(|r| class_bytes(r.class))
                .map_or(row.pack_len(), |l| l.min(row.pack_len()));
            if u64::from(row.place.offset) + u64::from(row.place.len) > limit {
                push_capped(&mut mf.outside_pack, name);
            }
            match view.pack(&pack) {
                None => {
                    if unknown.insert(pack) {
                        push_capped(
                            &mut mf.unknown_pack,
                            format!("{}: the ledger has no claim for it", short(&pack)),
                        );
                    }
                }
                Some(r) => {
                    if r.class != row.class {
                        push_capped(
                            &mut mf.class_mismatch,
                            format!(
                                "{}: the map says class {}, the ledger class {}",
                                short(&pack),
                                row.class,
                                r.class
                            ),
                        );
                    }
                    if let Some(owner) = view.pack_folder(&pack) {
                        if owner != f.id && unknown.insert(pack) {
                            push_capped(
                                &mut mf.unknown_pack,
                                format!(
                                    "{}: the ledger gives it to folder {}",
                                    short(&pack),
                                    short(&owner)
                                ),
                            );
                        }
                    }
                }
            }
            let obj8 = u64::from_le_bytes(row.object[..8].try_into().expect("8 bytes"));
            spans.push((pi, row.place.offset, row.place.len, obj8));
        }
        mf.packs = pack_index.len() as u64;
        let by_number: HashMap<u32, PackId> = pack_index.iter().map(|(p, n)| (*n, *p)).collect();
        spans.sort_unstable();
        let mut prev: Option<(u32, u32, u32, u64, u64)> = None; // pack, off, len, obj, end
        for s in spans {
            if let Some(p) = prev.filter(|p| p.0 == s.0 && u64::from(s.1) < p.4) {
                if !(p.1 == s.1 && p.2 == s.2 && p.3 == s.3) {
                    push_capped(
                        &mut mf.overlapping,
                        format!(
                            "{}: offset {} (length {}) lies inside the place at {} (length {})",
                            short(&by_number[&s.0]),
                            s.1,
                            s.2,
                            p.1,
                            p.2
                        ),
                    );
                }
            }
            let end = u64::from(s.1) + u64::from(s.2);
            prev = Some(match prev {
                Some(p) if p.0 == s.0 && p.4 > end => (s.0, s.1, s.2, s.3, p.4),
                _ => (s.0, s.1, s.2, s.3, end),
            });
        }
        // Packs the view gives to the folder that its applied maps do not
        // list (a map record not applied yet is not a finding).
        let mut unmapped: Vec<String> = view
            .packs
            .iter()
            .filter(|(id, r)| {
                !pack_index.contains_key(*id)
                    && r.map_seq != 0
                    && view.pack_folder(id) == Some(f.id)
                    && !view.holders(id).is_empty()
                    && view
                        .pack_writer(id)
                        .and_then(|w| f.map.marker(&w))
                        .is_some_and(|m| r.map_seq <= m.applied)
            })
            .map(|(id, _)| hex::encode(id))
            .collect();
        unmapped.sort();
        unmapped.truncate(LIST_CAP);
        mf.unmapped_packs = unmapped;
        rep.maps.push(mf);
    }

    // 5. Manifests: every referenced object has a live place.
    for f in input.folders {
        let objects = f.manifests.reference_set();
        let mut missing: HashSet<Hash32> = HashSet::new();
        let mut counts = BlockCounts::default();
        for object in &objects {
            counts.referenced += 1;
            match classify(view, f.map, &bad, object) {
                Place3::Live => counts.live += 1,
                Place3::OnlyMarked => counts.only_marked += 1,
                Place3::Missing => {
                    counts.missing += 1;
                    missing.insert(*object);
                }
            }
        }
        rep.blocks.referenced += counts.referenced;
        rep.blocks.live += counts.live;
        rep.blocks.only_marked += counts.only_marked;
        rep.blocks.missing += counts.missing;
        if missing.is_empty() {
            continue;
        }
        for (writer, v) in &f.manifests.views {
            for e in v.current() {
                let n = e
                    .chunks
                    .iter()
                    .filter(|c| missing.contains(&c.object))
                    .count();
                if n > 0 {
                    rep.damaged_files.push(DamagedFile {
                        folder: hex::encode(f.id),
                        writer: hex::encode(writer),
                        path: e.path.clone(),
                        blocks: e.chunks.len() as u64,
                        blocks_missing: n as u64,
                    });
                }
            }
        }
        for dev in &f.manifests.forked {
            rep.forked_streams.push(format!(
                "manifest stream of {} in folder {}",
                short(dev),
                short(&f.id)
            ));
        }
    }

    // 6. Orphans: packs on a storage that the ledger does not claim there.
    for (name, list) in &listed {
        let desc = by_name[name].1;
        for id in list.keys() {
            if view.is_held(id, name) {
                continue;
            }
            let kind = if view.dropped_from(id, name) {
                "dropped"
            } else if mapped.contains(id) {
                "mapped"
            } else if !view.holders(id).is_empty() {
                "claimed_elsewhere"
            } else {
                "unknown"
            };
            let age = input
                .modified_utc
                .and_then(|f| f(name, id))
                .map(|m| input.now_utc - m);
            rep.orphans.push(Orphan {
                storage: name.to_string(),
                pack: hex::encode(id),
                kind: kind.to_string(),
                bytes: find_class_len(desc.storage, id, desc.max_class())
                    .ok()
                    .flatten(),
                age_days: age.map(|a| a.max(0) / 86_400),
                gc_due: kind != "mapped" && age.is_some_and(|a| a >= ORPHAN_DAYS * 86_400),
            });
        }
    }

    // 7. Announced records are stored, complete and accepted.
    if let Some(probe) = input.records {
        check_records(input, probe, &mut rep);
    }

    // 8. Forks and refusals.
    rep.forked_devices = view.forked.iter().map(hex::encode).collect();
    for ((kind, scope, device), seq) in &view.forked_streams {
        rep.forked_streams.push(format!(
            "{} stream of {} in {}: two records at seq {seq}",
            Kind::from_code(*kind).map_or("?", Kind::name),
            short(device),
            short(scope)
        ));
    }
    if let Some(r) = input.refused {
        rep.records_refused = r.by_kind.clone();
    }
    rep.events_refused = view.events_refused;
    rep.events_unknown = view.events_unknown;
    rep.marks_refused = view.marks_refused;
    rep.unchecked_storages = unchecked.into_iter().collect();
    Ok(rep)
}

enum Place3 {
    Live,
    OnlyMarked,
    Missing,
}

/// An object has a live place when an unmarked place of it is in a pack
/// some storage really holds (claimed and not found bad).
fn classify(
    view: &LedgerView,
    table: &crate::blockmap::MapTable,
    bad: &HashSet<(PackId, String)>,
    object: &Hash32,
) -> Place3 {
    let rows = match table.rows_of(object) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("block map table {}: {e:#}", table.path().display());
            return Place3::Missing;
        }
    };
    let mut marked = false;
    for r in rows {
        let held = view
            .holders(&r.place.pack)
            .into_iter()
            .any(|s| !bad.contains(&(r.place.pack, s.to_string())));
        if !held {
            continue;
        }
        let dead = r.flagged_dead()
            || table
                .mark_state(&r.place.pack, r.place.offset)
                .map(|m| m.is_dead())
                .unwrap_or(false);
        if !dead {
            return Place3::Live;
        }
        marked = true;
    }
    if marked {
        Place3::OnlyMarked
    } else {
        Place3::Missing
    }
}

fn check_records(input: &Fsck3Input, probe: &dyn super::RecordProbe, rep: &mut Fsck3Report) {
    let view = input.view;
    for ((code, scope, device), stream) in &view.streams {
        let Some(kind) = Kind::from_code(*code).filter(|k| k.announced()) else {
            continue;
        };
        for (seq, ann) in &stream.records {
            rep.records.announced += 1;
            let rr = RecordRef {
                kind,
                scope: *scope,
                device: *device,
                seq: *seq,
                announced: *ann,
            };
            let mut states: Vec<(&str, RecordState)> = Vec::new();
            for s in input.storages.iter().filter(|s| s.meta) {
                match probe.probe(s.storage, &rr) {
                    Ok(st) => {
                        rep.records.checked += 1;
                        states.push((s.name.as_str(), st));
                    }
                    Err(e) => rep.storage_errors.push(StorageError {
                        storage: s.name.clone(),
                        detail: format!("{} {seq}: {e:#}", kind.name()),
                    }),
                }
            }
            let issue = |storage: &str, detail: String| RecordIssue {
                kind: kind.name().to_string(),
                scope: hex::encode(scope),
                device: hex::encode(device),
                seq: *seq,
                storage: storage.to_string(),
                detail,
            };
            let good = states
                .iter()
                .any(|(_, s)| matches!(s, RecordState::Accepted | RecordState::Present));
            let mut absent: Vec<&str> = Vec::new();
            for (name, st) in &states {
                match st {
                    RecordState::Accepted | RecordState::Present => {}
                    RecordState::Waiting => rep.records.waiting.push(issue(
                        name,
                        "waits for an announcement that is not accepted".into(),
                    )),
                    RecordState::Refused(why) => rep.records.refused.push(issue(name, why.clone())),
                    RecordState::Missing => absent.push(name),
                    RecordState::Incomplete { have, parts } => {
                        if good {
                            rep.records
                                .missing_on
                                .push(issue(name, format!("incomplete: {have} of {parts} parts")));
                        } else {
                            absent.push(name);
                        }
                    }
                }
            }
            if good {
                for n in absent {
                    rep.records
                        .missing_on
                        .push(issue(n, "not on this storage".into()));
                }
            } else if !absent.is_empty()
                && states.iter().all(|(_, s)| {
                    matches!(s, RecordState::Missing | RecordState::Incomplete { .. })
                })
            {
                rep.records.missing.push(issue(
                    &absent.join(","),
                    "announced by its batch, on no metadata storage".into(),
                ));
            }
        }
    }
}
