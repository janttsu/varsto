// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Garbage collection (section 3, "Garbage collection"): which places are
//! collectable, which packs are dropped, rewritten or compacted, and the
//! orphan rule.
//!
//! One run is one action: the new packs of rewrites and compactions are
//! written first, then one map delta lists their members, then one batch
//! carries `pack_stored` for the new packs, `record_published` for the
//! delta and `pack_dropped` for every pack that goes; it is pushed, and
//! only then are the old packs deleted.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{folder_pack, Commit, MapOut, References, Standing, StorageClass, Storages};
use crate::blockmap::{
    class_of_len, MapRow, MapTable, MapWriter, MarkKind, WrittenMember, WrittenPack,
};
use crate::ledger3::envelope::kind::BLOCK_MAP;
use crate::ledger3::events::{class_bytes, Event, PackOn};
use crate::ledger3::{DeviceBin, LedgerView, ObjectBin, PackId};
use crate::packs::{self, pack_key, pack_of_key};

/// Knobs of one run; the defaults are the design's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcOptions {
    /// Now (UTC seconds): cold minimum durations and the orphan rule.
    pub now_utc: i64,
    /// Hot packs of a smaller class are compacted once their live members
    /// fill this many bytes (64 MiB).
    pub compact_bytes: u64,
    /// An unclaimed pack no map lists goes after this long (7 days).
    pub orphan_secs: i64,
}

impl Default for GcOptions {
    fn default() -> Self {
        GcOptions {
            now_utc: crate::util::now_utc(),
            compact_bytes: super::COMPACT_BYTES,
            orphan_secs: super::ORPHAN_SECS,
        }
    }
}

/// What garbage collection makes of one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaceVerdict {
    /// No dead mark of a current writer (or a newer undead mark).
    Live,
    /// Dead-marked, but something references the object (the marking
    /// round publishes undead marks).
    Referenced,
    /// Dead-marked, unreferenced, the mark not settled: these writers have
    /// not acknowledged the marker's batch yet.
    Waiting(Vec<DeviceBin>),
    Collectable,
}

/// Section 3's "collectable" for this device: a settled dead mark (every
/// current writer of the folder acknowledged the marker's batch that
/// announced the mark's map record), no undead mark with a larger
/// (Lamport, device) stamp, and nothing references the object. Only marks
/// of current writers count; the second number is the dead marks of
/// others on the place (ignored).
pub fn place_verdict(
    table: &MapTable,
    view: &LedgerView,
    writers: &[DeviceBin],
    row: &MapRow,
    references: &dyn References,
) -> Result<(PlaceVerdict, u64)> {
    let folder = *table.folder();
    let marks = table.marks_at(&row.place.pack, row.place.offset)?;
    let ignored = marks
        .iter()
        .filter(|m| m.kind == MarkKind::Dead && !writers.contains(&m.marker))
        .count() as u64;
    let dead: Vec<_> = marks
        .iter()
        .filter(|m| {
            m.kind == MarkKind::Dead
                && writers.contains(&m.marker)
                && !marks
                    .iter()
                    .any(|u| u.kind == MarkKind::Undead && u.stamp() > m.stamp())
        })
        .collect();
    if dead.is_empty() {
        return Ok((PlaceVerdict::Live, ignored));
    }
    if references.is_referenced(&row.object) {
        return Ok((PlaceVerdict::Referenced, ignored));
    }
    let mut best: Option<Vec<DeviceBin>> = None;
    for m in dead {
        let waiting = match view.announced(BLOCK_MAP, &folder, &m.marker, m.map_seq) {
            Some(a) => view.settle_waiting_for(&folder, writers, &m.marker, a.batch),
            None => vec![m.marker],
        };
        if waiting.is_empty() {
            return Ok((PlaceVerdict::Collectable, ignored));
        }
        if best.as_ref().is_none_or(|b| waiting.len() < b.len()) {
            best = Some(waiting);
        }
    }
    Ok((PlaceVerdict::Waiting(best.unwrap_or_default()), ignored))
}

/// One pack of the folder as a run sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackState {
    pub id: PackId,
    pub class: u8,
    /// Storages holding it in the view.
    pub holders: Vec<String>,
    /// One row per member place, by offset, with its verdict.
    pub members: Vec<(MapRow, PlaceVerdict)>,
    pub member_bytes: u64,
    pub collectable_bytes: u64,
    /// The members follow one another from offset 0 (no member this table
    /// does not know is between them).
    pub complete: bool,
}

impl PackState {
    pub fn all_collectable(&self) -> bool {
        !self.members.is_empty() && self.collectable_bytes == self.member_bytes
    }
    pub fn live_bytes(&self) -> u64 {
        self.member_bytes - self.collectable_bytes
    }
}

/// What one run would do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcPlan {
    /// Packs every member of which is collectable: drop on these storages
    /// now.
    pub drops: Vec<(PackId, Vec<String>)>,
    /// Drops waiting for a cold storage's minimum duration: (pack,
    /// storage, UTC seconds from when it may go).
    pub drops_later: Vec<(PackId, String, i64)>,
    /// Hot packs with more than half their member bytes collectable.
    pub rewrites: Vec<PackId>,
    /// Groups of small hot packs (same storages) merged into full ones.
    pub compactions: Vec<Vec<PackId>>,
    /// Who settling waits for, with the number of places waiting on each:
    /// what `varsto status` shows ("collection waits for <device>").
    pub waiting: BTreeMap<DeviceBin, u64>,
    /// Writers whose announced reference records this device has not
    /// applied: nothing is collected until it has.
    pub behind: Vec<DeviceBin>,
    /// Dead marks of devices that are not current writers (ignored).
    pub marks_ignored: u64,
    /// Packs with a member this table does not list: left alone.
    pub incomplete: Vec<PackId>,
    pub packs: BTreeMap<PackId, PackState>,
}

/// Whether the members (offset, len) follow one another from 0.
fn complete(members: &BTreeMap<u32, MapRow>) -> bool {
    let mut at = 0u64;
    for (off, r) in members {
        if u64::from(*off) != at {
            return false;
        }
        at += u64::from(r.place.len);
    }
    true
}

/// Plan one run over the folder's packs in the view.
pub fn plan(
    table: &MapTable,
    view: &LedgerView,
    writers: &[DeviceBin],
    references: &dyn References,
    storages: &dyn Storages,
    opts: &GcOptions,
) -> Result<GcPlan> {
    let folder = *table.folder();
    let mut out = GcPlan {
        behind: references.behind(view, &folder, writers),
        ..Default::default()
    };
    if !out.behind.is_empty() {
        return Ok(out);
    }
    let mut by_pack: BTreeMap<PackId, (u8, BTreeMap<u32, MapRow>)> = BTreeMap::new();
    for row in table.scan() {
        let row = row?;
        if view.pack_folder(&row.place.pack) != Some(folder) {
            continue;
        }
        by_pack
            .entry(row.place.pack)
            .or_insert((row.class, BTreeMap::new()))
            .1
            .entry(row.place.offset)
            .or_insert(row);
    }
    for (id, (class, members)) in by_pack {
        let holders: Vec<String> = view.holders(&id).into_iter().map(str::to_string).collect();
        if holders.is_empty() {
            continue;
        }
        let mut st = PackState {
            id,
            class,
            holders,
            members: Vec::with_capacity(members.len()),
            member_bytes: 0,
            collectable_bytes: 0,
            complete: complete(&members),
        };
        for row in members.values() {
            let (v, ignored) = place_verdict(table, view, writers, row, references)?;
            out.marks_ignored += ignored;
            let len = u64::from(row.place.len);
            st.member_bytes += len;
            match &v {
                PlaceVerdict::Collectable => st.collectable_bytes += len,
                PlaceVerdict::Waiting(w) => {
                    for d in w {
                        *out.waiting.entry(*d).or_default() += 1;
                    }
                }
                _ => {}
            }
            st.members.push((*row, v));
        }
        out.packs.insert(id, st);
    }
    // Compaction candidates per set of holders: (live bytes, packs).
    let mut small: BTreeMap<Vec<String>, (u64, Vec<PackId>)> = BTreeMap::new();
    for st in out.packs.values() {
        if !st.complete {
            out.incomplete.push(st.id);
            continue;
        }
        let all_hot = st
            .holders
            .iter()
            .all(|s| storages.info(s).class == StorageClass::Hot);
        if st.all_collectable() {
            let mut now = Vec::new();
            for s in &st.holders {
                let info = storages.info(s);
                let stored = view
                    .copies(&st.id)
                    .into_iter()
                    .find(|c| &c.storage == s)
                    .map_or(0, |c| c.stored_utc);
                match info.minimum_secs {
                    Some(min)
                        if info.class == StorageClass::Cold && opts.now_utc < stored + min =>
                    {
                        out.drops_later.push((st.id, s.clone(), stored + min));
                    }
                    _ => now.push(s.clone()),
                }
            }
            if !now.is_empty() {
                out.drops.push((st.id, now));
            }
        } else if all_hot && st.collectable_bytes * 2 > st.member_bytes {
            out.rewrites.push(st.id);
        } else if all_hot
            && class_bytes(st.class).is_some_and(|b| b < opts.compact_bytes)
            && st.live_bytes() > 0
        {
            let e = small.entry(st.holders.clone()).or_default();
            e.0 += st.live_bytes();
            e.1.push(st.id);
        }
    }
    for (_, (live, ids)) in small {
        if live >= opts.compact_bytes && ids.len() > 1 {
            out.compactions.push(ids);
        }
    }
    Ok(out)
}

/// What one run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// This device may not collect in the folder (members, viewers, K3
    /// only): nothing was done.
    pub refused: bool,
    /// Packs dropped whole, and (pack, storage) drops sealed.
    pub packs_dropped: u64,
    pub drops: u64,
    pub packs_rewritten: u64,
    pub packs_compacted: u64,
    /// New packs written for rewrites and compactions.
    pub packs_written: u64,
    pub blocks_moved: u64,
    pub bytes_moved: u64,
    /// Bytes of packs deleted from storages.
    pub bytes_freed: u64,
    /// The map record of the new places (0: none).
    pub map_seq: u64,
    pub plan_waiting: BTreeMap<DeviceBin, u64>,
    pub behind: Vec<DeviceBin>,
    pub drops_later: Vec<(PackId, String, i64)>,
    pub marks_ignored: u64,
    /// Packs that failed their id or a member check while being rewritten
    /// (left for verification and repair), and deletions that failed
    /// (the orphan sweep deletes them later: the drop is sealed).
    pub unreadable: Vec<PackId>,
    pub delete_failed: Vec<(PackId, String)>,
}

/// A live member read out of an old pack.
struct Moved {
    row: MapRow,
    bytes: Vec<u8>,
}

/// Read packs (one GET each, id checked) and their live members (each
/// checked against its name). Packs that fail are left out and reported.
fn read_live(
    states: &[&PackState],
    storages: &dyn Storages,
    unreadable: &mut Vec<PackId>,
) -> Result<(Vec<PackId>, Vec<Moved>)> {
    let mut read = Vec::new();
    let mut moved = Vec::new();
    let mut objects: BTreeSet<ObjectBin> = BTreeSet::new();
    'packs: for st in states {
        let size = class_bytes(st.class).unwrap_or(0);
        let mut bytes = None;
        for h in &st.holders {
            let Some(s) = storages.open(h) else { continue };
            match s.get_bounded(&pack_key(&hex::encode(st.id)), size) {
                Ok(Some(b)) => {
                    bytes = Some(b);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!(storage = h.as_str(); "gc: read pack {}: {e:#}", hex::encode(st.id))
                }
            }
        }
        let Some(bytes) = bytes else {
            unreadable.push(st.id);
            continue;
        };
        if bytes.len() as u64 != size || crate::crypto::hash(&bytes) != st.id {
            unreadable.push(st.id);
            continue;
        }
        let mut here = Vec::new();
        for (row, v) in &st.members {
            if *v == PlaceVerdict::Collectable {
                continue;
            }
            let (o, l) = (row.place.offset as usize, row.place.len as usize);
            let Some(b) = bytes.get(o..o + l) else {
                unreadable.push(st.id);
                continue 'packs;
            };
            if crate::crypto::hash(b) != row.object {
                unreadable.push(st.id);
                continue 'packs;
            }
            here.push(Moved {
                row: *row,
                bytes: b.to_vec(),
            });
        }
        read.push(st.id);
        for m in here {
            if objects.insert(m.row.object) {
                moved.push(m);
            }
        }
    }
    Ok((read, moved))
}

/// Build padded packs of `moved` (first-fit decreasing up to `target`'s
/// top class) and write each to every storage of `to`.
pub(crate) fn write_packs(
    moved: &[(MapRow, &[u8])],
    to: &[String],
    target: usize,
    storages: &dyn Storages,
) -> Result<Vec<WrittenPack>> {
    let sizes: Vec<usize> = moved.iter().map(|(_, b)| b.len()).collect();
    let mut out = Vec::new();
    for bin in packs::first_fit_decreasing(&sizes, packs::top_class(target).min(target)) {
        let group: Vec<(String, &[u8])> = bin
            .iter()
            .map(|&i| (hex::encode(moved[i].0.object), moved[i].1))
            .collect();
        let (id_hex, data, locs) = packs::build(&group, target);
        let mut id = [0u8; 32];
        hex::decode_to_slice(&id_hex, &mut id)?;
        let class = class_of_len(data.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("a pack of {} bytes", data.len()))?;
        for s in to {
            let st = storages
                .open(s)
                .ok_or_else(|| anyhow::anyhow!("storage {s} is not reachable"))?;
            st.put_if_absent(&pack_key(&id_hex), &data)?;
        }
        let members = bin
            .iter()
            .zip(locs)
            .map(|(&i, (_, l))| {
                let r = &moved[i].0;
                WrittenMember {
                    object: r.object,
                    chunk: r.chunk,
                    offset: l.offset as u32,
                    len: l.len as u32,
                    plain_len: r.plain_len,
                    epoch: r.epoch,
                }
            })
            .collect();
        out.push(WrittenPack {
            id,
            class,
            storages: to.to_vec(),
            members,
        });
    }
    Ok(out)
}

/// One garbage collection run of the folder of `table`: drops, rewrites
/// and compaction as `plan` finds them, as one action (new packs, one map
/// delta, one batch, then the deletes). Runs only where `standing` may
/// collect.
#[allow(clippy::too_many_arguments)]
pub fn collect(
    standing: &Standing,
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    storages: &dyn Storages,
    references: &dyn References,
    writers: &[DeviceBin],
    sink: &mut dyn Commit,
    opts: &GcOptions,
) -> Result<GcReport> {
    let mut report = GcReport::default();
    if !standing.may_collect()
        || writer.device != standing.device
        || writer.folder != *table.folder()
    {
        report.refused = true;
        return Ok(report);
    }
    let plan = plan(table, view, writers, references, storages, opts)?;
    report.plan_waiting = plan.waiting.clone();
    report.behind = plan.behind.clone();
    report.drops_later = plan.drops_later.clone();
    report.marks_ignored = plan.marks_ignored;

    let mut events: Vec<Event> = Vec::new();
    // (pack, storage, bytes) to delete once the batch is pushed.
    let mut deletes: Vec<(PackId, String, u64)> = Vec::new();
    let mut drop_on = |id: PackId, holders: &[String], size: u64, events: &mut Vec<Event>| {
        for s in holders {
            events.push(Event::PackDropped(PackOn {
                storage: s.clone(),
                pack: id,
            }));
            deletes.push((id, s.clone(), size));
        }
    };

    for (id, on) in &plan.drops {
        let reachable: Vec<String> = on
            .iter()
            .filter(|s| storages.open(s).is_some())
            .cloned()
            .collect();
        if reachable.is_empty() {
            continue;
        }
        let size = plan
            .packs
            .get(id)
            .and_then(|p| class_bytes(p.class))
            .unwrap_or(0);
        drop_on(*id, &reachable, size, &mut events);
        report.packs_dropped += 1;
    }

    let mut new_packs: Vec<WrittenPack> = Vec::new();
    let groups = plan
        .rewrites
        .iter()
        .map(|id| (vec![*id], false))
        .chain(plan.compactions.iter().map(|g| (g.clone(), true)));
    for (ids, compaction) in groups {
        let states: Vec<&PackState> = ids.iter().filter_map(|id| plan.packs.get(id)).collect();
        let Some(first) = states.first() else {
            continue;
        };
        let holders = first.holders.clone();
        if holders.iter().any(|s| storages.open(s).is_none()) {
            continue;
        }
        let (read, moved) = read_live(&states, storages, &mut report.unreadable)?;
        if read.is_empty() || (compaction && read.len() < 2) {
            continue;
        }
        let refs: Vec<(MapRow, &[u8])> = moved.iter().map(|m| (m.row, &m.bytes[..])).collect();
        let written = write_packs(&refs, &holders, crate::packs::HOT_TARGET, storages)?;
        report.packs_written += written.len() as u64;
        report.blocks_moved += moved.len() as u64;
        report.bytes_moved += moved.iter().map(|m| m.bytes.len() as u64).sum::<u64>();
        for id in &read {
            let size = plan
                .packs
                .get(id)
                .and_then(|p| class_bytes(p.class))
                .unwrap_or(0);
            drop_on(*id, &holders, size, &mut events);
        }
        if compaction {
            report.packs_compacted += read.len() as u64;
        } else {
            report.packs_rewritten += read.len() as u64;
        }
        new_packs.extend(written);
    }

    if events.is_empty() {
        return Ok(report);
    }
    let mut publish = None;
    if !new_packs.is_empty() {
        let lamport = sink.tick();
        let p = writer.publish(out.writer, out.meta, &new_packs, lamport, Some(table), view)?;
        let mut all = p.events.clone();
        all.append(&mut events);
        events = all;
        report.map_seq = p.body.seq;
        publish = Some(p);
    }
    report.drops = events
        .iter()
        .filter(|e| matches!(e, Event::PackDropped(_)))
        .count() as u64;
    if let Err(e) = sink.commit(events) {
        if let Some(p) = &publish {
            *writer =
                MapWriter::from_view(writer.folder, writer.device, writer.epoch, view, p.body.seq);
        }
        return Err(e);
    }
    if let Some(p) = &publish {
        p.apply_to(table, &folder_pack(view, writer.folder))?;
    }
    for (id, s, size) in deletes {
        let Some(st) = storages.open(&s) else {
            report.delete_failed.push((id, s));
            continue;
        };
        match st.delete(&pack_key(&hex::encode(id))) {
            Ok(()) => report.bytes_freed += size,
            Err(e) => {
                log::warn!(storage = s.as_str(); "gc: delete pack {}: {e:#}", hex::encode(id));
                report.delete_failed.push((id, s));
            }
        }
    }
    Ok(report)
}

/// When each pack no claim and no map names was first seen, per storage
/// (kept by the caller between runs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanState {
    /// (storage, pack id hex) -> UTC seconds first seen.
    pub first_seen: BTreeMap<String, BTreeMap<String, i64>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrphanReport {
    /// Unclaimed packs no map lists, deleted after the orphan time.
    pub orphans_deleted: u64,
    /// Packs the view shows dropped from the storage, still there (a
    /// crash between the batch and the delete): deleted.
    pub leftovers_deleted: u64,
    /// Unclaimed packs still within the orphan time.
    pub orphans_waiting: u64,
    pub skipped: Vec<String>,
}

/// The orphan rule: a pack on one of `names` that the view does not show
/// held there and no map table of `tables` lists is deleted once it was
/// first seen `opts.orphan_secs` ago; a pack the view shows deliberately
/// dropped there goes at once. Runs only on own full devices with write
/// role (`standing` of any folder this device collects).
pub fn collect_orphans(
    standing: &Standing,
    storages: &dyn Storages,
    names: &[String],
    view: &LedgerView,
    tables: &[&MapTable],
    state: &mut OrphanState,
    opts: &GcOptions,
) -> Result<OrphanReport> {
    let mut report = OrphanReport::default();
    if !standing.may_collect() {
        return Ok(report);
    }
    let mut listed: BTreeSet<PackId> = BTreeSet::new();
    for t in tables {
        listed.extend(t.packs().iter().map(|p| p.id));
    }
    for name in names {
        let Some(s) = storages.open(name) else {
            report.skipped.push(name.clone());
            continue;
        };
        let keys = match s.list(packs::PREFIX) {
            Ok(k) => k,
            Err(e) => {
                report.skipped.push(format!("{name}: {e:#}"));
                continue;
            }
        };
        let seen = state.first_seen.entry(name.clone()).or_default();
        let mut present: BTreeSet<String> = BTreeSet::new();
        for key in keys {
            let Some(hex_id) = pack_of_key(&key) else {
                continue;
            };
            let mut id = [0u8; 32];
            if hex::decode_to_slice(hex_id, &mut id).is_err() {
                continue;
            }
            if view.is_held(&id, name) {
                continue;
            }
            if view.dropped_from(&id, name) {
                if s.delete(&key).is_ok() {
                    report.leftovers_deleted += 1;
                }
                continue;
            }
            if listed.contains(&id) {
                continue;
            }
            present.insert(hex_id.to_string());
            let first = *seen.entry(hex_id.to_string()).or_insert(opts.now_utc);
            if opts.now_utc - first >= opts.orphan_secs {
                if s.delete(&key).is_ok() {
                    report.orphans_deleted += 1;
                    present.remove(hex_id);
                }
            } else {
                report.orphans_waiting += 1;
            }
        }
        seen.retain(|k, _| present.contains(k));
    }
    Ok(report)
}
