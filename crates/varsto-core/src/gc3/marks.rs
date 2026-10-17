// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Dead and undead marks (section 3, "Dead marks, settling and
//! collection", "Who may mark"): a writer of the folder that finds an
//! object referenced by nothing publishes `dead` marks for its places in
//! its next map delta; one that finds a reference to a dead-marked place
//! publishes `undead` marks for it.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use super::{folder_pack, Commit, MapOut, References, Standing};
use crate::blockmap::{MapPublish, MapTable, MapWriter, MarkKind};
use crate::ledger3::{DeviceBin, LedgerView, ObjectBin, PackId, Place};

/// What one marking round did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarkReport {
    /// Places newly marked dead and undead.
    pub dead: u64,
    pub undead: u64,
    /// The map record that carries them (0: none written).
    pub map_seq: u64,
    /// Writers whose reference records this device has not applied yet:
    /// no dead marks until it has (a mark made now could name a block they
    /// reference).
    pub behind: Vec<DeviceBin>,
    /// This device may not mark in the folder (viewer, K3 only, removed).
    pub refused: bool,
}

/// Whether a current writer's dead mark is on the place with no newer
/// undead mark.
fn dead_marked(table: &MapTable, place: &Place, writers: &[DeviceBin]) -> Result<bool> {
    let marks = table.marks_at(&place.pack, place.offset)?;
    Ok(marks.iter().any(|m| {
        m.kind == MarkKind::Dead
            && writers.contains(&m.marker)
            && !marks
                .iter()
                .any(|u| u.kind == MarkKind::Undead && u.stamp() > m.stamp())
    }))
}

/// The places of the table (one per (pack, offset)) whose pack the view
/// still shows on a storage and whose object nothing references, without
/// a dead mark of a current writer already on them: what this device
/// marks dead.
pub fn find_unreferenced(
    table: &MapTable,
    view: &LedgerView,
    references: &dyn References,
    writers: &[DeviceBin],
) -> Result<Vec<(ObjectBin, Place)>> {
    let folder = *table.folder();
    let mut seen: BTreeSet<(PackId, u32)> = BTreeSet::new();
    let mut out = Vec::new();
    for row in table.scan() {
        let row = row?;
        if !seen.insert((row.place.pack, row.place.offset)) {
            continue;
        }
        if view.pack_folder(&row.place.pack) != Some(folder)
            || view.holders(&row.place.pack).is_empty()
            || references.is_referenced(&row.object)
            || dead_marked(table, &row.place, writers)?
        {
            continue;
        }
        out.push((row.object, row.place));
    }
    Ok(out)
}

/// The places whose newest dead or undead mark is dead while their object
/// is referenced: what this device marks undead.
pub fn find_revived(
    table: &MapTable,
    view: &LedgerView,
    references: &dyn References,
) -> Result<Vec<(ObjectBin, Place)>> {
    let mut seen: BTreeSet<(PackId, u32)> = BTreeSet::new();
    let mut out = Vec::new();
    for m in table.scan_marks() {
        let m = m?;
        if !seen.insert((m.pack, m.offset)) {
            continue;
        }
        if view.holders(&m.pack).is_empty() || !references.is_referenced(&m.object) {
            continue;
        }
        if table.mark_state(&m.pack, m.offset)?.newest != Some(MarkKind::Dead) {
            continue;
        }
        let Some(row) = table
            .rows_of(&m.object)?
            .into_iter()
            .find(|r| r.place.pack == m.pack && r.place.offset == m.offset)
        else {
            continue;
        };
        out.push((m.object, row.place));
    }
    Ok(out)
}

/// Publish the writer's pending marks (and nothing else) as its next map
/// record, commit the batch and apply the record to this device's table.
/// On a failed commit the record stays unannounced: the writer is rebuilt
/// so that its next record is a base after it.
fn publish(
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    sink: &mut dyn Commit,
) -> Result<MapPublish> {
    let lamport = sink.tick();
    let p = writer.publish(out.writer, out.meta, &[], lamport, Some(table), view)?;
    if let Err(e) = sink.commit(p.events.clone()) {
        *writer =
            MapWriter::from_view(writer.folder, writer.device, writer.epoch, view, p.body.seq);
        return Err(e);
    }
    p.apply_to(table, &folder_pack(view, writer.folder))?;
    Ok(p)
}

fn check(standing: &Standing, writer: &MapWriter, table: &MapTable) -> Result<()> {
    if !standing.may_mark() {
        bail!("this device may not mark blocks of this folder (only owners and editors may)");
    }
    if writer.device != standing.device || writer.folder != *table.folder() {
        bail!("the map writer is not this device's for this folder");
    }
    Ok(())
}

/// Publish `dead` marks on `places` in the writer's next map delta.
pub fn publish_dead_marks(
    standing: &Standing,
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    places: &[(ObjectBin, Place)],
    sink: &mut dyn Commit,
) -> Result<MapPublish> {
    check(standing, writer, table)?;
    writer.mark_dead(places);
    publish(writer, table, view, out, sink)
}

/// Publish `undead` marks on `places` (this device found a reference to
/// them) in the writer's next map delta.
pub fn publish_undead_marks(
    standing: &Standing,
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    places: &[(ObjectBin, Place)],
    sink: &mut dyn Commit,
) -> Result<MapPublish> {
    check(standing, writer, table)?;
    writer.mark_undead(places);
    publish(writer, table, view, out, sink)
}

/// One marking round of the upkeep: dead marks for unreferenced places
/// (only when this device applied every writer's announced reference
/// records) and undead marks for referenced dead-marked ones, in one map
/// record and one batch. A device that may not mark does nothing.
#[allow(clippy::too_many_arguments)]
pub fn mark_round(
    standing: &Standing,
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    references: &dyn References,
    writers: &[DeviceBin],
    sink: &mut dyn Commit,
) -> Result<MarkReport> {
    let mut report = MarkReport::default();
    if check(standing, writer, table).is_err() {
        report.refused = true;
        return Ok(report);
    }
    report.behind = references.behind(view, table.folder(), writers);
    let dead = if report.behind.is_empty() {
        find_unreferenced(table, view, references, writers)?
    } else {
        Vec::new()
    };
    let undead = find_revived(table, view, references)?;
    if dead.is_empty() && undead.is_empty() {
        return Ok(report);
    }
    writer.mark_dead(&dead);
    writer.mark_undead(&undead);
    let p = publish(writer, table, view, out, sink)?;
    report.dead = dead.len() as u64;
    report.undead = undead.len() as u64;
    report.map_seq = p.body.seq;
    Ok(report)
}
