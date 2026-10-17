// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Dedup for a writer and the settling query (section 3, "Dedup for a
//! writer" and "Dead marks, settling and collection").

use std::collections::BTreeMap;

use anyhow::Result;

use super::record::MarkKind;
use super::table::{MapRow, MapTable};
use crate::ledger3::envelope::kind::BLOCK_MAP;
use crate::ledger3::{DeviceBin, FolderBin, LedgerView, ObjectBin, Place};

/// What a writer does with one block for a set of target storages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dedup {
    /// The object the folder already holds for this chunk (keep it: write
    /// these very bytes where they are missing); `None`: seal a new object
    /// under `epoch`.
    pub object: Option<ObjectBin>,
    /// The epoch of `object` (cross-epoch rule), else the one asked for.
    pub epoch: u32,
    /// Targets that lack a live, unmarked place of it: write the block
    /// there (and only there).
    pub missing: Vec<String>,
}

impl Dedup {
    /// Every target holds a live place: nothing is written.
    pub fn skip(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Whether a place counts for dedup and as a copy: not flagged dead by its
/// writer and without a dead or lost mark this device holds (settled or
/// not; an undead mark newer than every dead one revives it).
pub fn place_is_live(table: &MapTable, row: &MapRow) -> Result<bool> {
    Ok(!row.flagged_dead()
        && !table
            .mark_state(&row.place.pack, row.place.offset)?
            .is_dead())
}

/// Section 3, "Dedup for a writer": which of `targets` lack a live place of
/// chunk `chunk` for a writer sealing under `epoch`. A place counts on
/// storage S when its pack is held on S in the view and the place is live
/// ([`place_is_live`]). A block whose only places carry a dead mark is
/// written again (a new object or the same bytes in a new pack), never
/// revived by reuse. Across epochs, a chunk the folder already holds under
/// an older epoch keeps its object: the oldest epoch with a live place
/// anywhere wins, and within one epoch the object held on most targets.
pub fn needs_write(
    table: &MapTable,
    view: &LedgerView,
    chunk: &[u8; 32],
    epoch: u32,
    targets: &[String],
) -> Result<Dedup> {
    let mut groups: BTreeMap<(u32, ObjectBin), Vec<MapRow>> = BTreeMap::new();
    for row in table.rows_of_chunk(chunk)? {
        if row.epoch > epoch || !place_is_live(table, &row)? {
            continue;
        }
        if view.holders(&row.place.pack).is_empty() {
            continue;
        }
        groups.entry((row.epoch, row.object)).or_default().push(row);
    }
    let covered = |rows: &[MapRow]| -> Vec<&String> {
        targets
            .iter()
            .filter(|t| rows.iter().any(|r| view.is_held(&r.place.pack, t)))
            .collect()
    };
    let Some(oldest) = groups.keys().next().map(|k| k.0) else {
        return Ok(Dedup {
            object: None,
            epoch,
            missing: targets.to_vec(),
        });
    };
    let best = groups
        .iter()
        .filter(|((e, _), _)| *e == oldest)
        .max_by(|(ka, a), (kb, b)| {
            covered(a)
                .len()
                .cmp(&covered(b).len())
                .then(kb.1.cmp(&ka.1))
        })
        .expect("a group of the oldest epoch");
    let held = covered(best.1);
    Ok(Dedup {
        object: Some(best.0 .1),
        epoch: best.0 .0,
        missing: targets
            .iter()
            .filter(|t| !held.contains(t))
            .cloned()
            .collect(),
    })
}

/// The reference check until WP5/WP6 wire manifests, trash, history and
/// snapshots: everything is referenced, so nothing is collectable.
pub fn referenced_until_wired(_object: &ObjectBin) -> bool {
    true
}

/// Section 3, "collectable" for this device: a dead mark on the place is
/// settled (every current writer of the folder, `writers`, acknowledged
/// the marker's batch that announced the mark's map record), no undead
/// mark with a larger (Lamport, device) stamp is on the place, and nothing
/// references the object (`referenced`, the caller's check over every
/// writer's records announced up to the settling batches).
pub fn collectable(
    table: &MapTable,
    view: &LedgerView,
    folder: &FolderBin,
    writers: &[DeviceBin],
    place: &Place,
    referenced: impl Fn(&ObjectBin) -> bool,
) -> Result<bool> {
    let marks = table.marks_at(&place.pack, place.offset)?;
    let settled_dead = marks.iter().find(|m| {
        m.kind == MarkKind::Dead
            && view
                .announced(BLOCK_MAP, folder, &m.marker, m.map_seq)
                .is_some_and(|a| view.settled(folder, writers, &m.marker, a.batch))
            && !marks
                .iter()
                .any(|u| u.kind == MarkKind::Undead && u.stamp() > m.stamp())
    });
    Ok(settled_dead.is_some_and(|m| !referenced(&m.object)))
}
