// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Map pruning (section 3, "Pruning"): a writer deletes its map records
//! older than its newest base B on every hot metadata storage once every
//! reader of the folder (devices holding its K10: own full devices with a
//! grant, and members) has acknowledged the batch that announced B. Cold
//! storages are never pruned; readers that join later read B and its
//! deltas.

use anyhow::Result;

use crate::ledger3::{DeviceBin, FolderBin, LedgerView};
use crate::manifest3::PruneState;
use crate::record::{Kind, RecordName, StreamRef};
use crate::storage::Storage;

/// `me`'s newest map base of `folder` and the batch that announced it.
fn newest_base(view: &LedgerView, folder: &FolderBin, me: &DeviceBin) -> Option<(u64, u64)> {
    let s = view.stream(Kind::BlockMap.code(), folder, me)?;
    let (seq, _, _) = s.base()?;
    Some((seq, s.records.get(&seq)?.batch))
}

/// The readers (other than `me`) that have not acknowledged the batch
/// that announced `me`'s newest map base: what pruning waits for.
pub fn map_readers_waiting(
    view: &LedgerView,
    folder: &FolderBin,
    me: &DeviceBin,
    readers: &[DeviceBin],
) -> Vec<DeviceBin> {
    let Some((_, batch)) = newest_base(view, folder, me) else {
        return Vec::new();
    };
    let mut out: Vec<DeviceBin> = readers
        .iter()
        .filter(|r| *r != me && view.acked(r, me, Some(folder)) < batch)
        .copied()
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The seq below which `me`'s map records of `folder` may go: its newest
/// base, once every reader acknowledged the batch that announced it.
pub fn map_prune_floor(
    view: &LedgerView,
    folder: &FolderBin,
    me: &DeviceBin,
    readers: &[DeviceBin],
) -> Option<u64> {
    let (base, _) = newest_base(view, folder, me)?;
    (base > 1 && map_readers_waiting(view, folder, me, readers).is_empty()).then_some(base)
}

/// What one pruning pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Record parts deleted, over every storage.
    pub deleted: u64,
    /// Readers the newest base waits for.
    pub waiting: Vec<DeviceBin>,
}

/// Prune `me`'s map records of `folder` on `storages` ((storage, cold)):
/// nothing on cold storages, nothing on a storage that does not hold the
/// base (a reader there would find nothing to start from).
pub fn prune_map(
    storages: &[(&dyn Storage, bool)],
    view: &LedgerView,
    folder: &FolderBin,
    me: &DeviceBin,
    readers: &[DeviceBin],
    state: &mut PruneState,
) -> Result<PruneReport> {
    let mut report = PruneReport {
        waiting: map_readers_waiting(view, folder, me, readers),
        ..Default::default()
    };
    let Some(keep_from) = map_prune_floor(view, folder, me, readers) else {
        return Ok(report);
    };
    let s = StreamRef::new(Kind::BlockMap, *folder, *me);
    let (Some(prefix), Some(base_name)) = (s.prefix(), s.part_name(keep_from, 0)) else {
        return Ok(report);
    };
    for (storage, cold) in storages {
        if *cold {
            continue;
        }
        let below = state.pruned_below.get(storage.name()).copied().unwrap_or(1);
        if below >= keep_from || !storage.exists(&base_name)? {
            continue;
        }
        let start = if below <= 1 {
            String::new()
        } else {
            format!("{prefix}{:016}-9999.rec", below - 1)
        };
        for name in storage.list_after(&prefix, &start)? {
            let Some(n) = RecordName::parse_as(Kind::BlockMap, &name) else {
                continue;
            };
            if n.seq < keep_from && n.scope == *folder && n.device == Some(*me) {
                storage.delete(&name)?;
                report.deleted += 1;
            }
        }
        state
            .pruned_below
            .insert(storage.name().to_string(), keep_from);
    }
    Ok(report)
}
