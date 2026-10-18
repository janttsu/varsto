// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pruning a device's trash records (design section 7: "pruning as
//! manifests"): records below the writer's newest base go from the hot
//! metadata storages once every reader of the folder has acknowledged the
//! batch that announced that base. Cold storages are never pruned.
//!
//! The functions are the manifests' (`crate::manifest3::prune`) with the
//! kind `trash`; `PruneState` is shared.

use super::{stream, Id16};
use crate::ledger3::LedgerView;
use crate::manifest3::PruneState;
use crate::record::{Kind, RecordName};
use crate::storage::Storage;
use anyhow::Result;

/// `me`'s newest trash base of `folder` and the batch that announced it.
fn newest_base(view: &LedgerView, folder: &Id16, me: &Id16) -> Option<(u64, u64)> {
    let s = view.stream(Kind::Trash.code(), folder, me)?;
    let (seq, _, _) = s.base()?;
    Some((seq, s.records.get(&seq)?.batch))
}

/// The readers (other than `me`) that have not acknowledged the batch that
/// announced `me`'s newest trash base yet: what pruning waits for.
pub fn readers_waiting<'a>(
    view: &LedgerView,
    folder: &Id16,
    me: &Id16,
    readers: impl IntoIterator<Item = &'a Id16>,
) -> Vec<Id16> {
    let Some((_, batch)) = newest_base(view, folder, me) else {
        return Vec::new();
    };
    let mut out: Vec<Id16> = readers
        .into_iter()
        .filter(|r| *r != me && view.acked(r, me, Some(folder)) < batch)
        .copied()
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The seq below which `me`'s trash records of `folder` may be deleted: its
/// newest base, once every reader has acknowledged the batch that announced
/// it. None: not yet.
pub fn prune_floor<'a>(
    view: &LedgerView,
    folder: &Id16,
    me: &Id16,
    readers: impl IntoIterator<Item = &'a Id16>,
) -> Option<u64> {
    let (base, _) = newest_base(view, folder, me)?;
    if base <= 1 {
        return None;
    }
    readers_waiting(view, folder, me, readers)
        .is_empty()
        .then_some(base)
}

/// Delete `me`'s trash records of `folder` below `keep_from` from one
/// storage. Nothing on a cold storage, nor on one that does not hold the
/// record `keep_from`. Returns the number of objects deleted.
pub fn prune_stream(
    storage: &dyn Storage,
    cold: bool,
    folder: &Id16,
    me: &Id16,
    keep_from: u64,
    state: &mut PruneState,
) -> Result<u64> {
    if cold {
        return Ok(0);
    }
    let below = state.pruned_below.get(storage.name()).copied().unwrap_or(1);
    if below >= keep_from {
        return Ok(0);
    }
    let s = stream(*folder, *me);
    let (Some(prefix), Some(base_name)) = (s.prefix(), s.part_name(keep_from, 0)) else {
        return Ok(0);
    };
    if !storage.exists(&base_name)? {
        return Ok(0);
    }
    let start = if below <= 1 {
        String::new()
    } else {
        format!("{prefix}{:016}-9999.rec", below - 1)
    };
    let mut deleted = 0;
    for name in storage.list_after(&prefix, &start)? {
        let Some(n) = RecordName::parse_as(Kind::Trash, &name) else {
            continue;
        };
        if n.seq < keep_from && n.scope == *folder && n.device == Some(*me) {
            storage.delete(&name)?;
            deleted += 1;
        }
    }
    state
        .pruned_below
        .insert(storage.name().to_string(), keep_from);
    Ok(deleted)
}
