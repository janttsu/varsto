// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The bit-rot check on packs (`docs/spec/alpha-0-format.md` section 33
//! adapted to `docs/spec/format-3-design.md` section 3, "Verification and
//! repair"; work package 10b). Built behind the `format3` feature.
//!
//! What changes from format 2 is the unit. A target (a storage, a pool
//! disk) is swept pack by pack: the items are the packs the ledger view
//! holds on a storage (or the pack files on a disk), their size is the
//! pack's size class, and each is read whole (one GET) and hashed against
//! its id. A pack needs no folder key to be checked, so K3-only devices
//! and replicas scrub too. The schedule, the budgets (`scrub::plan`,
//! `scrub::Budget`), the cursor (`scrub::Sweep`, now the last pack id of
//! the pass) and the report (`scrub::ScrubReport`; its `objects_*` count
//! packs) are the format-2 ones, so the state file and the status text
//! need no change. Reads go through `parverify::run_ordered` in the lanes
//! of section 39, results consumed in key order, so the cursor never
//! passes a pack that was not checked.
//!
//! A mismatch (missing, wrong length, hash differs) is not repaired here:
//! it is handed to `on_mismatch`, WP5's repair queue (a pack's good
//! members are rewritten into a new pack, the bad places get `lost`
//! marks). For a pool disk the callback is also where the bad copy is
//! forgotten (`PoolStorage::drop_bad_copy`), exactly as format 2 does.
//! Scrub checks are still not recorded in the ledger: a writer re-reading
//! its own copy is not an independent verification.
//!
//! Interpretations of the design (for review):
//! - The size of an item is the class length the view gives, so budgets
//!   count whole packs (a 64 MiB pack costs 64 MiB of the budget however
//!   full it is).
//! - Local files and the block cache stay per object; they are not part of
//!   this module (the engine keeps `engine/scrub.rs` for them).

use crate::ledger3::LedgerView;
use crate::parverify::{self, Job, LanePlan};
use crate::scrub::{plan, Budget, Pace, ScrubReport, ScrubSchedule, ScrubState, TargetReport};
use anyhow::Result;
use serde::Serialize;

/// One whole-pack read: the bytes, or `None` when the pack is not there.
pub type ReadPack<'a> = dyn Fn(&str) -> Result<Option<Vec<u8>>> + Sync + 'a;

/// One target to sweep: a storage or an attached pool disk.
pub struct PackTarget<'a> {
    /// The key in `ScrubState::sweeps`: `storage:<name>` or
    /// `disk:<pool>/<disk id>`.
    pub target: String,
    pub label: String,
    /// The name used in reports (storage name, or `pool/disk label`).
    pub name: String,
    pub lane: LanePlan,
    /// Counts against the remote budget (S3, rclone).
    pub remote: bool,
    /// (pack id hex, length it must have), sorted by id.
    pub items: Vec<(String, u64)>,
    /// One whole-pack read.
    pub read: Box<ReadPack<'a>>,
}

/// The packs the view holds on `storage`, as sweep items.
pub fn storage_items(view: &LedgerView, storage: &str) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = view
        .packs_on(storage)
        .map(|(id, rec)| {
            (
                hex::encode(id),
                crate::ledger3::events::class_bytes(rec.class).unwrap_or(0),
            )
        })
        .collect();
    items.sort();
    items
}

/// The pack files among the objects of a pool disk (key, size), as sweep
/// items (`packs/<xx>/<id>` keys only).
pub fn disk_items(objects: &[(String, u64)]) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = objects
        .iter()
        .filter_map(|(key, size)| Some((crate::packs::pack_of_key(key)?.to_string(), *size)))
        .collect();
    items.sort();
    items
}

/// What was wrong with a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    Missing,
    /// The length is not the one the ledger (or the disk index) gives, or
    /// no size class.
    WrongLength {
        len: u64,
    },
    /// The bytes hash to something else.
    Corrupt {
        hash: String,
    },
}

/// A pack that did not check out, handed to the repair of WP5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PackMismatch {
    pub target: String,
    pub name: String,
    pub pack: String,
    pub kind: MismatchKind,
}

/// The result of a run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PackScrubResult {
    pub report: ScrubReport,
    pub mismatches: Vec<PackMismatch>,
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// Sweep `targets` pack by pack. `on_mismatch` is called in key order for
/// every bad pack and returns whether it was queued for repair.
#[allow(clippy::too_many_arguments)]
pub fn scrub_packs(
    targets: &[PackTarget],
    state: &mut ScrubState,
    schedule: &ScrubSchedule,
    pace: Pace,
    local: &mut Budget,
    remote: &mut Budget,
    now_utc: i64,
    on_mismatch: &mut dyn FnMut(&PackMismatch) -> bool,
) -> PackScrubResult {
    let mut out = PackScrubResult::default();
    out.report.started_utc = now_utc;
    out.report.full = pace == Pace::Full;
    // The pass that began longest ago first.
    let mut order: Vec<&PackTarget> = targets.iter().collect();
    order.sort_by_key(|t| {
        state
            .sweeps
            .get(&t.target)
            .map_or(0, |s| s.pass_started_utc)
    });
    for t in order {
        let budget = if t.remote { &mut *remote } else { &mut *local };
        let sweep = state.sweeps.entry(t.target.clone()).or_default();
        sweep.label = t.label.clone();
        let p = plan(&t.items, sweep, now_utc, schedule, pace, budget);
        let mut tr = TargetReport {
            target: t.target.clone(),
            label: t.label.clone(),
            behind: p.behind,
            ..Default::default()
        };
        let mut done = p.finishes_pass;
        let mut last: Option<&str> = None;
        let jobs: Vec<Job<usize>> = p
            .picks
            .iter()
            .map(|&i| Job {
                item: i,
                lane: 0,
                size: t.items[i].1,
            })
            .collect();
        parverify::run_ordered(
            &jobs,
            &[t.lane],
            |&i| crate::storage::guarded(&t.items[i].0, || (t.read)(&t.items[i].0)),
            |_, got| got.map(|b| b.map(|b| (b.len() as u64, hex::encode(crate::crypto::hash(&b))))),
            |_, &i, got| {
                let (id, want_len) = &t.items[i];
                let bad = |kind| PackMismatch {
                    target: t.target.clone(),
                    name: t.name.clone(),
                    pack: id.clone(),
                    kind,
                };
                let found = match got {
                    Ok(None) => {
                        out.report.missing.push(format!("{}:{}", t.name, short(id)));
                        Some(bad(MismatchKind::Missing))
                    }
                    Ok(Some((len, hash))) => {
                        tr.bytes += len;
                        if len != *want_len || !crate::packs::is_class(len) {
                            out.report.corrupt.push(format!("{}:{}", t.name, short(id)));
                            Some(bad(MismatchKind::WrongLength { len }))
                        } else if hash != *id {
                            out.report.corrupt.push(format!("{}:{}", t.name, short(id)));
                            Some(bad(MismatchKind::Corrupt { hash }))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        // Unreachable now: the pass goes on from here next time.
                        out.report
                            .skipped
                            .push(format!("{} (read failed: {e:#})", t.name));
                        done = false;
                        return false;
                    }
                };
                tr.checked += 1;
                last = Some(id);
                if let Some(m) = found {
                    if on_mismatch(&m) {
                        out.report.queued_for_repair += 1;
                    }
                    out.mismatches.push(m);
                }
                true
            },
        );
        sweep.advance(now_utc, last, tr.checked, done);
        tr.pass_done = done;
        tr.left_in_pass = p.remaining - tr.checked;
        out.report.objects_checked += tr.checked;
        out.report.object_bytes += tr.bytes;
        out.report.targets.push(tr);
    }
    out.report.finished_utc = now_utc;
    out
}

#[cfg(test)]
mod tests;
