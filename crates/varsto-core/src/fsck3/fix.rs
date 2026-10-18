// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `fsck --fix`: only the repairs section 3 allows without a folder key.

use super::report::{FixAction, Fsck3Report, PackIssue};
use super::{Fsck3Input, RepairPack};
use crate::ledger3::events::class_bytes;
use crate::ledger3::PackId;
use anyhow::Result;
use std::collections::HashSet;

/// What `fix` may do.
#[derive(Default)]
pub struct FixOptions<'a> {
    /// Hand corrupt, short and unrecoverable copies to the repair of
    /// WP5 (it rewrites a pack's good members into a new pack and marks
    /// the bad places lost). Without it they stay in the report.
    pub repair_pack: Option<&'a RepairPack<'a>>,
}

fn key_of(pack: &PackId) -> String {
    crate::packs::pack_key(&hex::encode(pack))
}

/// Copy every pack the report found missing on a storage from a storage
/// that holds it intact. The bytes are checked against the pack id; the
/// ledger claims the pack on the target already, so nothing is
/// announced. The report is updated: copied packs leave
/// `missing_copies` and go to `fixed`; what could not be copied goes to
/// `fix_failed`; with `repair_pack` the rest is handed over.
pub fn fix(input: &Fsck3Input, report: &mut Fsck3Report, opts: &FixOptions) -> Result<()> {
    // Copies found bad are no source for each other.
    let bad: HashSet<(String, String)> = report
        .missing_copies
        .iter()
        .chain(&report.wrong_length)
        .chain(&report.corrupt_copies)
        .map(|i| (i.pack.clone(), i.storage.clone()))
        .collect();
    let mut still_missing = Vec::new();
    for issue in std::mem::take(&mut report.missing_copies) {
        match copy_back(input, &bad, &issue) {
            Ok(Some(action)) => report.fixed.push(action),
            Ok(None) => {
                report.fix_failed.push(PackIssue {
                    detail: "no storage holds an intact copy to copy it from".into(),
                    ..issue.clone()
                });
                still_missing.push(issue);
            }
            Err(e) => {
                report.fix_failed.push(PackIssue {
                    detail: format!("{e:#}"),
                    ..issue.clone()
                });
                still_missing.push(issue);
            }
        }
    }
    report.missing_copies = still_missing;
    if let Some(repair) = opts.repair_pack {
        for list in [
            &mut report.missing_copies,
            &mut report.wrong_length,
            &mut report.corrupt_copies,
        ] {
            let mut open = Vec::new();
            for issue in std::mem::take(list) {
                report.handed_to_repair.push(issue.clone());
                if !repair(&issue).unwrap_or(false) {
                    open.push(issue);
                }
            }
            *list = open;
        }
    }
    Ok(())
}

fn copy_back(
    input: &Fsck3Input,
    bad: &HashSet<(String, String)>,
    issue: &PackIssue,
) -> Result<Option<FixAction>> {
    let mut id: PackId = [0; 32];
    hex::decode_to_slice(&issue.pack, &mut id)?;
    let Some(rec) = input.view.pack(&id) else {
        return Ok(None);
    };
    let class_len = class_bytes(rec.class).unwrap_or(0);
    let Some(target) = input.storages.iter().find(|s| s.name == issue.storage) else {
        return Ok(None);
    };
    if rec.class > target.max_class() {
        anyhow::bail!("class {} is not allowed on this storage", rec.class);
    }
    let key = key_of(&id);
    for from in input.view.holders(&id) {
        if from == issue.storage {
            continue;
        }
        // A copy found missing, short or corrupt is no source.
        let bad_there = bad.contains(&(issue.pack.clone(), from.to_string()));
        let Some(src) = input.storages.iter().find(|s| s.name == from) else {
            continue;
        };
        if bad_there {
            continue;
        }
        let Some(bytes) = src.storage.get_bounded(&key, crate::storage::MAX_PACK)? else {
            continue;
        };
        if bytes.len() as u64 != class_len || crate::crypto::hash(&bytes) != id {
            continue;
        }
        target.storage.put_if_absent(&key, &bytes)?;
        return Ok(Some(FixAction {
            pack: issue.pack.clone(),
            from: from.to_string(),
            to: issue.storage.clone(),
            bytes: bytes.len() as u64,
        }));
    }
    Ok(None)
}
