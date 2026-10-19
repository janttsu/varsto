// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Draining or removing a storage, and quota usage, in packs (design
//! sections 4 and 13; spec section 44). A drain works through the packs the
//! ledger shows held on the storage. For each pack it asks what the blocks
//! in it need: the copies a block keeps without this storage (live places
//! on other storages, counting the folder's other packs) must still meet
//! the folder's copy rules as far as they were met before (capped at what
//! was there), and a block is never left without a copy. Missing copies are
//! whole copies of the pack onto the folder's other storages
//! ([`super::moves::run_drain`] writes and checks them), and only then is
//! the pack dropped. A pack whose needs cannot be met elsewhere is a
//! refusal: the drain stays unfinished and says what is missing.

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Result;

use super::moves::members_of_packs;
use crate::blockmap::MapTable;
use crate::ledger3::events::class_bytes;
use crate::ledger3::{FolderBin, LedgerView, ObjectBin, PackId};
use crate::policy::{place_phrase, Policy};

/// What a storage holds, counted from the ledger: whole packs (padding
/// included, the storage holds it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub bytes: u64,
    pub packs: u64,
}

/// A storage's use against its quota: the packs claimed on it and not
/// dropped.
pub fn storage_usage(view: &LedgerView, storage: &str) -> Usage {
    let mut u = Usage::default();
    for (_, r) in view.packs_on(storage) {
        u.packs += 1;
        u.bytes += class_bytes(r.class).unwrap_or(0);
    }
    u
}

/// What a folder's blocks need, for a drain.
#[derive(Clone, Debug, Default)]
pub struct DrainNeeds {
    pub name: String,
    /// The folder's copy rules (verification left out), if it has any.
    pub rules: Option<Policy>,
    /// Storages the folder's packs may be copied to (placement, drained and
    /// full storages left out), warm ones first.
    pub targets: Vec<String>,
    /// Blocks current files and known snapshots use; `None`: unknown, all
    /// live blocks count.
    pub referenced: Option<HashSet<ObjectBin>>,
    /// Keep the number of copies where a target can take one: a pack whose
    /// blocks keep their rules without this storage is still copied to the
    /// first target that lacks it (a drain moves data; a removal only keeps
    /// what the rules need).
    pub replace: bool,
}

/// The copies of a block (storage, place) before a drain and without the
/// draining storage.
type BlockSides = (Vec<(String, String)>, Vec<(String, String)>);

/// One pack on the draining storage, worked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainItem {
    pub pack: PackId,
    pub class: u8,
    pub folder: Option<FolderBin>,
    /// Storages to copy the whole pack to first (empty: the copies it
    /// needs are there already).
    pub copy_to: Vec<String>,
    /// Blocks in the pack that something still uses.
    pub needed_blocks: u64,
    /// Why the copies that stay do not hold even with `copy_to`.
    pub shortfall: Option<String>,
}

/// A drain worked out from the ledger and the maps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainPlan {
    pub storage: String,
    /// Packs that only have to be dropped come first, then the others.
    pub items: Vec<DrainItem>,
    pub packs_to_drop: u64,
    pub packs_to_copy: u64,
    pub bytes_to_copy: u64,
    pub packs_blocked: u64,
    pub reasons: Vec<String>,
}

impl DrainPlan {
    /// The drain cannot finish while any pack is blocked: the storage is
    /// not removed while a place is the only live one.
    pub fn refusal(&self) -> Option<String> {
        (self.packs_blocked > 0).then(|| {
            format!(
                "{} pack{} on {} cannot be moved off it: {}",
                self.packs_blocked,
                if self.packs_blocked == 1 { "" } else { "s" },
                self.storage,
                self.reasons.join("; ")
            )
        })
    }
}

const REASONS: usize = 5;

/// Why the copies that stay do not hold, or `None` when they do. `after`
/// is (storage, place) of the remaining live copies.
pub fn shortfall(
    folder: &str,
    after: &[(String, String)],
    rules: Option<&Policy>,
) -> Option<String> {
    if after.is_empty() {
        return Some(format!(
            "a block of {folder} has no other copy and no other storage can take one: add another storage"
        ));
    }
    let r = rules?;
    for (place, n) in &r.min_per_place {
        let have = after.iter().filter(|(_, p)| p == place).count() as u32;
        if have < *n {
            return Some(format!(
                "folder {folder} needs {n} cop{} {} and no other storage there can take {}: add another {place} storage or lower the policy",
                if *n == 1 { "y" } else { "ies" },
                place_phrase(place),
                if *n - have == 1 { "it" } else { "them" }
            ));
        }
    }
    if (after.len() as u32) < r.min_copies {
        return Some(format!(
            "folder {folder} needs {} copies and no other storage can take another one: add another storage or lower the policy",
            r.min_copies
        ));
    }
    None
}

/// The rules capped at what the copies met before.
fn capped(rules: &Policy, before: &[(String, String)]) -> Policy {
    Policy {
        min_copies: rules.min_copies.min(before.len() as u32),
        min_per_place: rules
            .min_per_place
            .iter()
            .map(|(p, n)| {
                let have = before.iter().filter(|(_, bp)| bp == p).count() as u32;
                (p.clone(), (*n).min(have))
            })
            .collect(),
        verified_within_days: None,
    }
}

/// Work out draining `storage`. `tables` are the maps of the folders
/// (folder to table), `needs` what each folder's blocks need, `place_of`
/// the place of a storage, `fallback_targets` where packs of no known
/// folder may be copied. Packs of a folder with no map here are treated as
/// packs of no folder: they need one other copy at least.
pub fn drain_plan(
    view: &LedgerView,
    storage: &str,
    tables: &HashMap<FolderBin, &MapTable>,
    needs: &HashMap<FolderBin, DrainNeeds>,
    place_of: &dyn Fn(&str) -> String,
    fallback_targets: &[String],
) -> Result<DrainPlan> {
    let mut plan = DrainPlan {
        storage: storage.to_string(),
        ..Default::default()
    };
    let mut on: Vec<(PackId, u8)> = view
        .packs_on(storage)
        .map(|(id, r)| (*id, r.class))
        .collect();
    on.sort_unstable();
    // Members per folder, one scan of each table.
    let mut by_folder: HashMap<FolderBin, HashSet<PackId>> = HashMap::new();
    for (id, _) in &on {
        if let Some(f) = view.pack_folder(id) {
            if tables.contains_key(&f) {
                by_folder.entry(f).or_default().insert(*id);
            }
        }
    }
    let mut members = HashMap::new();
    for (f, set) in &by_folder {
        members.extend(members_of_packs(tables[f], set)?);
    }
    let push_reason = |list: &mut Vec<String>, why: String| {
        if !list.contains(&why) && list.len() < REASONS {
            list.push(why);
        }
    };
    for (pack, class) in on {
        let folder = view.pack_folder(&pack).filter(|f| tables.contains_key(f));
        let holders: BTreeSet<String> = view.holders(&pack).into_iter().map(String::from).collect();
        let mut item = DrainItem {
            pack,
            class,
            folder,
            copy_to: Vec::new(),
            needed_blocks: 0,
            shortfall: None,
        };
        let need = folder.and_then(|f| needs.get(&f));
        let name = need.map(|n| n.name.as_str()).unwrap_or("the vault");
        // The copies each needed block keeps without this storage.
        let mut afters: Vec<BlockSides> = Vec::new();
        match (folder, members.get(&pack)) {
            (Some(f), Some(live)) => {
                let table = tables[&f];
                for m in live.iter().filter(|m| {
                    need.and_then(|n| n.referenced.as_ref())
                        .is_none_or(|r| r.contains(&m.object))
                }) {
                    let before: Vec<(String, String)> = view
                        .block_copies(&m.object, table)
                        .into_iter()
                        .map(|s| {
                            let p = place_of(&s);
                            (s, p)
                        })
                        .collect();
                    let after: Vec<(String, String)> = before
                        .iter()
                        .filter(|(s, _)| s != storage)
                        .cloned()
                        .collect();
                    afters.push((before, after));
                }
            }
            _ => {
                // No members known: the pack as a whole is one block.
                let before: Vec<(String, String)> =
                    holders.iter().map(|s| (s.clone(), place_of(s))).collect();
                let after = before
                    .iter()
                    .filter(|(s, _)| s != storage)
                    .cloned()
                    .collect();
                afters.push((before, after));
            }
        }
        item.needed_blocks = if folder.is_some() {
            afters.len() as u64
        } else {
            0
        };
        if folder.is_some() && afters.is_empty() {
            // Nothing uses the pack: it only has to be dropped.
            plan.items.push(item);
            plan.packs_to_drop += 1;
            continue;
        }
        let rules = need.and_then(|n| n.rules.as_ref());
        let candidates: &[String] = need
            .map(|n| n.targets.as_slice())
            .unwrap_or(fallback_targets);
        let mut added: Vec<(String, String)> = Vec::new();
        let lacking = |added: &[(String, String)]| -> Option<String> {
            afters.iter().find_map(|(before, after)| {
                let have: Vec<(String, String)> =
                    after.iter().chain(added.iter()).cloned().collect();
                let rules = rules.map(|r| capped(r, before));
                shortfall(name, &have, rules.as_ref())
            })
        };
        let mut why = lacking(&added);
        for t in candidates {
            if why.is_none() {
                break;
            }
            if t == storage || holders.contains(t) || added.iter().any(|(s, _)| s == t) {
                continue;
            }
            added.push((t.clone(), place_of(t)));
            item.copy_to.push(t.clone());
            why = lacking(&added);
        }
        if why.is_none()
            && item.copy_to.is_empty()
            && !afters.is_empty()
            && need.is_some_and(|n| n.replace)
        {
            if let Some(t) = candidates
                .iter()
                .find(|t| t.as_str() != storage && !holders.contains(*t))
            {
                item.copy_to.push(t.clone());
            }
        }
        item.shortfall = why;
        match &item.shortfall {
            Some(w) => {
                plan.packs_blocked += 1;
                push_reason(&mut plan.reasons, w.clone());
            }
            None if item.copy_to.is_empty() => plan.packs_to_drop += 1,
            None => {
                plan.packs_to_copy += 1;
                plan.bytes_to_copy += class_bytes(class).unwrap_or(0) * item.copy_to.len() as u64;
            }
        }
        plan.items.push(item);
    }
    // Packs that need nothing first, then the rest.
    plan.items
        .sort_by_key(|i| (!i.copy_to.is_empty(), i.shortfall.is_some(), i.pack));
    Ok(plan)
}
