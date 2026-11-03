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
//! the pack dropped. A block the local file state does not list is not
//! unused: that state can be older than the block map, and so can the map
//! be older than the writer's map record. Such a pack is dropped only when
//! another readable copy is known (a copy this device has seen on another
//! storage, or a confirmed replica). A pack whose needs cannot be met
//! elsewhere is a refusal: the drain stays unfinished and says what is
//! missing.

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Result;

use super::moves::members_of_packs;
use crate::blockmap::MapTable;
use crate::ledger3::events::class_bytes;
use crate::ledger3::{DeviceBin, FolderBin, LedgerView, ObjectBin, PackId};
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
    /// Files, trash or snapshots here are older than the block map, or the
    /// map here is older than a record the ledger has announced. Blocks
    /// `referenced` omits are not unused, and a pack is not deleted on
    /// that basis.
    pub state_behind: bool,
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

/// A live block that local state does not list may be dropped only when
/// another readable copy is known and local state is not behind the block
/// map. `seen_elsewhere`: this device's block map shows a live place on
/// another storage. `confirmed_replica`: a replica verified a pack that
/// holds the block.
pub fn unreferenced_may_drop(
    state_behind: bool,
    seen_elsewhere: bool,
    confirmed_replica: bool,
) -> bool {
    !state_behind && (seen_elsewhere || confirmed_replica)
}

/// A pack the local block map does not explain (no live members, a gap in
/// them, or the writer's map record newer than the table) may be dropped
/// only when this device has claimed or verified it on another storage, or
/// a replica has confirmed it.
pub fn unexplained_may_drop(seen_elsewhere: bool, confirmed_replica: bool) -> bool {
    seen_elsewhere || confirmed_replica
}

/// The writer's map record that lists `pack` is in `table` (a claim that
/// names no record has nothing to catch up with).
fn map_caught_up(view: &LedgerView, pack: &PackId, table: &MapTable) -> bool {
    let Some(rec) = view.pack(pack) else {
        return false;
    };
    if rec.map_seq == 0 {
        return true;
    }
    let Some(writer) = view.pack_writer(pack) else {
        return false;
    };
    table
        .marker(&writer)
        .is_some_and(|m| m.applied >= rec.map_seq)
}

/// Live members follow one another from offset 0. A gap is a member the
/// table does not list.
fn members_cover(rows: &[super::moves::PackMember]) -> bool {
    if rows.is_empty() {
        return false;
    }
    let mut rows: Vec<_> = rows.iter().collect();
    rows.sort_by_key(|r| r.place.offset);
    let mut at = 0u64;
    for r in rows {
        if u64::from(r.place.offset) != at {
            return false;
        }
        at += u64::from(r.place.len);
    }
    true
}

/// Other storages where this device has claimed or verified `pack`, and
/// replica storages that confirmed it.
fn pack_copies_seen(
    view: &LedgerView,
    pack: &PackId,
    storage: &str,
    me: &DeviceBin,
) -> (Vec<String>, bool) {
    let mut seen = Vec::new();
    let mut replica = false;
    for c in view.copies(pack) {
        if c.storage == storage {
            continue;
        }
        let confirmed = c.storage.starts_with("replica:") && c.independently_verified;
        if confirmed {
            replica = true;
            seen.push(c.storage);
        } else if c.verified_by.contains(me) || c.claimed_by.contains(me) {
            seen.push(c.storage);
        }
    }
    (seen, replica)
}

/// A replica storage in `names` verified a pack that holds `object`.
fn replica_confirmed(
    view: &LedgerView,
    table: &MapTable,
    object: &ObjectBin,
    names: &[(String, String)],
) -> bool {
    let replicas: Vec<&str> = names
        .iter()
        .filter(|(s, _)| s.starts_with("replica:"))
        .map(|(s, _)| s.as_str())
        .collect();
    if replicas.is_empty() {
        return false;
    }
    view.block_places(object, table).into_iter().any(|p| {
        p.storages.iter().any(|s| replicas.contains(&s.as_str()))
            && view
                .copies(&p.place.pack)
                .into_iter()
                .any(|c| c.storage.starts_with("replica:") && c.independently_verified)
    })
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
/// packs of no folder: they need one other copy this device has seen, or
/// a confirmed replica. `me` is this device: its own claims and
/// verifications are the copies it has seen.
pub fn drain_plan(
    view: &LedgerView,
    storage: &str,
    tables: &HashMap<FolderBin, &MapTable>,
    needs: &HashMap<FolderBin, DrainNeeds>,
    place_of: &dyn Fn(&str) -> String,
    fallback_targets: &[String],
    me: &DeviceBin,
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
        let state_behind = need.is_some_and(|n| n.state_behind);
        let referenced = need.and_then(|n| n.referenced.as_ref());
        // The copies each needed block keeps without this storage.
        let mut afters: Vec<BlockSides> = Vec::new();
        let rows = members.get(&pack);
        let explained = folder.is_some_and(|f| {
            map_caught_up(view, &pack, tables[&f]) && rows.is_some_and(|r| members_cover(r))
        });
        if let (true, Some(f), Some(live)) = (explained, folder, rows) {
            let table = tables[&f];
            for m in live {
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
                // Not listed by local state. That state can be older than
                // the map: omitting the block is not a reason to drop the
                // pack unless another readable copy is already known.
                let listed = referenced.is_none_or(|r| r.contains(&m.object));
                if !listed {
                    let seen = after.iter().any(|(s, _)| !s.starts_with("replica:"));
                    let replica = replica_confirmed(view, table, &m.object, &after);
                    if unreferenced_may_drop(state_behind, seen, replica) {
                        continue;
                    }
                }
                afters.push((before, after));
            }
        } else {
            // The map does not explain the pack. A claim this device has
            // not seen is not a copy that lets the bytes go; a confirmed
            // replica is.
            // Only copies this device has claimed or verified, and
            // confirmed replicas. Anything else is not a copy that lets
            // the bytes go; the pack stays, or is copied first.
            let (seen, replica) = pack_copies_seen(view, &pack, storage, me);
            let mut names = vec![storage.to_string()];
            if unexplained_may_drop(!seen.is_empty(), replica) {
                for s in &seen {
                    if s != storage && !names.contains(s) {
                        names.push(s.clone());
                    }
                }
            }
            let before: Vec<(String, String)> = names
                .into_iter()
                .map(|s| {
                    let p = place_of(&s);
                    (s, p)
                })
                .collect();
            let after = before
                .iter()
                .filter(|(s, _)| s != storage)
                .cloned()
                .collect();
            afters.push((before, after));
        }
        item.needed_blocks = if folder.is_some() {
            afters.len() as u64
        } else {
            0
        };
        if folder.is_some() && afters.is_empty() {
            // Every live block is unused and another readable copy is
            // known. The pack only has to be dropped.
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
        // Behind the block map: do not delete on the strength of places
        // the local state has not caught up with. A copy this device has
        // claimed or verified elsewhere, or a confirmed replica, may go;
        // so may a pack this run copies first (that copy is read back).
        if state_behind && why.is_none() && item.copy_to.is_empty() {
            let (seen, replica) = pack_copies_seen(view, &pack, storage, me);
            if !unexplained_may_drop(!seen.is_empty(), replica) {
                why = Some(format!(
                    "local state of {name} is behind the block map: a pack is not deleted until this device has caught up, or a copy it has seen (or a confirmed replica) holds it"
                ));
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

#[cfg(test)]
mod verdict_tests {
    use super::{unexplained_may_drop, unreferenced_may_drop};

    #[test]
    fn an_unreferenced_block_is_not_dropped_without_a_copy_or_while_behind() {
        assert!(!unreferenced_may_drop(false, false, false));
        assert!(unreferenced_may_drop(false, true, false));
        assert!(unreferenced_may_drop(false, false, true));
        // Local state is behind the block map: do not delete on the
        // strength of a block it does not list, even when a place exists.
        assert!(!unreferenced_may_drop(true, true, true));
    }

    #[test]
    fn an_unexplained_pack_needs_a_seen_copy_or_a_confirmed_replica() {
        assert!(!unexplained_may_drop(false, false));
        assert!(unexplained_may_drop(true, false));
        assert!(unexplained_may_drop(false, true));
    }
}
