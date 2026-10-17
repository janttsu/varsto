// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Disk pools on packs (design sections 4 and 13; spec sections 19, 34, 40
//! and 59 of `alpha-0-format.md`). A pool holds `packs/<xx>/<pack id>` files
//! on removable disks; which packs a pool should keep is known from the
//! ledger: each `pack_stored` names the pack and its class, and a pack no
//! live claim names is junk. The pool's own bookkeeping
//! ([`crate::pool::PoolStorage`]) is unchanged; this module is the pack
//! side of the engine's questions to it.

use std::collections::{BTreeMap, HashSet};

use anyhow::Result;

use super::copies::DiskCopy;
use crate::ledger3::events::{class_bytes, Event, PackOn};
use crate::ledger3::{LedgerView, PackId};
use crate::packs::{pack_key, pack_of_key};
use crate::pool::{BookInput, PoolStorage, TidyOutcome, VerifyOutcome};
use crate::storage::Storage;

fn pack_id(hex_id: &str) -> Option<PackId> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(hex_id, &mut id).ok()?;
    Some(id)
}

/// The pool's question "does the vault still need this file" for packs:
/// the object name (a pack id in hex) is a pack the ledger shows held on
/// `storage`. With `ledger_current` false (the ledger could not be brought
/// up to date first) a pack is kept unless the ledger says it was dropped
/// from `storage`: files this device does not know yet are not removed.
pub fn pack_referenced<'a>(
    view: &'a LedgerView,
    storage: &'a str,
    ledger_current: bool,
) -> impl Fn(&str) -> bool + 'a {
    move |name| match pack_id(name) {
        None => false,
        Some(id) if ledger_current => view.is_held(&id, storage),
        Some(id) => !view.dropped_from(&id, storage),
    }
}

/// Packs the pool no longer holds on any disk after `keys` were forgotten
/// on one: drops to record (only for packs the ledger shows held there).
fn lost_events(pool: &PoolStorage, view: &LedgerView, keys: &[String]) -> Vec<Event> {
    let storage = pool.name().to_string();
    keys.iter()
        .filter_map(|k| pack_of_key(k).and_then(pack_id))
        .filter(|id| view.is_held(id, &storage))
        .filter(|id| pool.locate_all(&pack_key(&hex::encode(id))).is_empty())
        .map(|pack| {
            Event::PackDropped(PackOn {
                storage: storage.clone(),
                pack,
            })
        })
        .collect()
}

/// The first phase of a disk insert: listings only. Applies the queued
/// deletions, removes temporary files, forgets packs the disk lost or
/// holds at the wrong size, and removes the packs no live claim names.
/// Returns what it did and the `pack_dropped` events for packs that the
/// pool no longer holds on any disk.
pub fn tidy_disk_packs(
    pool: &PoolStorage,
    disk_id: &str,
    view: &LedgerView,
    ledger_current: bool,
) -> Result<(TidyOutcome, Vec<Event>)> {
    let keep = pack_referenced(view, pool.name(), ledger_current);
    let out = pool.tidy_disk(disk_id, &keep)?;
    let gone: Vec<String> = out.missing.iter().chain(&out.bad).cloned().collect();
    let events = lost_events(pool, view, &gone);
    Ok((out, events))
}

/// A disk check: every pack the index places on the disk is read back and
/// hashed against its id. Returns the outcome, `pack_verified` for every
/// pack that hashed right and `pack_dropped` for packs that are bad or
/// gone and that the pool holds on no other disk. Bad packs are removed
/// from the disk; the repair that follows reads them from another storage.
pub fn check_disk_packs(
    pool: &PoolStorage,
    disk_id: &str,
    view: &LedgerView,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(VerifyOutcome, Vec<Event>)> {
    let keys = pool.objects_on(disk_id);
    let out = pool.verify_objects(disk_id, &keys, progress)?;
    let storage = pool.name().to_string();
    let mut events: Vec<Event> = out
        .verified_keys
        .iter()
        .filter_map(|k| pack_of_key(k).and_then(pack_id))
        .map(|pack| {
            Event::PackVerified(PackOn {
                storage: storage.clone(),
                pack,
            })
        })
        .collect();
    let gone: Vec<String> = out.bad.iter().chain(&out.missing).cloned().collect();
    events.extend(lost_events(pool, view, &gone));
    Ok((out, events))
}

/// The disks of a pool that hold a pack, as policies count them (one copy
/// per disk, at the disk's place).
pub fn pool_pack_copies(pool: &PoolStorage, pack: &PackId) -> Vec<DiskCopy> {
    pool.locate_all(&pack_key(&hex::encode(pack)))
        .into_iter()
        .map(|l| DiskCopy {
            name: l.label,
            place: l.place,
            readable: l.attached,
        })
        .collect()
}

/// Whether the pool holds the pack in as many different places as its disk
/// group rule asks, adding copies on attached disks of other places when it
/// can (a staged move counts a pack as moved when this is true). Records
/// the labels of disks written to in `used`.
pub fn group_rule_met(pool: &PoolStorage, pack: &PackId, used: &mut Vec<String>) -> bool {
    let want = pool.copies() as usize;
    if want <= 1 {
        return true;
    }
    let key = pack_key(&hex::encode(pack));
    let mut places = pool.places_of(&key);
    if places.len() >= want {
        return true;
    }
    let Ok(Some(bytes)) = pool.get(&key) else {
        return false;
    };
    if crate::crypto::hash(&bytes) != *pack {
        return false; // never copy a damaged pack
    }
    for d in pool.disks() {
        if places.len() >= want {
            break;
        }
        if d.retired || pool.mount_of(&d.id).is_none() || !pool.wants_copy(&d.id, &key) {
            continue;
        }
        if pool.add_copy_on_disk(&d.id, &key, &bytes).is_ok() {
            if !used.contains(&d.label) {
                used.push(d.label.clone());
            }
            places = pool.places_of(&key);
        }
    }
    places.len() >= want
}

/// What the ledger knows about a pool, for the "next disk to dock"
/// counting ([`crate::pool::PoolStorage::statuses_with`]): pack copies
/// instead of block copies. Pack ids in lower-case hex.
#[derive(Clone, Debug, Default)]
pub struct BookSets {
    /// Packs the ledger shows held on the pool.
    pub wanted: HashSet<String>,
    /// Packs of the pool that some other storage holds as well.
    pub elsewhere: HashSet<String>,
    /// Object keys (`packs/<xx>/<id>`) of the packs current files use;
    /// `None`: every pack counts for further disk group copies.
    pub current: Option<HashSet<String>>,
    /// Bytes of packs the pool should hold (a staged move or a placement
    /// puts them there) that it holds on no disk yet.
    pub first_copy_bytes: u64,
}

impl BookSets {
    /// The pool's input, with a queued repair's packs and the fetch plan's
    /// keys per disk.
    pub fn input<'a>(
        &'a self,
        repair: Option<&'a HashSet<String>>,
        fetch: Option<&'a BTreeMap<String, Vec<String>>>,
    ) -> BookInput<'a> {
        BookInput {
            wanted: Some(&self.wanted),
            elsewhere: Some(&self.elsewhere),
            repair,
            fetch,
            first_copy_bytes: self.first_copy_bytes,
            current: self.current.as_ref(),
        }
    }
}

/// Count a pool's packs from the ledger. `lacking` are packs the pool
/// should hold but holds on no disk, with their classes (the bytes a new
/// disk could take); `current` the packs that hold a block of a current
/// file (`None`: all).
pub fn book_sets(
    view: &LedgerView,
    pool: &str,
    lacking: &[(PackId, u8)],
    current: Option<&HashSet<PackId>>,
) -> BookSets {
    let mut sets = BookSets::default();
    for (id, _) in view.packs_on(pool) {
        let name = hex::encode(id);
        if view.holders(id).iter().any(|s| *s != pool) {
            sets.elsewhere.insert(name.clone());
        }
        sets.wanted.insert(name);
    }
    sets.first_copy_bytes = lacking
        .iter()
        .filter_map(|(_, class)| class_bytes(*class))
        .sum();
    sets.current = current.map(|c| c.iter().map(|id| pack_key(&hex::encode(id))).collect());
    sets
}
