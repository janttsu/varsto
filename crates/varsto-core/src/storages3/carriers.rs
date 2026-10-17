// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Transferrers (spec section F-048) on the pack-level ledger. A transferrer
//! is a storage that carries data between devices that are never online
//! together: it takes what no other device has yet (or, with destinations,
//! what one of them still lacks) and is emptied when every destination
//! holds it.
//!
//! "Device D holds object O" was the ledger event `chunk_on_device`; in
//! format 3 it is a flag in the device's own newest manifest (`held` on
//! the file entry, design section 4). The question is [`ObjectHolders`]:
//! the devices whose newest manifest names the object with `held`;
//! `manifest3::HeldIndex` answers it, and so does any callback. A
//! transferrer holds whole packs, so a pack is emptied from it when every
//! live member is delivered.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;

use super::moves::members_of_packs;
use crate::blockmap::MapTable;
use crate::ledger3::events::{Event, PackOn};
use crate::ledger3::{DeviceBin, FolderBin, LedgerView, ObjectBin, PackId};

/// The devices that hold an object (it is `held` in their newest manifest).
pub trait ObjectHolders {
    fn holders(&self, object: &ObjectBin) -> Vec<DeviceBin>;
}

impl<F: Fn(&ObjectBin) -> Vec<DeviceBin>> ObjectHolders for F {
    fn holders(&self, object: &ObjectBin) -> Vec<DeviceBin> {
        self(object)
    }
}

/// The holders `manifest3` reads from every writer's newest manifest
/// (`held` flags, design section 4).
impl ObjectHolders for crate::manifest3::HeldIndex {
    fn holders(&self, object: &ObjectBin) -> Vec<DeviceBin> {
        crate::manifest3::HeldIndex::holders(self, object).to_vec()
    }
}

/// [`carrier_destinations`] for a folder whose manifests are read: a
/// destination uses the folder when it published a manifest of it.
pub fn carrier_destinations_held(
    configured: &BTreeMap<String, Vec<DeviceBin>>,
    held: &crate::manifest3::HeldIndex,
) -> HashMap<String, Vec<DeviceBin>> {
    carrier_destinations(configured, &|d| held.uses(d))
}

/// Per transferrer with destinations: those of them that use the folder
/// (`uses`: they published its manifest or hold some of its blocks).
/// Transferrers without destinations are absent (any device that lacks a
/// block).
pub fn carrier_destinations(
    configured: &BTreeMap<String, Vec<DeviceBin>>,
    uses: &dyn Fn(&DeviceBin) -> bool,
) -> HashMap<String, Vec<DeviceBin>> {
    configured
        .iter()
        .filter(|(_, ts)| !ts.is_empty())
        .map(|(name, ts)| {
            (
                name.clone(),
                ts.iter().filter(|t| uses(t)).copied().collect(),
            )
        })
        .collect()
}

/// Whether a transferrer takes the block: with destinations, when one of
/// them still lacks it; without, when no device but `me` holds it.
pub fn carrier_wants(
    holders: &dyn ObjectHolders,
    object: &ObjectBin,
    me: &DeviceBin,
    destinations: Option<&[DeviceBin]>,
) -> bool {
    let held = holders.holders(object);
    match destinations {
        Some(targets) => !targets.is_empty() && targets.iter().any(|t| !held.contains(t)),
        None => !held.iter().any(|d| d != me),
    }
}

/// Whether the transferrer has done its job for the block: every
/// destination holds it, or (without destinations) another device holds it
/// as well as `me`.
pub fn carrier_delivered(
    holders: &dyn ObjectHolders,
    object: &ObjectBin,
    me: &DeviceBin,
    destinations: Option<&[DeviceBin]>,
) -> bool {
    let held = holders.holders(object);
    match destinations {
        Some(targets) => targets.iter().all(|t| held.contains(t)),
        None => held.iter().any(|d| d != me) && held.contains(me),
    }
}

/// The transferrers (name, destinations if any) that take a block, for the
/// target set of a pack the writer is building.
pub fn carrier_targets(
    holders: &dyn ObjectHolders,
    object: &ObjectBin,
    me: &DeviceBin,
    carriers: &[(String, Option<Vec<DeviceBin>>)],
) -> Vec<String> {
    carriers
        .iter()
        .filter(|(_, dest)| carrier_wants(holders, object, me, dest.as_deref()))
        .map(|(n, _)| n.clone())
        .collect()
}

/// Packs of `folder` on the transferrer `carrier` that can go: every live
/// member is delivered (a pack with no live member goes too). A pack the
/// map lists nothing of stays.
pub fn delivered_packs(
    view: &LedgerView,
    table: &MapTable,
    folder: &FolderBin,
    carrier: &str,
    holders: &dyn ObjectHolders,
    me: &DeviceBin,
    destinations: Option<&[DeviceBin]>,
) -> Result<Vec<PackId>> {
    let mut on: Vec<PackId> = view
        .packs_on(carrier)
        .filter(|(id, _)| view.pack_folder(id).is_some_and(|f| f == *folder))
        .map(|(id, _)| *id)
        .collect();
    on.sort_unstable();
    let set: HashSet<PackId> = on.iter().copied().collect();
    let members = members_of_packs(table, &set)?;
    Ok(on
        .into_iter()
        .filter(|id| {
            members.get(id).is_some_and(|m| {
                m.iter()
                    .all(|r| carrier_delivered(holders, &r.object, me, destinations))
            })
        })
        .collect())
}

/// `pack_dropped` for packs removed from a storage.
pub fn drop_events(storage: &str, packs: &[PackId]) -> Vec<Event> {
    packs
        .iter()
        .map(|p| {
            Event::PackDropped(PackOn {
                storage: storage.to_string(),
                pack: *p,
            })
        })
        .collect()
}
