// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Copies of a block on the pack-level ledger (design section 4): the
//! storages holding a live place of it. A place is live on storage S when
//! its pack is held there (claimed, not dropped, S not retired) and the
//! place carries no dead or lost mark. Policies ([`crate::policy`]),
//! placement (section 23), staged moves, disk groups, drains, quotas and
//! the forwarding engine (section 70) count this way; they need the map
//! only to go from a file to its blocks and places.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};

use crate::ids::ObjectName;
use crate::ledger3::{BlockMapView, LedgerView, ObjectBin, PackId};
use crate::manifest::ChunkRef;
use crate::policy::ChunkFacts;

/// The object name of a manifest entry's chunk as the map and the view
/// name it.
pub fn object_bin(o: &ObjectName) -> Result<ObjectBin> {
    o.as_bytes()
        .try_into()
        .map_err(|_| anyhow!("object name {o} is not 32 bytes"))
}

/// Storages holding a live place of the block (pack held there, place not
/// marked dead or lost).
pub fn block_copies(
    view: &LedgerView,
    map: &impl BlockMapView,
    object: &ObjectBin,
) -> BTreeSet<String> {
    view.block_copies(object, map)
}

/// One storage's standing for one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockCopy {
    pub storage: String,
    /// Some live place of the block is in a pack that a device other than
    /// its claimants read back whole after its newest drop (a replica's own
    /// check counts).
    pub independently_verified: bool,
    /// Newest verification of such a pack (UTC seconds), 0 without.
    pub verified_utc: i64,
    /// When a pack with a live place of the block was first stored there
    /// (UTC seconds), 0 when unknown.
    pub stored_utc: i64,
    /// A pack on this storage with a live place of the block.
    pub pack: PackId,
}

/// Every copy of a block with what policies ask of it, sorted by storage.
pub fn block_copy_details(
    view: &LedgerView,
    map: &impl BlockMapView,
    object: &ObjectBin,
) -> Vec<BlockCopy> {
    let mut by_storage: BTreeMap<String, BlockCopy> = BTreeMap::new();
    for bp in view
        .block_places(object, map)
        .into_iter()
        .filter(|p| !p.marked)
    {
        for pc in view.copies(&bp.place.pack) {
            let e = by_storage.entry(pc.storage.clone()).or_insert(BlockCopy {
                storage: pc.storage.clone(),
                independently_verified: false,
                verified_utc: 0,
                stored_utc: 0,
                pack: bp.place.pack,
            });
            if pc.independently_verified {
                e.independently_verified = true;
                e.verified_utc = e.verified_utc.max(pc.verified_utc);
            }
            if pc.stored_utc > 0 && (e.stored_utc == 0 || pc.stored_utc < e.stored_utc) {
                e.stored_utc = pc.stored_utc;
            }
        }
    }
    by_storage.into_values().collect()
}

/// What a storage is for the purpose of counting copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A transferrer: carries data, holds no copy a policy counts.
    Carrier,
    /// A storage at this place (`"other"` for one no place is known for).
    Place(String),
}

/// A copy of a pack on one disk of a pool that holds it (disk groups keep
/// several, each at its disk's place).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskCopy {
    /// How the copy is named in reports (the disk's label).
    pub name: String,
    pub place: String,
    /// The disk is attached.
    pub readable: bool,
    /// When the pool last checked the disk (UTC seconds, 0: never): a copy
    /// on a disk that is away counts as verified then.
    pub verified_utc: i64,
}

/// How the copies of a block are classified.
pub struct CopyEnv<'a> {
    /// A storage name to its standing. Replica storages (`replica:`) are
    /// always at the place `"replica"`.
    pub place_of: &'a dyn Fn(&str) -> Standing,
    /// For a pool storage and a pack it holds, the disks that hold it
    /// (`None`: not a pool, count the storage as one copy).
    pub disks_of: &'a dyn Fn(&str, &PackId) -> Option<Vec<DiskCopy>>,
}

impl<'a> CopyEnv<'a> {
    /// An environment without pools.
    pub fn new(place_of: &'a dyn Fn(&str) -> Standing) -> Self {
        CopyEnv {
            place_of,
            disks_of: &|_, _| None,
        }
    }
}

/// The facts a policy evaluates for one block, and the copies on media
/// that cannot be read right now (place, copy name).
#[derive(Clone, Debug)]
pub struct BlockFacts {
    pub facts: ChunkFacts,
    pub unreadable: Vec<(String, String)>,
}

/// The block as [`crate::policy::evaluate`] wants it: one copy per storage
/// (per disk for a pool) with its place, whether another device verified
/// it and when, and when the block was first stored.
pub fn block_facts(
    view: &LedgerView,
    map: &impl BlockMapView,
    object: &ObjectBin,
    env: &CopyEnv,
) -> BlockFacts {
    let mut copies = Vec::new();
    let mut unreadable = Vec::new();
    let mut stored_utc = 0i64;
    for c in block_copy_details(view, map, object) {
        let place = if c.storage.starts_with("replica:") {
            "replica".to_string()
        } else {
            match (env.place_of)(&c.storage) {
                Standing::Carrier => continue,
                Standing::Place(p) => p,
            }
        };
        if c.stored_utc > 0 && (stored_utc == 0 || c.stored_utc < stored_utc) {
            stored_utc = c.stored_utc;
        }
        if let Some(disks) = (env.disks_of)(&c.storage, &c.pack) {
            if disks.is_empty() {
                // The ledger says the pool holds it, but no disk is known to.
                let name = format!("{}:unknown disk", c.storage);
                unreadable.push((place.clone(), name.clone()));
                copies.push((name, place, false, 0));
                continue;
            }
            // One copy per disk that holds the pack, at the disk's place;
            // the first attached one keeps the pool's name, as the ledger
            // names it, and a disk that is away counts at its last check.
            let mut named_pool = false;
            for d in disks {
                if d.readable {
                    let name = if named_pool {
                        format!("{}:{}", c.storage, d.name)
                    } else {
                        named_pool = true;
                        c.storage.clone()
                    };
                    copies.push((
                        name,
                        d.place,
                        c.independently_verified || d.verified_utc > 0,
                        c.verified_utc.max(d.verified_utc),
                    ));
                } else {
                    let name = format!("{}:{}", c.storage, d.name);
                    unreadable.push((d.place.clone(), name.clone()));
                    copies.push((name, d.place, d.verified_utc > 0, d.verified_utc));
                }
            }
            continue;
        }
        copies.push((c.storage, place, c.independently_verified, c.verified_utc));
    }
    BlockFacts {
        facts: ChunkFacts { copies, stored_utc },
        unreadable,
    }
}

/// The copies of a file's blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCopies {
    /// Per block (in file order), the storages holding a live place.
    pub blocks: Vec<BTreeSet<String>>,
    /// Storages that hold every block of the file.
    pub on_every_block: BTreeSet<String>,
    /// The fewest copies any block has (0 for a file without blocks).
    pub fewest: usize,
    /// Blocks with no live place anywhere.
    pub without_copy: usize,
}

/// Copies of the blocks of one manifest entry (`FileState::chunks`).
pub fn file_copies(
    view: &LedgerView,
    map: &impl BlockMapView,
    chunks: &[ChunkRef],
) -> Result<FileCopies> {
    let mut out = FileCopies::default();
    for (i, c) in chunks.iter().enumerate() {
        let set = block_copies(view, map, &object_bin(&c.object)?);
        if i == 0 {
            out.on_every_block = set.clone();
            out.fewest = set.len();
        } else {
            out.on_every_block = out.on_every_block.intersection(&set).cloned().collect();
            out.fewest = out.fewest.min(set.len());
        }
        if set.is_empty() {
            out.without_copy += 1;
        }
        out.blocks.push(set);
    }
    Ok(out)
}

/// The policy facts of a file's blocks, and the copies on unreadable
/// media of all of them (place to copy names).
pub type FileFacts = (Vec<ChunkFacts>, BTreeMap<String, Vec<String>>);

/// [`block_facts`] for each block of a manifest entry, in order.
pub fn file_facts(
    view: &LedgerView,
    map: &impl BlockMapView,
    chunks: &[ChunkRef],
    env: &CopyEnv,
) -> Result<FileFacts> {
    let mut facts = Vec::with_capacity(chunks.len());
    let mut unreadable: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in chunks {
        let f = block_facts(view, map, &object_bin(&c.object)?, env);
        for (place, name) in f.unreadable {
            let list = unreadable.entry(place).or_default();
            if !list.contains(&name) {
                list.push(name);
            }
        }
        facts.push(f.facts);
    }
    Ok((facts, unreadable))
}
