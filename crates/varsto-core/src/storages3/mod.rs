// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storages on the pack-level ledger of storage format 3
//! (`docs/spec/format-3-design.md` sections 3, 4, 10 and 13, work package
//! 10a). The engine calls these engine-independent functions in
//! place of the per-block code of format 2.
//!
//! Everything here decides from three inputs: the ledger view
//! ([`crate::ledger3::LedgerView`], packs and their holders), the folder's
//! block map ([`crate::blockmap::MapTable`], block to place) and the
//! storages themselves. No function opens a vault, a folder key or an
//! engine.
//!
//! - [`copies`]: what a copy of a block is (a storage holding a live place
//!   of it), and the helpers that policies ([`crate::policy`]), placement,
//!   drains, quotas and the forwarding engine count with.
//! - [`replica`]: a replica round copies packs whole, checks each against
//!   its id, claims them with a zero folder and records that it read them
//!   back; records and everything else are copied as they are.
//! - [`pools`]: disk pools on packs: what a disk may keep follows the ledger,
//!   a check hashes every pack against its id, the "next disk to dock"
//!   counting works on pack copies, and a disk group rule counts the places
//!   that hold a pack.
//! - [`moves`]: data moves and staged moves at pack granularity.
//! - [`drain`]: draining or removing a storage, and quota usage, in packs.
//! - [`carriers`]: transferrer targeting and emptying from the `held`
//!   flags of manifests (`manifest3::HeldIndex`, or any callback).
//!
//! Interpretations of the design (for review):
//! - A whole pack copied by anyone other than its writer is claimed with a
//!   zero folder and `map_seq` 0 (as a replica's claims), so the claim that
//!   decides a pack's folder, writer and map record in the view stays the
//!   writer's. New packs built by a move are claims of the mover with the
//!   folder and the mover's own map record.
//! - A place is a copy on a storage when the pack is held there and the
//!   place has no dead or lost mark; the dead flag the writer keeps in its
//!   own entries counts like a dead mark.
//! - A move never drops a pack from the source while a live block of it
//!   that is not in scope remains: those blocks are rebuilt into a new pack
//!   on the source first (a "remainder"), and the old pack goes after the
//!   remainder is written and checked.
//! - The caller seals and pushes the batch (and publishes the map delta)
//!   between a step's writes and its deletions ([`moves::MoveRun::delete_dropped`]):
//!   a pack is deleted only after its drop is in a pushed batch.

pub mod aliases;
pub mod carriers;
pub mod copies;
pub mod drain;
pub mod moves;
pub mod pools;
pub mod replica;

#[cfg(test)]
mod tests;

pub use aliases::localize;
pub use carriers::{
    carrier_delivered, carrier_destinations, carrier_destinations_held, carrier_targets,
    carrier_wants, delivered_packs, drop_events, ObjectHolders,
};
pub use copies::{
    block_copies, block_copy_details, block_facts, file_copies, file_facts, object_bin, BlockCopy,
    BlockFacts, CopyEnv, DiskCopy, FileCopies, FileFacts, Standing,
};
pub use drain::{drain_plan, shortfall, storage_usage, DrainItem, DrainNeeds, DrainPlan, Usage};
pub use moves::{
    leftovers, members_of_packs, objects_moving, plan_move, run_drain, run_drain_with, run_move,
    run_move_with, Endpoint, MoveOptions, MovePlan, MoveReport, MoveRun, PackAction, PackMember,
    Sources,
};
pub use pools::{
    book_sets, check_disk_packs, disk_check_events, group_rule_met, pool_pack_copies,
    stray_pack_action, tidy_disk_packs, BookSets, StrayPack, StrayPackFacts, CLEANUP_GRACE_SECS,
};
pub use replica::{check_replica_events, replicate, ReplicaReport, ReplicaRound};
