// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The folder block map of storage format 3 (`docs/spec/format-3-design.md`
//! section 3; work package 4).
//!
//! For every block of a folder the map says in which pack and at which
//! offset it is. It is per folder and per writer device: a stream of
//! `block-map` records (`maps/<folder>/<device>/<seq>-<part>.rec`, signed,
//! under the folder's K10, announced by the writer's batches), each a base
//! (every live place the writer wrote) or a delta (places added since the
//! record before), plus dead, undead and lost marks on places of any
//! writer.
//!
//! - [`record`]: the body (`BlockMap`, `PackRef`, `MapEntry`, `Mark`) and
//!   its limits, checked by `record::accept`'s step (6).
//! - [`table`]: the local map table per folder (`state/maps/<folder>.tbl`),
//!   sorted fixed-width rows read with positioned reads, rebuilt atomically.
//! - [`reader`]: lookups, `ledger3::BlockMapView` for the table, the pull
//!   of new records, finding and reading a block through its places, and
//!   the hand-over of places to the pack layer (`packs::PlaceSource`).
//! - [`writer`]: the delta of a push (or import, move, repair, rewrite),
//!   marks, the seq counter, the base rule and the base rewrite, and the
//!   batch events (`pack_stored`, `record_published`).
//! - [`dedup`]: which target storages lack a live place of a block, and
//!   whether a marked place is collectable.
//!
//! Interpretations of the design (for review):
//! - The limits "per record part" (4 194 304 entries, 1 048 576 marks)
//!   are checked as that many times the record's part count, since parts
//!   are byte ranges of one compressed body; the 65 536 packs "per record"
//!   are counted the same way, so that a base of a writer with more packs
//!   than that is still possible once it spans several parts.
//! - A mark's stamp is (Lamport time of the record that carries it, marker
//!   device). Lost marks are sticky (an undead mark does not lift them);
//!   between dead and undead marks on a place the newest stamp decides.
//! - A writer whose seq was taken by a record no batch announced (a crash
//!   between writing the record and pushing the batch) continues after it
//!   with a base, because a delta would name a `prev` no reader can check.

pub mod dedup;
pub mod reader;
pub mod record;
pub mod table;
pub mod writer;

#[cfg(test)]
mod tests;

pub use dedup::{collectable, needs_write, place_is_live, referenced_until_wired, Dedup};
pub use reader::{find_block, open_block, pull, FoundBlock};
pub use record::{
    BlockMap, MapEntry, Mark, MarkKind, PackRef, FLAG_DEAD, MAX_ENTRIES_PER_PART,
    MAX_MARKS_PER_PART, MAX_PACKS,
};
pub use table::{
    table_path, ApplyReport, MapRow, MapTable, MapUpdate, MarkRow, MarkState, StreamMarker,
};
pub use writer::{
    class_of_len, written_packs, ChunkInfo, MapPublish, MapWriter, WrittenMember, WrittenPack,
    BASE_AFTER_DELTAS, BASE_BYTES_DIVISOR,
};
