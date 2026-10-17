// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder manifests of storage format 3 as base + delta records
//! (`docs/spec/format-3-design.md`, section 7; work package 6), and the
//! per-file `held` flag that replaces the `chunk_on_device` event
//! (section 4). Built behind the `format3` feature; nothing in the
//! format-2 code path calls it yet (the switch is WP12).
//!
//! - [`record`]: the body of a `manifest` record (`ManifestBody`), its
//!   in-memory entry (`FileEntry`), limits and the kind-specific checks.
//! - [`state`]: one writer's reconstructed view (`WriterView`): the newest
//!   announced base and its deltas applied in order, `prev` checked.
//! - [`merge`]: section 7's merge rules as pure functions over views.
//! - [`writer`]: the base/delta rule and sealing (`ManifestWriter`).
//! - [`reader`]: every writer's newest view of one folder
//!   (`FolderManifests`): which streams a pull reads, `held`/`holders`,
//!   references for garbage collection.
//! - [`prune`]: when a writer's records below its newest base may go.
//!
//! Interpretations of the design (for review):
//! - One body type for bases and deltas (`base == seq` marks a base), as
//!   section 7 writes `Manifest`; `removed` is empty in a base.
//! - Paths travel as bytes and must be UTF-8 (format 2's `FileState` paths
//!   are strings, so a non-UTF-8 name could not be applied anyway).
//! - The base rule counts records after the base: the record `n` places
//!   after a base is itself a base when `n >= 64` and the deltas since the
//!   base hold at least 1/16 of the base's bytes, or when `n >= 1024`. So
//!   a base is followed by at most 63 (size condition) or 1023 deltas, as
//!   test 12 ("base + 63 deltas, then a base") reads. Bytes are the stored
//!   (padded) sizes of `record_published`.
//! - A writer that could not publish a seq (taken, or a half-written
//!   earlier attempt) moves to the next seq and writes a base there, so a
//!   reader never needs an unannounced `prev`.

pub mod merge;
pub mod prune;
pub mod reader;
pub mod record;
pub mod state;
pub mod writer;

#[cfg(test)]
mod tests;

pub use merge::{merge_entry, merge_views, resolve, Conflict, Merge3, Merged, Resolved};
pub use prune::{prune_floor, prune_stream, readers_waiting, PruneState};
pub use reader::{announcement, FolderManifests, HeldIndex, PullReport, Want};
pub use record::{
    Chunk3, FileEntry, ManifestBody, MAX_CHUNKS_PER_ENTRY, MAX_ENTRIES, MAX_PATH, MAX_VV,
};
pub use state::{ApplyError, WriterView};
pub use writer::{BaseRule, ManifestWriter, Pending};

/// A vault, folder or device id on the wire.
pub use crate::record::Id16;
/// An object name or chunk id (32 bytes).
pub type Hash32 = [u8; 32];

/// The stream of `device`'s manifests of `folder`.
pub fn stream(folder: Id16, device: Id16) -> crate::record::StreamRef {
    crate::record::StreamRef::new(crate::record::Kind::Manifest, folder, device)
}
