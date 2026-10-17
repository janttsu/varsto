// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Trash and version history of storage format 3 as signed base + delta
//! records (`docs/spec/format-3-design.md`, section 7; work package 7),
//! the `settings` record they are timed by, and the combined references
//! garbage collection uses. Built behind the `format3` feature; nothing in
//! the format-2 code path calls it yet (the switch is WP12). Snapshots are
//! in `crate::snapshot3`.
//!
//! - [`record`]: the body of a `trash` record (`TrashBody`), its entries,
//!   removals and the version history, limits and entry checks.
//! - [`state`]: one device's reconstructed record (`DeviceTrash`) and the
//!   difference of two records (what a delta carries).
//! - [`writer`]: the base/delta rule and sealing (`TrashWriter`).
//! - [`reader`]: every device's record of one folder (`FolderTrash`): which
//!   streams a pull reads, the merged trash and history at a time, and
//!   references.
//! - [`settings`]: the `settings` record: trash days, history days, trash
//!   storage.
//! - [`prune`]: when a writer's records below its newest base may go.
//! - [`gc_refs`]: manifests + trash + history + snapshots as one predicate.
//!
//! Interpretations of the design (for review):
//! - The change history of section 57 is not a record: it is derived from
//!   manifests and kept in local files that are never published, so there
//!   is nothing to put in a record. The version history of section 50 is
//!   the `versions` list of the trash record, as the design says.
//! - Base rule: the manifests' (64 deltas AND the deltas hold 1/16 of the
//!   base's bytes, forced at 1024), as the work package asks; the design's
//!   section 7 text for trash says "every 64 deltas or at 1/4".
//! - `forget` is applied before the other lists of the same record and
//!   removes the id from entries, removals and versions alike; a writer
//!   that forgets an id from one list only lists it again in the others.
//! - Restore against purge of one entry: the removal with the largest
//!   (Lamport time, purge, device) wins; section 43's "purged anywhere
//!   counts as purged" only differs for a restore stamped later than a
//!   purge, which cannot happen on one device and is the later decision on
//!   two.
//! - Removals carry no `by`: the record's device is the remover.

pub mod gc_refs;
pub mod prune;
pub mod reader;
pub mod record;
pub mod settings;
pub mod state;
pub mod writer;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use gc_refs::{all, Refs};
pub use prune::{prune_floor, prune_stream, readers_waiting};
pub use reader::{FolderTrash, TrashSets, Trust, KEEP_LISTED_SECS};
pub use record::{entry_id, Entry, HistoryEntry, Removal, TrashBody, MAX_ITEMS};
pub use settings::{
    settings_stream, Settings, SettingsBody, DEFAULT_HISTORY_DAYS, DEFAULT_TRASH_DAYS, MAX_DAYS,
};
pub use state::{ApplyError, Delta, DeviceTrash, TrashSnapshot};
pub use writer::{Pending, TrashWriter};

/// A vault, folder or device id on the wire.
pub use crate::record::Id16;
/// An object name or chunk id (32 bytes).
pub type Hash32 = [u8; 32];

/// The stream of `device`'s trash records of `folder`.
pub fn stream(folder: Id16, device: Id16) -> crate::record::StreamRef {
    crate::record::StreamRef::new(crate::record::Kind::Trash, folder, device)
}
