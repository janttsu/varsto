// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backup snapshots of storage format 3 (`docs/spec/format-3-design.md`,
//! section 7; work package 7). Built behind the `format3` feature; nothing
//! in the format-2 code path calls it yet.
//!
//! A snapshot is either a base (a full listing) or a differential against
//! a base (`base` = that base's seq): every entry that differs from the
//! base and every path removed since. Differential, never incremental, so
//! expiring any snapshot never breaks another. A base is kept (its record
//! stays on the storages, hidden from listings) while any unexpired
//! snapshot names it; when the last one expires, the base goes too, and
//! garbage collection may drop the blocks only it used.
//!
//! - [`record`]: the body of a `snapshot` record.
//! - [`writer`]: when a snapshot is a base, sealing (`SnapshotWriter`).
//! - [`reader`]: loading the announced snapshots of a backup, rebuilding
//!   any snapshot from its base + itself, expiry, retained bases and the
//!   references garbage collection starts from (`BackupSnapshots`).
//!
//! Interpretations of the design (for review):
//! - Snapshot entries are the manifests' wire entries; `held` is on the
//!   wire but must be false (a backup is held by no device).
//! - A snapshot has no `prev`: it never chains. A reader checks that the
//!   base a differential names is a base the same device announced.
//! - A snapshot is unexpired while the ledger has no `snapshot_expired`
//!   for it and `now < expires_utc` of its signed body.
//! - Records are never pruned; only expiry deletes them.

pub mod reader;
pub mod record;
pub mod writer;

#[cfg(test)]
mod tests;

pub use reader::{BackupSnapshots, PullReport, SnapshotInfo, WantSnap};
pub use record::{SnapHeader, SnapshotBody};
pub use writer::{Pending, SnapRule, SnapshotWriter};

/// A vault, backup or device id on the wire.
pub use crate::record::Id16;
/// An object name or chunk id (32 bytes).
pub type Hash32 = [u8; 32];

/// The stream of `device`'s snapshots of `backup`.
pub fn stream(backup: Id16, device: Id16) -> crate::record::StreamRef {
    crate::record::StreamRef::new(crate::record::Kind::Snapshot, backup, device)
}
