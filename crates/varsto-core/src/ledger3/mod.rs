// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The format-3 ledger (`docs/spec/format-3-design.md` section 4): binary
//! batch bodies of tagged events, pack-level claims instead of per-block
//! claims, record announcements, and a location view whose size grows with
//! the number of packs, not blocks.
//!
//! What is unchanged from the format-2 ledger (`crate::ledger`) is kept as
//! it was and reused where its types are format independent: per-device
//! hash chains, Lamport times, the mailbox layout (one object per batch
//! under `ledger/<device>/`), batches waiting for a missing predecessor
//! (`pending/`), fork detection, checkpoints that speak for their signer
//! only, acknowledgements (`seen`) and the pruning rule (a checkpoint's
//! batches go once every reader has acknowledged it). What is new:
//!
//! - `events`: the ten events of section 4 as `RawEvent { code, payload }`
//!   (postcard), unknown codes skipped and counted, and the `Batch` body.
//! - `envelope`: the signed record envelope of section 5 that batches and
//!   checkpoints travel in. It stands in for WP1's `crate::record` until the
//!   integration (`// WP1 integration` marks every seam).
//! - `view`: `LedgerView` with `packs`, `streams`, interned ids, device
//!   bitsets per (pack, storage), the "copies of a block" API and the
//!   `BlockMapView` hook for the folder block map (WP4), and the settle
//!   queries over acknowledgements (WP5).
//! - `scope`: who may make which event (section 4's table, section 9).
//! - `checkpoint`: checkpoints with the pack-level view as body, in parts.
//! - `store`: the local copy of every device's batches (`LedgerStore`).
//!
//! Nothing here is used by the engine yet: the switch is WP12.

pub mod checkpoint;
pub mod envelope;
pub mod events;
pub mod scope;
pub mod store;
pub mod view;

#[cfg(test)]
mod tests;

pub use checkpoint::{Checkpoint, LedgerObject};
pub use envelope::SignedRecord;
pub use events::{Announcement, Batch, Event, RawEvent};
pub use scope::EventScope;
pub use store::{LedgerStore, ViewCache};
pub use view::{BlockMapView, LedgerView, PackCopy, PackPlace, PackRecord, Place, Stream};

/// A device id on the wire (16 bytes).
pub type DeviceBin = [u8; 16];
/// A folder or backup id on the wire (16 bytes); all zeros is "none".
pub type FolderBin = [u8; 16];
/// A pack id: BLAKE3 of every byte of the pack.
pub type PackId = [u8; 32];
/// An object name (BLAKE3 of a chunk object).
pub type ObjectBin = [u8; 32];
/// A body hash or a batch hash (BLAKE3).
pub type Hash32 = [u8; 32];

/// The zero folder id: claims of replicas, vault-wide records.
pub const NO_FOLDER: FolderBin = [0; 16];

/// Largest compressed batch body, and most events in one batch; an action
/// that would exceed either seals further batches.
pub const MAX_BATCH_BODY: usize = 16 << 20;
pub const MAX_EVENTS: usize = 65_536;

/// The format-2 store's limits and outcomes, unchanged.
pub use crate::ledger::{Ingest, MAX_AHEAD};

/// The hex form of a binary id, as `crate::ids` shows ids.
pub fn id_of(bytes: &[u8]) -> crate::ids::Id {
    crate::ids::Id::from_bytes(bytes)
}

/// A 16-byte id from its `crate::ids` form.
pub fn bin16(id: &crate::ids::Id) -> anyhow::Result<[u8; 16]> {
    let b = id.as_bytes();
    b.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("an id of {} bytes, not 16", b.len()))
}

/// A device id as format 3 writes it: the first 16 bytes of the BLAKE3 of
/// its signing key (as `crate::ledger::device_id_for`).
pub fn device_bin_for(pubkey: &crate::crypto::VerifyingKey) -> DeviceBin {
    let h = crate::crypto::hash(&pubkey.to_bytes());
    h[..16].try_into().expect("16 bytes")
}
