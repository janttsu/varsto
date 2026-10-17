// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Varsto core library, alpha-0.
//!
//! This is the first vertical slice of the design described in the project
//! plan: content-defined chunking, client-side authenticated encryption,
//! a local-folder storage backend, a per-device append-only signed ledger
//! that is replicated through the storage ("mailbox"), and a two-way folder
//! sync between devices that are never online at the same time.
//!
//! Everything here is **alpha**: formats may change without migration, and
//! the cryptography (hybrid Ed25519 + ML-DSA-65 signatures, X25519 + ML-KEM-768
//! key encapsulation, XChaCha20-Poly1305) has not been reviewed independently.
//! Do not use it as the only copy of anything.

pub mod activity;
pub mod advice;
pub mod autoverify;
pub mod blockdev;
#[cfg(feature = "format3")]
pub mod blockmap;
pub mod changes;
pub mod chunk_seal;
pub mod chunking;
pub mod crypto;
pub mod diskconf;
pub mod diskformat;
pub mod disksuggest;
pub mod engine;
pub mod events;
pub mod freespace;
pub mod fsmeta;
pub mod help;
pub mod ids;
pub mod ignore_rules;
pub mod import;
pub mod kem;
pub mod ledger;
#[cfg(feature = "format3")]
pub mod ledger3;
pub mod ledger_heads;
pub mod logging;
pub mod manifest;
#[cfg(feature = "format3")]
pub mod manifest3;
pub mod media;
#[cfg(feature = "format3")]
pub mod membership3;
pub mod names;
pub mod netif;
pub mod org;
pub mod p2p;
pub mod pack;
pub mod packs;
pub mod pair;
pub mod parverify;
pub mod placement;
pub mod policy;
pub mod pool;
pub mod price;
pub mod progress;
pub mod providers;
pub mod qr;
pub mod rclone;
#[cfg(feature = "format3")]
pub mod record;
pub mod record_shim;
pub mod recovery;
pub mod recovery_guide;
pub mod replica;
pub mod restic;
pub mod s3;
pub mod scrub;
pub mod share;
pub mod snapshot;
pub mod staged_move;
pub mod storage;
pub mod storage_settings;
#[cfg(feature = "format3")]
pub mod storages3;
pub mod strongroom;
pub mod thumbs;
pub mod util;
pub mod vault;
pub mod viz;

/// Storage format version written into every object header. See
/// `docs/spec/format-versions.md`.
pub const FORMAT_VERSION: u16 = 2;

/// Why a vault of storage format `found` cannot be opened by this build, in
/// words a person can act on: an older vault (0.0.1-alpha.14 and earlier
/// wrote format 1: block objects of their own, no packs) is not read and has
/// to be created again; a newer one needs a newer Varsto.
pub fn format_mismatch(found: u16) -> String {
    if found < FORMAT_VERSION {
        format!(
            "this vault uses storage format {found}, which this version of Varsto ({FORMAT_VERSION}) does not read \
             (0.0.1-alpha.14 and earlier wrote format 1). Recreate the vault: \
             run `varsto reset --yes` on this device, then `varsto init`, and sync your files into the new vault"
        )
    } else {
        format!(
            "this vault uses storage format {found}, which is newer than this version of Varsto reads ({FORMAT_VERSION}). \
             Update Varsto on this device"
        )
    }
}

pub use engine::{Engine, FsckReport, PullReport, PushReport, StatusReport};
