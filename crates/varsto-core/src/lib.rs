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
pub mod changes;
pub mod chunk_seal;
pub mod chunking;
pub mod crypto;
pub mod diskconf;
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
pub mod logging;
pub mod manifest;
pub mod media;
pub mod names;
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
pub mod strongroom;
pub mod thumbs;
pub mod util;
pub mod vault;

/// Storage format version written into every object header. See
/// `docs/spec/format-versions.md` and `docs/spec/format-2-design.md`.
pub const FORMAT_VERSION: u16 = 2;

/// Refuse a vault (on a storage, or a device directory) written in another
/// storage format. Format 2 is read by nothing older and reads nothing
/// older: its vaults are created fresh.
pub fn check_format(found: u16, what: &str) -> anyhow::Result<()> {
    if found == FORMAT_VERSION {
        return Ok(());
    }
    if found < FORMAT_VERSION {
        anyhow::bail!(
            "{what} uses storage format {found}, which this version of Varsto no longer reads \
             (it reads format {FORMAT_VERSION} only, and nothing older reads format {FORMAT_VERSION}). \
             Format-{FORMAT_VERSION} vaults are created fresh: keep the files you synced, \
             create a new vault with `varsto init` and add the folders again"
        );
    }
    anyhow::bail!(
        "{what} uses storage format {found}, which is newer than this version of Varsto \
         reads (format {FORMAT_VERSION}): update Varsto"
    )
}

pub use engine::{Engine, FsckReport, PullReport, PushReport, StatusReport};

#[cfg(test)]
mod tests {
    #[test]
    fn older_and_newer_formats_are_refused() {
        assert!(super::check_format(super::FORMAT_VERSION, "x").is_ok());
        for old in [0, 1] {
            let e = super::check_format(old, "the vault").unwrap_err().to_string();
            assert!(e.contains(&format!("format {old}")), "{e}");
            assert!(e.contains("created fresh"), "{e}");
        }
        let e = super::check_format(super::FORMAT_VERSION + 1, "the vault")
            .unwrap_err()
            .to_string();
        assert!(e.contains("update Varsto"), "{e}");
    }
}
