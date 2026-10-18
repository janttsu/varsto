// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder membership of storage format 3 (`docs/spec/format-3-design.md`,
//! sections 1, 5, 6 and 9; work package 8a). Built behind the `format3`
//! feature; nothing in the format-2 code path calls it yet.
//!
//! Every object here is a [`crate::record::SignedRecord`]:
//!
//! - [`devices`]: `device` records (K6 and K8 public keys, the device id
//!   rule `BLAKE3(K6 public)[..16]`) and the [`DeviceRegistry`].
//! - [`folders`]: `folder` records (name, settings, participants with
//!   roles, denied devices, no key) and the [`FolderRegistry`], which
//!   applies the owner-only rule and answers roles per folder epoch.
//! - [`grants`]: `grant` records, a folder key epoch (or a vault key epoch)
//!   sealed to one device's K8, and the [`GrantedKeys`] a device holds.
//! - [`epochs`]: folder epochs (`share-epoch` records, one sequence
//!   0, 1, 2, ... per folder), vault epochs and revocations as signed
//!   records, the chain of vault keys back to K3₀, and "two epochs under
//!   one number".
//! - [`requests`]: `request` records, the six-word fingerprint over K6 and
//!   K8, and the data side of approve and deny.
//! - [`escrow`]: the recovery key K1, `escrow` records under
//!   `derive(K2, "folder-escrow", vault, K3₀)`, recovery of every folder
//!   key, and which folder epochs lack a recovery copy.
//! - [`keys`]: [`VaultKeys`] (K3 per vault epoch) and [`KeyRing`], the
//!   `record::RecordKeys` of one device.
//! - [`trust`]: [`Trust`], the `record::RecordTrust` built from the
//!   registries (section 9's matrix).
//!
//! [`Membership`] ties these together for one device: it reads the records
//! of every metadata storage, keeps what it accepted, and writes new ones.
//!
//! Interpretations of the design (for review):
//! - Grant and escrow bodies are sealed with the generic record body AAD of
//!   WP1 (vault, scope, device, seq, part, parts, key_id); the epoch, the
//!   recipient and the issuer that section 6 puts in their AAD are in the
//!   body and checked against the storage name and the envelope, which the
//!   signature covers.
//! - A folder id is `BLAKE3(creator device || nonce)[..16]` and the
//!   creator's first record carries the nonce, so exactly one device can be
//!   the creator of a folder id (section 6 says "the creator's first record
//!   makes it the owner" without saying who the creator is).
//! - Removing a participant is a `denied` entry with a newer stamp:
//!   participants and denied entries merge per device by the largest
//!   (Lamport, device) stamp, the entry with the largest stamp decides.
//! - An entry of a folder record counts when its writer was an owner just
//!   before the entry's stamp (a replay in stamp order). A demoted owner
//!   can still backdate entries below its demotion's stamp; Lamport stamps
//!   cannot tell that from a slow device.
//! - Folder epoch records list the participants that stay with their
//!   roles; epoch 0 has no record (the folder records and the creator's
//!   grant to itself start the folder).

pub mod devices;
pub mod epochs;
pub mod escrow;
pub mod folders;
pub mod grants;
pub mod keys;
pub mod member_view;
pub mod members;
pub mod requests;
mod session;
mod store;
pub mod strongrooms;
pub mod trust;

#[cfg(test)]
mod tests;

pub use devices::{device_id, DeviceRecord, DeviceRegistry};
pub use epochs::{
    FolderEpochRecord, FolderEpochs, RemovalReport, Removed, RevocationRecord, VaultEpochRecord,
};
pub use escrow::{EscrowRecord, MissingEscrow, RecoveryKey};
pub use folders::{Denied, FolderRecord, FolderRegistry, FolderState, Participant};
pub use grants::{
    Directory, DirectoryEntry, FolderKeys, GrantRecord, GrantedKeys, VaultGrantRecord,
};
pub use keys::{KeyRing, VaultKeys};
pub use member_view::MemberView;
pub use members::{MemberDevice, MemberRegistry};
pub use requests::{fingerprint, PendingRequest, RequestRecord};
pub use session::{EpochStart, Membership};
pub use trust::Trust;

use crate::crypto::SecretKey;
use crate::record::Id16;
use serde::{Deserialize, Serialize};

/// The context prefix of every format-3 key derivation (design, notation).
pub const CONTEXT3: &str = "e2ee-sync-format/3";

/// `derive(K, purpose, scope...)` of the design: BLAKE3 `derive_key` with
/// the context `e2ee-sync-format/3/<purpose>` and length-prefixed scope ids.
pub fn derive3(key: &SecretKey, purpose: &str, scope: &[&[u8]]) -> SecretKey {
    key.derive_with_prefix(CONTEXT3, purpose, scope)
}

/// Most participants or denied entries one folder record may carry.
pub const MAX_PARTICIPANTS: usize = 65_536;
/// Longest device or folder name (bytes).
pub const MAX_NAME: usize = 128;

/// A (Lamport, device) stamp: orders entries written by different devices.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Stamp {
    pub lamport: u64,
    pub device: Id16,
}

/// A device's role in a folder (section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Editor,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
        }
    }
}

/// The zero scope (vault-wide records, vault grants).
pub const VAULT_SCOPE: Id16 = [0u8; 16];
