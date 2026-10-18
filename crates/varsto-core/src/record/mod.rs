// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Signed records of storage format 3 (`docs/spec/format-3-design.md`,
//! section 5; work package 1). Built behind the `format3` feature; nothing
//! in the format-2 code path calls it yet.
//!
//! Every object a device publishes, except packs, is a [`SignedRecord`]:
//! `"VSR3" || postcard(envelope)`. The envelope names the kind, vault,
//! scope, writing device, seq, part and part count and the `key_id` of the
//! key that opens the body, and carries `body_hash` = BLAKE3(body) and an
//! Ed25519 + ML-DSA-65 signature over all of these. The body is
//! `nonce || XChaCha20-Poly1305 ciphertext || tag`, with the envelope's
//! fields as associated data; its plaintext is `len: u32 LE ||` a slice of
//! `zstd(postcard(body struct)) ||` random padding, so that every body
//! length is a size class ([`pad`]). A body larger than one part's 32 MiB
//! is split into up to 1024 parts; a batch announces BLAKE3 over the
//! parts' `body_hash` ([`record_hash`]).
//!
//! - [`kinds`]: the kind table (codes 1-22), stream names, `key_id`.
//! - [`envelope`]: encoding, signing, sealing and opening, [`RecordWriter`].
//! - [`accept`]: the acceptance rule, refusals, [`RecordStore`].
//!
//! Keys and trust come from the engine through [`RecordKeys`],
//! [`RecordSigner`] and [`RecordTrust`]; this module derives no key and
//! holds no state of its own.
//!
//! Interpretations of the design (for review):
//! - `aad(...)` of records binds format version 3
//!   (`crypto::aad_for_format`), while the vault format is still 2.
//! - A body's size class applies to the whole `body` field (nonce, KEM
//!   ciphertext and tag included), as section 5's "Padding" says for
//!   nonce and tag.
//! - `kem:` bodies are `KEM ciphertext || nonce || ciphertext || tag`, the
//!   AEAD key being the KEM secret and the associated data the generic body
//!   AAD; `none` bodies are the framed plaintext without encryption.
//!   Escrow bodies are opened with the generic body AAD too, under the key
//!   the engine resolves for `recovery`.
//! - The `vault/revocations/<device>/<issuer>/` stream puts the revoked
//!   device in `scope`, so it is signed; vault grants are named
//!   `vault/grants/vault/...` (zero scope).
//! - The epoch in grant and escrow names is not in the envelope: it is
//!   handed to the body's own check ([`RecordMeta::epoch`]).
//! - A one-part record's announced hash is its part's `body_hash`.

pub mod accept;
pub mod envelope;
pub mod kinds;
pub mod pad;

#[cfg(test)]
mod tests;

pub use accept::{
    Acceptor, Announced, Junk, Listed, Outcome, Parts, Record, RecordBody, RecordMeta, RecordStore,
    RecordTrust, RecordsRefused, Refusal, Refused, StreamRead, MAX_AHEAD,
};
pub use envelope::{
    record_hash, DeviceSigner, RecordKeys, RecordPublished, RecordSigner, RecordWriter,
    SealedRecord, SignedRecord, MAGIC, MAX_PARTS, MAX_PART_BODY, MAX_PART_READ, SIG_ALG_HYBRID,
};
pub use kinds::{KeyId, Kind, RecordName, StreamRef, MAX_KEY_ID};

/// A binary vault, folder, device or backup id (16 bytes on the wire).
pub type Id16 = [u8; 16];

/// The storage format these records belong to.
pub const FORMAT: u16 = 3;

/// The 16 bytes of an id (`crate::ids::Id`), when it has exactly 16.
pub fn id16(id: &crate::ids::Id) -> Option<Id16> {
    parse_hex16(id.as_str())
}

fn parse_hex16(s: &str) -> Option<Id16> {
    kinds::parse_id16(s)
}

/// A writer's relation to the scope of a record: the rows of section 9.
/// The engine picks the row (for a vault-wide record a device of the
/// vault is `FullVault`; for a folder, its role there).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterClass {
    /// A full device of the vault, writing vault-wide records.
    FullVault,
    FullOwner,
    FullEditor,
    FullViewer,
    /// A full device without a grant for the folder (K3 only).
    FullNoGrant,
    MemberEditor,
    MemberViewer,
    Replica,
    /// Storages, peers, anyone else.
    Untrusted,
}

/// Whether section 9 lets `class` write records of `kind`.
pub fn section9_allows(class: WriterClass, kind: Kind) -> bool {
    use Kind::*;
    match class {
        WriterClass::FullOwner => true,
        // Snapshots are written by the backup's source device, a full
        // device of the vault (sections 4 and 9); `snapshot_expired` and
        // `backup_stopped` are full-only ledger events (WP3).
        WriterClass::FullVault => matches!(
            kind,
            Snapshot
                | Peer
                | Epoch
                | Grant
                | Revocation
                | Policy
                | Checkpoint
                | Batch
                | Device
                | Settings
                | StorageNames
        ),
        WriterClass::FullEditor => {
            matches!(
                kind,
                Manifest | BlockMap | Trash | Access | Notes | Thumbs | Batch
            )
        }
        WriterClass::FullViewer => matches!(kind, Access | Batch),
        WriterClass::FullNoGrant => matches!(
            kind,
            Request | Device | Peer | Policy | Placement | Settings | StorageNames | Batch
        ),
        WriterClass::MemberEditor => matches!(kind, Manifest | BlockMap | Trash | Batch),
        WriterClass::MemberViewer | WriterClass::Replica => kind == Batch,
        WriterClass::Untrusted => false,
    }
}
