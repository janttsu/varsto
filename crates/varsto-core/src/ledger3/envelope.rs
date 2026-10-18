// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Batches and checkpoints are signed records of `crate::record`
//! (`docs/spec/format-3-design.md` sections 4 and 5): kind `batch` at
//! `ledger/<device hex>/<seq 16>-0000.rec`, kind `checkpoint` at
//! `ledger/<device hex>/checkpoint-<seq 16>-<part 4>.rec`. This module is
//! the ledger's door to that envelope: it seals through
//! `record::RecordWriter` (one sealing path for every kind, binding format
//! 3 into the signature and the body's associated data) and opens through
//! `record::Acceptor` (one acceptance rule for every kind: the name, the
//! envelope, the signature, the writer, then the body).
//!
//! The ledger chooses its keys by key id itself (`ledger@<e>`,
//! `share-ledger:<folder>@<e>`, `replica`), so the record keys here are
//! "the one key the caller hands in" ([`OneKey`]) and the record trust is
//! "the one device whose key the caller hands in" ([`OneSigner`]); which
//! events of a batch count is the ledger's scope rule (`super::scope`).

use super::checkpoint::{batch_key, checkpoint_key};
use super::{DeviceBin, FolderBin, Hash32};
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::record::accept::Acceptor;
use crate::record::envelope::{DeviceSigner, RecordKeys, RecordWriter};
use crate::record::{KeyId, Kind, RecordTrust, StreamRef};
use anyhow::{anyhow, bail, Context, Result};

pub use crate::record::SignedRecord;
pub use crate::record::{MAGIC, MAX_PARTS, MAX_PART_BODY, SIG_ALG_HYBRID};

/// The storage format of every record.
pub const RECORD_FORMAT: u16 = crate::record::FORMAT;
pub const MAX_KEY_ID: usize = crate::record::MAX_KEY_ID;
/// What a reader fetches of one part at most.
pub const READ_LIMIT: usize = crate::record::MAX_PART_READ as usize;

/// Record kinds (section 5's table), by code.
pub mod kind {
    use crate::record::Kind;

    pub const MANIFEST: u8 = 1;
    pub const BLOCK_MAP: u8 = 2;
    pub const TRASH: u8 = 3;
    pub const SNAPSHOT: u8 = 4;
    pub const PEER: u8 = 5;
    pub const EPOCH: u8 = 6;
    pub const SHARE_EPOCH: u8 = 7;
    pub const GRANT: u8 = 8;
    pub const REQUEST: u8 = 9;
    pub const REVOCATION: u8 = 10;
    pub const POLICY: u8 = 11;
    pub const PLACEMENT: u8 = 12;
    pub const CHECKPOINT: u8 = 13;
    pub const BATCH: u8 = 14;
    pub const FOLDER: u8 = 15;
    pub const DEVICE: u8 = 16;
    pub const ESCROW: u8 = 17;
    pub const SETTINGS: u8 = 18;
    pub const STORAGE_NAMES: u8 = 19;
    pub const ACCESS: u8 = 20;
    pub const NOTES: u8 = 21;
    pub const THUMBS: u8 = 22;

    /// The kind's name, used in the body AAD.
    pub fn name(kind: u8) -> Option<&'static str> {
        Kind::from_code(kind).map(Kind::name)
    }

    /// Kinds announced in a batch (`record_published`).
    pub fn announced(kind: u8) -> bool {
        Kind::from_code(kind).is_some_and(Kind::announced)
    }
}

/// What a batch or checkpoint says about itself before it is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub vault: [u8; 16],
    pub scope: FolderBin,
    pub device: DeviceBin,
    pub seq: u64,
    /// Set by the sealing functions (a batch is always one part).
    pub part: u16,
    pub parts: u16,
    pub key_id: String,
}

impl Header {
    fn kind(&self) -> Result<Kind> {
        match Kind::from_code(self.kind) {
            Some(k @ (Kind::Batch | Kind::Checkpoint)) => Ok(k),
            _ => bail!("the ledger seals batches and checkpoints only"),
        }
    }

    fn key(&self) -> Result<KeyId> {
        KeyId::parse(&self.key_id)
            .ok_or_else(|| anyhow!("key id {:?} is not one Varsto writes", self.key_id))
    }
}

/// The one key a caller hands in, whatever key id the record names: the
/// ledger looks its keys up by key id before it seals or opens.
pub struct OneKey<'a>(pub &'a SecretKey);

impl RecordKeys for OneKey<'_> {
    fn symmetric(&self, _key_id: &KeyId) -> Option<SecretKey> {
        Some(self.0.clone())
    }
}

/// No key at all: steps (1) to (3) only.
struct NoKey;

impl RecordKeys for NoKey {
    fn symmetric(&self, _key_id: &KeyId) -> Option<SecretKey> {
        None
    }
}

/// The one device whose signing key the caller trusts for this record.
/// Which of its events count is the ledger's scope rule, so step (3)
/// allows the kind (`section9_allows` puts batches in every row but the
/// untrusted one; the caller trusts the device by handing in its key).
pub struct OneSigner<'a> {
    pub device: DeviceBin,
    pub key: &'a VerifyingKey,
}

impl RecordTrust for OneSigner<'_> {
    fn signer_key(&self, device: &[u8; 16], _: Kind, _: &[u8; 16]) -> Option<VerifyingKey> {
        (*device == self.device).then(|| self.key.clone())
    }

    fn may_write(&self, device: &[u8; 16], kind: Kind, _: &[u8; 16], _: &KeyId) -> bool {
        *device == self.device && matches!(kind, Kind::Batch | Kind::Checkpoint)
    }
}

/// The storage name of a batch or checkpoint part.
pub fn storage_name(rec: &SignedRecord) -> String {
    if rec.kind == kind::CHECKPOINT {
        checkpoint_key(&rec.device, rec.seq, rec.part)
    } else {
        batch_key(&rec.device, rec.seq)
    }
}

/// Seal an already compressed body as one or more parts.
pub fn seal_compressed(
    h: &Header,
    key: &SecretKey,
    compressed: &[u8],
    signer: &SigningKey,
) -> Result<Vec<SignedRecord>> {
    let kind = h.kind()?;
    let stream = StreamRef::new(kind, h.scope, h.device);
    let writer = RecordWriter {
        vault: h.vault,
        signer: &DeviceSigner {
            device: h.device,
            key: signer,
        },
        keys: &OneKey(key),
    };
    let sealed = writer.seal_compressed(&stream, h.seq, h.seq, &h.key()?, compressed)?;
    sealed
        .parts
        .iter()
        .map(|(_, bytes)| SignedRecord::decode(bytes).map_err(|j| anyhow!("{j}")))
        .collect()
}

/// Seal a body of any size: postcard, zstd over the whole, the compressed
/// bytes cut into parts (`record::RecordWriter`).
pub fn seal_parts(
    h: &Header,
    key: &SecretKey,
    postcard: &[u8],
    signer: &SigningKey,
) -> Result<Vec<SignedRecord>> {
    let packed = zstd::bulk::compress(postcard, crate::record::envelope::ZSTD_LEVEL)?;
    seal_compressed(h, key, &packed, signer)
}

/// The postcard bytes of a record: every part of one (kind, vault, scope,
/// device, seq, key id), in order, none missing, each opened under `key`;
/// at most `limit` bytes after decompression.
pub fn open_parts(parts: &[SignedRecord], key: &SecretKey, limit: usize) -> Result<Vec<u8>> {
    let Some(first) = parts.first() else {
        bail!("a record without parts");
    };
    if parts.len() != first.parts as usize {
        bail!("record has {} of its {} parts", parts.len(), first.parts);
    }
    let mut packed = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if p.part as usize != i
            || p.parts != first.parts
            || p.kind != first.kind
            || p.vault != first.vault
            || p.scope != first.scope
            || p.device != first.device
            || p.seq != first.seq
            || p.key_id != first.key_id
        {
            bail!("record part {i} does not belong with the others");
        }
        packed.extend(p.open_part(&OneKey(key)).map_err(|j| anyhow!("{j}"))?);
    }
    zstd::bulk::decompress(&packed, limit).context("record body does not decompress")
}

/// BLAKE3 over the concatenated `body_hash` of the parts in order (one
/// part: its own hash): what a `record_published` carries.
pub fn parts_hash(parts: &[SignedRecord]) -> Hash32 {
    crate::record::record_hash(parts.iter().map(|p| &p.body_hash))
}

/// The `body` length a part with `data` bytes of compressed content gets.
pub fn padded_body_len(data: usize) -> usize {
    crate::record::pad::class_for(data + crate::record::pad::LEN_PREFIX + BODY_OVERHEAD)
}

/// AEAD nonce and tag around every body.
pub const BODY_OVERHEAD: usize = crate::crypto::NONCE_LEN + 16;

/// Steps (1) to (3) of `record::accept` for one batch or checkpoint part
/// read under `name`, and step (4) when `key` is given: the parsed
/// envelope and, with a key, the decompressed body (at most `limit`).
pub fn accept_part(
    name: &str,
    bytes: &[u8],
    vault: &[u8; 16],
    pubkey: &VerifyingKey,
    key: Option<&SecretKey>,
    limit: usize,
) -> Result<(SignedRecord, Option<Vec<u8>>)> {
    let env = SignedRecord::decode(bytes).map_err(|j| anyhow!("{name}: {j}"))?;
    let trust = OneSigner {
        device: env.device,
        key: pubkey,
    };
    let none = NoKey;
    let acceptor = Acceptor {
        vault: *vault,
        keys: &none,
        trust: &trust,
    };
    let parts = [(name.to_string(), bytes.to_vec())];
    let checked = acceptor.check_parts(&parts).map_err(|r| anyhow!("{r}"))?;
    if !matches!(checked.kind, Kind::Batch | Kind::Checkpoint) {
        bail!("{name} is not a batch or checkpoint");
    }
    let Some(key) = key else {
        return Ok((env, None));
    };
    let packed = env
        .open_part(&OneKey(key))
        .map_err(|j| anyhow!("{name}: {j}"))?;
    let plain =
        zstd::bulk::decompress(&packed, limit).context("record body does not decompress")?;
    Ok((env, Some(plain)))
}

/// Methods the ledger uses on its records, kept from the stand-in this
/// module replaced.
pub trait LedgerRecord: Sized {
    /// Seal a one-part record: `postcard` is compressed here.
    fn seal(h: &Header, key: &SecretKey, postcard: &[u8], signer: &SigningKey) -> Result<Self>;
    /// Seal a one-part record whose body is compressed already.
    fn seal_raw(h: &Header, key: &SecretKey, packed: &[u8], signer: &SigningKey) -> Result<Self>;
    /// The compressed body (one part's share of it).
    fn open_raw(&self, key: &SecretKey) -> Result<Vec<u8>>;
    /// The postcard bytes of a one-part record, at most `limit` of them.
    fn open(&self, key: &SecretKey, limit: usize) -> Result<Vec<u8>>;
}

impl LedgerRecord for SignedRecord {
    fn seal(h: &Header, key: &SecretKey, postcard: &[u8], signer: &SigningKey) -> Result<Self> {
        let packed = zstd::bulk::compress(postcard, crate::record::envelope::ZSTD_LEVEL)?;
        Self::seal_raw(h, key, &packed, signer)
    }

    fn seal_raw(h: &Header, key: &SecretKey, packed: &[u8], signer: &SigningKey) -> Result<Self> {
        let mut parts = seal_compressed(h, key, packed, signer)?;
        if parts.len() != 1 {
            bail!(
                "a {} record of {} bytes does not fit one part",
                h.kind()?,
                packed.len()
            );
        }
        Ok(parts.remove(0))
    }

    fn open_raw(&self, key: &SecretKey) -> Result<Vec<u8>> {
        self.open_part(&OneKey(key)).map_err(|j| anyhow!("{j}"))
    }

    fn open(&self, key: &SecretKey, limit: usize) -> Result<Vec<u8>> {
        let packed = self.open_raw(key)?;
        zstd::bulk::decompress(&packed, limit).context("record body does not decompress")
    }
}
