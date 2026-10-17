// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! WP1 integration: this module stands in for the signed record envelope of
//! `docs/spec/format-3-design.md` section 5, which work package 1 builds as
//! `crate::record` (branch `f3-records`). It follows section 5 field for
//! field so that the integrator can replace it by re-exporting the real
//! `SignedRecord` (and its `kind` table) here; the ledger uses only
//! `seal_raw`, `seal`, `encode`, `decode`, `verify`, `open_raw`, `open` and
//! the public fields. Where WP1 decides a detail that section 5 leaves open
//! (how a body is split into parts), the choice made here is marked
//! `// WP1 integration` and must follow WP1's.

use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{DeviceBin, FolderBin, Hash32};

/// The four bytes before the postcard encoding of every record.
pub const MAGIC: &[u8; 4] = b"VSR3";
pub const RECORD_FORMAT: u16 = 3;
/// `sig_alg` 1: an Ed25519 and an ML-DSA-65 signature, both must verify.
pub const SIG_ALG_HYBRID: u8 = 1;
pub const MAX_KEY_ID: usize = 64;
/// Largest body of one part, most parts of one record, and what a reader
/// fetches of one part at most.
pub const MAX_PART_BODY: usize = 32 << 20;
pub const MAX_PARTS: u16 = 1024;
pub const READ_LIMIT: usize = 33 << 20;

/// Record kinds (section 5's table).
pub mod kind {
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
        Some(match kind {
            MANIFEST => "manifest",
            BLOCK_MAP => "block-map",
            TRASH => "trash",
            SNAPSHOT => "snapshot",
            PEER => "peer",
            EPOCH => "epoch",
            SHARE_EPOCH => "share-epoch",
            GRANT => "grant",
            REQUEST => "request",
            REVOCATION => "revocation",
            POLICY => "policy",
            PLACEMENT => "placement",
            CHECKPOINT => "checkpoint",
            BATCH => "batch",
            FOLDER => "folder",
            DEVICE => "device",
            ESCROW => "escrow",
            SETTINGS => "settings",
            STORAGE_NAMES => "storage-names",
            ACCESS => "access",
            NOTES => "notes",
            THUMBS => "thumbs",
            _ => return None,
        })
    }

    /// Kinds announced in a batch (`record_published`).
    pub fn announced(kind: u8) -> bool {
        matches!(kind, MANIFEST | BLOCK_MAP | TRASH | SNAPSHOT)
    }
}

/// The envelope of every published object but packs (section 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    pub format: u16,
    pub kind: u8,
    pub vault: [u8; 16],
    /// Zeros: vault-wide.
    pub scope: FolderBin,
    pub device: DeviceBin,
    pub seq: u64,
    pub part: u16,
    pub parts: u16,
    pub key_id: String,
    pub body_hash: Hash32,
    pub sig_alg: u8,
    pub sig: Vec<u8>,
    /// nonce || AEAD ciphertext || tag.
    pub body: Vec<u8>,
}

/// What a record says about itself before it is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub vault: [u8; 16],
    pub scope: FolderBin,
    pub device: DeviceBin,
    pub seq: u64,
    pub part: u16,
    pub parts: u16,
    pub key_id: String,
}

fn kind_name(kind: u8) -> Result<&'static str> {
    kind::name(kind).with_context(|| format!("unknown record kind {kind}"))
}

impl Header {
    fn body_aad(&self) -> Result<Vec<u8>> {
        Ok(crypto::aad(
            kind_name(self.kind)?,
            &[
                &self.vault,
                &self.scope,
                &self.device,
                &self.seq.to_le_bytes(),
                &self.part.to_le_bytes(),
                &self.parts.to_le_bytes(),
                self.key_id.as_bytes(),
            ],
        ))
    }

    fn signed_message(&self, body_hash: &Hash32) -> Vec<u8> {
        crypto::aad(
            "record-signature",
            &[
                &[self.kind],
                &self.vault,
                &self.scope,
                &self.device,
                &self.seq.to_le_bytes(),
                &self.part.to_le_bytes(),
                &self.parts.to_le_bytes(),
                self.key_id.as_bytes(),
                body_hash,
            ],
        )
    }
}

impl SignedRecord {
    pub fn header(&self) -> Header {
        Header {
            kind: self.kind,
            vault: self.vault,
            scope: self.scope,
            device: self.device,
            seq: self.seq,
            part: self.part,
            parts: self.parts,
            key_id: self.key_id.clone(),
        }
    }

    /// Seal `plain` (already compressed, or a part of a compressed body)
    /// under `key` and sign the envelope. The AEAD plaintext is
    /// `len: u32 || plain || random padding` (section 5, "Padding").
    pub fn seal_raw(
        h: &Header,
        key: &SecretKey,
        plain: &[u8],
        signer: &SigningKey,
    ) -> Result<Self> {
        if h.key_id.len() > MAX_KEY_ID {
            bail!("key id longer than {MAX_KEY_ID} bytes");
        }
        if h.parts == 0 || h.parts > MAX_PARTS || h.part >= h.parts {
            bail!("part {} of {} is not allowed", h.part, h.parts);
        }
        if signer.alg() != crypto::SIG_ALG {
            bail!("format 3 records are signed with {} only", crypto::SIG_ALG);
        }
        let body = crypto::encrypt(key, &h.body_aad()?, &pad(plain)?)?;
        if body.len() > MAX_PART_BODY {
            bail!("a record part of {} bytes is over the limit", body.len());
        }
        let body_hash = crypto::hash(&body);
        let sig = signer.sign(&h.signed_message(&body_hash));
        Ok(SignedRecord {
            format: RECORD_FORMAT,
            kind: h.kind,
            vault: h.vault,
            scope: h.scope,
            device: h.device,
            seq: h.seq,
            part: h.part,
            parts: h.parts,
            key_id: h.key_id.clone(),
            body_hash,
            sig_alg: SIG_ALG_HYBRID,
            sig,
            body,
        })
    }

    /// Seal a one-part record whose plaintext is `zstd(postcard)`: `plain`
    /// is the postcard encoding, compressed here.
    pub fn seal(h: &Header, key: &SecretKey, postcard: &[u8], signer: &SigningKey) -> Result<Self> {
        let packed = zstd::bulk::compress(postcard, 3)?;
        Self::seal_raw(h, key, &packed, signer)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = MAGIC.to_vec();
        out.extend(postcard::to_allocvec(self)?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > READ_LIMIT + 8192 {
            bail!("record of {} bytes is over the read limit", bytes.len());
        }
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .context("not a format-3 record (magic)")?;
        let rec: SignedRecord = postcard::from_bytes(rest).context("record envelope")?;
        if rec.format != RECORD_FORMAT {
            bail!("record of format {}, not {RECORD_FORMAT}", rec.format);
        }
        if rec.key_id.len() > MAX_KEY_ID {
            bail!("key id longer than {MAX_KEY_ID} bytes");
        }
        if rec.parts == 0 || rec.parts > MAX_PARTS || rec.part >= rec.parts {
            bail!("part {} of {} is not allowed", rec.part, rec.parts);
        }
        Ok(rec)
    }

    /// The body hash and the signature over the envelope; does not decrypt.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<()> {
        if crypto::hash(&self.body) != self.body_hash {
            bail!("record body does not match its body_hash");
        }
        if self.sig_alg != SIG_ALG_HYBRID {
            bail!("record signature algorithm {} is not allowed", self.sig_alg);
        }
        pubkey.verify(
            crypto::SIG_ALG,
            &self.header().signed_message(&self.body_hash),
            &self.sig,
        )
    }

    /// The decrypted body as it was sealed (compressed bytes, or a part),
    /// without its length field and padding.
    pub fn open_raw(&self, key: &SecretKey) -> Result<Vec<u8>> {
        unpad(crypto::decrypt(
            key,
            &self.header().body_aad()?,
            &self.body,
        )?)
    }

    /// The postcard bytes of a one-part record, at most `limit` of them.
    pub fn open(&self, key: &SecretKey, limit: usize) -> Result<Vec<u8>> {
        let packed = self.open_raw(key)?;
        zstd::bulk::decompress(&packed, limit).context("record body does not decompress")
    }
}

/// AEAD nonce and tag around every body.
pub const BODY_OVERHEAD: usize = crypto::NONCE_LEN + 16;

/// The `body` length a record with `data` bytes of compressed content
/// gets: the length field, nonce and tag included, rounded up to 64 KiB
/// below 4 MiB and to 1 MiB from 4 MiB up.
pub fn padded_body_len(data: usize) -> usize {
    let n = data + 4 + BODY_OVERHEAD;
    let step = if n < (4 << 20) { 64 << 10 } else { 1 << 20 };
    n.div_ceil(step) * step
}

/// WP1 integration: section 5's padding, `len: u32 || data || CSPRNG bytes`.
fn pad(data: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(data.len()).context("record body over 4 GiB")?;
    let total = padded_body_len(data.len()) - BODY_OVERHEAD;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    let start = out.len();
    out.resize(total, 0);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out[start..]);
    Ok(out)
}

fn unpad(mut plain: Vec<u8>) -> Result<Vec<u8>> {
    if plain.len() < 4 {
        bail!("record body without its length field");
    }
    let len = u32::from_le_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
    if len > plain.len() - 4 {
        bail!("record body length {len} passes the end of the body");
    }
    plain.truncate(4 + len);
    plain.drain(..4);
    Ok(plain)
}

/// Seal a body of any size as `parts` records: postcard, zstd over the
/// whole, then the compressed bytes cut into parts of at most
/// `MAX_PART_BODY` of padded body each. `h.part`/`h.parts` are set here.
///
/// WP1 integration: section 5 leaves open whether parts are cut before or
/// after compression; this follows "plaintext = zstd(postcard)" over the
/// whole record and cuts the compressed stream. Use WP1's splitter instead.
pub fn seal_parts(
    h: &Header,
    key: &SecretKey,
    postcard: &[u8],
    signer: &SigningKey,
) -> Result<Vec<SignedRecord>> {
    let packed = zstd::bulk::compress(postcard, 3)?;
    let room = MAX_PART_BODY - BODY_OVERHEAD - 4;
    let chunks: Vec<&[u8]> = if packed.is_empty() {
        vec![&packed[..]]
    } else {
        packed.chunks(room).collect()
    };
    if chunks.len() > MAX_PARTS as usize {
        bail!(
            "a record of {} bytes needs more than {MAX_PARTS} parts",
            packed.len()
        );
    }
    let parts = chunks.len() as u16;
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let hp = Header {
                part: i as u16,
                parts,
                ..h.clone()
            };
            SignedRecord::seal_raw(&hp, key, c, signer)
        })
        .collect()
}

/// The postcard bytes of a record sealed by `seal_parts`: every part of one
/// (kind, vault, scope, device, seq, key_id), in order, none missing.
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
        packed.extend(p.open_raw(key)?);
    }
    zstd::bulk::decompress(&packed, limit).context("record body does not decompress")
}

/// BLAKE3 over the concatenated `body_hash` of the parts in order: the hash
/// a `record_published` of a multi-part record carries (section 4).
pub fn parts_hash(parts: &[SignedRecord]) -> Hash32 {
    if parts.len() == 1 {
        return parts[0].body_hash;
    }
    let mut cat = Vec::with_capacity(parts.len() * 32);
    for p in parts {
        cat.extend_from_slice(&p.body_hash);
    }
    crypto::hash(&cat)
}
