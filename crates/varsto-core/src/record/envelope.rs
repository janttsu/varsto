// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The SignedRecord envelope (format 3 design, section 5): encoding,
//! signature, body sealing and opening, parts, and the writer.

use super::accept::Junk;
use super::accept::RecordBody;
use super::kinds::{KeyId, Kind, StreamRef, MAX_KEY_ID};
use super::pad;
use super::{Id16, FORMAT};
use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::kem::{self, EncapsKey};
use crate::storage::Storage;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::io::Read as _;

/// The four bytes in front of every encoded envelope.
pub const MAGIC: &[u8; 4] = b"VSR3";
/// Largest body of one part (bytes on the storage, after padding).
pub const MAX_PART_BODY: usize = 32 << 20;
/// Most parts of one record.
pub const MAX_PARTS: u16 = 1024;
/// Largest object a reader fetches for one part: the body plus the
/// envelope around it.
pub const MAX_PART_READ: u64 = 33 << 20;
/// `sig_alg` of an Ed25519 + ML-DSA-65 signature, the only one accepted.
pub const SIG_ALG_HYBRID: u8 = 1;
/// Length of that signature (64 + 3309).
pub const SIG_LEN: usize = 64 + 3309;
/// Largest decompressed body of a whole record. A record cannot make a
/// reader allocate more, whatever its compressed size.
pub const MAX_DECODED_BODY: u64 = 4 << 30;
/// zstd level of record bodies.
pub const ZSTD_LEVEL: i32 = 3;

const AEAD_OVERHEAD: usize = crypto::NONCE_LEN + 16;

/// Byte vectors encoded as postcard byte strings: the same bytes on the
/// wire as a `Vec<u8>` sequence (varint length, then the bytes), decoded
/// without going through one `u8` at a time.
mod bytes {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bytes")
        }
        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }
        fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut out = Vec::new();
            while let Some(b) = seq.next_element()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_byte_buf(V)
    }
}

/// One part of a record as stored: `"VSR3" || postcard(SignedRecord)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    pub format: u16,
    pub kind: u8,
    pub vault: Id16,
    /// Zeros for vault-wide kinds.
    pub scope: Id16,
    pub device: Id16,
    pub seq: u64,
    pub part: u16,
    pub parts: u16,
    pub key_id: String,
    /// BLAKE3 of `body`.
    pub body_hash: [u8; 32],
    pub sig_alg: u8,
    #[serde(with = "bytes")]
    pub sig: Vec<u8>,
    /// nonce || AEAD ciphertext || tag (`kem:` bodies: the KEM ciphertext
    /// first; `none` bodies: the framed plaintext).
    #[serde(with = "bytes")]
    pub body: Vec<u8>,
}

/// What the signature covers (section 5).
#[allow(clippy::too_many_arguments)]
pub fn signed_message(
    kind: u8,
    vault: &Id16,
    scope: &Id16,
    device: &Id16,
    seq: u64,
    part: u16,
    parts: u16,
    key_id: &str,
    body_hash: &[u8; 32],
) -> Vec<u8> {
    crypto::aad_for_format(
        FORMAT,
        "record-signature",
        &[
            &[kind],
            vault,
            scope,
            device,
            &seq.to_le_bytes(),
            &part.to_le_bytes(),
            &parts.to_le_bytes(),
            key_id.as_bytes(),
            body_hash,
        ],
    )
}

/// The AEAD associated data of a part's body (section 5).
#[allow(clippy::too_many_arguments)]
pub fn body_aad(
    kind: Kind,
    vault: &Id16,
    scope: &Id16,
    device: &Id16,
    seq: u64,
    part: u16,
    parts: u16,
    key_id: &str,
) -> Vec<u8> {
    crypto::aad_for_format(
        FORMAT,
        kind.name(),
        &[
            vault,
            scope,
            device,
            &seq.to_le_bytes(),
            &part.to_le_bytes(),
            &parts.to_le_bytes(),
            key_id.as_bytes(),
        ],
    )
}

/// The hash a batch announces for a record: the part's `body_hash` for a
/// one-part record, else BLAKE3 over the parts' `body_hash` in order.
pub fn record_hash<'a>(part_hashes: impl IntoIterator<Item = &'a [u8; 32]>) -> [u8; 32] {
    let hashes: Vec<&[u8; 32]> = part_hashes.into_iter().collect();
    if let [one] = hashes.as_slice() {
        return **one;
    }
    let mut h = blake3::Hasher::new();
    for p in hashes {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

impl SignedRecord {
    pub fn kind(&self) -> Option<Kind> {
        Kind::from_code(self.kind)
    }

    /// The parsed `key_id` (decode guarantees it parses).
    pub fn key(&self) -> Option<KeyId> {
        KeyId::parse(&self.key_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + self.body.len() + self.sig.len() + 160);
        out.extend_from_slice(MAGIC);
        // Serialising a struct of plain fields into a Vec cannot fail.
        if let Ok(enc) = postcard::to_stdvec(self) {
            out.extend_from_slice(&enc);
        }
        out
    }

    /// Parse an envelope and check everything that needs no key: magic,
    /// format 3, a known kind, a key_id of the grammar and of a class that
    /// fits the kind, the part index and count, the signature algorithm and
    /// length, and the body length (a size class, at most
    /// `MAX_PART_BODY`; an empty body is allowed for envelopes sent as
    /// proofs, section 8, and refused when the body is opened).
    pub fn decode(bytes: &[u8]) -> Result<SignedRecord, Junk> {
        if bytes.len() as u64 > MAX_PART_READ {
            return Err(Junk::OversizePart);
        }
        let rest = bytes.strip_prefix(MAGIC).ok_or(Junk::BadMagic)?;
        let (rec, tail): (SignedRecord, &[u8]) =
            postcard::take_from_bytes(rest).map_err(|e| Junk::Malformed(e.to_string()))?;
        if !tail.is_empty() {
            return Err(Junk::Malformed(format!(
                "{} bytes after the envelope",
                tail.len()
            )));
        }
        if rec.format != FORMAT {
            return Err(Junk::WrongFormat(rec.format));
        }
        let kind = Kind::from_code(rec.kind).ok_or(Junk::UnknownKind(rec.kind))?;
        if rec.key_id.len() > MAX_KEY_ID {
            return Err(Junk::KeyIdTooLong);
        }
        let key = KeyId::parse(&rec.key_id).ok_or(Junk::BadKeyId)?;
        if !kind.key_fits(&key, &rec.scope, rec.seq) {
            return Err(Junk::KeyNotForKind);
        }
        if rec.parts == 0 || rec.parts > MAX_PARTS {
            return Err(Junk::TooManyParts);
        }
        if rec.part >= rec.parts {
            return Err(Junk::PartOutOfRange);
        }
        if rec.sig_alg != SIG_ALG_HYBRID || rec.sig.len() != SIG_LEN {
            return Err(Junk::BadSignature);
        }
        if rec.body.len() > MAX_PART_BODY {
            return Err(Junk::OversizePart);
        }
        if !rec.body.is_empty() && !pad::is_class(rec.body.len()) {
            return Err(Junk::BadBodyLength(rec.body.len()));
        }
        Ok(rec)
    }

    fn message(&self) -> Vec<u8> {
        signed_message(
            self.kind,
            &self.vault,
            &self.scope,
            &self.device,
            self.seq,
            self.part,
            self.parts,
            &self.key_id,
            &self.body_hash,
        )
    }

    /// Check the signature alone (an envelope without its body proves
    /// that its signer wrote a record with this `body_hash`).
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), Junk> {
        if !key.is_hybrid() || self.sig_alg != SIG_ALG_HYBRID {
            return Err(Junk::BadSignature);
        }
        key.verify(crypto::SIG_ALG, &self.message(), &self.sig)
            .map_err(|_| Junk::BadSignature)
    }

    /// Check `body_hash` against the body and the signature.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Junk> {
        if self.body.is_empty() || crypto::hash(&self.body) != self.body_hash {
            return Err(Junk::BadSignature);
        }
        self.verify_signature(key)
    }

    fn aad(&self, kind: Kind) -> Vec<u8> {
        body_aad(
            kind,
            &self.vault,
            &self.scope,
            &self.device,
            self.seq,
            self.part,
            self.parts,
            &self.key_id,
        )
    }

    /// Open this part's body: its share of the compressed body bytes.
    pub fn open_part(&self, keys: &dyn RecordKeys) -> Result<Vec<u8>, Junk> {
        let kind = self.kind().ok_or(Junk::UnknownKind(self.kind))?;
        let key = self.key().ok_or(Junk::BadKeyId)?;
        if self.body.is_empty() {
            return Err(Junk::BodyDoesNotOpen);
        }
        let aad = self.aad(kind);
        let plain = match &key {
            KeyId::None => self.body.clone(),
            KeyId::Kem(recipient) => {
                let ct = self
                    .body
                    .get(..kem::CIPHERTEXT_LEN)
                    .ok_or(Junk::BodyDoesNotOpen)?;
                let secret = keys
                    .kem_decapsulate(recipient, ct)
                    .ok_or(Junk::KeyNotHeld)?
                    .map_err(|_| Junk::BodyDoesNotOpen)?;
                crypto::decrypt(&secret, &aad, &self.body[kem::CIPHERTEXT_LEN..])
                    .map_err(|_| Junk::BodyDoesNotOpen)?
            }
            other => {
                let k = keys.symmetric(other).ok_or(Junk::KeyNotHeld)?;
                crypto::decrypt(&k, &aad, &self.body).map_err(|_| Junk::BodyDoesNotOpen)?
            }
        };
        pad::unframe(&plain)
            .map(<[u8]>::to_vec)
            .ok_or(Junk::BodyDoesNotOpen)
    }
}

/// Decompress the joined parts of a record and decode its body struct.
pub fn decode_body<T: RecordBody>(compressed: &[u8]) -> Result<T, Junk> {
    decode_body_limited(compressed, MAX_DECODED_BODY)
}

/// `decode_body` with a smaller limit on the decompressed size.
pub fn decode_body_limited<T: RecordBody>(compressed: &[u8], limit: u64) -> Result<T, Junk> {
    let limit = limit.min(MAX_DECODED_BODY);
    let mut dec = zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| Junk::BadBody(format!("zstd: {e}")))?;
    let mut plain = Vec::new();
    (&mut dec)
        .take(limit + 1)
        .read_to_end(&mut plain)
        .map_err(|e| Junk::BadBody(format!("zstd: {e}")))?;
    if plain.len() as u64 > limit {
        return Err(Junk::BadBody("body larger than a record may be".into()));
    }
    let (mut body, tail): (T, &[u8]) =
        postcard::take_from_bytes(&plain).map_err(|e| Junk::BadBody(e.to_string()))?;
    body.take_tail(tail).map_err(Junk::BadBody)?;
    Ok(body)
}

/// Keys that open and seal record bodies, named by `key_id`. Implemented by
/// the engine (registry, ledger, folder keys, the device's own K8); this
/// module never derives a key itself. `None` is "not held".
pub trait RecordKeys {
    /// The symmetric key of `registry@`, `ledger@`, `epoch@`, `meta:`,
    /// `share-ledger:`, `recovery` and `replica` key_ids.
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey>;
    /// Writer side of `kem:<recipient>`: the recipient's K8 public key.
    fn kem_public(&self, _recipient: &Id16) -> Option<EncapsKey> {
        None
    }
    /// Reader side of `kem:<recipient>`: decapsulate `ct` with this
    /// device's K8 when it is the recipient.
    fn kem_decapsulate(&self, _recipient: &Id16, _ct: &[u8]) -> Option<Result<SecretKey>> {
        None
    }
}

/// The device that signs the records it writes (K6).
pub trait RecordSigner {
    fn device(&self) -> Id16;
    /// An Ed25519 + ML-DSA-65 signature of `msg` (`SIG_LEN` bytes).
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// A device's signing key with its id.
pub struct DeviceSigner<'a> {
    pub device: Id16,
    pub key: &'a SigningKey,
}

impl RecordSigner for DeviceSigner<'_> {
    fn device(&self) -> Id16 {
        self.device
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg)
    }
}

/// What a writer's batch says about a record (`record_published`, section
/// 4); the ledger event itself is built by the ledger code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPublished {
    pub kind: u8,
    pub scope: Id16,
    pub seq: u64,
    pub base: u64,
    pub parts: u16,
    /// `record_hash` of the parts.
    pub body_hash: [u8; 32],
    /// Bytes of all part objects together.
    pub size: u64,
}

/// A sealed record: its part objects in order and its announcement.
#[derive(Clone, Debug)]
pub struct SealedRecord {
    /// (storage name, encoded envelope) per part.
    pub parts: Vec<(String, Vec<u8>)>,
    pub published: RecordPublished,
}

/// Seals records of one device.
pub struct RecordWriter<'a> {
    pub vault: Id16,
    pub signer: &'a dyn RecordSigner,
    pub keys: &'a dyn RecordKeys,
}

enum SealWith {
    Symmetric(SecretKey),
    Kem(EncapsKey),
    Plain,
}

impl SealWith {
    fn overhead(&self) -> usize {
        match self {
            SealWith::Symmetric(_) => AEAD_OVERHEAD,
            SealWith::Kem(_) => kem::CIPHERTEXT_LEN + AEAD_OVERHEAD,
            SealWith::Plain => 0,
        }
    }
}

impl RecordWriter<'_> {
    /// Seal `body` as record `seq` of `stream` under `key_id`. `base` is
    /// the seq of the base the record builds on (`seq` itself for a base
    /// and for kinds without bases). The stream's device must be the
    /// signer's.
    pub fn seal<T: Serialize>(
        &self,
        stream: &StreamRef,
        seq: u64,
        base: u64,
        key_id: &KeyId,
        body: &T,
    ) -> Result<SealedRecord> {
        let plain = postcard::to_stdvec(body).map_err(|e| anyhow!("encode record body: {e}"))?;
        let compressed = zstd::bulk::compress(&plain, ZSTD_LEVEL)?;
        self.seal_compressed(stream, seq, base, key_id, &compressed)
    }

    /// `seal` for an already encoded and compressed body.
    pub fn seal_compressed(
        &self,
        stream: &StreamRef,
        seq: u64,
        base: u64,
        key_id: &KeyId,
        compressed: &[u8],
    ) -> Result<SealedRecord> {
        let kind = stream.kind;
        let device = self.signer.device();
        if stream.device != device {
            bail!("a device seals records only in its own streams");
        }
        if !kind.key_fits(key_id, &stream.scope, seq) {
            bail!("key {key_id} does not seal {kind} records in this scope");
        }
        if let (KeyId::Kem(r), Some(name_r)) = (key_id, stream.recipient) {
            if *r != name_r {
                bail!("a grant is sealed to the device its name gives");
            }
        }
        let key_text = key_id.to_string();
        let with = match key_id {
            KeyId::None => SealWith::Plain,
            KeyId::Kem(r) => SealWith::Kem(
                self.keys
                    .kem_public(r)
                    .ok_or_else(|| anyhow!("no KEM key for {key_text}"))?,
            ),
            other => SealWith::Symmetric(
                self.keys
                    .symmetric(other)
                    .ok_or_else(|| anyhow!("key {key_text} is not held"))?,
            ),
        };
        let capacity = MAX_PART_BODY - with.overhead() - pad::LEN_PREFIX;
        let chunks: Vec<&[u8]> = if compressed.is_empty() {
            vec![&[][..]]
        } else {
            compressed.chunks(capacity).collect()
        };
        if chunks.len() > usize::from(MAX_PARTS) {
            bail!(
                "a {kind} record of {} bytes needs more than {MAX_PARTS} parts",
                compressed.len()
            );
        }
        let parts = chunks.len() as u16;
        let mut out = Vec::with_capacity(chunks.len());
        let mut hashes = Vec::with_capacity(chunks.len());
        let mut size = 0u64;
        for (i, data) in chunks.iter().enumerate() {
            let part = i as u16;
            let name = stream
                .part_name(seq, part)
                .ok_or_else(|| anyhow!("{kind} stream without its epoch or recipient"))?;
            let class = pad::class_for(with.overhead() + pad::LEN_PREFIX + data.len());
            let framed = pad::frame(data, class - with.overhead());
            let aad = body_aad(
                kind,
                &self.vault,
                &stream.scope,
                &device,
                seq,
                part,
                parts,
                &key_text,
            );
            let body = match &with {
                SealWith::Plain => framed,
                SealWith::Symmetric(k) => crypto::encrypt(k, &aad, &framed)?,
                SealWith::Kem(ek) => {
                    let (ct, secret) = ek.encapsulate()?;
                    let mut b = ct;
                    b.extend_from_slice(&crypto::encrypt(&secret, &aad, &framed)?);
                    b
                }
            };
            debug_assert_eq!(body.len(), class);
            let body_hash = crypto::hash(&body);
            let sig = self.signer.sign(&signed_message(
                kind.code(),
                &self.vault,
                &stream.scope,
                &device,
                seq,
                part,
                parts,
                &key_text,
                &body_hash,
            ));
            let rec = SignedRecord {
                format: FORMAT,
                kind: kind.code(),
                vault: self.vault,
                scope: stream.scope,
                device,
                seq,
                part,
                parts,
                key_id: key_text.clone(),
                body_hash,
                sig_alg: SIG_ALG_HYBRID,
                sig,
                body,
            };
            let bytes = rec.encode();
            size += bytes.len() as u64;
            hashes.push(body_hash);
            out.push((name, bytes));
        }
        Ok(SealedRecord {
            parts: out,
            published: RecordPublished {
                kind: kind.code(),
                scope: stream.scope,
                seq,
                base,
                parts,
                body_hash: record_hash(hashes.iter()),
                size,
            },
        })
    }

    /// Write the parts put-if-absent, in order. Fails when a part is
    /// already there (the seq is taken, or an earlier attempt stopped
    /// half-way: the writer moves on to the next seq).
    pub fn publish(storage: &dyn Storage, sealed: &SealedRecord) -> Result<()> {
        for (name, bytes) in &sealed.parts {
            if !storage.put_if_absent(name, bytes)? {
                bail!("{name} is already on {}", storage.name());
            }
        }
        Ok(())
    }
}
