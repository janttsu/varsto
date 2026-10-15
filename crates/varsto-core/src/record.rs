// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One signed envelope for every object a device publishes except chunks
//! and packs (`docs/spec/format-2-design.md` section 3).
//!
//! ```text
//! SignedRecord {
//!   format, kind, vault, scope, device, seq, key_id,
//!   body_hash: BLAKE3(body), sig_alg,
//!   sig:  hybrid signature over aad("record-signature",
//!         [format, kind, vault, scope, device, seq, key_id, body_hash]),
//!   body: AEAD ciphertext under the key `key_id` names,
//!         AAD = aad(kind, [format, vault, scope, device, seq, key_id]),
//! }
//! ```
//!
//! Every field a reader acts on is inside the signed message, the key id
//! included, so a storage can neither relabel a record (another key, scope
//! or sequence number) nor move it to another vault or device: the
//! signature or the AEAD fails. A record whose body is sealed to a
//! recipient's key-exchange key (grants) carries the hybrid KEM ciphertext
//! in front of the AEAD ciphertext and names the recipient in its key id
//! (`kem:<recipient>`).
//!
//! What a reader must check besides the envelope is the same for every
//! kind and lives with the caller: that the signer is authorized for the
//! kind and scope (section 6), and for manifests, trash records, snapshots
//! and pack indexes that a ledger batch of the same device announced
//! `(kind, scope, seq, body_hash)`.

use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, VaultId};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// What a record is. The kind is part of the signed message and of the
/// body's associated data, so a record of one kind never passes for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKind {
    Manifest,
    Trash,
    Snapshot,
    PackIndex,
    Tombstones,
    Peer,
    Epoch,
    ShareEpoch,
    Grant,
    Request,
    Revocation,
    Policy,
    Placement,
    Checkpoint,
    Batch,
    /// Settings of one storage (quota, trash storage).
    StorageSettings,
    /// A copy of a folder key under the recovery key (section 5).
    Escrow,
    /// A folder record: name, settings, participants (no key).
    Folder,
    /// The roles of a folder's participants.
    FolderRoles,
}

impl RecordKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::Manifest => "manifest",
            RecordKind::Trash => "trash",
            RecordKind::Snapshot => "snapshot",
            RecordKind::PackIndex => "pack-index",
            RecordKind::Tombstones => "tombstones",
            RecordKind::Peer => "peer",
            RecordKind::Epoch => "epoch",
            RecordKind::ShareEpoch => "share-epoch",
            RecordKind::Grant => "grant",
            RecordKind::Request => "request",
            RecordKind::Revocation => "revocation",
            RecordKind::Policy => "policy",
            RecordKind::Placement => "placement",
            RecordKind::Checkpoint => "checkpoint",
            RecordKind::Batch => "batch",
            RecordKind::StorageSettings => "storage-settings",
            RecordKind::Escrow => "escrow",
            RecordKind::Folder => "folder",
            RecordKind::FolderRoles => "folder-roles",
        }
    }

    /// Kinds that count only once a ledger batch of their writer announced
    /// them (section 3): the reader applies such a record only when the
    /// announced `(kind, scope, seq, body_hash)` matches.
    pub fn needs_announcement(&self) -> bool {
        matches!(
            self,
            RecordKind::Manifest | RecordKind::Trash | RecordKind::Snapshot | RecordKind::PackIndex
        )
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Key id of a body sealed to a recipient's key-exchange key.
pub const KEM_KEY_PREFIX: &str = "kem:";

/// Largest record body a reader opens (a checkpoint of a large vault is the
/// biggest legitimate record).
pub const MAX_BODY: usize = 1 << 30;

/// The envelope as stored (JSON, body and signature in hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub format: u16,
    pub kind: RecordKind,
    pub vault: VaultId,
    /// A folder id, a checkpoint's head hash, or empty.
    #[serde(default)]
    pub scope: String,
    pub device: DeviceId,
    pub seq: u64,
    pub key_id: String,
    /// BLAKE3 of the body bytes, hex.
    pub body_hash: String,
    pub sig_alg: String,
    /// Hybrid signature, hex.
    pub sig: String,
    /// The body bytes, hex.
    pub body: String,
}

/// The header fields of a record, without body and signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub kind: RecordKind,
    pub vault: &'a VaultId,
    pub scope: &'a str,
    pub device: &'a DeviceId,
    pub seq: u64,
    pub key_id: &'a str,
}

impl Header<'_> {
    fn message(&self, body_hash: &str) -> Vec<u8> {
        crypto::aad(
            "record-signature",
            &[
                &crate::FORMAT_VERSION.to_le_bytes(),
                self.kind.as_str().as_bytes(),
                self.vault.as_str().as_bytes(),
                self.scope.as_bytes(),
                self.device.as_str().as_bytes(),
                &self.seq.to_le_bytes(),
                self.key_id.as_bytes(),
                body_hash.as_bytes(),
            ],
        )
    }

    /// Associated data of the body.
    pub fn body_aad(&self) -> Vec<u8> {
        crypto::aad(
            self.kind.as_str(),
            &[
                &crate::FORMAT_VERSION.to_le_bytes(),
                self.vault.as_str().as_bytes(),
                self.scope.as_bytes(),
                self.device.as_str().as_bytes(),
                &self.seq.to_le_bytes(),
                self.key_id.as_bytes(),
            ],
        )
    }

    /// Encrypt `plain` under `key` and sign the result.
    pub fn seal(&self, key: &SecretKey, plain: &[u8], signer: &SigningKey) -> Result<SignedRecord> {
        let body = crypto::encrypt(key, &self.body_aad(), plain)?;
        Ok(self.sign_body(body, signer))
    }

    /// Seal `plain` to a recipient's key-exchange key: the key id must be
    /// `kem:<recipient>`; the body is the KEM ciphertext followed by the
    /// AEAD ciphertext under the encapsulated secret.
    pub fn seal_to(
        &self,
        to: &crate::kem::EncapsKey,
        plain: &[u8],
        signer: &SigningKey,
    ) -> Result<SignedRecord> {
        if !self.key_id.starts_with(KEM_KEY_PREFIX) {
            bail!("a record sealed to a key-exchange key needs a kem: key id");
        }
        let (kem_ct, shared) = to.encapsulate()?;
        let key = shared.derive("record-kem", &[self.body_aad().as_slice()]);
        let mut body = kem_ct;
        body.extend_from_slice(&crypto::encrypt(&key, &self.body_aad(), plain)?);
        Ok(self.sign_body(body, signer))
    }

    /// Sign an already encrypted body (or a body that needs no encryption).
    pub fn sign_body(&self, body: Vec<u8>, signer: &SigningKey) -> SignedRecord {
        let body_hash = hex::encode(crypto::hash(&body));
        let sig = signer.sign(&self.message(&body_hash));
        SignedRecord {
            format: crate::FORMAT_VERSION,
            kind: self.kind,
            vault: self.vault.clone(),
            scope: self.scope.to_string(),
            device: self.device.clone(),
            seq: self.seq,
            key_id: self.key_id.to_string(),
            body_hash,
            sig_alg: signer.alg().to_string(),
            sig: hex::encode(sig),
            body: hex::encode(body),
        }
    }
}

impl SignedRecord {
    pub fn header(&self) -> Header<'_> {
        Header {
            kind: self.kind,
            vault: &self.vault,
            scope: &self.scope,
            device: &self.device,
            seq: self.seq,
            key_id: &self.key_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a record always serializes")
    }

    /// Parse a stored record. Anything that is not a format-2 record of a
    /// known kind is refused.
    pub fn parse(blob: &[u8]) -> Result<SignedRecord> {
        let r: SignedRecord = serde_json::from_slice(blob).context("not a signed record")?;
        if r.format != crate::FORMAT_VERSION {
            bail!("record of storage format {}", r.format);
        }
        Ok(r)
    }

    /// Parse and require a kind.
    pub fn parse_kind(blob: &[u8], kind: RecordKind) -> Result<SignedRecord> {
        let r = Self::parse(blob)?;
        if r.kind != kind {
            bail!("a {} record where a {kind} record was expected", r.kind);
        }
        Ok(r)
    }

    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        if self.body.len() / 2 > MAX_BODY {
            bail!("record body too large");
        }
        Ok(hex::decode(&self.body)?)
    }

    /// The raw body hash.
    pub fn body_hash_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.body_hash)?;
        v.try_into()
            .map_err(|_| anyhow!("record body hash has the wrong length"))
    }

    /// Check the body hash and the writer's signature. Only the hybrid
    /// algorithm is accepted.
    pub fn verify(&self, pk: &VerifyingKey) -> Result<()> {
        if self.sig_alg != crypto::SIG_ALG {
            bail!(
                "record signed with {}, not {}",
                self.sig_alg,
                crypto::SIG_ALG
            );
        }
        let body = self.body_bytes()?;
        if hex::encode(crypto::hash(&body)) != self.body_hash {
            bail!("record body does not match its hash");
        }
        if crate::ledger::device_id_for(pk) != self.device {
            bail!("record names another device than the key that verifies it");
        }
        pk.verify(
            &self.sig_alg,
            &self.header().message(&self.body_hash),
            &hex::decode(&self.sig)?,
        )
    }

    /// Check what the reader expects of the header: the kind, the vault,
    /// and (when given) the scope, device and sequence number its object
    /// name says.
    pub fn expect(&self, e: &Expect<'_>) -> Result<()> {
        if self.kind != e.kind {
            bail!(
                "a {} record where a {} record was expected",
                self.kind,
                e.kind
            );
        }
        if &self.vault != e.vault {
            bail!("record of another vault");
        }
        if let Some(s) = e.scope {
            if self.scope != s {
                bail!("record names another scope");
            }
        }
        if let Some(d) = e.device {
            if &self.device != d {
                bail!("record names another device than its object name");
            }
        }
        if let Some(q) = e.seq {
            if self.seq != q {
                bail!("record names another sequence number than its object name");
            }
        }
        Ok(())
    }

    /// Decrypt the body under `key` (the caller resolved `key_id` to it).
    pub fn open(&self, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::decrypt(key, &self.header().body_aad(), &self.body_bytes()?)
    }

    /// Decrypt the body under the key its key id names, as `key_for`
    /// resolves it; a key id this device holds no key for is an error.
    pub fn open_with(&self, key_for: &dyn Fn(&str) -> Option<SecretKey>) -> Result<Vec<u8>> {
        let key = key_for(&self.key_id)
            .ok_or_else(|| anyhow!("no key {} on this device", self.key_id))?;
        self.open(&key)
    }

    /// The common acceptance of a vault record: header as expected, writer
    /// known (`writer_key`) and its signature valid, body opened under the
    /// key its key id names.
    pub fn accept(
        &self,
        e: &Expect<'_>,
        writer_key: &dyn Fn(&DeviceId) -> Option<VerifyingKey>,
        key_for: &dyn Fn(&str) -> Option<SecretKey>,
    ) -> Result<Vec<u8>> {
        self.expect(e)?;
        let pk = writer_key(&self.device).ok_or_else(|| anyhow!("unknown writer"))?;
        self.verify(&pk)?;
        self.open_with(key_for)
    }

    /// Decrypt a body sealed to this device's key-exchange key.
    pub fn open_sealed(&self, dk: &crate::kem::DecapsKey) -> Result<Vec<u8>> {
        if !self.key_id.starts_with(KEM_KEY_PREFIX) {
            bail!("record is not sealed to a key-exchange key");
        }
        let body = self.body_bytes()?;
        if body.len() < crate::kem::CIPHERTEXT_LEN {
            bail!("sealed record too short");
        }
        let (kem_ct, ct) = body.split_at(crate::kem::CIPHERTEXT_LEN);
        let shared = dk.decapsulate(kem_ct)?;
        let aad = self.header().body_aad();
        let key = shared.derive("record-kem", &[aad.as_slice()]);
        crypto::decrypt(&key, &aad, ct)
    }

    /// The whole acceptance of an envelope: header as expected, hash and
    /// signature valid against `pk`, body opens under `key`.
    pub fn verify_open(
        &self,
        e: &Expect<'_>,
        pk: &VerifyingKey,
        key: &SecretKey,
    ) -> Result<Vec<u8>> {
        self.expect(e)?;
        self.verify(pk)?;
        self.open(key)
    }
}

/// What a reader knows about a record before it reads it.
#[derive(Clone, Debug)]
pub struct Expect<'a> {
    pub kind: RecordKind,
    pub vault: &'a VaultId,
    pub scope: Option<&'a str>,
    pub device: Option<&'a DeviceId>,
    pub seq: Option<u64>,
}

impl<'a> Expect<'a> {
    pub fn new(kind: RecordKind, vault: &'a VaultId) -> Self {
        Expect {
            kind,
            vault,
            scope: None,
            device: None,
            seq: None,
        }
    }
    pub fn scope(mut self, scope: &'a str) -> Self {
        self.scope = Some(scope);
        self
    }
    pub fn device(mut self, device: &'a DeviceId) -> Self {
        self.device = Some(device);
        self
    }
    pub fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }
}

/// The key id of a folder metadata key of epoch `epoch` (`meta@<epoch>`).
pub fn meta_key_id(epoch: u32) -> String {
    format!("meta@{epoch}")
}

/// The epoch a `meta@<epoch>` key id names.
pub fn parse_meta_key_id(id: &str) -> Option<u32> {
    id.strip_prefix("meta@")?.parse().ok()
}

/// The key id of the folder-record key of vault epoch `epoch`
/// (`folder-record@<epoch>`): policies, placements, storage settings.
pub fn folder_record_key_id(epoch: u32) -> String {
    format!("folder-record@{epoch}")
}

/// The epoch a `folder-record@<epoch>` key id names.
pub fn parse_folder_record_key_id(id: &str) -> Option<u32> {
    id.strip_prefix("folder-record@")?.parse().ok()
}

/// The key id of the device-registry key of vault epoch `epoch`
/// (`registry@<epoch>`): folder records, requests, peer records.
pub fn registry_key_id(epoch: u32) -> String {
    format!("registry@{epoch}")
}

/// The epoch a `registry@<epoch>` key id names.
pub fn parse_registry_key_id(id: &str) -> Option<u32> {
    id.strip_prefix("registry@")?.parse().ok()
}

/// The key id of a body sealed to `recipient`'s key-exchange key.
pub fn kem_key_id(recipient: &str) -> String {
    format!("{KEM_KEY_PREFIX}{recipient}")
}

/// The envelope as the block layer uses it for pack indexes and tombstone
/// lists (`crate::packs`, design section 2): this device seals and signs;
/// a reader opens a record only when its header is the one its name says,
/// its writer is a device it knows (`writers`: the vault's devices and the
/// members of shared folders) and the signature holds. The key id is a
/// short keyed hash of the key, so a reader skips a key that is not the
/// record's without trying it.
#[derive(Clone)]
pub struct Records {
    vault: VaultId,
    device: DeviceId,
    signer: std::sync::Arc<SigningKey>,
    writers: std::sync::Arc<std::collections::BTreeMap<DeviceId, VerifyingKey>>,
}

impl std::fmt::Debug for Records {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Records")
            .field("vault", &self.vault)
            .field("device", &self.device)
            .field("writers", &self.writers.len())
            .finish()
    }
}

/// The record kind of a block-layer record name.
fn block_kind(kind: &str) -> Result<RecordKind> {
    match kind {
        "pack-index" => Ok(RecordKind::PackIndex),
        "tombstones" => Ok(RecordKind::Tombstones),
        other => bail!("{other} is not a record kind of the block layer"),
    }
}

/// The key id of a block-layer record: a keyed hash of the key itself.
pub fn key_fingerprint_id(key: &SecretKey) -> String {
    format!(
        "k:{}",
        hex::encode(&crypto::keyed_hash(key, b"varsto record key id")[..8])
    )
}

impl Records {
    /// `signer` is this device's signing key; `writers` the keys of the
    /// devices whose records this device accepts (itself included).
    pub fn new(
        vault: VaultId,
        device: DeviceId,
        signer: std::sync::Arc<SigningKey>,
        writers: std::collections::BTreeMap<DeviceId, VerifyingKey>,
    ) -> Records {
        Records {
            vault,
            device,
            signer,
            writers: std::sync::Arc::new(writers),
        }
    }

    /// The device that writes this device's records.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// Seal and sign record `seq` of `kind` in `scope` (a folder id, or
    /// empty for the vault) written by this device.
    pub fn seal(
        &self,
        kind: &str,
        scope: &str,
        seq: u64,
        key: &SecretKey,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = key_fingerprint_id(key);
        Ok(Header {
            kind: block_kind(kind)?,
            vault: &self.vault,
            scope,
            device: &self.device,
            seq,
            key_id: &key_id,
        }
        .seal(key, body, &self.signer)?
        .to_bytes())
    }

    /// Open record `seq` of `kind` in `scope` that `writer` published.
    pub fn open(
        &self,
        kind: &str,
        scope: &str,
        writer: &DeviceId,
        seq: u64,
        key: &SecretKey,
        blob: &[u8],
    ) -> Result<Vec<u8>> {
        let env = SignedRecord::parse(blob)?;
        env.expect(
            &Expect::new(block_kind(kind)?, &self.vault)
                .scope(scope)
                .device(writer)
                .seq(seq),
        )?;
        if env.key_id != key_fingerprint_id(key) {
            bail!("the record is sealed under another key");
        }
        let pk = self
            .writers
            .get(writer)
            .ok_or_else(|| anyhow!("record of an unknown writer"))?;
        env.verify(pk)?;
        env.open(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (VaultId, SigningKey, DeviceId) {
        let sk = SigningKey::generate();
        let dev = crate::ledger::device_id_for(&sk.public());
        (VaultId::random(), sk, dev)
    }

    #[test]
    fn seal_verify_open() {
        let (vault, sk, dev) = ids();
        let key = SecretKey::random();
        let h = Header {
            kind: RecordKind::Manifest,
            vault: &vault,
            scope: "folder",
            device: &dev,
            seq: 7,
            key_id: "meta@0",
        };
        let r = h.seal(&key, b"body", &sk).unwrap();
        let back = SignedRecord::parse(&r.to_bytes()).unwrap();
        let e = Expect::new(RecordKind::Manifest, &vault)
            .scope("folder")
            .device(&dev)
            .seq(7);
        assert_eq!(back.verify_open(&e, &sk.public(), &key).unwrap(), b"body");
    }

    #[test]
    fn every_header_field_is_signed() {
        let (vault, sk, dev) = ids();
        let key = SecretKey::random();
        let h = Header {
            kind: RecordKind::Trash,
            vault: &vault,
            scope: "f",
            device: &dev,
            seq: 1,
            key_id: "meta@1",
        };
        let r = h.seal(&key, b"x", &sk).unwrap();
        r.verify(&sk.public()).unwrap();
        type Tamper = Box<dyn Fn(&mut SignedRecord)>;
        let tamper: Vec<Tamper> = vec![
            Box::new(|r| r.kind = RecordKind::Manifest),
            Box::new(|r| r.vault = VaultId::random()),
            Box::new(|r| r.scope = "g".into()),
            Box::new(|r| r.seq = 2),
            Box::new(|r| r.key_id = "meta@0".into()),
            Box::new(|r| {
                let mut b = hex::decode(&r.body).unwrap();
                b[30] ^= 1;
                r.body = hex::encode(b);
            }),
            Box::new(|r| {
                let mut b = hex::decode(&r.body).unwrap();
                b[30] ^= 1;
                r.body = hex::encode(&b);
                r.body_hash = hex::encode(crypto::hash(&b));
            }),
            Box::new(|r| r.sig_alg = "ed25519".into()),
        ];
        for t in tamper {
            let mut bad = r.clone();
            t(&mut bad);
            assert!(bad.verify(&sk.public()).is_err());
        }
        // Another device's key does not verify it, and a record cannot be
        // passed off as that device's by renaming it.
        let other = SigningKey::generate();
        assert!(r.verify(&other.public()).is_err());
        let mut renamed = r.clone();
        renamed.device = crate::ledger::device_id_for(&other.public());
        assert!(renamed.verify(&other.public()).is_err());
    }

    #[test]
    fn relabelled_key_id_does_not_open() {
        // Even a writer re-signing a record under another key id cannot make
        // the body open there: the key id is in the body's associated data.
        let (vault, sk, dev) = ids();
        let key = SecretKey::random();
        let h = Header {
            kind: RecordKind::Batch,
            vault: &vault,
            scope: "",
            device: &dev,
            seq: 3,
            key_id: "ledger",
        };
        let r = h.seal(&key, b"events", &sk).unwrap();
        let body = r.body_bytes().unwrap();
        let relabelled = Header {
            key_id: "replica",
            ..h.clone()
        }
        .sign_body(body, &sk);
        relabelled.verify(&sk.public()).unwrap();
        assert!(relabelled.open(&key).is_err());
    }

    #[test]
    fn sealed_to_a_key_exchange_key() {
        let (vault, sk, dev) = ids();
        let dk = crate::kem::DecapsKey::generate();
        let h = Header {
            kind: RecordKind::Grant,
            vault: &vault,
            scope: "folder",
            device: &dev,
            seq: 1,
            key_id: &kem_key_id("recipient"),
        };
        let r = h.seal_to(&dk.public(), b"key", &sk).unwrap();
        r.verify(&sk.public()).unwrap();
        assert_eq!(r.open_sealed(&dk).unwrap(), b"key");
        let other = crate::kem::DecapsKey::generate();
        assert!(r.open_sealed(&other).is_err());
        assert!(Header {
            key_id: "ledger",
            ..h
        }
        .seal_to(&dk.public(), b"key", &sk)
        .is_err());
    }

    #[test]
    fn parse_refuses_other_formats_and_kinds() {
        let (vault, sk, dev) = ids();
        let h = Header {
            kind: RecordKind::Peer,
            vault: &vault,
            scope: "",
            device: &dev,
            seq: 1,
            key_id: "registry",
        };
        let r = h.seal(&SecretKey::random(), b"p", &sk).unwrap();
        let mut old = r.clone();
        old.format = 1;
        assert!(SignedRecord::parse(&old.to_bytes()).is_err());
        assert!(SignedRecord::parse_kind(&r.to_bytes(), RecordKind::Manifest).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&r.to_bytes()).unwrap();
        v["kind"] = "something-else".into();
        assert!(SignedRecord::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(SignedRecord::parse(b"{}").is_err());
        assert!(SignedRecord::parse(b"junk").is_err());
    }

    #[test]
    fn meta_key_ids_round_trip() {
        assert_eq!(parse_meta_key_id(&meta_key_id(5)), Some(5));
        assert_eq!(parse_meta_key_id("meta@x"), None);
        assert_eq!(parse_meta_key_id("ledger"), None);
    }

    #[test]
    fn block_records_open_only_under_their_name_writer_and_key() {
        let (vault, sk, a) = ids();
        let (_, other_sk, b) = ids();
        let mut writers = std::collections::BTreeMap::new();
        writers.insert(a.clone(), sk.public());
        writers.insert(b.clone(), other_sk.public());
        let r = Records::new(vault.clone(), a.clone(), std::sync::Arc::new(sk), writers.clone());
        let key = SecretKey([4; 32]);
        let blob = r.seal("pack-index", "f", 7, &key, b"body").unwrap();
        assert_eq!(r.open("pack-index", "f", &a, 7, &key, &blob).unwrap(), b"body");
        assert!(r.open("pack-index", "f", &a, 8, &key, &blob).is_err());
        assert!(r.open("pack-index", "f", &b, 7, &key, &blob).is_err());
        assert!(r.open("tombstones", "f", &a, 7, &key, &blob).is_err());
        assert!(r.open("pack-index", "g", &a, 7, &key, &blob).is_err());
        assert!(r
            .open("pack-index", "f", &a, 7, &SecretKey([5; 32]), &blob)
            .is_err());
        assert!(r.seal("manifest", "f", 1, &key, b"x").is_err());
        // B signs a record as A (its own key): refused.
        let forged = Records::new(vault.clone(), a.clone(), std::sync::Arc::new(other_sk), writers);
        let blob = forged.seal("tombstones", "", 3, &key, b"dead").unwrap();
        assert!(r.open("tombstones", "", &a, 3, &key, &blob).is_err());
        // A writer this device does not know: refused.
        let (_, sk3, c) = ids();
        let stranger = Records::new(vault, c.clone(), std::sync::Arc::new(sk3), Default::default());
        let blob = stranger.seal("tombstones", "", 1, &key, b"dead").unwrap();
        assert!(r.open("tombstones", "", &c, 1, &key, &blob).is_err());
    }
}
