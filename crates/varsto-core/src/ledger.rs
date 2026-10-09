// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Per-device append-only ledger (plan 6.19, `docs/spec/ledger-signing-notes.md`
//! model B). Each device writes only its own log: batches are numbered,
//! hash-chained, encrypted under a vault-derived key and signed by the device.
//! Every storage acts as a mailbox: devices push their own batches and pull
//! everyone else's, so devices that are never online together still converge
//! as long as they share one hot storage.
//!
//! The ledger records *claims*. A chunk is "verified" on a storage only when a
//! device other than the writer has fetched it and checked the hash.

use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName};
use crate::util;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Key identifiers in batch envelopes: which vault-derived key encrypts the body.
pub const KEY_LEDGER: &str = "ledger";
pub const KEY_REPLICA: &str = "replica";
/// Batches sealed under the ledger key of vault key epoch `e >= 1` carry the
/// key id `ledger@<e>` (epoch 0 keeps the plain `ledger`).
pub const KEY_LEDGER_EPOCH_PREFIX: &str = "ledger@";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// This device joined the vault.
    DeviceEnrolled { name: String },
    /// A folder was created by this device.
    FolderAdded { folder: FolderId },
    /// This device wrote `object` to `storage` (a claim, self-attested).
    ChunkStored {
        folder: FolderId,
        chunk: ChunkId,
        object: ObjectName,
        storage: String,
        size: u64,
    },
    /// This device fetched `object` from `storage` and the hash matched.
    ChunkVerified {
        folder: FolderId,
        chunk: ChunkId,
        object: ObjectName,
        storage: String,
    },
    /// This device holds the plaintext of the chunk (as part of a file).
    ChunkOnDevice {
        folder: FolderId,
        chunk: ChunkId,
        object: ObjectName,
        size: u64,
    },
    /// This device published folder manifest `seq`.
    ManifestPublished {
        folder: FolderId,
        seq: u64,
        manifest_hash: String,
        files: u64,
    },
}

/// Plaintext batch body (encrypted before signing and storage).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Batch {
    pub device: DeviceId,
    pub seq: u64,
    /// Hash of the previous signed batch of this device (hex), none for seq 1.
    pub prev: Option<String>,
    pub lamport: u64,
    pub created_utc: i64,
    pub events: Vec<Event>,
}

/// What is stored and replicated. The signature covers `device || seq || hash`
/// where `hash` is the hash of the encrypted body, so payloads can later be
/// cryptographically erased without breaking the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBatch {
    pub format_version: u16,
    pub sig_alg: String,
    /// Which key encrypts the body: "ledger" (own devices), "replica", or "share:<folder>".
    #[serde(default = "default_key_id")]
    pub key_id: String,
    pub device: DeviceId,
    pub seq: u64,
    pub body_hex: String,
    pub hash: String,
    pub sig_hex: String,
}

fn default_key_id() -> String {
    KEY_LEDGER.to_string()
}

impl SignedBatch {
    fn signed_message(device: &DeviceId, seq: u64, hash: &str) -> Vec<u8> {
        crypto::aad(
            "ledger-batch-signature",
            &[
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
                hash.as_bytes(),
            ],
        )
    }

    pub fn storage_key(device: &DeviceId, seq: u64) -> String {
        format!("ledger/{}/{:016}.json", device, seq)
    }

    pub fn seal(batch: &Batch, ledger_key: &SecretKey, signer: &SigningKey) -> Result<Self> {
        Self::seal_with(batch, ledger_key, KEY_LEDGER, signer)
    }

    pub fn seal_with(
        batch: &Batch,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Self> {
        let plain = serde_json::to_vec(batch)?;
        let aad = crypto::aad(
            "ledger-batch",
            &[batch.device.as_str().as_bytes(), &batch.seq.to_le_bytes()],
        );
        let ct = crypto::encrypt(ledger_key, &aad, &plain)?;
        let hash = hex::encode(crypto::hash(&ct));
        let sig = signer.sign(&Self::signed_message(&batch.device, batch.seq, &hash));
        Ok(SignedBatch {
            format_version: crate::FORMAT_VERSION,
            sig_alg: signer.alg().to_string(),
            key_id: key_id.to_string(),
            device: batch.device.clone(),
            seq: batch.seq,
            body_hex: hex::encode(ct),
            hash,
            sig_hex: hex::encode(sig),
        })
    }

    /// Check signature and hash; does not decrypt.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<()> {
        let ct = hex::decode(&self.body_hex)?;
        if hex::encode(crypto::hash(&ct)) != self.hash {
            bail!("batch hash does not match body");
        }
        // The algorithm identifier travels with the batch; the key decides
        // which identifiers it accepts (hybrid keys never accept Ed25519 alone).
        pubkey.verify(
            &self.sig_alg,
            &Self::signed_message(&self.device, self.seq, &self.hash),
            &hex::decode(&self.sig_hex)?,
        )
    }

    pub fn open(&self, ledger_key: &SecretKey) -> Result<Batch> {
        let ct = hex::decode(&self.body_hex)?;
        let aad = crypto::aad(
            "ledger-batch",
            &[self.device.as_str().as_bytes(), &self.seq.to_le_bytes()],
        );
        let plain = crypto::decrypt(ledger_key, &aad, &ct)?;
        let batch: Batch = serde_json::from_slice(&plain)?;
        if batch.device != self.device || batch.seq != self.seq {
            bail!("batch body does not match its envelope");
        }
        Ok(batch)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Head {
    pub seq: u64,
    pub hash: Option<String>,
    /// Set when two different batches with the same sequence number were seen.
    pub forked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct HeadsFile {
    heads: BTreeMap<DeviceId, Head>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    New,
    Known,
    /// Same device and sequence number, different content.
    Fork,
}

/// Local copy of every device's batches, plus heads.
pub struct LedgerStore {
    dir: PathBuf,
    heads: HeadsFile,
}

impl LedgerStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let heads = util::read_json_or_default(&dir.join("heads.json"))?;
        Ok(LedgerStore {
            dir: dir.to_path_buf(),
            heads,
        })
    }

    fn save_heads(&self) -> Result<()> {
        util::write_json(&self.dir.join("heads.json"), &self.heads)
    }

    fn batch_path(&self, device: &DeviceId, seq: u64) -> PathBuf {
        self.dir
            .join(device.as_str())
            .join(format!("{seq:016}.json"))
    }

    pub fn head(&self, device: &DeviceId) -> Head {
        self.heads.heads.get(device).cloned().unwrap_or_default()
    }

    pub fn devices(&self) -> Vec<DeviceId> {
        self.heads.heads.keys().cloned().collect()
    }

    pub fn is_forked(&self, device: &DeviceId) -> bool {
        self.head(device).forked
    }

    pub fn get(&self, device: &DeviceId, seq: u64) -> Result<Option<SignedBatch>> {
        let p = self.batch_path(device, seq);
        if p.exists() {
            Ok(Some(util::read_json(&p)?))
        } else {
            Ok(None)
        }
    }

    /// Append a batch of this device's own events.
    pub fn append_own(
        &mut self,
        device: &DeviceId,
        events: Vec<Event>,
        lamport: u64,
        ledger_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<SignedBatch> {
        self.append_own_with(device, events, lamport, ledger_key, KEY_LEDGER, signer)
    }

    pub fn append_own_with(
        &mut self,
        device: &DeviceId,
        events: Vec<Event>,
        lamport: u64,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<SignedBatch> {
        let head = self.head(device);
        if head.forked {
            bail!(
                "this device's ledger is forked (restored from an old copy?); refusing to append"
            );
        }
        let batch = Batch {
            device: device.clone(),
            seq: head.seq + 1,
            prev: head.hash.clone(),
            lamport,
            created_utc: util::now_utc(),
            events,
        };
        let signed = SignedBatch::seal_with(&batch, ledger_key, key_id, signer)?;
        util::write_json(&self.batch_path(device, signed.seq), &signed)?;
        self.heads.heads.insert(
            device.clone(),
            Head {
                seq: signed.seq,
                hash: Some(signed.hash.clone()),
                forked: false,
            },
        );
        self.save_heads()?;
        Ok(signed)
    }

    /// Store a batch received from a mailbox after verifying its signature.
    /// Chain continuity is checked against the previous batch when known.
    pub fn ingest(
        &mut self,
        signed: SignedBatch,
        pubkey: &VerifyingKey,
        ledger_key: &SecretKey,
    ) -> Result<Ingest> {
        signed
            .verify(pubkey)
            .with_context(|| format!("batch {}/{}", signed.device, signed.seq))?;
        let batch = signed.open(ledger_key)?;
        if let Some(existing) = self.get(&signed.device, signed.seq)? {
            if existing.hash == signed.hash {
                return Ok(Ingest::Known);
            }
            let mut h = self.head(&signed.device);
            h.forked = true;
            self.heads.heads.insert(signed.device.clone(), h);
            self.save_heads()?;
            return Ok(Ingest::Fork);
        }
        if signed.seq > 1 {
            if let Some(prev) = self.get(&signed.device, signed.seq - 1)? {
                if batch.prev.as_deref() != Some(prev.hash.as_str()) {
                    let mut h = self.head(&signed.device);
                    h.forked = true;
                    self.heads.heads.insert(signed.device.clone(), h);
                    self.save_heads()?;
                    return Ok(Ingest::Fork);
                }
            }
        }
        util::write_json(&self.batch_path(&signed.device, signed.seq), &signed)?;
        let mut h = self.head(&signed.device);
        if signed.seq > h.seq {
            h.seq = signed.seq;
            h.hash = Some(signed.hash.clone());
        }
        self.heads.heads.insert(signed.device.clone(), h);
        self.save_heads()?;
        Ok(Ingest::New)
    }

    /// All locally known batches in (device, seq) order.
    pub fn all(&self) -> Result<Vec<SignedBatch>> {
        let mut out = Vec::new();
        for (device, head) in &self.heads.heads {
            for seq in 1..=head.seq {
                if let Some(b) = self.get(device, seq)? {
                    out.push(b);
                }
            }
        }
        Ok(out)
    }

    /// Build the location view by replaying every batch (own devices only).
    pub fn view(&self, ledger_key: &SecretKey) -> Result<LedgerView> {
        self.view_with(|id| {
            if id == KEY_LEDGER {
                Some(ledger_key.clone())
            } else {
                None
            }
        })
    }

    /// Build the view with a key chosen per batch key id; batches whose key is
    /// unknown are skipped (for example replica batches on a device that is
    /// not the owner).
    pub fn view_with(&self, key_for: impl Fn(&str) -> Option<SecretKey>) -> Result<LedgerView> {
        self.view_filtered(key_for, |_, _| true)
    }

    /// Like `view_with`, replaying only the batches `keep(device, seq)`
    /// accepts: batches a revoked device signed after its cut-off are left
    /// out even if they were stored before the revocation arrived.
    pub fn view_filtered(
        &self,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceId, u64) -> bool,
    ) -> Result<LedgerView> {
        let mut view = LedgerView::default();
        for signed in self.all()? {
            if !keep(&signed.device, signed.seq) {
                continue;
            }
            let Some(key) = key_for(&signed.key_id) else {
                continue;
            };
            let batch = match signed.open(&key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            view.apply(&batch);
        }
        view.fold_object_claims();
        for d in self.heads.heads.keys() {
            if self.is_forked(d) {
                view.forked.insert(d.clone());
            }
        }
        Ok(view)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Location {
    pub claimed_by: BTreeSet<DeviceId>,
    pub verified_by: BTreeSet<DeviceId>,
    /// Newest claim and verification times (batch creation time, UTC seconds).
    #[serde(default)]
    pub claimed_utc: i64,
    #[serde(default)]
    pub verified_utc: i64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ChunkRecord {
    pub object: ObjectName,
    pub size: u64,
    pub storages: BTreeMap<String, Location>,
    pub devices: BTreeSet<DeviceId>,
}

impl Location {
    /// Verified by someone other than the writer (a replica's own check counts).
    pub fn independently_verified(&self, storage_name: &str) -> bool {
        storage_name.starts_with("replica:") && !self.verified_by.is_empty()
            || self
                .verified_by
                .iter()
                .any(|d| !self.claimed_by.contains(d))
    }
}

impl ChunkRecord {
    /// A copy is verified when some device other than the one that wrote it
    /// has checked it, or when the writer itself re-read it is not enough.
    pub fn verified_storages(&self) -> usize {
        self.storages
            .iter()
            .filter(|(name, l)| {
                name.starts_with("replica:") && !l.verified_by.is_empty()
                    || l.verified_by.iter().any(|d| !l.claimed_by.contains(d))
            })
            .count()
    }
    pub fn claimed_storages(&self) -> usize {
        self.storages.len()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LedgerView {
    pub chunks: HashMap<(FolderId, ChunkId), ChunkRecord>,
    /// Highest manifest sequence published per (folder, device).
    pub manifests: BTreeMap<(FolderId, DeviceId), u64>,
    pub devices: BTreeMap<DeviceId, String>,
    pub folders: BTreeSet<FolderId>,
    pub max_lamport: u64,
    pub batches: u64,
    pub forked: BTreeSet<DeviceId>,
    /// Objects claimed by replicas (folded into chunk records).
    pub object_claims: u64,
}

impl LedgerView {
    fn apply(&mut self, batch: &Batch) {
        self.batches += 1;
        self.max_lamport = self.max_lamport.max(batch.lamport);
        for ev in &batch.events {
            match ev {
                Event::DeviceEnrolled { name } => {
                    self.devices.insert(batch.device.clone(), name.clone());
                }
                Event::FolderAdded { folder } => {
                    self.folders.insert(folder.clone());
                }
                Event::ChunkStored {
                    folder,
                    chunk,
                    object,
                    storage,
                    size,
                } => {
                    let rec = self
                        .chunks
                        .entry((folder.clone(), chunk.clone()))
                        .or_default();
                    rec.object = object.clone();
                    rec.size = *size;
                    let loc = rec.storages.entry(storage.clone()).or_default();
                    loc.claimed_by.insert(batch.device.clone());
                    loc.claimed_utc = loc.claimed_utc.max(batch.created_utc);
                }
                Event::ChunkVerified {
                    folder,
                    chunk,
                    object,
                    storage,
                } => {
                    let rec = self
                        .chunks
                        .entry((folder.clone(), chunk.clone()))
                        .or_default();
                    rec.object = object.clone();
                    let loc = rec.storages.entry(storage.clone()).or_default();
                    loc.verified_by.insert(batch.device.clone());
                    loc.verified_utc = loc.verified_utc.max(batch.created_utc);
                }
                Event::ChunkOnDevice {
                    folder,
                    chunk,
                    object,
                    size,
                } => {
                    let rec = self
                        .chunks
                        .entry((folder.clone(), chunk.clone()))
                        .or_default();
                    rec.object = object.clone();
                    rec.size = *size;
                    rec.devices.insert(batch.device.clone());
                }
                Event::ManifestPublished { folder, seq, .. } => {
                    let e = self
                        .manifests
                        .entry((folder.clone(), batch.device.clone()))
                        .or_insert(0);
                    *e = (*e).max(*seq);
                }
            }
        }
    }

    pub fn locate(&self, folder: &FolderId, chunk: &ChunkId) -> Option<&ChunkRecord> {
        self.chunks.get(&(folder.clone(), chunk.clone()))
    }

    /// Replica claims carry only the object name (empty folder and chunk ids).
    /// Merge them into the records of every chunk that uses that object.
    pub fn fold_object_claims(&mut self) {
        let keys: Vec<(FolderId, ChunkId)> = self
            .chunks
            .keys()
            .filter(|(f, _)| f.as_str().is_empty())
            .cloned()
            .collect();
        if keys.is_empty() {
            return;
        }
        let mut by_object: HashMap<ObjectName, ChunkRecord> = HashMap::new();
        for k in keys {
            if let Some(rec) = self.chunks.remove(&k) {
                by_object.insert(rec.object.clone(), rec);
            }
        }
        for rec in self.chunks.values_mut() {
            if let Some(claim) = by_object.get(&rec.object) {
                for (storage, loc) in &claim.storages {
                    let e = rec.storages.entry(storage.clone()).or_default();
                    e.claimed_by.extend(loc.claimed_by.iter().cloned());
                    e.verified_by.extend(loc.verified_by.iter().cloned());
                }
            }
        }
        self.object_claims = by_object.len() as u64;
    }
}

/// Map device id -> verifying key, for signature checks.
pub type KeyDirectory = HashMap<DeviceId, VerifyingKey>;

pub fn device_id_for(pubkey: &VerifyingKey) -> DeviceId {
    DeviceId::from_bytes(&crypto::hash(&pubkey.to_bytes())[..16])
}

pub fn lookup<'a>(dir: &'a KeyDirectory, device: &DeviceId) -> Result<&'a VerifyingKey> {
    dir.get(device)
        .ok_or_else(|| anyhow!("unknown device {device}: no device record"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (
        tempfile::TempDir,
        LedgerStore,
        SecretKey,
        SigningKey,
        DeviceId,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = LedgerStore::open(&dir.path().join("ledger")).unwrap();
        let key = SecretKey::random();
        let signer = SigningKey::generate();
        let device = device_id_for(&signer.public());
        (dir, store, key, signer, device)
    }

    #[test]
    fn append_chain_and_ingest() {
        let (_d, mut a, key, signer, device) = setup();
        let b1 = a
            .append_own(
                &device,
                vec![Event::DeviceEnrolled { name: "a".into() }],
                1,
                &key,
                &signer,
            )
            .unwrap();
        let b2 = a.append_own(&device, vec![], 2, &key, &signer).unwrap();
        assert_eq!(b2.seq, 2);
        assert_eq!(
            b2.open(&key).unwrap().prev.as_deref(),
            Some(b1.hash.as_str())
        );

        let dir2 = tempfile::tempdir().unwrap();
        let mut b = LedgerStore::open(&dir2.path().join("ledger")).unwrap();
        let pk = signer.public();
        assert_eq!(b.ingest(b1.clone(), &pk, &key).unwrap(), Ingest::New);
        assert_eq!(b.ingest(b1.clone(), &pk, &key).unwrap(), Ingest::Known);
        assert_eq!(b.ingest(b2.clone(), &pk, &key).unwrap(), Ingest::New);
        assert_eq!(b.head(&device).seq, 2);
        assert_eq!(b.view(&key).unwrap().devices.get(&device).unwrap(), "a");
    }

    #[test]
    fn fork_is_detected() {
        let (_d, mut a, key, signer, device) = setup();
        let b1 = a.append_own(&device, vec![], 1, &key, &signer).unwrap();
        // A second copy of the same device (restored from backup) signs seq 1 again.
        let dir2 = tempfile::tempdir().unwrap();
        let mut restored = LedgerStore::open(&dir2.path().join("ledger")).unwrap();
        let b1_again = restored
            .append_own(
                &device,
                vec![Event::DeviceEnrolled { name: "x".into() }],
                5,
                &key,
                &signer,
            )
            .unwrap();
        assert_ne!(b1.hash, b1_again.hash);
        let dir3 = tempfile::tempdir().unwrap();
        let mut observer = LedgerStore::open(&dir3.path().join("ledger")).unwrap();
        let pk = signer.public();
        assert_eq!(observer.ingest(b1, &pk, &key).unwrap(), Ingest::New);
        assert_eq!(observer.ingest(b1_again, &pk, &key).unwrap(), Ingest::Fork);
        assert!(observer.is_forked(&device));
    }

    #[test]
    fn tampered_batch_is_rejected() {
        let (_d, mut a, key, signer, device) = setup();
        let mut b1 = a.append_own(&device, vec![], 1, &key, &signer).unwrap();
        b1.seq = 2;
        assert!(b1.verify(&signer.public()).is_err());
    }

    #[test]
    fn legacy_batches_verify_and_hybrid_batches_resist_downgrade() {
        let key = SecretKey::random();
        let legacy = SigningKey::from_bytes(&[9u8; 32]).unwrap();
        let dev = device_id_for(&legacy.public());
        let batch = Batch {
            device: dev.clone(),
            seq: 1,
            prev: None,
            lamport: 1,
            created_utc: 0,
            events: vec![],
        };
        let sealed = SignedBatch::seal(&batch, &key, &legacy).unwrap();
        assert_eq!(sealed.sig_alg, crypto::SIG_ALG_LEGACY);
        sealed.verify(&legacy.public()).unwrap();

        let hybrid = SigningKey::generate();
        let dev2 = device_id_for(&hybrid.public());
        let batch2 = Batch {
            device: dev2,
            ..batch
        };
        let mut sealed2 = SignedBatch::seal(&batch2, &key, &hybrid).unwrap();
        assert_eq!(sealed2.sig_alg, crypto::SIG_ALG);
        sealed2.verify(&hybrid.public()).unwrap();
        // Strip the post-quantum half and relabel: must be rejected.
        let sig = hex::decode(&sealed2.sig_hex).unwrap();
        sealed2.sig_hex = hex::encode(&sig[..64]);
        sealed2.sig_alg = crypto::SIG_ALG_LEGACY.to_string();
        assert!(sealed2.verify(&hybrid.public()).is_err());
    }
}
