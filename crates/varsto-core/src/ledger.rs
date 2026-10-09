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

pub mod checkpoint;
pub use checkpoint::{Checkpoint, LedgerObject, SignedCheckpoint};

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
    /// The storage was removed from the vault: every claim on it made before
    /// this event no longer counts as a copy (later claims count again).
    StorageRetired { storage: String },
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
    /// The newest batch of every other device this device held when it
    /// sealed this one: lets a device know when everyone has seen past its
    /// checkpoint. Older versions neither write nor read it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seen: BTreeMap<DeviceId, u64>,
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
    /// The newest checkpoint of this device held here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Base>,
    /// Batches up to this sequence number were dropped here (a checkpoint
    /// covers them).
    #[serde(default)]
    pub dropped: u64,
}

/// A checkpoint held locally, as named in the heads file.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Base {
    pub seq: u64,
    pub key_id: String,
    pub head_hash: String,
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

/// How far this device's own batches are known to be on each storage
/// (`pushed.json`, by storage name), so a push lists only the newer ones.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PushedFile {
    storages: BTreeMap<String, u64>,
    /// Own batches up to this sequence number were deleted there.
    #[serde(default)]
    pruned: BTreeMap<String, u64>,
}

/// Local copy of every device's batches, plus heads.
pub struct LedgerStore {
    dir: PathBuf,
    heads: HeadsFile,
    pushed: PushedFile,
}

impl LedgerStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let heads = util::read_json_or_default(&dir.join("heads.json"))?;
        let pushed = util::read_json_or_default(&dir.join("pushed.json"))?;
        Ok(LedgerStore {
            dir: dir.to_path_buf(),
            heads,
            pushed,
        })
    }

    /// Own batches up to this sequence number are on the named storage.
    pub fn pushed(&self, storage: &str) -> u64 {
        self.pushed.storages.get(storage).copied().unwrap_or(0)
    }

    /// Own batches up to this sequence number were deleted from the storage.
    pub fn pruned(&self, storage: &str) -> u64 {
        self.pushed.pruned.get(storage).copied().unwrap_or(0)
    }

    pub fn set_pruned(&mut self, storage: &str, seq: u64) -> Result<()> {
        self.pushed.pruned.insert(storage.to_string(), seq);
        util::write_json(&self.dir.join("pushed.json"), &self.pushed)
    }

    pub fn set_pushed(&mut self, storage: &str, seq: u64) -> Result<()> {
        if self.pushed(storage) == seq && self.pushed.storages.contains_key(storage) {
            return Ok(());
        }
        self.pushed.storages.insert(storage.to_string(), seq);
        util::write_json(&self.dir.join("pushed.json"), &self.pushed)
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
        self.append_own_seen(
            device,
            events,
            BTreeMap::new(),
            lamport,
            ledger_key,
            key_id,
            signer,
        )
    }

    /// Like `append_own_with`, recording which batches of the other devices
    /// this device holds.
    #[allow(clippy::too_many_arguments)]
    pub fn append_own_seen(
        &mut self,
        device: &DeviceId,
        events: Vec<Event>,
        seen: BTreeMap<DeviceId, u64>,
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
            seen,
        };
        let signed = SignedBatch::seal_with(&batch, ledger_key, key_id, signer)?;
        util::write_json(&self.batch_path(device, signed.seq), &signed)?;
        self.heads.heads.insert(
            device.clone(),
            Head {
                seq: signed.seq,
                hash: Some(signed.hash.clone()),
                forked: false,
                ..head
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
        self.ingest_with(signed, pubkey, Some(ledger_key))
    }

    /// Like `ingest`; without a key (a batch sealed under a key this device
    /// does not hold) the signature is checked and the batch is kept unread,
    /// so it is not downloaded again and is read once the key is known. The
    /// hash chain is then checked from the next batch this device can open.
    pub fn ingest_with(
        &mut self,
        signed: SignedBatch,
        pubkey: &VerifyingKey,
        ledger_key: Option<&SecretKey>,
    ) -> Result<Ingest> {
        signed
            .verify(pubkey)
            .with_context(|| format!("batch {}/{}", signed.device, signed.seq))?;
        let batch = ledger_key.map(|k| signed.open(k)).transpose()?;
        let base = self.head(&signed.device).base;
        if let Some(base) = base.as_ref().filter(|b| signed.seq <= b.seq) {
            if self.get(&signed.device, signed.seq)?.is_none() {
                // Covered by a checkpoint: not kept, but it must agree with it.
                if signed.seq == base.seq && signed.hash != base.head_hash {
                    return self.mark_fork(&signed.device);
                }
                return Ok(Ingest::Known);
            }
        }
        if let Some(existing) = self.get(&signed.device, signed.seq)? {
            if existing.hash == signed.hash {
                // Heads are written after the batch: catch up after a crash.
                let mut h = self.head(&signed.device);
                if signed.seq > h.seq {
                    h.seq = signed.seq;
                    h.hash = Some(signed.hash.clone());
                    self.heads.heads.insert(signed.device.clone(), h);
                    self.save_heads()?;
                }
                return Ok(Ingest::Known);
            }
            let mut h = self.head(&signed.device);
            h.forked = true;
            self.heads.heads.insert(signed.device.clone(), h);
            self.save_heads()?;
            return Ok(Ingest::Fork);
        }
        if let (true, Some(batch)) = (signed.seq > 1, &batch) {
            let prev = match self.get(&signed.device, signed.seq - 1)? {
                Some(prev) => Some(prev.hash),
                None => base
                    .filter(|b| b.seq == signed.seq - 1)
                    .map(|b| b.head_hash),
            };
            if let Some(prev) = prev {
                if batch.prev.as_deref() != Some(prev.as_str()) {
                    return self.mark_fork(&signed.device);
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

    fn mark_fork(&mut self, device: &DeviceId) -> Result<Ingest> {
        let mut h = self.head(device);
        h.forked = true;
        self.heads.heads.insert(device.clone(), h);
        self.save_heads()?;
        Ok(Ingest::Fork)
    }

    fn checkpoint_path(&self, device: &DeviceId, seq: u64) -> PathBuf {
        self.dir
            .join(device.as_str())
            .join(format!("{}{seq:016}.json", checkpoint::CHECKPOINT_PREFIX))
    }

    /// The newest checkpoint of `device` held here.
    pub fn checkpoint(&self, device: &DeviceId) -> Result<Option<SignedCheckpoint>> {
        let Some(base) = self.head(device).base else {
            return Ok(None);
        };
        let p = self.checkpoint_path(device, base.seq);
        if p.exists() {
            Ok(Some(util::read_json(&p)?))
        } else {
            Ok(None)
        }
    }

    /// Keep a checkpoint as the newest of its device. The caller has
    /// verified its signature and that it opens. A checkpoint that
    /// contradicts a batch held here marks the device forked.
    pub fn ingest_checkpoint(&mut self, cp: SignedCheckpoint) -> Result<Ingest> {
        let device = cp.device.clone();
        let mut h = self.head(&device);
        if let Some(base) = &h.base {
            if base.seq == cp.seq {
                if base.head_hash == cp.head_hash {
                    return Ok(Ingest::Known);
                }
                return self.mark_fork(&device);
            }
            if base.seq > cp.seq {
                return Ok(Ingest::Known);
            }
        }
        if let Some(b) = self.get(&device, cp.seq)? {
            if b.hash != cp.head_hash {
                return self.mark_fork(&device);
            }
        }
        util::write_json(&self.checkpoint_path(&device, cp.seq), &cp)?;
        if let Some(old) = &h.base {
            let _ = std::fs::remove_file(self.checkpoint_path(&device, old.seq));
        }
        h.base = Some(Base {
            seq: cp.seq,
            key_id: cp.key_id.clone(),
            head_hash: cp.head_hash.clone(),
        });
        if cp.seq > h.seq {
            h.seq = cp.seq;
            h.hash = Some(cp.head_hash.clone());
        }
        self.heads.heads.insert(device, h);
        self.save_heads()?;
        Ok(Ingest::New)
    }

    /// What `device`'s batches up to `seq` add to the view: its checkpoint
    /// (when it is not newer than `seq`) and the batches after it. Fails if
    /// one of those batches is missing or does not open: a checkpoint must
    /// not leave anything out.
    pub fn contribution(
        &self,
        device: &DeviceId,
        seq: u64,
        key_for: impl Fn(&str) -> Option<SecretKey>,
    ) -> Result<LedgerView> {
        let mut view = LedgerView::default();
        let head = self.head(device);
        let base = head.base.as_ref().map(|b| b.seq).filter(|b| *b <= seq);
        if let Some(b) = base {
            let signed = self
                .checkpoint(device)?
                .ok_or_else(|| anyhow!("checkpoint {b} of {device} is missing"))?;
            let key = key_for(&signed.key_id)
                .ok_or_else(|| anyhow!("no key for checkpoint {b} of {device}"))?;
            view.merge(&signed.open(&key)?.view);
        }
        for s in base.unwrap_or(0) + 1..=seq {
            let signed = self
                .get(device, s)?
                .ok_or_else(|| anyhow!("batch {s} of {device} is missing"))?;
            let key = key_for(&signed.key_id)
                .ok_or_else(|| anyhow!("no key for batch {s} of {device}"))?;
            view.apply(&signed.open(&key)?);
        }
        Ok(view)
    }

    /// Seal a checkpoint of this device's own batches up to `seq` and keep
    /// it as its newest one.
    pub fn make_checkpoint(
        &mut self,
        device: &DeviceId,
        seq: u64,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<SignedCheckpoint> {
        let view = self.contribution(device, seq, key_for)?;
        self.seal_checkpoint(device, seq, view, ledger_key, key_id, signer)
    }

    /// Seal `view` (the `contribution` up to `seq`) as this device's newest
    /// checkpoint.
    pub fn seal_checkpoint(
        &mut self,
        device: &DeviceId,
        seq: u64,
        view: LedgerView,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<SignedCheckpoint> {
        let head_hash = self
            .get(device, seq)?
            .ok_or_else(|| anyhow!("batch {seq} of {device} is missing"))?
            .hash;
        let cp = Checkpoint {
            device: device.clone(),
            seq,
            head_hash,
            created_utc: util::now_utc(),
            view,
        };
        let signed = SignedCheckpoint::seal(&cp, ledger_key, key_id, signer)?;
        if self.ingest_checkpoint(signed.clone())? == Ingest::Fork {
            bail!("checkpoint {seq} of {device} contradicts this device's ledger");
        }
        Ok(signed)
    }

    /// Delete the local batches of `device` up to `seq`; never beyond its
    /// newest checkpoint, which must cover them.
    pub fn drop_through(&mut self, device: &DeviceId, seq: u64) -> Result<u64> {
        let mut h = self.head(device);
        let upto = seq.min(h.base.as_ref().map(|b| b.seq).unwrap_or(0));
        if upto <= h.dropped {
            return Ok(0);
        }
        let mut n = 0;
        for s in h.dropped + 1..=upto {
            match std::fs::remove_file(self.batch_path(device, s)) {
                Ok(()) => n += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        h.dropped = upto;
        self.heads.heads.insert(device.clone(), h);
        self.save_heads()?;
        Ok(n)
    }

    /// The checkpoint a view starts from for `device`, if it may be used:
    /// its key is known and the device's batches up to it are accepted.
    fn usable_base(
        head: &Head,
        device: &DeviceId,
        key_for: &impl Fn(&str) -> Option<SecretKey>,
        keep: &impl Fn(&DeviceId, u64) -> bool,
    ) -> u64 {
        match &head.base {
            Some(b) if keep(device, b.seq) && key_for(&b.key_id).is_some() => b.seq,
            _ => 0,
        }
    }

    /// Merge the checkpoint `seq` of `device` into a view (nothing if it
    /// does not open).
    fn apply_checkpoint(
        &self,
        view: &mut LedgerView,
        device: &DeviceId,
        seq: u64,
        key_for: &impl Fn(&str) -> Option<SecretKey>,
    ) -> Result<()> {
        let p = self.checkpoint_path(device, seq);
        if !p.exists() {
            return Ok(());
        }
        let signed: SignedCheckpoint = util::read_json(&p)?;
        if let Some(cp) = key_for(&signed.key_id).and_then(|k| signed.open(&k).ok()) {
            view.merge(&cp.view);
        }
        Ok(())
    }

    /// All locally known batches in (device, seq) order.
    pub fn all(&self) -> Result<Vec<SignedBatch>> {
        let mut out = Vec::new();
        for (device, head) in &self.heads.heads {
            for seq in head.dropped + 1..=head.seq {
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
        for (device, head) in &self.heads.heads {
            let base = Self::usable_base(head, device, &key_for, &keep);
            if base > 0 {
                self.apply_checkpoint(&mut view, device, base, &key_for)?;
            }
            for seq in (base.max(head.dropped) + 1)..=head.seq {
                if let Some(signed) = self.get(device, seq)? {
                    apply_signed(&mut view, &signed, &key_for, &keep);
                }
            }
        }
        Ok(self.finish(&view))
    }

    /// Bring a cached view up to date with the local batches: apply every
    /// batch after the last one applied per device, and batches that were
    /// missing then and have arrived since. Returns whether anything was
    /// applied. Applying is order-independent, so the result equals a full
    /// replay of the same batches under the same keys and cut-offs.
    pub fn update_view(
        &self,
        cache: &mut ViewCache,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceId, u64) -> bool,
    ) -> Result<u64> {
        let mut applied = 0;
        let bases: BTreeMap<DeviceId, u64> = self
            .heads
            .heads
            .iter()
            .map(|(d, h)| (d.clone(), Self::usable_base(h, d, &key_for, &keep)))
            .filter(|(_, b)| *b > 0)
            .collect();
        if bases != cache.bases {
            // A device's contribution now starts from another checkpoint:
            // start over from the checkpoints.
            *cache = ViewCache {
                bases,
                ..ViewCache::new(std::mem::take(&mut cache.context))
            };
            for (device, seq) in cache.bases.clone() {
                self.apply_checkpoint(&mut cache.raw, &device, seq, &key_for)?;
                cache.applied.insert(device, seq);
                applied += 1;
            }
        }
        for (device, head) in &self.heads.heads {
            if let Some(gaps) = cache.gaps.get_mut(device) {
                let filled: Vec<u64> = gaps
                    .iter()
                    .copied()
                    .filter(|seq| self.batch_path(device, *seq).exists())
                    .collect();
                for seq in filled {
                    if let Some(signed) = self.get(device, seq)? {
                        apply_signed(&mut cache.raw, &signed, &key_for, &keep);
                        applied += 1;
                    }
                    gaps.remove(&seq);
                }
                if gaps.is_empty() {
                    cache.gaps.remove(device);
                }
            }
            let from = cache
                .applied
                .get(device)
                .copied()
                .unwrap_or(0)
                .max(head.dropped);
            for seq in from + 1..=head.seq {
                match self.get(device, seq)? {
                    Some(signed) => {
                        apply_signed(&mut cache.raw, &signed, &key_for, &keep);
                        applied += 1;
                    }
                    None => {
                        cache.gaps.entry(device.clone()).or_default().insert(seq);
                    }
                }
            }
            if head.seq > from {
                cache.applied.insert(device.clone(), head.seq);
            }
        }
        Ok(applied)
    }

    /// Whether a cached view can be brought up to date incrementally: it
    /// must not claim batches beyond the local heads (a ledger directory
    /// restored from an older copy).
    pub fn cache_fits(&self, cache: &ViewCache) -> bool {
        cache
            .applied
            .iter()
            .all(|(device, seq)| *seq <= self.head(device).seq)
    }

    /// The view as callers see it: retirements applied, replica claims
    /// folded in, forked devices marked. `raw` is left as it was.
    pub fn finish(&self, raw: &LedgerView) -> LedgerView {
        self.finish_owned(raw.clone())
    }

    pub fn finish_owned(&self, mut view: LedgerView) -> LedgerView {
        view.apply_retirements();
        view.fold_object_claims();
        for (d, head) in &self.heads.heads {
            if head.forked {
                view.forked.insert(d.clone());
            }
        }
        view
    }
}

/// Apply one stored batch to a view if `keep` accepts it and its key is known.
fn apply_signed(
    view: &mut LedgerView,
    signed: &SignedBatch,
    key_for: &impl Fn(&str) -> Option<SecretKey>,
    keep: &impl Fn(&DeviceId, u64) -> bool,
) {
    if !keep(&signed.device, signed.seq) {
        return;
    }
    let Some(key) = key_for(&signed.key_id) else {
        return;
    };
    if let Ok(batch) = signed.open(&key) {
        view.apply(&batch);
    }
}

/// A location view kept between runs (`ledger/view.enc`): the batches
/// applied so far, before retirements and replica claims are folded in,
/// with what was applied and under which keys and cut-offs (`context`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ViewCache {
    pub format: u32,
    /// Fingerprint of the keys and revocation cut-offs the view was built
    /// with; a different one means rebuilding from the batches.
    pub context: String,
    /// Per device, every local batch up to this sequence number was applied
    /// (or skipped for good: unknown key, after a cut-off) ...
    pub applied: BTreeMap<DeviceId, u64>,
    /// ... except these, which were missing locally at the time.
    #[serde(default)]
    pub gaps: BTreeMap<DeviceId, BTreeSet<u64>>,
    /// The checkpoint each device's contribution starts from.
    #[serde(default)]
    pub bases: BTreeMap<DeviceId, u64>,
    pub raw: LedgerView,
}

impl ViewCache {
    pub const FORMAT: u32 = 2;

    pub fn new(context: String) -> Self {
        ViewCache {
            format: Self::FORMAT,
            context,
            ..Default::default()
        }
    }
}

/// Which event set a value last: Lamport time, device, batch sequence and
/// position in the batch. The largest wins, whatever order batches arrive in.
pub type Stamp = (u64, DeviceId, u64, u32);

/// Serialize maps with tuple keys as lists of pairs (JSON keys are strings).
mod pairs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<'a, S, M, K, V>(map: &'a M, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        &'a M: IntoIterator<Item = (&'a K, &'a V)>,
        K: Serialize + 'a,
        V: Serialize + 'a,
    {
        s.collect_seq(map)
    }

    pub fn deserialize<'de, D, M, K, V>(d: D) -> Result<M, D::Error>
    where
        D: Deserializer<'de>,
        M: FromIterator<(K, V)>,
        K: Deserialize<'de>,
        V: Deserialize<'de>,
    {
        Ok(Vec::<(K, V)>::deserialize(d)?.into_iter().collect())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub claimed_by: BTreeSet<DeviceId>,
    pub verified_by: BTreeSet<DeviceId>,
    /// Newest claim and verification times (batch creation time, UTC seconds).
    #[serde(default)]
    pub claimed_utc: i64,
    #[serde(default)]
    pub verified_utc: i64,
    /// Newest claim or verification (Lamport time), to apply retirements.
    #[serde(default)]
    pub lamport: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub object: ObjectName,
    pub size: u64,
    pub storages: BTreeMap<String, Location>,
    pub devices: BTreeSet<DeviceId>,
    /// Which events set `object` and `size`.
    #[serde(default)]
    pub object_at: Option<Stamp>,
    #[serde(default)]
    pub size_at: Option<Stamp>,
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
    fn set_object(&mut self, object: &ObjectName, at: Option<Stamp>) {
        if at > self.object_at {
            self.object = object.clone();
            self.object_at = at;
        }
    }

    fn set_size(&mut self, size: u64, at: Option<Stamp>) {
        if at > self.size_at {
            self.size = size;
            self.size_at = at;
        }
    }

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerView {
    #[serde(with = "pairs")]
    pub chunks: HashMap<(FolderId, ChunkId), ChunkRecord>,
    /// Highest manifest sequence published per (folder, device).
    #[serde(with = "pairs")]
    pub manifests: BTreeMap<(FolderId, DeviceId), u64>,
    pub devices: BTreeMap<DeviceId, String>,
    /// Which enrolment event set each device name.
    #[serde(default)]
    pub devices_at: BTreeMap<DeviceId, Stamp>,
    pub folders: BTreeSet<FolderId>,
    pub max_lamport: u64,
    /// Retired storages and when (Lamport time).
    pub retired: BTreeMap<String, u64>,
    pub batches: u64,
    /// Per device, the newest batch of each other device it said it held.
    #[serde(default)]
    pub acks: BTreeMap<DeviceId, BTreeMap<DeviceId, u64>>,
    #[serde(default)]
    pub forked: BTreeSet<DeviceId>,
    /// Objects claimed by replicas (folded into chunk records).
    #[serde(default)]
    pub object_claims: u64,
}

impl LedgerView {
    pub(crate) fn apply(&mut self, batch: &Batch) {
        self.batches += 1;
        self.max_lamport = self.max_lamport.max(batch.lamport);
        if !batch.seen.is_empty() {
            let acks = self.acks.entry(batch.device.clone()).or_default();
            for (d, seq) in &batch.seen {
                let a = acks.entry(d.clone()).or_insert(0);
                *a = (*a).max(*seq);
            }
        }
        for (i, ev) in batch.events.iter().enumerate() {
            let stamp = || Some((batch.lamport, batch.device.clone(), batch.seq, i as u32));
            match ev {
                Event::DeviceEnrolled { name } => {
                    let at = stamp().expect("some");
                    if self.devices_at.get(&batch.device).is_none_or(|s| *s < at) {
                        self.devices.insert(batch.device.clone(), name.clone());
                        self.devices_at.insert(batch.device.clone(), at);
                    }
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
                    rec.set_object(object, stamp());
                    rec.set_size(*size, stamp());
                    let loc = rec.storages.entry(storage.clone()).or_default();
                    loc.claimed_by.insert(batch.device.clone());
                    loc.claimed_utc = loc.claimed_utc.max(batch.created_utc);
                    loc.lamport = loc.lamport.max(batch.lamport);
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
                    rec.set_object(object, stamp());
                    let loc = rec.storages.entry(storage.clone()).or_default();
                    loc.verified_by.insert(batch.device.clone());
                    loc.verified_utc = loc.verified_utc.max(batch.created_utc);
                    loc.lamport = loc.lamport.max(batch.lamport);
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
                    rec.set_object(object, stamp());
                    rec.set_size(*size, stamp());
                    rec.devices.insert(batch.device.clone());
                }
                Event::ManifestPublished { folder, seq, .. } => {
                    let e = self
                        .manifests
                        .entry((folder.clone(), batch.device.clone()))
                        .or_insert(0);
                    *e = (*e).max(*seq);
                }
                Event::StorageRetired { storage } => {
                    let r = self.retired.entry(storage.clone()).or_insert(0);
                    *r = (*r).max(batch.lamport);
                }
            }
        }
    }

    /// Merge another view, as if its batches had been applied to this one
    /// (every field is a union, a maximum, a sum or stamped).
    pub fn merge(&mut self, other: &LedgerView) {
        for (key, rec) in &other.chunks {
            let mine = self.chunks.entry(key.clone()).or_default();
            if rec.object_at > mine.object_at {
                mine.object = rec.object.clone();
                mine.object_at = rec.object_at.clone();
            }
            if rec.size_at > mine.size_at {
                mine.size = rec.size;
                mine.size_at = rec.size_at.clone();
            }
            for (name, loc) in &rec.storages {
                let m = mine.storages.entry(name.clone()).or_default();
                m.claimed_by.extend(loc.claimed_by.iter().cloned());
                m.verified_by.extend(loc.verified_by.iter().cloned());
                m.claimed_utc = m.claimed_utc.max(loc.claimed_utc);
                m.verified_utc = m.verified_utc.max(loc.verified_utc);
                m.lamport = m.lamport.max(loc.lamport);
            }
            mine.devices.extend(rec.devices.iter().cloned());
        }
        for (key, seq) in &other.manifests {
            let e = self.manifests.entry(key.clone()).or_insert(0);
            *e = (*e).max(*seq);
        }
        for (device, at) in &other.devices_at {
            if self.devices_at.get(device).is_none_or(|s| s < at) {
                if let Some(name) = other.devices.get(device) {
                    self.devices.insert(device.clone(), name.clone());
                    self.devices_at.insert(device.clone(), at.clone());
                }
            }
        }
        self.folders.extend(other.folders.iter().cloned());
        self.max_lamport = self.max_lamport.max(other.max_lamport);
        for (storage, at) in &other.retired {
            let r = self.retired.entry(storage.clone()).or_insert(0);
            *r = (*r).max(*at);
        }
        self.batches += other.batches;
        for (device, seen) in &other.acks {
            let acks = self.acks.entry(device.clone()).or_default();
            for (d, seq) in seen {
                let a = acks.entry(d.clone()).or_insert(0);
                *a = (*a).max(*seq);
            }
        }
    }

    /// Drop the copies on retired storages that were recorded before the
    /// retirement. Batches arrive per device, not in Lamport order, so this
    /// runs once all of them are applied.
    fn apply_retirements(&mut self) {
        if self.retired.is_empty() {
            return;
        }
        for rec in self.chunks.values_mut() {
            rec.storages.retain(|name, loc| {
                self.retired
                    .get(name)
                    .is_none_or(|retired| loc.lamport > *retired)
            });
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
    fn batch_under_an_unknown_key_is_kept_unread() {
        let (_d, mut a, key, signer, device) = setup();
        let b1 = a.append_own(&device, vec![], 1, &key, &signer).unwrap();
        let b2 = a
            .append_own(
                &device,
                vec![Event::DeviceEnrolled { name: "a".into() }],
                2,
                &key,
                &signer,
            )
            .unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let mut b = LedgerStore::open(&dir2.path().join("ledger")).unwrap();
        let pk = signer.public();
        assert_eq!(b.ingest_with(b1, &pk, None).unwrap(), Ingest::New);
        assert_eq!(b.ingest(b2.clone(), &pk, &key).unwrap(), Ingest::New);
        assert_eq!(b.head(&device).seq, 2);
        assert_eq!(b.view(&key).unwrap().batches, 2);
        // The signature is still checked.
        let mut forged = b2;
        forged.seq = 3;
        assert!(b.ingest_with(forged, &pk, None).is_err());
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
            seen: BTreeMap::new(),
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

    /// Small deterministic generator for the property test.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_event(rng: &mut Rng) -> Event {
        let chunk = |rng: &mut Rng| ChunkId::from_bytes(&[rng.below(6) as u8, 7]);
        let object = |rng: &mut Rng| ObjectName::from_bytes(&[rng.below(3) as u8, 9]);
        let storage = |rng: &mut Rng| ["s1", "s2", "replica:r"][rng.below(3) as usize].to_string();
        if rng.below(5) == 0 {
            // A replica's claim: no folder, the object name as chunk id.
            let object = object(rng);
            return Event::ChunkStored {
                folder: FolderId::default(),
                chunk: ChunkId::from_hex(object.as_str()).unwrap(),
                object,
                storage: "replica:r".into(),
                size: 5,
            };
        }
        let folder = |rng: &mut Rng| FolderId::from_bytes(&[1 + rng.below(3) as u8]);
        match rng.below(8) {
            0 => Event::DeviceEnrolled {
                name: format!("n{}", rng.below(5)),
            },
            1 => Event::FolderAdded {
                folder: folder(rng),
            },
            2 | 3 => Event::ChunkStored {
                folder: folder(rng),
                chunk: chunk(rng),
                object: object(rng),
                storage: storage(rng),
                size: rng.below(1000),
            },
            4 => Event::ChunkVerified {
                folder: folder(rng),
                chunk: chunk(rng),
                object: object(rng),
                storage: storage(rng),
            },
            5 => Event::ChunkOnDevice {
                folder: folder(rng),
                chunk: chunk(rng),
                object: object(rng),
                size: rng.below(1000),
            },
            6 => Event::ManifestPublished {
                folder: folder(rng),
                seq: rng.below(20),
                manifest_hash: String::new(),
                files: 0,
            },
            _ => Event::StorageRetired {
                storage: storage(rng),
            },
        }
    }

    /// A cached view brought up to date at random moments, while batches of
    /// three devices arrive in random order (some under a key the reader
    /// lacks, some after a revocation cut-off), always equals a full replay,
    /// also after a round trip through its saved form.
    #[test]
    fn cached_view_equals_full_replay() {
        for round in 0..12u64 {
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ ((round + 1) * 0x1234_5678_9abc));
            let key = SecretKey::random();
            let other = SecretKey::random();
            let dir = tempfile::tempdir().unwrap();
            let signers: Vec<SigningKey> = (0..3)
                .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]).unwrap())
                .collect();
            let ids: Vec<DeviceId> = signers.iter().map(|s| device_id_for(&s.public())).collect();
            // Every device writes its own chain.
            enum Item {
                Batch(usize, SignedBatch),
                Checkpoint(usize, SignedCheckpoint),
            }
            let mut pending: Vec<Item> = Vec::new();
            let both = |id: &str| match id {
                KEY_LEDGER => Some(key.clone()),
                "other" => Some(other.clone()),
                _ => None,
            };
            for (i, signer) in signers.iter().enumerate() {
                let mut own = LedgerStore::open(&dir.path().join(format!("own{i}"))).unwrap();
                let mut lamport = 0;
                let n = 5 + rng.below(25);
                for _ in 0..n {
                    lamport += 1 + rng.below(3);
                    let events = (0..rng.below(5)).map(|_| random_event(&mut rng)).collect();
                    let (k, id) = if rng.below(6) == 0 {
                        (&other, "other")
                    } else {
                        (&key, KEY_LEDGER)
                    };
                    let b = own
                        .append_own_with(&ids[i], events, lamport, k, id, signer)
                        .unwrap();
                    pending.push(Item::Batch(i, b));
                }
                if i != 1 {
                    // Devices 0 and 2 also publish a checkpoint (2's may lie
                    // beyond its cut-off and must then be ignored).
                    let at = 1 + rng.below(n);
                    let cp = own
                        .make_checkpoint(&ids[i], at, both, &key, KEY_LEDGER, signer)
                        .unwrap();
                    pending.push(Item::Checkpoint(i, cp));
                }
            }
            let cutoff = 3 + rng.below(10);
            let key_for = |id: &str| (id == KEY_LEDGER).then(|| key.clone());
            let keep = |d: &DeviceId, seq: u64| d != &ids[2] || seq <= cutoff;
            let mut reader = LedgerStore::open(&dir.path().join("reader")).unwrap();
            let mut cache = ViewCache::new("ctx".into());
            while !pending.is_empty() {
                match pending.remove(rng.below(pending.len() as u64) as usize) {
                    Item::Batch(i, b) => {
                        let k = (b.key_id == KEY_LEDGER).then_some(&key);
                        reader.ingest_with(b, &signers[i].public(), k).unwrap();
                    }
                    Item::Checkpoint(i, cp) => {
                        cp.verify(&signers[i].public()).unwrap();
                        cp.open(&key).unwrap();
                        let at = cp.seq;
                        assert_ne!(reader.ingest_checkpoint(cp).unwrap(), Ingest::Fork);
                        if i == 0 && rng.below(2) == 0 {
                            reader.drop_through(&ids[0], at).unwrap();
                        }
                    }
                }
                if rng.below(3) == 0 {
                    reader.update_view(&mut cache, key_for, keep).unwrap();
                    let full = reader.view_filtered(key_for, keep).unwrap();
                    assert_eq!(reader.finish(&cache.raw), full, "round {round}");
                }
                if rng.below(8) == 0 {
                    cache = serde_json::from_slice(&serde_json::to_vec(&cache).unwrap()).unwrap();
                }
            }
            reader.update_view(&mut cache, key_for, keep).unwrap();
            let full = reader.view_filtered(key_for, keep).unwrap();
            assert_eq!(reader.finish(&cache.raw), full, "round {round}");
            assert!(full.batches > 0);
            assert!(reader.cache_fits(&cache));
        }
    }

    /// A reader that starts from a checkpoint and applies only the later
    /// batches gets the same view as one that replays every batch; batches
    /// the checkpoint covers are not kept; a checkpoint or batch that
    /// contradicts it is a fork.
    #[test]
    fn checkpoint_stands_in_for_its_batches() {
        let mut rng = Rng(77);
        let (dir, mut own, key, signer, device) = setup();
        let mut batches = Vec::new();
        for lamport in 1..=30 {
            let events = (0..3).map(|_| random_event(&mut rng)).collect();
            batches.push(
                own.append_own(&device, events, lamport, &key, &signer)
                    .unwrap(),
            );
        }
        let key_for = |id: &str| (id == KEY_LEDGER).then(|| key.clone());
        let keep = |_: &DeviceId, _: u64| true;
        let cp = own
            .make_checkpoint(&device, 20, key_for, &key, KEY_LEDGER, &signer)
            .unwrap();
        // The writer's own view is unchanged by its checkpoint.
        let pk = signer.public();
        let mut full = LedgerStore::open(&dir.path().join("full")).unwrap();
        for b in &batches {
            full.ingest(b.clone(), &pk, &key).unwrap();
        }
        let expected = full.view_filtered(key_for, keep).unwrap();
        assert_eq!(own.view_filtered(key_for, keep).unwrap(), expected);

        let mut fresh = LedgerStore::open(&dir.path().join("fresh")).unwrap();
        cp.verify(&pk).unwrap();
        assert_eq!(fresh.ingest_checkpoint(cp.clone()).unwrap(), Ingest::New);
        assert_eq!(fresh.head(&device).seq, 20);
        // Covered batches are acknowledged without being kept.
        assert_eq!(
            fresh.ingest(batches[4].clone(), &pk, &key).unwrap(),
            Ingest::Known
        );
        assert!(fresh.get(&device, 5).unwrap().is_none());
        for b in &batches[20..] {
            assert_eq!(fresh.ingest(b.clone(), &pk, &key).unwrap(), Ingest::New);
        }
        assert_eq!(fresh.view_filtered(key_for, keep).unwrap(), expected);
        let mut cache = ViewCache::new("ctx".into());
        fresh.update_view(&mut cache, key_for, keep).unwrap();
        assert_eq!(fresh.finish(&cache.raw), expected);

        // The full reader adopts the checkpoint and drops what it covers.
        assert_eq!(full.ingest_checkpoint(cp.clone()).unwrap(), Ingest::New);
        assert_eq!(full.drop_through(&device, 20).unwrap(), 20);
        assert_eq!(full.all().unwrap().len(), 10);
        assert_eq!(full.view_filtered(key_for, keep).unwrap(), expected);

        // A copy of the device restored to seq 20 signs another batch 21.
        let restored_dir = dir.path().join("restored");
        let mut restored = LedgerStore::open(&restored_dir).unwrap();
        for b in &batches[..20] {
            restored.ingest(b.clone(), &pk, &key).unwrap();
        }
        let other21 = restored
            .append_own(&device, vec![], 99, &key, &signer)
            .unwrap();
        let mut observer = LedgerStore::open(&dir.path().join("observer")).unwrap();
        observer.ingest_checkpoint(cp.clone()).unwrap();
        assert_eq!(observer.ingest(other21, &pk, &key).unwrap(), Ingest::New);
        assert_eq!(
            observer.ingest(batches[21].clone(), &pk, &key).unwrap(),
            Ingest::Fork
        );
        // A different checkpoint at the same place is a fork as well.
        let other_cp = restored
            .make_checkpoint(&device, 21, key_for, &key, KEY_LEDGER, &signer)
            .unwrap();
        assert_eq!(
            fresh.ingest_checkpoint(other_cp).unwrap(),
            Ingest::Fork,
            "it contradicts batch 21"
        );
        let mut third = LedgerStore::open(&dir.path().join("third")).unwrap();
        third.ingest(batches[20].clone(), &pk, &key).unwrap();
        let cp21 = own
            .make_checkpoint(&device, 21, key_for, &key, KEY_LEDGER, &signer)
            .unwrap();
        assert_eq!(third.ingest_checkpoint(cp21).unwrap(), Ingest::New);
        let forged = restored
            .make_checkpoint(&device, 21, key_for, &key, KEY_LEDGER, &signer)
            .unwrap();
        assert_eq!(third.ingest_checkpoint(forged).unwrap(), Ingest::Fork);
    }
}
