// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Signed checkpoints of one device's ledger (`docs/spec/alpha-0-format.md`
//! section 22). A checkpoint holds what that device's batches 1..=seq add to
//! the location view, sealed and signed like a batch, and names the hash of
//! batch `seq` so the chain continues from it. A reader starts from the
//! newest checkpoint of each device and applies only later batches, and old
//! batches can be dropped once every device has seen past the checkpoint.

use super::LedgerView;
use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ids::DeviceId;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Plaintext checkpoint body (compressed and encrypted before signing).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub device: DeviceId,
    /// Covers batches 1..=seq of `device`.
    pub seq: u64,
    /// Hash of batch `seq`; batch `seq + 1` names it as its predecessor.
    pub head_hash: String,
    pub created_utc: i64,
    /// The view built from this device's own batches 1..=seq alone, before
    /// retirements and replica claims are folded in.
    pub view: LedgerView,
}

/// What is stored and replicated, at `ledger/<device>/checkpoint-<seq>.json`.
/// The signature covers `device || seq || head_hash || hash`, where `hash`
/// is the hash of the encrypted body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub format_version: u16,
    pub sig_alg: String,
    pub key_id: String,
    pub device: DeviceId,
    pub seq: u64,
    pub head_hash: String,
    pub body_hex: String,
    pub hash: String,
    pub sig_hex: String,
}

/// Object name prefix of checkpoints inside `ledger/<device>/`. Versions
/// before checkpoints skip these names: they only read numeric ones.
pub const CHECKPOINT_PREFIX: &str = "checkpoint-";

impl SignedCheckpoint {
    fn signed_message(device: &DeviceId, seq: u64, head_hash: &str, hash: &str) -> Vec<u8> {
        crypto::aad(
            "ledger-checkpoint-signature",
            &[
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
                head_hash.as_bytes(),
                hash.as_bytes(),
            ],
        )
    }

    fn body_aad(device: &DeviceId, seq: u64, head_hash: &str) -> Vec<u8> {
        crypto::aad(
            "ledger-checkpoint",
            &[
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
                head_hash.as_bytes(),
            ],
        )
    }

    pub fn storage_key(device: &DeviceId, seq: u64) -> String {
        format!("ledger/{device}/{CHECKPOINT_PREFIX}{seq:016}.json")
    }

    pub fn seal(
        cp: &Checkpoint,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Self> {
        let plain = zstd::bulk::compress(&serde_json::to_vec(cp)?, 3)?;
        let ct = crypto::encrypt(
            ledger_key,
            &Self::body_aad(&cp.device, cp.seq, &cp.head_hash),
            &plain,
        )?;
        let hash = hex::encode(crypto::hash(&ct));
        let sig = signer.sign(&Self::signed_message(
            &cp.device,
            cp.seq,
            &cp.head_hash,
            &hash,
        ));
        Ok(SignedCheckpoint {
            format_version: crate::FORMAT_VERSION,
            sig_alg: signer.alg().to_string(),
            key_id: key_id.to_string(),
            device: cp.device.clone(),
            seq: cp.seq,
            head_hash: cp.head_hash.clone(),
            body_hex: hex::encode(ct),
            hash,
            sig_hex: hex::encode(sig),
        })
    }

    /// Check signature and hash; does not decrypt.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<()> {
        let ct = hex::decode(&self.body_hex)?;
        if hex::encode(crypto::hash(&ct)) != self.hash {
            bail!("checkpoint hash does not match body");
        }
        pubkey.verify(
            &self.sig_alg,
            &Self::signed_message(&self.device, self.seq, &self.head_hash, &self.hash),
            &hex::decode(&self.sig_hex)?,
        )
    }

    pub fn open(&self, ledger_key: &SecretKey) -> Result<Checkpoint> {
        let ct = hex::decode(&self.body_hex)?;
        let packed = crypto::decrypt(
            ledger_key,
            &Self::body_aad(&self.device, self.seq, &self.head_hash),
            &ct,
        )?;
        let plain = zstd::bulk::decompress(&packed, 1 << 30)?;
        let cp: Checkpoint = serde_json::from_slice(&plain)?;
        if cp.device != self.device || cp.seq != self.seq || cp.head_hash != self.head_hash {
            bail!("checkpoint body does not match its envelope");
        }
        Ok(cp)
    }
}

/// What a name inside `ledger/<device>/` stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LedgerObject {
    Batch(u64),
    Checkpoint(u64),
}

impl LedgerObject {
    pub fn parse(file: &str) -> Option<Self> {
        let digits = |s: &str| -> Option<u64> {
            if s.len() != 16 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        let stem = file.strip_suffix(".json")?;
        match stem.strip_prefix(CHECKPOINT_PREFIX) {
            Some(n) => digits(n).map(LedgerObject::Checkpoint),
            None => digits(stem).map(LedgerObject::Batch),
        }
    }
}
