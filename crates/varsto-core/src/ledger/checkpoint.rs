// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Signed checkpoints of one device's ledger (`docs/spec/alpha-0-format.md`
//! section 22). A checkpoint holds what that device's batches 1..=seq add to
//! the location view, sealed and signed like a batch, and names the hash of
//! batch `seq` so the chain continues from it. A reader starts from the
//! newest checkpoint of each device and applies only later batches, and old
//! batches can be dropped once every device has seen past the checkpoint.

use super::LedgerView;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, VaultId};
use crate::record::{self, RecordKind, SignedRecord};
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

/// What is stored and replicated, at `ledger/<device>/checkpoint-<seq>.json`:
/// a signed record of kind `checkpoint` (`crate::record`) whose scope is
/// the hash of batch `seq` (the chain continues from it), so the head hash
/// and the key id are both covered by the signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SignedCheckpoint(pub SignedRecord);

impl std::ops::Deref for SignedCheckpoint {
    type Target = SignedRecord;
    fn deref(&self) -> &SignedRecord {
        &self.0
    }
}

/// Object name prefix of checkpoints inside `ledger/<device>/`. Versions
/// before checkpoints skip these names: they only read numeric ones.
pub const CHECKPOINT_PREFIX: &str = "checkpoint-";

impl SignedCheckpoint {
    pub fn storage_key(device: &DeviceId, seq: u64) -> String {
        format!("ledger/{device}/{CHECKPOINT_PREFIX}{seq:016}.json")
    }

    /// The hash of batch `seq` this checkpoint ends at (its signed scope).
    pub fn head_hash(&self) -> &str {
        &self.0.scope
    }

    pub fn seal(
        vault: &VaultId,
        cp: &Checkpoint,
        ledger_key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Self> {
        let plain = zstd::bulk::compress(&serde_json::to_vec(cp)?, 3)?;
        let header = record::Header {
            kind: RecordKind::Checkpoint,
            vault,
            scope: &cp.head_hash,
            device: &cp.device,
            seq: cp.seq,
            key_id,
        };
        Ok(SignedCheckpoint(header.seal(ledger_key, &plain, signer)?))
    }

    /// Check kind, signature and hash; does not decrypt.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<()> {
        if self.kind != RecordKind::Checkpoint {
            bail!("not a ledger checkpoint");
        }
        self.0.verify(pubkey)
    }

    pub fn open(&self, ledger_key: &SecretKey) -> Result<Checkpoint> {
        if self.kind != RecordKind::Checkpoint {
            bail!("not a ledger checkpoint");
        }
        let packed = self.0.open(ledger_key)?;
        let plain = zstd::bulk::decompress(&packed, 1 << 30)?;
        let cp: Checkpoint = serde_json::from_slice(&plain)?;
        if cp.device != self.device || cp.seq != self.seq || cp.head_hash != self.head_hash() {
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
