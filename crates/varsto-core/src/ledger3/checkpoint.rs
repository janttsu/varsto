// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Checkpoints of one device's ledger with the pack-level view as body
//! (`docs/spec/format-3-design.md` section 4): a signed record of kind
//! `checkpoint` at `ledger/<device>/checkpoint-<seq 16>-<part 4>.rec`, in
//! parts when large. Rules unchanged from format 2: written by the device
//! itself, read only from full devices, a checkpoint speaks for its signer
//! only (`LedgerView::restricted_to`), and one more than `MAX_AHEAD` beyond
//! the batches held is kept only beside the batch it ends at.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::envelope::{self, kind, Header, SignedRecord};
use super::view::LedgerView;
use super::{DeviceBin, Hash32, NO_FOLDER};
use crate::crypto::{SecretKey, SigningKey};

/// Plaintext checkpoint body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub device: DeviceBin,
    /// Covers batches 1..=seq of `device`.
    pub seq: u64,
    /// Body hash of batch `seq`; batch `seq + 1` names it as `prev`.
    pub head_hash: Hash32,
    pub created_utc: i64,
    /// The raw view of this device's own batches 1..=seq.
    pub view: LedgerView,
}

/// Object name prefix of checkpoints inside `ledger/<device>/`; it sorts
/// after every batch name.
pub const CHECKPOINT_PREFIX: &str = "checkpoint-";

/// Largest plaintext of a checkpoint a reader decompresses.
pub const MAX_CHECKPOINT_PLAIN: usize = 1 << 30;

/// The storage name of batch `seq` of `device` (a batch is one part).
pub fn batch_key(device: &DeviceBin, seq: u64) -> String {
    format!("ledger/{}/{seq:016}-0000.rec", hex::encode(device))
}

/// The storage name of part `part` of checkpoint `seq` of `device`.
pub fn checkpoint_key(device: &DeviceBin, seq: u64, part: u16) -> String {
    format!(
        "ledger/{}/{CHECKPOINT_PREFIX}{seq:016}-{part:04}.rec",
        hex::encode(device)
    )
}

impl Checkpoint {
    /// Seal as one or more parts under the ledger key `key_id`.
    pub fn seal(
        &self,
        vault: &[u8; 16],
        key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Vec<SignedRecord>> {
        let h = Header {
            kind: kind::CHECKPOINT,
            vault: *vault,
            scope: NO_FOLDER,
            device: self.device,
            seq: self.seq,
            part: 0,
            parts: 1,
            key_id: key_id.to_string(),
        };
        envelope::seal_parts(&h, key, &postcard::to_allocvec(self)?, signer)
    }

    /// Open the parts of a checkpoint (signatures checked by the caller).
    pub fn open(parts: &[SignedRecord], key: &SecretKey) -> Result<Checkpoint> {
        let Some(first) = parts.first() else {
            bail!("a checkpoint without parts");
        };
        if first.kind != kind::CHECKPOINT || first.scope != NO_FOLDER {
            bail!("not a checkpoint record");
        }
        let plain = envelope::open_parts(parts, key, MAX_CHECKPOINT_PLAIN)?;
        let cp: Checkpoint = postcard::from_bytes(&plain)?;
        if cp.device != first.device || cp.seq != first.seq {
            bail!("checkpoint body does not match its envelope");
        }
        Ok(cp)
    }
}

/// What a name inside `ledger/<device>/` stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LedgerObject {
    Batch(u64),
    Checkpoint(u64, u16),
}

impl LedgerObject {
    pub fn parse(file: &str) -> Option<Self> {
        let digits = |s: &str, n: usize| -> Option<u64> {
            if s.len() != n || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        let stem = file.strip_suffix(".rec")?;
        let (cp, rest) = match stem.strip_prefix(CHECKPOINT_PREFIX) {
            Some(r) => (true, r),
            None => (false, stem),
        };
        let (seq, part) = rest.split_once('-')?;
        let seq = digits(seq, 16)?;
        let part = digits(part, 4)? as u16;
        if cp {
            Some(LedgerObject::Checkpoint(seq, part))
        } else {
            (part == 0).then_some(LedgerObject::Batch(seq))
        }
    }
}
