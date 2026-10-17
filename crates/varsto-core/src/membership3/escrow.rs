// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Recovery escrow (format 3 design, sections 1 and 6).
//!
//! K1, the recovery key, is 256 random bits shown as 24 BIP-39 words (or
//! Shamir 2-of-3 shares, the kit code of section 18). K2 = derive(K1,
//! "recovery-wrap"). Every folder epoch is escrowed as an `escrow` record
//! at `vault/escrow/<folder>/<epoch 10>/<device>/`, key_id `recovery`,
//! body `{K9ₑ, K11}` under `derive(K2, "folder-escrow", vault, K3₀)`.
//! Binding K3₀ keeps "the recovery words alone give nothing" true even for
//! someone who can list the storage; the vault words alone open no escrow
//! either. Vault words + recovery words rebuild every folder key.

use super::{derive3, VAULT_SCOPE};
use crate::crypto::SecretKey;
use crate::record::{Id16, RecordBody, RecordMeta, StreamRef};
use crate::recovery::{self, Share};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// K1. Wiped when dropped.
#[derive(Clone)]
pub struct RecoveryKey(SecretKey);

crate::redacted_opaque!(RecoveryKey);

impl RecoveryKey {
    pub fn generate() -> RecoveryKey {
        RecoveryKey(SecretKey::random())
    }

    pub fn from_secret(k: SecretKey) -> RecoveryKey {
        RecoveryKey(k)
    }

    /// The 24 words of the kit.
    pub fn words(&self) -> Result<Zeroizing<String>> {
        recovery::words_from_key(&self.0.to_hex())
    }

    /// From the 24 words (any spacing and case; the checksum is checked).
    pub fn from_words(words: &str) -> Result<RecoveryKey> {
        let hex = recovery::key_from_words(words)?;
        Ok(RecoveryKey(SecretKey::from_hex(&hex)?))
    }

    /// Shamir shares, any 2 of 3 rebuild K1 (section 18's code).
    pub fn shares(&self) -> Result<Vec<Share>> {
        recovery::split(&self.0.to_hex(), 2, 3)
    }

    /// From two shares, checked against the kit's key check when given.
    pub fn from_shares(shares: &[Share], check: Option<&str>) -> Result<RecoveryKey> {
        let hex = recovery::combine(shares, 2, check)?;
        Ok(RecoveryKey(SecretKey::from_hex(&hex)?))
    }

    /// The kit's "Key check" for K1.
    pub fn key_check(&self) -> Result<String> {
        recovery::key_check(&self.0.to_hex())
    }

    /// K2 = derive(K1, "recovery-wrap").
    pub fn k2(&self) -> SecretKey {
        derive3(&self.0, "recovery-wrap", &[])
    }

    /// The escrow key: derive(K2, "folder-escrow", vault, K3₀).
    pub fn escrow_key(&self, vault: &Id16, k3_0: &SecretKey) -> SecretKey {
        derive3(&self.k2(), "folder-escrow", &[vault, k3_0.as_bytes()])
    }
}

/// The body of an escrow record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowRecord {
    pub folder: Id16,
    pub epoch: u32,
    pub k9: [u8; 32],
    pub k11: [u8; 32],
}

crate::redacted_debug!(EscrowRecord { folder, epoch ; k9, k11 });

impl Drop for EscrowRecord {
    fn drop(&mut self) {
        self.k9.zeroize();
        self.k11.zeroize();
    }
}

impl RecordBody for EscrowRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if meta.scope == VAULT_SCOPE || self.folder != meta.scope {
            return Err("folder differs from the record's scope".into());
        }
        if meta.epoch != Some(self.epoch) {
            return Err("epoch differs from the record's name".into());
        }
        Ok(())
    }
}

impl EscrowRecord {
    pub fn stream(folder: Id16, epoch: u32, device: Id16) -> StreamRef {
        StreamRef::escrow(folder, epoch, device)
    }
}

/// A folder epoch this device holds with no escrow on the storages: the
/// data behind `"folder <name> has no recovery copy: run varsto recovery
/// escrow <folder>"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingEscrow {
    pub folder: Id16,
    pub name: String,
    pub epoch: u32,
}

impl MissingEscrow {
    pub fn warning(&self) -> String {
        format!(
            "folder {} has no recovery copy: run varsto recovery escrow {}",
            self.name, self.name
        )
    }
}

/// The printable kit of format 3: the newest vault key and K1, two word
/// sets.
pub fn kit_text(
    vault: &Id16,
    vault_epoch: u32,
    k3: &SecretKey,
    k1: &RecoveryKey,
) -> Result<String> {
    let rows = |words: &str| -> String {
        let numbered: Vec<String> = words
            .split(' ')
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {w}", i + 1))
            .collect();
        let mut t = String::new();
        for row in numbered.chunks(4) {
            t.push_str(&row.join("   "));
            t.push('\n');
        }
        t
    };
    let vault_words = recovery::words_from_key(&k3.to_hex())?;
    let recovery_words = k1.words()?;
    let mut t = String::new();
    t.push_str("VARSTO RECOVERY KIT\n");
    t.push_str(&format!("Vault {}\n\n", hex::encode(vault)));
    t.push_str(&format!(
        "VAULT WORDS (vault key, epoch {vault_epoch}): device names, folder names and the storage ledger, no content.\n"
    ));
    t.push_str(&rows(&vault_words));
    t.push_str(&format!(
        "Key check: {}\n\n",
        recovery::key_check(&k3.to_hex())?
    ));
    t.push_str(
        "RECOVERY WORDS: with the vault words, every folder's content. Alone they open nothing.\n",
    );
    t.push_str(&rows(&recovery_words));
    t.push_str(&format!("Key check: {}\n\n", k1.key_check()?));
    t.push_str(
        "Keep both on paper or metal, in more than one place, never in a photo or a cloud note.\n",
    );
    t.push_str("Removing a device changes the vault words (print a new kit then); the recovery words stay.\n");
    Ok(t)
}
