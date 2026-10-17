// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `grant` records (format 3 design, section 6): a folder key epoch sealed
//! to one device's K8 (hybrid X25519 + ML-KEM-768, the `kem:` body of the
//! record envelope), at `vault/grants/<folder>/<epoch 10>/<recipient>/
//! <issuer>/`. Vault grants (scope zero, `vault/grants/vault/...`) carry a
//! vault key K3ₑ instead (section 21's grants as signed records).
//!
//! Whether a grant counts (its issuer is an owner of the folder at that
//! epoch) is decided by `Membership`, which holds the folder records and
//! folder epochs; this module has the bodies and the keys they give.

use super::{derive3, store, Role, VAULT_SCOPE};
use crate::crypto::SecretKey;
use crate::record::{
    Id16, KeyId, Kind, Record, RecordBody, RecordKeys, RecordMeta, RecordTrust, RecordsRefused,
    StreamRef,
};
use crate::storage::Storage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// Most older epochs one grant carries.
pub const MAX_OLDER: usize = 65_536;

/// The body of a folder grant: K9ₑ, K11 and every older K9 the recipient
/// should read, and the role it was granted with.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub folder: Id16,
    pub epoch: u32,
    pub recipient: Id16,
    pub issuer: Id16,
    pub role: Role,
    pub k9: [u8; 32],
    pub k11: [u8; 32],
    pub older: Vec<(u32, [u8; 32])>,
}

crate::redacted_debug!(GrantRecord { folder, epoch, recipient, issuer, role ; k9, k11, older });

impl Drop for GrantRecord {
    fn drop(&mut self) {
        self.k9.zeroize();
        self.k11.zeroize();
        for (_, k) in &mut self.older {
            k.zeroize();
        }
    }
}

impl RecordBody for GrantRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if meta.scope == VAULT_SCOPE || self.folder != meta.scope {
            return Err("folder differs from the record's scope".into());
        }
        if meta.epoch != Some(self.epoch) {
            return Err("epoch differs from the record's name".into());
        }
        if meta.recipient != Some(self.recipient) || meta.key_id != KeyId::Kem(self.recipient) {
            return Err("recipient differs from the record's name".into());
        }
        if self.issuer != meta.device {
            return Err("issuer is not the writer".into());
        }
        if self.older.len() > MAX_OLDER {
            return Err("too many older epochs".into());
        }
        let mut last = None;
        for (e, _) in &self.older {
            if *e >= self.epoch || last.is_some_and(|l| l >= *e) {
                return Err("older epochs must be below the epoch, ascending".into());
            }
            last = Some(*e);
        }
        Ok(())
    }
}

impl GrantRecord {
    pub fn stream(&self) -> StreamRef {
        StreamRef::grant(self.folder, self.epoch, self.recipient, self.issuer)
    }
}

/// The body of a vault grant: K3ₑ for one device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrantRecord {
    pub epoch: u32,
    pub recipient: Id16,
    pub issuer: Id16,
    pub k3: [u8; 32],
}

crate::redacted_debug!(VaultGrantRecord { epoch, recipient, issuer ; k3 });

impl Drop for VaultGrantRecord {
    fn drop(&mut self) {
        self.k3.zeroize();
    }
}

impl RecordBody for VaultGrantRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if meta.scope != VAULT_SCOPE {
            return Err("a vault grant is vault-wide".into());
        }
        if meta.epoch != Some(self.epoch) || self.epoch == 0 {
            return Err("epoch differs from the record's name".into());
        }
        if meta.recipient != Some(self.recipient) || meta.key_id != KeyId::Kem(self.recipient) {
            return Err("recipient differs from the record's name".into());
        }
        if self.issuer != meta.device {
            return Err("issuer is not the writer".into());
        }
        Ok(())
    }
}

/// The keys of one folder that a device holds.
#[derive(Clone)]
pub struct FolderKeys {
    pub folder: Id16,
    /// K9ₑ by folder epoch.
    pub epochs: BTreeMap<u32, SecretKey>,
    /// K11 = derive(K9₀, "dedup-hash", folder).
    pub k11: SecretKey,
}

crate::redacted_debug!(FolderKeys { folder ; epochs, k11 });

impl FolderKeys {
    /// The keys of a new folder: K9₀ and the K11 it gives.
    pub fn new_folder(folder: Id16, k9_0: SecretKey) -> FolderKeys {
        let k11 = k11_of(&folder, &k9_0);
        FolderKeys {
            folder,
            epochs: BTreeMap::from([(0, k9_0)]),
            k11,
        }
    }

    pub fn newest(&self) -> Option<(u32, &SecretKey)> {
        self.epochs.iter().next_back().map(|(e, k)| (*e, k))
    }

    pub fn holds(&self, epoch: u32) -> bool {
        self.epochs.contains_key(&epoch)
    }

    /// K10ₑ = derive(K9ₑ, "folder-metadata", folder).
    pub fn k10(&self, epoch: u32) -> Option<SecretKey> {
        Some(k10_of(&self.folder, self.epochs.get(&epoch)?))
    }

    /// share-ledger key = derive(K9ₑ, "share-ledger", folder).
    pub fn share_ledger(&self, epoch: u32) -> Option<SecretKey> {
        Some(derive3(
            self.epochs.get(&epoch)?,
            "share-ledger",
            &[&self.folder],
        ))
    }

    /// Add the keys another source gives (a grant, an escrow). K11 must be
    /// the same: a different one is a different folder's keys.
    pub fn merge(&mut self, other: &FolderKeys) -> bool {
        if other.folder != self.folder || other.k11.0 != self.k11.0 {
            return false;
        }
        for (e, k) in &other.epochs {
            self.epochs.entry(*e).or_insert_with(|| k.clone());
        }
        true
    }
}

pub(crate) fn k10_of(folder: &Id16, k9: &SecretKey) -> SecretKey {
    derive3(k9, "folder-metadata", &[folder])
}

pub(crate) fn k11_of(folder: &Id16, k9_0: &SecretKey) -> SecretKey {
    derive3(k9_0, "dedup-hash", &[folder])
}

/// The folder keys a device holds: from grants to itself (and, after a
/// recovery, from escrow). Feeds `record::RecordKeys` with `meta:` and
/// `share-ledger:` keys.
#[derive(Clone, Debug, Default)]
pub struct GrantedKeys {
    pub folders: BTreeMap<Id16, FolderKeys>,
}

impl GrantedKeys {
    pub fn get(&self, folder: &Id16) -> Option<&FolderKeys> {
        self.folders.get(folder)
    }

    pub fn holds(&self, folder: &Id16, epoch: u32) -> bool {
        self.folders.get(folder).is_some_and(|k| k.holds(epoch))
    }

    /// Add keys; false when they conflict with keys already held.
    pub fn add(&mut self, keys: FolderKeys) -> bool {
        match self.folders.get_mut(&keys.folder) {
            Some(have) => have.merge(&keys),
            None => {
                self.folders.insert(keys.folder, keys);
                true
            }
        }
    }
}

impl RecordKeys for GrantedKeys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        match key_id {
            KeyId::Meta { folder, epoch } => self.folders.get(folder)?.k10(*epoch),
            KeyId::ShareLedger { folder, epoch } => self.folders.get(folder)?.share_ledger(*epoch),
            _ => None,
        }
    }
}

/// Every folder grant to `me` on the storages that opens and passes the
/// record rule (not yet the owner check).
pub(crate) fn read_folder_grants(
    storages: &[&dyn Storage],
    vault: Id16,
    me: &Id16,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    counter: &mut RecordsRefused,
) -> Result<Vec<Record<GrantRecord>>> {
    store::read_where(
        storages,
        vault,
        Kind::Grant,
        "vault/grants/",
        &|s| s.recipient == Some(*me) && s.scope != VAULT_SCOPE,
        keys,
        trust,
        counter,
    )
}

/// Every vault grant to `me`.
pub(crate) fn read_vault_grants(
    storages: &[&dyn Storage],
    vault: Id16,
    me: &Id16,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    counter: &mut RecordsRefused,
) -> Result<Vec<Record<VaultGrantRecord>>> {
    store::read_where(
        storages,
        vault,
        Kind::Grant,
        "vault/grants/vault/",
        &|s| s.recipient == Some(*me) && s.scope == VAULT_SCOPE,
        keys,
        trust,
        counter,
    )
}
