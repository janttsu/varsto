// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The keys of one device as `record::RecordKeys` (format 3 design,
//! section 1): K3 per vault epoch and what is derived from it, the folder
//! keys it holds through grants, its own K8, the K8 public keys of the
//! devices in the registry, and the escrow key while K1 is in memory.

use super::derive3;
use super::devices::DeviceRegistry;
use super::grants::GrantedKeys;
use crate::crypto::SecretKey;
use crate::kem::{DecapsKey, EncapsKey};
use crate::record::{Id16, KeyId, RecordKeys};
use anyhow::Result;
use std::collections::BTreeMap;

/// The vault key K3ₑ of every vault epoch this device holds.
#[derive(Clone, Default)]
pub struct VaultKeys {
    pub keys: BTreeMap<u32, SecretKey>,
}

crate::redacted_opaque!(VaultKeys);

impl VaultKeys {
    /// A vault at epoch 0.
    pub fn genesis(k3_0: SecretKey) -> VaultKeys {
        VaultKeys {
            keys: BTreeMap::from([(0, k3_0)]),
        }
    }

    pub fn get(&self, epoch: u32) -> Option<&SecretKey> {
        self.keys.get(&epoch)
    }

    /// The newest epoch and its key.
    pub fn newest(&self) -> Option<(u32, &SecretKey)> {
        self.keys.iter().next_back().map(|(e, k)| (*e, k))
    }

    pub fn newest_epoch(&self) -> u32 {
        self.newest().map_or(0, |(e, _)| e)
    }

    /// K3₀, which the escrow key binds (reached from a newer key through
    /// the chain of vault epoch records, `epochs::walk_vault_chain`).
    pub fn k3_0(&self) -> Option<&SecretKey> {
        self.get(0)
    }

    /// registry key = derive(K3ₑ, "device-registry").
    pub fn registry(&self, epoch: u32) -> Option<SecretKey> {
        Some(derive3(self.get(epoch)?, "device-registry", &[]))
    }

    /// ledger key = derive(K3ₑ, "ledger").
    pub fn ledger(&self, epoch: u32) -> Option<SecretKey> {
        Some(derive3(self.get(epoch)?, "ledger", &[]))
    }

    /// The key of the vault epoch record of `epoch` (`epoch@<e>`).
    pub fn epoch_record(&self, epoch: u32) -> Option<SecretKey> {
        Some(derive3(self.get(epoch)?, "epoch-record", &[]))
    }
}

/// `RecordKeys` of one device. Every part is optional, so the same type
/// serves a device that holds only K3, a fully approved device, and a
/// recovering one.
pub struct KeyRing<'a> {
    pub me: Id16,
    pub vault: &'a VaultKeys,
    /// This device's K8.
    pub kem: Option<&'a DecapsKey>,
    /// K8 public keys of other devices (grant writers need them).
    pub devices: Option<&'a DeviceRegistry>,
    /// Folder keys held through grants.
    pub folders: Option<&'a GrantedKeys>,
    /// The escrow key `derive(K2, "folder-escrow", vault, K3₀)`.
    pub recovery: Option<SecretKey>,
    /// Keys a writer uses before they are held (a new folder epoch's K10).
    pub extra: Vec<(KeyId, SecretKey)>,
    /// K8 public keys of member devices (other people's) of shared folders.
    pub members: Option<&'a super::members::MemberRegistry>,
}

impl<'a> KeyRing<'a> {
    pub fn vault_only(me: Id16, vault: &'a VaultKeys) -> KeyRing<'a> {
        KeyRing {
            me,
            vault,
            kem: None,
            devices: None,
            folders: None,
            recovery: None,
            extra: Vec::new(),
            members: None,
        }
    }
}

impl RecordKeys for KeyRing<'_> {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        if let Some((_, k)) = self.extra.iter().find(|(id, _)| id == key_id) {
            return Some(k.clone());
        }
        match key_id {
            KeyId::Registry(e) => self.vault.registry(*e),
            KeyId::Ledger(e) => self.vault.ledger(*e),
            KeyId::Epoch(e) => self.vault.epoch_record(*e),
            KeyId::Meta { .. } | KeyId::ShareLedger { .. } => self.folders?.symmetric(key_id),
            KeyId::Recovery => self.recovery.clone(),
            KeyId::Kem(_) | KeyId::Replica | KeyId::None => None,
        }
    }
    fn kem_public(&self, recipient: &Id16) -> Option<EncapsKey> {
        if let Some(k) = self.devices.and_then(|d| d.kem_key(recipient)) {
            return Some(k);
        }
        let m = self.members?;
        m.members
            .values()
            .find(|m| m.device == *recipient)
            .and_then(|m| EncapsKey::from_bytes(&m.k8).ok())
    }
    fn kem_decapsulate(&self, recipient: &Id16, ct: &[u8]) -> Option<Result<SecretKey>> {
        if *recipient != self.me {
            return None;
        }
        Some(self.kem?.decapsulate(ct))
    }
}
