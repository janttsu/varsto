// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `record::RecordTrust` from the registries: step (2) (signer keys from
//! accepted device records) and step (3) (section 9's matrix with the
//! writer's role in the folder at the epoch its key_id names).
//!
//! Folder records, folder epochs, grants and escrow pass step (3) for any
//! device of the vault: whether their writer was an owner is decided on
//! the body (the folder record replay, the epoch the grant names), where
//! the epoch and the entries' stamps are known.

use super::devices::DeviceRegistry;
use super::folders::FolderRegistry;
use super::{Role, VAULT_SCOPE};
use crate::crypto::VerifyingKey;
use crate::record::{section9_allows, Id16, KeyId, Kind, RecordTrust, WriterClass};
use std::collections::BTreeSet;

pub struct Trust<'a> {
    pub devices: &'a DeviceRegistry,
    /// Devices removed from the vault (accepted revocations).
    pub revoked: &'a BTreeSet<Id16>,
    pub folders: Option<&'a FolderRegistry>,
}

impl Trust<'_> {
    /// Kinds whose writer stays trusted after its removal for what it
    /// wrote before (the epoch and stamp rules cut it off).
    fn survives_removal(kind: Kind, scope: &Id16) -> bool {
        *scope != VAULT_SCOPE
            && matches!(
                kind,
                Kind::Folder | Kind::ShareEpoch | Kind::Grant | Kind::Escrow
            )
    }

    /// The section 9 row of `device` in `folder` at `epoch`.
    pub fn class(&self, device: &Id16, folder: &Id16, epoch: u32) -> WriterClass {
        match self.folders.and_then(|f| f.role(device, folder, epoch)) {
            Some(Role::Owner) => WriterClass::FullOwner,
            Some(Role::Editor) => WriterClass::FullEditor,
            Some(Role::Viewer) => WriterClass::FullViewer,
            None => WriterClass::FullNoGrant,
        }
    }
}

impl RecordTrust for Trust<'_> {
    fn signer_key(&self, device: &Id16, kind: Kind, scope: &Id16) -> Option<VerifyingKey> {
        if self.revoked.contains(device) && !Self::survives_removal(kind, scope) {
            return None;
        }
        self.devices.signing_key(device)
    }

    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool {
        if self.devices.get(device).is_none() {
            return false;
        }
        let revoked = self.revoked.contains(device);
        match kind {
            Kind::Device => !revoked,
            Kind::Folder | Kind::ShareEpoch | Kind::Escrow => true,
            Kind::Grant => *scope != VAULT_SCOPE || !revoked,
            Kind::Request | Kind::Placement => !revoked,
            Kind::Manifest
            | Kind::BlockMap
            | Kind::Trash
            | Kind::Access
            | Kind::Notes
            | Kind::Thumbs => {
                let KeyId::Meta { epoch, .. } = key_id else {
                    return false;
                };
                !revoked && section9_allows(self.class(device, scope, *epoch), kind)
            }
            Kind::Batch => match key_id {
                KeyId::ShareLedger { folder, epoch } => {
                    !revoked && section9_allows(self.class(device, folder, *epoch), kind)
                }
                _ => !revoked,
            },
            _ => !revoked && section9_allows(WriterClass::FullVault, kind),
        }
    }
}
