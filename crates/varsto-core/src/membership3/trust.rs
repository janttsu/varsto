// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `record::RecordTrust` from the registries: step (2) (signer keys from
//! accepted device records, or for a member of a shared folder from what
//! this vault knows of it in that folder) and step (3) (section 9's matrix
//! with the writer's role in the folder at the epoch its key_id names).
//!
//! The row of a writer: a device of this vault's registry is a full device
//! (owner, editor, viewer or without a grant in a folder; vault-wide for
//! vault records); a device known only as a member of a folder
//! (`MemberRegistry`) is a member editor or viewer of that folder and
//! nothing anywhere else.
//!
//! Folder records, folder epochs, grants and escrow pass step (3) for any
//! device of the vault: whether their writer was an owner is decided on
//! the body (the folder record replay, the epoch the grant names), where
//! the epoch and the entries' stamps are known.

use super::devices::DeviceRegistry;
use super::folders::FolderRegistry;
use super::members::MemberRegistry;
use super::{Role, VAULT_SCOPE};
use crate::crypto::VerifyingKey;
use crate::record::{section9_allows, Id16, KeyId, Kind, RecordTrust, WriterClass};
use std::collections::BTreeSet;

pub struct Trust<'a> {
    pub devices: &'a DeviceRegistry,
    /// Devices removed from the vault (accepted revocations).
    pub revoked: &'a BTreeSet<Id16>,
    pub folders: Option<&'a FolderRegistry>,
    /// Member devices of shared folders (other people's devices).
    pub members: Option<&'a MemberRegistry>,
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
            || Self::announced(kind)
    }

    /// Kinds a batch announces: a removed device's records of them count
    /// up to its cut-off (their announcements in its batches after it do
    /// not count).
    fn announced(kind: Kind) -> bool {
        matches!(
            kind,
            Kind::Manifest | Kind::BlockMap | Kind::Trash | Kind::Snapshot
        )
    }

    /// The role a record of `device` is judged with (`writer_role`).
    fn role(&self, device: &Id16, folder: &Id16, epoch: u32) -> Option<Role> {
        self.folders
            .and_then(|f| f.writer_role(device, folder, epoch))
    }

    /// The section 9 row of `device` in `folder` at `epoch`.
    pub fn class(&self, device: &Id16, folder: &Id16, epoch: u32) -> WriterClass {
        if self.devices.get(device).is_none() {
            return self.member_class(device, folder, epoch);
        }
        match self.role(device, folder, epoch) {
            Some(Role::Owner) => WriterClass::FullOwner,
            Some(Role::Editor) => WriterClass::FullEditor,
            Some(Role::Viewer) => WriterClass::FullViewer,
            None => WriterClass::FullNoGrant,
        }
    }

    /// The member rows: a device known as a member of `folder` with the
    /// editor role writes as a member editor, with the viewer role as a
    /// member viewer; owners are full devices of the vault, so a member
    /// listed as owner counts as an editor. Anyone else is untrusted.
    fn member_class(&self, device: &Id16, folder: &Id16, epoch: u32) -> WriterClass {
        if self.members.and_then(|m| m.get(folder, device)).is_none() {
            return WriterClass::Untrusted;
        }
        match self.role(device, folder, epoch) {
            Some(Role::Owner | Role::Editor) => WriterClass::MemberEditor,
            Some(Role::Viewer) => WriterClass::MemberViewer,
            None => WriterClass::Untrusted,
        }
    }

    /// The folder a member's record belongs to: its scope for folder
    /// kinds, the folder of a `share-ledger:` key for batches.
    fn member_folder(kind: Kind, scope: &Id16, key_id: Option<&KeyId>) -> Option<Id16> {
        match (kind, key_id) {
            (Kind::Batch, Some(KeyId::ShareLedger { folder, .. })) => Some(*folder),
            (Kind::Batch, None) if *scope != VAULT_SCOPE => Some(*scope),
            (Kind::Manifest | Kind::BlockMap | Kind::Trash, _) if *scope != VAULT_SCOPE => {
                Some(*scope)
            }
            _ => None,
        }
    }
}

impl RecordTrust for Trust<'_> {
    fn signer_key(&self, device: &Id16, kind: Kind, scope: &Id16) -> Option<VerifyingKey> {
        if self.revoked.contains(device) && !Self::survives_removal(kind, scope) {
            return None;
        }
        if let Some(k) = self.devices.signing_key(device) {
            return Some(k);
        }
        let folder = Self::member_folder(kind, scope, None)?;
        self.members?.signing_key(&folder, device)
    }

    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool {
        if self.devices.get(device).is_none() {
            // A member device: its folder's rows only, under that folder's keys.
            let Some(folder) = Self::member_folder(kind, scope, Some(key_id)) else {
                return false;
            };
            let epoch = match key_id {
                KeyId::Meta { folder: f, epoch } | KeyId::ShareLedger { folder: f, epoch }
                    if *f == folder =>
                {
                    *epoch
                }
                _ => return false,
            };
            if self.revoked.contains(device) {
                return false;
            }
            return section9_allows(self.member_class(device, &folder, epoch), kind);
        }
        let revoked = self.revoked.contains(device);
        match kind {
            Kind::Device => !revoked,
            Kind::Folder | Kind::ShareEpoch | Kind::Escrow => true,
            Kind::Grant => *scope != VAULT_SCOPE || !revoked,
            Kind::Request | Kind::Placement => !revoked,
            // A Strongroom's key wraps are its owners' to write.
            Kind::Strongroom => {
                !revoked
                    && self
                        .folders
                        .and_then(|f| f.get(scope))
                        .and_then(|s| s.role(device))
                        == Some(Role::Owner)
            }
            Kind::Manifest
            | Kind::BlockMap
            | Kind::Trash
            | Kind::Access
            | Kind::Notes
            | Kind::Thumbs => {
                let KeyId::Meta { epoch, .. } = key_id else {
                    return false;
                };
                (!revoked || Self::announced(kind))
                    && section9_allows(self.class(device, scope, *epoch), kind)
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
