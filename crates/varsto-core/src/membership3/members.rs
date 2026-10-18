// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Member devices of shared folders (format 3 design, sections 6 and 9):
//! devices of other people's vaults that take part in one folder. They
//! have no device record in this vault's registry (they cannot read the
//! registry key); what this vault knows of one is its K6 and K8 public
//! keys and its name, from the request code an owner accepted, and its
//! role, from the folder records.
//!
//! The record trust ([`super::Trust`]) takes them as section 9's member
//! rows: an editor writes manifests, block maps and trash records of its
//! folder and its folder-scoped batches; a viewer only its folder-scoped
//! batches. Nothing of the vault (registry kinds, epochs, revocations,
//! snapshots, policy, placement, settings) counts from a member.

use crate::crypto::VerifyingKey;
use crate::record::Id16;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What this vault knows of one member device in one folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDevice {
    pub device: Id16,
    pub folder: Id16,
    pub name: String,
    /// K6 public key (Ed25519 + ML-DSA-65); its BLAKE3 prefix is `device`.
    pub k6: Vec<u8>,
    /// K8 public key (X25519 + ML-KEM-768): grants are sealed to it.
    pub k8: Vec<u8>,
}

impl MemberDevice {
    /// Whether the keys belong to the id (BLAKE3(K6)[..16]).
    pub fn id_matches(&self) -> bool {
        crate::crypto::hash(&self.k6)[..16] == self.device
    }

    pub fn signing_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.k6).ok()
    }
}

/// Member devices by (folder, device).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRegistry {
    pub members: BTreeMap<(Id16, Id16), MemberDevice>,
}

impl MemberRegistry {
    /// Add a member whose keys give its id; other entries are refused.
    pub fn insert(&mut self, m: MemberDevice) -> bool {
        if !m.id_matches() || m.signing_key().is_none() {
            return false;
        }
        self.members.insert((m.folder, m.device), m);
        true
    }

    pub fn get(&self, folder: &Id16, device: &Id16) -> Option<&MemberDevice> {
        self.members.get(&(*folder, *device))
    }

    /// The K6 public key of `device` as a member of `folder`.
    pub fn signing_key(&self, folder: &Id16, device: &Id16) -> Option<VerifyingKey> {
        self.get(folder, device)?.signing_key()
    }

    /// Whether `device` is a member of any folder here.
    pub fn is_member(&self, device: &Id16) -> bool {
        self.members.keys().any(|(_, d)| d == device)
    }

    /// The folders `device` is a member of.
    pub fn folders_of(&self, device: &Id16) -> Vec<Id16> {
        self.members
            .keys()
            .filter(|(_, d)| d == device)
            .map(|(f, _)| *f)
            .collect()
    }
}
