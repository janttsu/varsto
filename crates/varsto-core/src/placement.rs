// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Per-folder placement: which storages a folder's blocks are written to.
//! By default a block goes to every storage of the device; a placement names
//! storages ("box", "glacier") or places ("home", "cloud", "offsite"), and
//! pushes then write only there. A placement belongs to the folder and is
//! published like its policy (`PlacementRecord`), so every device writes the
//! folder the same way; policies still count every copy the ledger records.
//!
//! Storage names are local to a device. A placement therefore also carries
//! the identity (`vault/storage-id.json`) of each storage it names, where the
//! device that set it could read one, and a device that calls the same
//! bucket by another name still matches it.

use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, FolderId, VaultId};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Placement {
    /// Storages by name, as the device that set the placement names them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storages: Vec<String>,
    /// Identity of each named storage, where known (name -> identity).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage_ids: BTreeMap<String, String>,
    /// Every storage whose place is one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<String>,
}

impl Placement {
    /// No restriction: every storage (the default).
    pub fn is_everywhere(&self) -> bool {
        self.storages.is_empty() && self.places.is_empty()
    }

    /// Does the storage `name` at `place` (with `identity`, if known) take
    /// the folder's blocks?
    pub fn includes(&self, name: &str, place: &str, identity: Option<&str>) -> bool {
        self.is_everywhere()
            || self.storages.iter().any(|s| s == name)
            || self.places.iter().any(|p| p == place)
            || identity.is_some_and(|id| self.storage_ids.values().any(|v| v == id))
    }

    /// Whether some named storage is not known by that name here, so the
    /// identities must be compared.
    pub fn needs_identities(&self, local_names: &[&str]) -> bool {
        !self.storage_ids.is_empty()
            && self
                .storages
                .iter()
                .any(|s| !local_names.contains(&s.as_str()))
    }

    pub fn describe(&self) -> String {
        if self.is_everywhere() {
            return "every storage".to_string();
        }
        let mut parts = Vec::new();
        if !self.storages.is_empty() {
            parts.push(format!(
                "storage{} {}",
                if self.storages.len() == 1 { "" } else { "s" },
                self.storages.join(", ")
            ));
        }
        if !self.places.is_empty() {
            parts.push(format!(
                "place{} {}",
                if self.places.len() == 1 { "" } else { "s" },
                self.places.join(", ")
            ));
        }
        parts.join(" and ")
    }

    /// Check the names: no empty or repeated entries.
    pub fn validate(&self) -> Result<()> {
        for list in [&self.storages, &self.places] {
            let mut seen = std::collections::BTreeSet::new();
            for s in list {
                if s.trim().is_empty() {
                    bail!("empty storage or place name in a placement");
                }
                if !seen.insert(s) {
                    bail!("{s} is named twice in the placement");
                }
            }
        }
        Ok(())
    }
}

/// A placement change for a folder, published append-only at
/// `vault/placement/<folder>/<device>/<updated_utc>.enc` under the folder
/// record key; every device adopts the newest one it can read. `None`
/// returns the folder to every storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementRecord {
    pub folder_id: FolderId,
    pub device: DeviceId,
    pub updated_utc: i64,
    pub placement: Option<Placement>,
}

impl PlacementRecord {
    pub const PREFIX: &'static str = "vault/placement/";

    pub fn storage_key(&self) -> String {
        format!(
            "{}{}/{}/{:020}.enc",
            Self::PREFIX,
            self.folder_id,
            self.device,
            self.updated_utc
        )
    }

    fn aad(vault: &VaultId, folder: &FolderId) -> Vec<u8> {
        crypto::aad(
            "placement-record",
            &[vault.as_str().as_bytes(), folder.as_str().as_bytes()],
        )
    }

    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.folder_id),
            &serde_json::to_vec(self)?,
        )
    }

    pub fn open(blob: &[u8], vault: &VaultId, folder: &FolderId, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, folder), blob)?;
        let rec: PlacementRecord = serde_json::from_slice(&plain)?;
        if &rec.folder_id != folder {
            bail!("placement record folder mismatch");
        }
        Ok(rec)
    }
}

/// Amounts by currency (never converted).
pub type Costs = BTreeMap<String, f64>;

/// What a placement looks like on this device: the rule and the storages
/// here that take the folder's blocks.
#[derive(Clone, Debug, Serialize, Default)]
pub struct PlacementInfo {
    pub folder: String,
    pub placement: Option<Placement>,
    pub description: String,
    /// Local storage names the folder's blocks are written to.
    pub targets: Vec<String>,
    pub updated_utc: i64,
    /// Why the rule does not apply as written here, if it does not.
    pub warnings: Vec<String>,
}

/// Move a folder's blocks (or those of its idle files) from one storage to
/// another (`Engine::move_data`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MoveRequest {
    pub folder: String,
    pub from: String,
    pub to: String,
    /// Only files not used for this many days (and blocks no other file uses).
    #[serde(default)]
    pub idle_days: Option<i64>,
    /// Plan only: report what would move and what it would cost.
    #[serde(default)]
    pub dry_run: bool,
    /// Reading from a cold storage is confirmed: the copy may be read from
    /// `from` when it is cold, and a cold `to` is read back to verify.
    #[serde(default)]
    pub confirm_cold_read: bool,
}

/// What a move did (or, with `dry_run`, would do).
#[derive(Clone, Debug, Serialize, Default)]
pub struct MoveReport {
    pub folder: String,
    pub from: String,
    pub to: String,
    pub dry_run: bool,
    /// Files whose blocks are moved.
    pub files: u64,
    /// Blocks that are on `from` and go (planned).
    pub blocks: u64,
    pub bytes: u64,
    /// Blocks written to `to` (the others were there already).
    pub blocks_copied: u64,
    pub bytes_copied: u64,
    /// Copies on `to` read back and hash-checked (or, on cold storage
    /// without a confirmed read, found by name).
    pub blocks_verified: u64,
    /// Blocks removed from `from` and recorded as dropped.
    pub blocks_dropped: u64,
    pub bytes_dropped: u64,
    /// Blocks an earlier, interrupted move had recorded as dropped and that
    /// were still on `from`: deleted now.
    pub leftovers_removed: u64,
    /// Blocks already moved by an earlier run.
    pub already_moved: u64,
    /// Blocks that stay on `from`, with the reason (a few examples).
    pub kept: Vec<(String, String)>,
    pub blocks_kept: u64,
    /// Monthly storage cost of the moved bytes on `from` (goes away) and of
    /// the bytes newly stored on `to` (comes in).
    pub monthly_cost_from: Costs,
    pub monthly_cost_to: Costs,
    /// `monthly_cost_from` minus `monthly_cost_to`, per currency.
    pub monthly_saving: Costs,
    /// Reading the blocks that are not on this device from `from` once.
    pub one_time_cost: Costs,
    /// Billed anyway because `from` has a minimum storage duration.
    pub early_deletion_cost: Costs,
    /// Prices that are not known (the cost figures leave them out).
    pub unpriced: Vec<String>,
    /// Storages that hold the moved blocks afterwards.
    pub remaining_on: Vec<String>,
    /// The fewest copies any moved block keeps (transferrers not counted).
    pub min_copies_after: u64,
    /// Cold storage: what reading back needs and costs.
    pub cold_notes: Vec<String>,
    /// The folder's placement was changed so that new blocks go to `to`.
    pub placement_changed: Option<String>,
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_by_name_place_or_identity() {
        let p = Placement {
            storages: vec!["box".into()],
            storage_ids: [("box".to_string(), "id-1".to_string())].into(),
            places: vec!["offsite".into()],
        };
        assert!(p.includes("box", "cloud", None));
        assert!(p.includes("vault-disk", "offsite", None));
        assert!(p.includes("primary", "cloud", Some("id-1")));
        assert!(!p.includes("primary", "cloud", Some("id-2")));
        assert!(Placement::default().includes("anything", "home", None));
        assert!(p.needs_identities(&["primary"]));
        assert!(!p.needs_identities(&["box"]));
        assert_eq!(p.describe(), "storage box and place offsite");
    }

    #[test]
    fn record_round_trip() {
        let key = SecretKey::random();
        let vault = VaultId::random();
        let rec = PlacementRecord {
            folder_id: FolderId::random(),
            device: DeviceId::from_bytes(&[1; 16]),
            updated_utc: 5,
            placement: Some(Placement {
                places: vec!["cloud".into()],
                ..Default::default()
            }),
        };
        let blob = rec.seal(&vault, &key).unwrap();
        let back = PlacementRecord::open(&blob, &vault, &rec.folder_id, &key).unwrap();
        assert_eq!(back.placement, rec.placement);
        assert!(PlacementRecord::open(&blob, &vault, &FolderId::random(), &key).is_err());
    }
}
