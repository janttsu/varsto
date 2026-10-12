// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backup snapshots (`docs/spec/alpha-0-format.md` section 31): the files of
//! a backed-up directory at one moment, encrypted under the backup's
//! metadata key and written once to every storage that keeps metadata. A
//! snapshot is never changed: its ledger event (`Event::SnapshotTaken`)
//! names the hash of the stored object, and a restore refuses any copy that
//! does not match it.

use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, FolderId, VaultId};
use crate::manifest::FileState;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub format_version: u16,
    pub backup: FolderId,
    pub device: DeviceId,
    pub seq: u64,
    pub taken_utc: i64,
    /// Fixed when the snapshot is taken: a later change of the backup's
    /// retention applies to later snapshots only.
    pub expires_utc: i64,
    pub retention_days: u32,
    /// The files as they were, live ones only.
    pub files: BTreeMap<String, FileState>,
    /// Files left out because they could not be read or stored completely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
}

pub const PREFIX: &str = "snapshots/";

impl Snapshot {
    pub fn storage_key(backup: &FolderId, device: &DeviceId, seq: u64) -> String {
        format!("{PREFIX}{backup}/{device}/{seq:016}.enc")
    }

    pub fn backup_prefix(backup: &FolderId) -> String {
        format!("{PREFIX}{backup}/")
    }

    /// The device and sequence number a key under `backup_prefix` names.
    pub fn parse_key(backup: &FolderId, key: &str) -> Option<(DeviceId, u64)> {
        let rest = key.strip_prefix(&Self::backup_prefix(backup))?;
        let (dev, file) = rest.split_once('/')?;
        let digits = file.strip_suffix(".enc")?;
        if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((DeviceId::from_hex(dev).ok()?, digits.parse().ok()?))
    }

    fn aad(vault: &VaultId, backup: &FolderId, device: &DeviceId, seq: u64) -> Vec<u8> {
        crypto::aad(
            "snapshot",
            &[
                vault.as_str().as_bytes(),
                backup.as_str().as_bytes(),
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }

    pub fn seal(&self, vault: &VaultId, meta_key: &SecretKey) -> Result<Vec<u8>> {
        let plain = zstd::bulk::compress(&serde_json::to_vec(self)?, 3)?;
        crypto::encrypt(
            meta_key,
            &Self::aad(vault, &self.backup, &self.device, self.seq),
            &plain,
        )
    }

    /// Open with the first of the backup's metadata keys that fits (newest
    /// epoch first) and check the entries like a manifest's.
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        backup: &FolderId,
        device: &DeviceId,
        seq: u64,
        meta_keys: &[SecretKey],
    ) -> Result<Snapshot> {
        let aad = Self::aad(vault, backup, device, seq);
        let Some(packed) = meta_keys
            .iter()
            .find_map(|k| crypto::decrypt(k, &aad, blob).ok())
        else {
            bail!("snapshot {seq} does not open with this backup's keys");
        };
        let plain = zstd::bulk::decompress(&packed, 1 << 30)?;
        let s: Snapshot = serde_json::from_slice(&plain)?;
        if &s.backup != backup || &s.device != device || s.seq != seq {
            bail!("snapshot body does not match its name");
        }
        crate::manifest::validate_files(&s.files)?;
        if s.files.values().any(|f| f.deleted) {
            bail!("snapshot {seq} lists a deleted file");
        }
        Ok(s)
    }

    /// Plain bytes of the files.
    pub fn bytes(&self) -> u64 {
        self.files.values().map(|f| f.size).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trip_and_name() {
        let vault = VaultId::from_bytes(&[1; 16]);
        let backup = FolderId::from_bytes(&[2; 16]);
        let device = DeviceId::from_bytes(&[3; 16]);
        let key = SecretKey::random();
        let s = Snapshot {
            format_version: crate::FORMAT_VERSION,
            backup: backup.clone(),
            device: device.clone(),
            seq: 7,
            taken_utc: 100,
            expires_utc: 200,
            retention_days: 90,
            files: BTreeMap::new(),
            skipped: vec![],
        };
        let blob = s.seal(&vault, &key).unwrap();
        let back = Snapshot::open(
            &blob,
            &vault,
            &backup,
            &device,
            7,
            std::slice::from_ref(&key),
        )
        .unwrap();
        assert_eq!(back.expires_utc, 200);
        // Bound to its name: another sequence number does not open.
        assert!(Snapshot::open(&blob, &vault, &backup, &device, 8, &[key]).is_err());
        let k = Snapshot::storage_key(&backup, &device, 7);
        assert_eq!(Snapshot::parse_key(&backup, &k), Some((device, 7)));
        assert_eq!(Snapshot::parse_key(&backup, "snapshots/x/y.enc"), None);
    }
}
