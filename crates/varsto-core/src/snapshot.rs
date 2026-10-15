// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Backup snapshots (`docs/spec/alpha-0-format.md` section 31): the files of
//! a backed-up directory at one moment, encrypted under the backup's
//! metadata key and written once to every storage that keeps metadata. A
//! snapshot is never changed: its ledger event (`Event::SnapshotTaken`)
//! names the hash of the stored object, and a restore refuses any copy that
//! does not match it.

use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, FolderId, VaultId};
use crate::manifest::FileState;
use crate::record::{self, RecordKind, SignedRecord};
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

    /// Seal under the backup's metadata key of `epoch` and sign: a signed
    /// record of kind `snapshot`, scope the backup. Its `body_hash` is the
    /// `snapshot_hash` its ledger event announces.
    pub fn seal(
        &self,
        vault: &VaultId,
        epoch: u32,
        meta_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<SignedRecord> {
        let plain = zstd::bulk::compress(&serde_json::to_vec(self)?, 3)?;
        let key_id = record::meta_key_id(epoch);
        record::Header {
            kind: RecordKind::Snapshot,
            vault,
            scope: self.backup.as_str(),
            device: &self.device,
            seq: self.seq,
            key_id: &key_id,
        }
        .seal(meta_key, &plain, signer)
    }

    /// Open a stored snapshot of `device`: the signed record that names
    /// exactly this backup, device and number, signed by `writer`, opened
    /// under the metadata key its key id names, entries checked like a
    /// manifest's. Whether the ledger announced it (`body_hash`) is the
    /// caller's check.
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        backup: &FolderId,
        device: &DeviceId,
        seq: u64,
        writer: &VerifyingKey,
        meta_for: &dyn Fn(u32) -> Option<SecretKey>,
    ) -> Result<(Snapshot, SignedRecord)> {
        let env = SignedRecord::parse(blob)?;
        env.expect(
            &record::Expect::new(RecordKind::Snapshot, vault)
                .scope(backup.as_str())
                .device(device)
                .seq(seq),
        )?;
        env.verify(writer)?;
        let epoch = record::parse_meta_key_id(&env.key_id)
            .ok_or_else(|| anyhow::anyhow!("snapshot names no metadata key"))?;
        let Some(key) = meta_for(epoch) else {
            bail!("snapshot {seq} does not open with this backup's keys");
        };
        let packed = env.open(&key)?;
        let plain = zstd::bulk::decompress(&packed, 1 << 30)?;
        let s: Snapshot = serde_json::from_slice(&plain)?;
        if &s.backup != backup || &s.device != device || s.seq != seq {
            bail!("snapshot body does not match its name");
        }
        crate::manifest::validate_files(&s.files)?;
        if s.files.values().any(|f| f.deleted) {
            bail!("snapshot {seq} lists a deleted file");
        }
        Ok((s, env))
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
        let signer = SigningKey::generate();
        let device = crate::ledger::device_id_for(&signer.public());
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
        let blob = s.seal(&vault, 0, &key, &signer).unwrap().to_bytes();
        let k2 = key.clone();
        let meta_for = move |e: u32| (e == 0).then(|| k2.clone());
        let (back, _) = Snapshot::open(
            &blob,
            &vault,
            &backup,
            &device,
            7,
            &signer.public(),
            &meta_for,
        )
        .unwrap();
        assert_eq!(back.expires_utc, 200);
        // Bound to its name and its writer: another sequence number or
        // another signer does not open.
        assert!(Snapshot::open(
            &blob,
            &vault,
            &backup,
            &device,
            8,
            &signer.public(),
            &meta_for
        )
        .is_err());
        assert!(Snapshot::open(
            &blob,
            &vault,
            &backup,
            &device,
            7,
            &SigningKey::generate().public(),
            &meta_for
        )
        .is_err());
        let k = Snapshot::storage_key(&backup, &device, 7);
        assert_eq!(Snapshot::parse_key(&backup, &k), Some((device, 7)));
        assert_eq!(Snapshot::parse_key(&backup, "snapshots/x/y.enc"), None);
    }
}
