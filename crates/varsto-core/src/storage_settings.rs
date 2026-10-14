// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Vault-wide settings of one storage: its quota and whether it is being
//! drained (`docs/spec/alpha-0-format.md`, section "Storage quotas and
//! draining").
//!
//! Prices are a device's own estimate and stay in its `config.json`. A
//! quota or a drain is different: a quota only one device knows would be
//! broken by the others' uploads, and a storage being emptied must stop
//! receiving blocks from every device. These settings are therefore
//! published like a folder's placement: one sealed record per change,
//! `vault/storage-settings/<storage key>/<device>/<updated_utc>.enc`, on
//! every storage that holds records, and the newest record of a storage
//! wins on every device.
//!
//! Storage names are local to a device, so a record names its storage by a
//! key every device computes the same way: the storage identity
//! (`vault/storage-id.json`, section 20) when it can be read, the disk
//! pool's identity for a pool, and otherwise a keyed hash of the name.

use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, Id, VaultId};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Where the records are kept.
pub const PREFIX: &str = "vault/storage-settings/";

/// Writes keep this share of a quota free (1 %): usage is counted from the
/// ledger and the estimate of records, not measured on every write.
pub const QUOTA_MARGIN_PERCENT: u64 = 1;
/// A storage is reported as nearly full from this share of its quota on.
pub const QUOTA_WARN_PERCENT: u64 = 90;

/// What a drain is doing now.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DrainPhase {
    /// Blocks are being moved away; the storage takes no new blocks.
    #[default]
    Draining,
    /// Every block and record is elsewhere: the storage holds nothing
    /// Varsto needs, takes no writes and is not read for records.
    Drained,
}

/// A drain, as every device sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DrainSetting {
    pub phase: DrainPhase,
    pub started_utc: i64,
    /// The device that moves the blocks (the one that started the drain,
    /// or the last one that took it over).
    pub driver: DeviceId,
    /// Remove the storage from the driver's configuration once drained.
    #[serde(default)]
    pub remove_when_empty: bool,
    /// Most bytes copied to other storages per day (UTC); none: no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_bytes_per_day: Option<u64>,
    /// The user confirmed reading from this cold storage (retrieval fees,
    /// restore delays).
    #[serde(default)]
    pub confirm_cold_read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drained_utc: Option<i64>,
}

/// The shared settings of a storage.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageSettings {
    /// Most bytes Varsto keeps on the storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    /// Most objects Varsto keeps on the storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_objects: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<DrainSetting>,
}

impl StorageSettings {
    pub fn is_empty(&self) -> bool {
        self.quota_bytes.is_none() && self.quota_objects.is_none() && self.drain.is_none()
    }
    /// No new blocks go to the storage (draining or drained).
    pub fn closed(&self) -> bool {
        self.drain.is_some()
    }
    pub fn drained(&self) -> bool {
        self.drain
            .as_ref()
            .is_some_and(|d| d.phase == DrainPhase::Drained)
    }
}

/// This device's copy of a storage's settings and the time of the record
/// they came from (kept in `config.json`, by local storage name).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SettingsEntry {
    #[serde(flatten)]
    pub settings: StorageSettings,
    pub updated_utc: i64,
}

/// One published change of a storage's settings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageSettingsRecord {
    /// The storage key (see the module documentation).
    pub storage: Id,
    /// The writer's name for the storage (shown only).
    pub name: String,
    pub device: DeviceId,
    pub updated_utc: i64,
    pub settings: StorageSettings,
}

impl StorageSettingsRecord {
    pub fn storage_key(&self) -> String {
        format!(
            "{PREFIX}{}/{}/{:020}.enc",
            self.storage, self.device, self.updated_utc
        )
    }

    /// Seal and sign: a signed record of kind `storage-settings`, scope
    /// the storage, sequence number the time in its name.
    pub fn seal_signed(
        &self,
        vault: &VaultId,
        key_id: &str,
        key: &SecretKey,
        signer: &crypto::SigningKey,
    ) -> Result<Vec<u8>> {
        let header = crate::record::Header {
            kind: crate::record::RecordKind::StorageSettings,
            vault,
            scope: self.storage.as_str(),
            device: &self.device,
            seq: self.updated_utc.max(0) as u64,
            key_id,
        };
        Ok(header
            .seal(key, &serde_json::to_vec(self)?, signer)?
            .to_bytes())
    }

    /// Open a signed record found under `named_device`'s part of the key.
    pub fn open_any(
        blob: &[u8],
        vault: &VaultId,
        storage: &Id,
        named_device: &DeviceId,
        key_for: &dyn Fn(&str) -> Option<SecretKey>,
        verify: &dyn Fn(&DeviceId) -> Option<crypto::VerifyingKey>,
    ) -> Result<Self> {
        let env = crate::record::SignedRecord::parse(blob)?;
        let plain = env.accept(
            &crate::record::Expect::new(crate::record::RecordKind::StorageSettings, vault)
                .scope(storage.as_str())
                .device(named_device),
            verify,
            key_for,
        )?;
        let rec: Self = serde_json::from_slice(&plain)?;
        if &rec.storage != storage
            || rec.device != env.device
            || rec.updated_utc.max(0) as u64 != env.seq
        {
            bail!("storage settings record does not match its envelope");
        }
        Ok(rec)
    }
}

/// A size as people write it: "1TB", "500 GB", "1.5TiB", "2000000" (bytes).
/// kB, MB, GB, TB and PB are decimal; KiB, MiB, GiB, TiB and PiB binary.
pub fn parse_size(text: &str) -> Result<u64> {
    let t = text.trim().replace(' ', "");
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("not a size: {text} (for example 500GB or 1TB)"))?;
    let mult: f64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "t" | "tb" => 1e12,
        "p" | "pb" => 1e15,
        "kib" => 1024.0,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        "pib" => 1024f64.powi(5),
        _ => {
            bail!("unknown size unit {unit:?} in {text} (use kB, MB, GB, TB, KiB, MiB, GiB or TiB)")
        }
    };
    let bytes = value * mult;
    if !bytes.is_finite() || bytes < 1.0 || bytes > u64::MAX as f64 {
        bail!("a size must be at least one byte: {text}");
    }
    Ok(bytes.round() as u64)
}

/// The share of a quota writes may use (the quota less its margin).
pub fn usable(quota: u64) -> u64 {
    quota - quota / 100 * QUOTA_MARGIN_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_in_decimal_and_binary_units() {
        assert_eq!(parse_size("1TB").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_size("500 GB").unwrap(), 500_000_000_000);
        assert_eq!(parse_size("1.5kB").unwrap(), 1500);
        assert_eq!(parse_size("2GiB").unwrap(), 2 << 30);
        assert_eq!(parse_size("1234").unwrap(), 1234);
        assert!(parse_size("0").is_err());
        assert!(parse_size("ten GB").is_err());
        assert!(parse_size("5 parsecs").is_err());
    }

    #[test]
    fn records_open_only_for_their_storage_and_writer() {
        let vault = VaultId::random();
        let key = SecretKey::random();
        let signer = crypto::SigningKey::generate();
        let dev = crate::ledger::device_id_for(&signer.public());
        let storage = Id::random();
        let rec = StorageSettingsRecord {
            storage: storage.clone(),
            name: "box".into(),
            device: dev.clone(),
            updated_utc: 7,
            settings: StorageSettings {
                quota_bytes: Some(10),
                ..Default::default()
            },
        };
        let id = crate::record::folder_record_key_id(0);
        let blob = rec.seal_signed(&vault, &id, &key, &signer).unwrap();
        let k = key.clone();
        let key_for = move |i: &str| (i == "folder-record@0").then(|| k.clone());
        let pk = signer.public();
        let known = move |d: &DeviceId| {
            (d == &crate::ledger::device_id_for(&pk)).then(|| pk.clone())
        };
        let opened =
            StorageSettingsRecord::open_any(&blob, &vault, &storage, &dev, &key_for, &known)
                .unwrap();
        assert_eq!(opened, rec);
        // Another storage, another writer named, an unknown writer.
        assert!(StorageSettingsRecord::open_any(
            &blob,
            &vault,
            &Id::random(),
            &dev,
            &key_for,
            &known
        )
        .is_err());
        assert!(StorageSettingsRecord::open_any(
            &blob,
            &vault,
            &storage,
            &DeviceId::random(),
            &key_for,
            &known
        )
        .is_err());
        let none = |_: &DeviceId| None;
        assert!(
            StorageSettingsRecord::open_any(&blob, &vault, &storage, &dev, &key_for, &none)
                .is_err()
        );
    }

    #[test]
    fn the_margin_is_one_percent() {
        assert_eq!(usable(1000), 990);
        assert_eq!(usable(50), 50);
    }
}
