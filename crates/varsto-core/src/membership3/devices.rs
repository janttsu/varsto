// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `device` records (format 3 design, section 5): a device's name, its K6
//! signing key and its K8 KEM key, both public. The record is signed by the
//! K6 it carries, and the device id is the first 16 bytes of BLAKE3 of that
//! key, so a device record cannot be written for someone else's id.
//!
//! Format 2 makes device ids at random (`ids::Id::random`); format 3 derives
//! them from K6 here, and WP12 switches enrolment over.

use super::{store, Stamp, MAX_NAME, VAULT_SCOPE};
use crate::crypto::{self, VerifyingKey};
use crate::kem::EncapsKey;
use crate::record::{
    Id16, KeyId, Kind, Record, RecordBody, RecordKeys, RecordMeta, RecordTrust, RecordsRefused,
};
use crate::storage::Storage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The device id of a K6 public key (its encoded bytes): BLAKE3[..16].
pub fn device_id(k6_public: &VerifyingKey) -> Id16 {
    device_id_of_bytes(&k6_public.to_bytes())
}

fn device_id_of_bytes(raw: &[u8]) -> Id16 {
    let mut id = [0u8; 16];
    id.copy_from_slice(&crypto::hash(raw)[..16]);
    id
}

/// The body of a `device` record (`vault/devices/<device>/`, key_id
/// `registry@<e>`, newest seq wins).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device: Id16,
    pub name: String,
    /// K6 public key (Ed25519 + ML-DSA-65, `VerifyingKey::to_bytes`).
    pub sign_pub: Vec<u8>,
    /// K8 public key (X25519 + ML-KEM-768, `EncapsKey::to_bytes`).
    pub kem_pub: Vec<u8>,
    pub stamp: Stamp,
    /// The system and version the device runs (shown in the device list;
    /// an organization's platform policy is checked against `platform`).
    /// A device publishes a new record when they change.
    pub details: Option<DeviceDetails>,
}

/// Longest text of one field of [`DeviceDetails`] (bytes).
pub const MAX_DETAIL: usize = 256;

/// What a device says about itself in its device record (the format-2
/// `vault/devinfo/` record folded into the device record).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDetails {
    /// "Linux", "macOS", "Windows", "Android", "iOS".
    pub os: String,
    pub os_version: String,
    pub model: String,
    pub arch: String,
    pub app_version: String,
    /// `linux`, `macos`, `windows`, `android` or `ios` (`org::platform_id`).
    pub platform: String,
    pub updated_utc: i64,
    pub last_sync_utc: Option<i64>,
}

impl DeviceDetails {
    fn check(&self) -> Result<(), String> {
        for f in [
            &self.os,
            &self.os_version,
            &self.model,
            &self.arch,
            &self.app_version,
            &self.platform,
        ] {
            if f.len() > MAX_DETAIL {
                return Err(format!("a device detail longer than {MAX_DETAIL} bytes"));
            }
        }
        Ok(())
    }
}

impl RecordBody for DeviceRecord {
    fn embedded_signing_key(&self) -> Option<Vec<u8>> {
        Some(self.sign_pub.clone())
    }
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.device || device_id_of_bytes(&self.sign_pub) != self.device {
            return Err("the device id is not the hash of its signing key".into());
        }
        if meta.scope != VAULT_SCOPE {
            return Err("a device record is vault-wide".into());
        }
        if self.name.len() > MAX_NAME {
            return Err("device name longer than 128 bytes".into());
        }
        let pk = VerifyingKey::from_bytes(&self.sign_pub).map_err(|e| e.to_string())?;
        if !pk.is_hybrid() {
            return Err("the signing key is not Ed25519 + ML-DSA-65".into());
        }
        EncapsKey::from_bytes(&self.kem_pub).map_err(|e| e.to_string())?;
        if self.stamp.device != self.device {
            return Err("the stamp names another device".into());
        }
        if let Some(d) = &self.details {
            d.check()?;
        }
        Ok(())
    }
}

impl DeviceRecord {
    pub fn signing_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.sign_pub).ok()
    }
    pub fn kem_key(&self) -> Option<EncapsKey> {
        EncapsKey::from_bytes(&self.kem_pub).ok()
    }
    /// The stream this device's records live in.
    pub fn stream(device: Id16) -> crate::record::StreamRef {
        crate::record::StreamRef::new(Kind::Device, VAULT_SCOPE, device)
    }
}

/// Every accepted device record, newest per device (by stamp, then epoch),
/// with the vault epoch of the registry key it was written under.
#[derive(Clone, Debug, Default)]
pub struct DeviceRegistry {
    pub devices: BTreeMap<Id16, (DeviceRecord, u32)>,
}

/// Device records verify themselves; any holder of the registry key may
/// write one (that is a full device of the vault).
struct SelfSigned;
impl RecordTrust for SelfSigned {
    fn signer_key(&self, _: &Id16, _: Kind, _: &Id16) -> Option<VerifyingKey> {
        None
    }
    fn may_write(&self, _: &Id16, kind: Kind, _: &Id16, _: &KeyId) -> bool {
        kind == Kind::Device
    }
}

impl DeviceRegistry {
    /// Read `vault/devices/` on every storage with the registry keys `keys`
    /// holds (any vault epoch).
    pub fn read(
        storages: &[&dyn Storage],
        vault: Id16,
        keys: &dyn RecordKeys,
        counter: &mut RecordsRefused,
    ) -> Result<DeviceRegistry> {
        let recs: Vec<Record<DeviceRecord>> = store::read_all(
            storages,
            vault,
            Kind::Device,
            "vault/devices/",
            keys,
            &SelfSigned,
            counter,
        )?;
        let mut out = DeviceRegistry::default();
        for r in recs {
            let epoch = match r.meta.key_id {
                KeyId::Registry(e) => e,
                _ => continue,
            };
            match out.devices.get(&r.body.device) {
                Some((old, old_epoch)) if (old.stamp, *old_epoch) >= (r.body.stamp, epoch) => {}
                _ => {
                    out.devices.insert(r.body.device, (r.body, epoch));
                }
            }
        }
        Ok(out)
    }

    pub fn get(&self, device: &Id16) -> Option<&DeviceRecord> {
        self.devices.get(device).map(|(r, _)| r)
    }

    /// The vault epoch of the registry key `device`'s record was written
    /// under.
    pub fn epoch_of(&self, device: &Id16) -> Option<u32> {
        self.devices.get(device).map(|(_, e)| *e)
    }

    pub fn signing_key(&self, device: &Id16) -> Option<VerifyingKey> {
        self.get(device)?.signing_key()
    }

    pub fn kem_key(&self, device: &Id16) -> Option<EncapsKey> {
        self.get(device)?.kem_key()
    }

    pub fn name(&self, device: &Id16) -> String {
        self.get(device)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| hex::encode(device))
    }

    pub fn insert(&mut self, rec: DeviceRecord, epoch: u32) {
        self.devices.insert(rec.device, (rec, epoch));
    }
}
