// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The envelope of the records the block layer publishes: pack indexes and
//! tombstone lists (`crate::packs`).
//!
//! Format 2 wraps every record a device publishes in one signed envelope
//! (`docs/spec/format-2-design.md`, section 3). That envelope belongs to
//! the records work; this module is the narrow seam the block layer calls
//! through, so that integrating the two replaces the bodies of
//! [`Records::seal`] and [`Records::open`] and nothing else. Until then a
//! record is an AEAD body under the given key, with associated data that
//! names the format, the kind, the vault, the scope, the writing device and
//! its sequence number: a storage can neither open nor relabel it.

use crate::crypto::{self, SecretKey};
use crate::ids::{DeviceId, VaultId};
use anyhow::Result;

/// What a device needs to seal and open records: the vault and itself.
#[derive(Clone, Debug)]
pub struct Records {
    vault: VaultId,
    device: DeviceId,
}

impl Records {
    pub fn new(vault: VaultId, device: DeviceId) -> Records {
        Records { vault, device }
    }

    /// The device that writes this device's records.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    fn aad(&self, kind: &str, scope: &str, device: &DeviceId, seq: u64) -> Vec<u8> {
        crypto::aad(
            kind,
            &[
                self.vault.as_str().as_bytes(),
                scope.as_bytes(),
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }

    /// Seal record `seq` of `kind` in `scope` (a folder id, or empty for
    /// the vault) written by this device.
    pub fn seal(
        &self,
        kind: &str,
        scope: &str,
        seq: u64,
        key: &SecretKey,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        crypto::encrypt(key, &self.aad(kind, scope, &self.device, seq), body)
    }

    /// Open record `seq` of `kind` in `scope` that `writer` published.
    pub fn open(
        &self,
        kind: &str,
        scope: &str,
        writer: &DeviceId,
        seq: u64,
        key: &SecretKey,
        blob: &[u8],
    ) -> Result<Vec<u8>> {
        crypto::decrypt(key, &self.aad(kind, scope, writer, seq), blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_opens_only_under_its_own_name() {
        let vault = VaultId::from_bytes(&[1; 16]);
        let (a, b) = (
            DeviceId::from_bytes(&[2; 16]),
            DeviceId::from_bytes(&[3; 16]),
        );
        let r = Records::new(vault, a.clone());
        let key = SecretKey([4; 32]);
        let blob = r.seal("pack-index", "f", 7, &key, b"body").unwrap();
        assert_eq!(
            r.open("pack-index", "f", &a, 7, &key, &blob).unwrap(),
            b"body"
        );
        assert!(r.open("pack-index", "f", &a, 8, &key, &blob).is_err());
        assert!(r.open("pack-index", "f", &b, 7, &key, &blob).is_err());
        assert!(r.open("tombstones", "f", &a, 7, &key, &blob).is_err());
        assert!(r.open("pack-index", "g", &a, 7, &key, &blob).is_err());
    }
}
