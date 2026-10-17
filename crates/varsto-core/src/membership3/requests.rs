// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `request` records (format 3 design, section 6): a device that holds K3
//! but not a folder asks for it at `vault/requests/<folder>/<device>/`
//! under the registry key, with `{device, name, kem_pub, role_wanted}`.
//! Approval is manual: an owner compares the requester's name and the
//! six-word fingerprint of its K6 and K8 public keys, then issues a grant
//! (`Membership::approve`) or denies (`Membership::deny`). The commands
//! and pages are WP8b's.

use super::{Role, MAX_NAME};
use crate::kem::EncapsKey;
use crate::record::{Id16, Kind, RecordBody, RecordMeta, StreamRef};
use serde::{Deserialize, Serialize};

/// The body of a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub device: Id16,
    pub name: String,
    /// K8 public key: must be the one of the requester's device record.
    pub kem_pub: Vec<u8>,
    pub role_wanted: Role,
}

impl RecordBody for RequestRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.device {
            return Err("the request names another device".into());
        }
        if self.name.len() > MAX_NAME {
            return Err("device name longer than 128 bytes".into());
        }
        if self.role_wanted == Role::Owner {
            return Err("a request asks for editor or viewer".into());
        }
        EncapsKey::from_bytes(&self.kem_pub).map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl RequestRecord {
    pub fn stream(folder: Id16, device: Id16) -> StreamRef {
        StreamRef::new(Kind::Request, folder, device)
    }
}

/// A request an owner may answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    pub folder: Id16,
    pub device: Id16,
    pub name: String,
    pub role_wanted: Role,
    /// Six words over the requester's K6 and K8 public keys.
    pub fingerprint: String,
}

/// The six-word fingerprint of a device's K6 and K8 public keys (encoded
/// bytes): the derivation of section 24 (`share::fingerprint`) under a
/// format-3 context, over the two keys. Both sides show it; a request whose
/// keys were swapped on the way shows other words.
pub fn fingerprint(k6_public: &[u8], k8_public: &[u8]) -> String {
    crate::share::fingerprint_words(
        "varsto format-3 device fingerprint v1",
        &[k6_public, k8_public],
    )
}
