// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Identifiers. All identifiers are random or derived byte strings shown as
//! lower-case hex. Nothing in an identifier reveals a file name or content.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Id(hex::encode(b))
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        Id(hex::encode(b))
    }

    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s.trim())?;
        if bytes.is_empty() || bytes.len() > 64 {
            anyhow::bail!("an identifier has 1 to 64 bytes, not {}", bytes.len());
        }
        Ok(Id(hex::encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        hex::decode(&self.0).expect("identifier is valid hex")
    }

    /// Short prefix for human-readable output.
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(8)]
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0)
    }
}

pub type VaultId = Id;
pub type FolderId = Id;
pub type DeviceId = Id;
/// Keyed hash of a chunk's plaintext (hex). Only meaningful inside one folder.
pub type ChunkId = Id;
/// Hash of a chunk's ciphertext (hex); the storage object name.
pub type ObjectName = Id;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_have_a_fixed_size() {
        assert!(Id::from_hex("").is_err());
        assert!(Id::from_hex("ab").is_ok());
        assert!(Id::from_hex(&"ab".repeat(16)).is_ok());
        assert!(Id::from_hex(&"ab".repeat(32)).is_ok());
        assert!(Id::from_hex(&"ab".repeat(65)).is_err());
        assert!(Id::from_hex("zz".repeat(16).as_str()).is_err());
    }
}
