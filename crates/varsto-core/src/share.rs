// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Shared folders with other people (F-047) on storage format 3: what the
//! two sides compare, and the roles a member gets.
//!
//! - **Request code and fingerprint.** A request code (`vsr1`) carries the
//!   requester's device keys (K6 and K8 public keys) and, optionally, a
//!   name. Both sides derive six words from the three; the owner compares
//!   them with the requester over another channel (a call, in person)
//!   before it adds the member, so a code swapped on the way is noticed.
//!   The member compares the owner device's six words when it accepts.
//! - **Roles.** A member is an editor or a viewer (folder records and the
//!   grants to the member say which, `membership3`); nothing a viewer
//!   publishes for the folder is accepted by anyone.
//!
//! The format-2 tokens (`vst1`, `vst2`, plain), share epochs under keys
//! derived from the vault key and role records are gone: an owner answers a
//! request with a folder record that lists the member and a grant sealed to
//! the code's K8 (`Engine::share_add`), and removing a member starts a
//! folder epoch (`membership3`).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Number of words in a request fingerprint (11 bits each, 66 bits).
pub const FINGERPRINT_WORDS: usize = 6;

/// Six BIP-39 English words derived from a request's K6 and K8 public keys
/// and the name bound to it.
pub fn fingerprint(k6: &[u8], k8: &[u8], name: &str) -> String {
    fingerprint_words(
        "varsto share-request fingerprint v3",
        &[k6, k8, name.trim().as_bytes()],
    )
}

/// The derivation behind [`fingerprint`]: `FINGERPRINT_WORDS` BIP-39 words
/// from the top 66 bits of `BLAKE3.derive_key(context, len-prefixed
/// parts)`. Format 3 uses it over a device's K6 and K8 public keys.
pub fn fingerprint_words(context: &str, parts: &[&[u8]]) -> String {
    let mut ikm = Vec::new();
    for part in parts {
        ikm.extend_from_slice(&(part.len() as u32).to_le_bytes());
        ikm.extend_from_slice(part);
    }
    let h = blake3::derive_key(context, &ikm);
    let words = bip39::Language::English.word_list();
    let mut bits: u128 = 0;
    for b in &h[..9] {
        bits = (bits << 8) | *b as u128;
    }
    // 72 bits read; use the top 66.
    (0..FINGERPRINT_WORDS)
        .map(|i| {
            let idx = (bits >> (72 - 11 * (i + 1))) & 0x7ff;
            words[idx as usize]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compare a fingerprint typed or pasted by a person with the expected one
/// (case, spacing and punctuation do not matter).
pub fn fingerprint_matches(expected: &str, given: &str) -> bool {
    let norm = |s: &str| {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let (a, b) = (norm(expected), norm(given));
    !a.is_empty() && a == b
}

/// What a member of a shared folder may do. The owner's devices always write.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ShareRole {
    /// Reads and writes.
    #[default]
    Editor,
    /// Reads only: nothing it publishes for the folder is accepted.
    Viewer,
}

impl ShareRole {
    pub fn parse(s: &str) -> Result<ShareRole> {
        match s.trim().to_ascii_lowercase().as_str() {
            "editor" | "write" | "read-write" | "rw" => Ok(ShareRole::Editor),
            "viewer" | "read" | "read-only" | "ro" => Ok(ShareRole::Viewer),
            other => bail!("unknown role {other}: use viewer or editor"),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareRole::Editor => "editor",
            ShareRole::Viewer => "viewer",
        }
    }
    pub fn is_editor(&self) -> bool {
        *self == ShareRole::Editor
    }
    /// The folder role of format 3.
    pub fn role3(&self) -> crate::membership3::Role {
        match self {
            ShareRole::Editor => crate::membership3::Role::Editor,
            ShareRole::Viewer => crate::membership3::Role::Viewer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_covers_both_keys_and_the_name() {
        let (k6, k8) = (vec![1u8; 32], vec![2u8; 32]);
        let a = fingerprint(&k6, &k8, "Robin");
        assert_eq!(a.split(' ').count(), FINGERPRINT_WORDS);
        assert_eq!(a, fingerprint(&k6, &k8, " Robin "));
        assert_ne!(a, fingerprint(&k6, &k8, "Mallory"));
        assert_ne!(a, fingerprint(&[3u8; 32], &k8, "Robin"));
        assert_ne!(a, fingerprint(&k6, &[3u8; 32], "Robin"));
        assert!(fingerprint_matches(&a, &a.to_uppercase()));
        assert!(!fingerprint_matches(&a, ""));
    }
}
