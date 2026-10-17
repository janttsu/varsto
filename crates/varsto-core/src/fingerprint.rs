// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The six-word fingerprint of a device's public keys (format 3 design,
//! sections 6 and 8): what a person compares before a device is approved
//! for a folder or let in by pairing. The derivation is the one of
//! `share::fingerprint` (alpha-0-format.md section 24: BLAKE3 `derive_key`
//! over length-prefixed parts, the top 66 bits as six BIP-39 English
//! words), over the device's K6 (signing) and K8 (KEM) public keys, under
//! the context `varsto format-3 device fingerprint v1`.
//!
//! Work package 8a (`membership3::requests::fingerprint`, branch
//! `f3-grants`) computes the same words with the same context and parts;
//! once both are merged one of the two should call the other.

/// Words in a fingerprint (11 bits each, 66 bits).
pub const WORDS: usize = 6;

const CONTEXT: &str = "varsto format-3 device fingerprint v1";

/// The six words of a device: its K6 and K8 public keys (as their
/// `to_bytes`).
pub fn of_keys(signing_pub: &[u8], kem_pub: &[u8]) -> String {
    let mut ikm = Vec::with_capacity(signing_pub.len() + kem_pub.len() + 8);
    for part in [signing_pub, kem_pub] {
        ikm.extend_from_slice(&(part.len() as u32).to_le_bytes());
        ikm.extend_from_slice(part);
    }
    words(&blake3::derive_key(CONTEXT, &ikm))
}

/// Six words from the first 66 bits of `h`.
pub fn words(h: &[u8; 32]) -> String {
    let list = bip39::Language::English.word_list();
    let mut bits: u128 = 0;
    for b in &h[..9] {
        bits = (bits << 8) | u128::from(*b);
    }
    (0..WORDS)
        .map(|i| list[((bits >> (72 - 11 * (i + 1))) & 0x7ff) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_bind_both_keys() {
        let a = of_keys(&[1; 32], &[2; 32]);
        assert_eq!(a.split(' ').count(), WORDS);
        assert_eq!(a, of_keys(&[1; 32], &[2; 32]));
        assert_ne!(a, of_keys(&[9; 32], &[2; 32]));
        assert_ne!(a, of_keys(&[1; 32], &[9; 32]));
        // Length prefixes: moving a byte between the keys changes the words.
        assert_ne!(of_keys(&[1, 1], &[2]), of_keys(&[1], &[1, 2]));
    }
}
