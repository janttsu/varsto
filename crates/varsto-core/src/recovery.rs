// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Recovery kit (F-042): the vault key on paper or metal. The 32-byte vault
//! key becomes 24 BIP-39 English words (with the standard checksum, so a
//! copying mistake is caught), and optionally three Shamir shares of which
//! any two rebuild the key, for people who keep copies in several places
//! and do not want any single place to hold the whole key.

use anyhow::{anyhow, bail, Result};
use bip39::Mnemonic;

/// 24 words for a 32-byte key (hex in, words out).
pub fn words_from_key(key_hex: &str) -> Result<String> {
    let bytes = hex::decode(key_hex)?;
    if bytes.len() != 32 {
        bail!("vault key must be 32 bytes");
    }
    let m = Mnemonic::from_entropy(&bytes).map_err(|e| anyhow!("mnemonic: {e}"))?;
    Ok(m.words().collect::<Vec<_>>().join(" "))
}

/// Words in (any spacing, any case), hex key out. Fails on a wrong word or a
/// checksum mismatch.
pub fn key_from_words(words: &str) -> Result<String> {
    let normalised = words
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let m: Mnemonic = normalised
        .parse()
        .map_err(|e| anyhow!("these words are not a valid recovery phrase: {e}"))?;
    let entropy = m.to_entropy();
    if entropy.len() != 32 {
        bail!("the phrase must have 24 words");
    }
    Ok(hex::encode(entropy))
}

/// One share: an index 1..=255 and 24 words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub words: String,
}

impl Share {
    pub fn encode(&self) -> String {
        format!("{}: {}", self.index, self.words)
    }
    pub fn decode(s: &str) -> Result<Share> {
        let (idx, words) = s
            .trim()
            .split_once(':')
            .ok_or_else(|| anyhow!("a share looks like `<index>: <24 words>`"))?;
        Ok(Share {
            index: idx
                .trim()
                .parse()
                .map_err(|_| anyhow!("share index must be a number"))?,
            words: words.trim().to_string(),
        })
    }
}

/// Split the key into `count` shares, any `threshold` of which rebuild it.
pub fn split(key_hex: &str, threshold: u8, count: u8) -> Result<Vec<Share>> {
    let bytes = hex::decode(key_hex)?;
    if bytes.len() != 32 {
        bail!("vault key must be 32 bytes");
    }
    if threshold < 2 || count < threshold {
        bail!("need threshold >= 2 and count >= threshold");
    }
    let sharks = sharks::Sharks(threshold);
    let dealer = sharks.dealer(&bytes);
    let mut out = Vec::new();
    for (i, share) in dealer.take(count as usize).enumerate() {
        let raw: Vec<u8> = (&share).into();
        // sharks encodes the x coordinate as the first byte, then the 32 y bytes.
        let (x, y) = raw.split_first().ok_or_else(|| anyhow!("empty share"))?;
        let m = Mnemonic::from_entropy(y).map_err(|e| anyhow!("mnemonic: {e}"))?;
        out.push(Share {
            index: *x,
            words: m.words().collect::<Vec<_>>().join(" "),
        });
        let _ = i;
    }
    Ok(out)
}

/// Rebuild the key from enough shares.
pub fn combine(shares: &[Share], threshold: u8) -> Result<String> {
    let mut raw_shares = Vec::new();
    for s in shares {
        let y = hex::decode(key_from_words(&s.words)?)?;
        let mut raw = vec![s.index];
        raw.extend_from_slice(&y);
        let share = sharks::Share::try_from(raw.as_slice()).map_err(|e| anyhow!("share: {e}"))?;
        raw_shares.push(share);
    }
    let key = sharks::Sharks(threshold)
        .recover(raw_shares.iter())
        .map_err(|e| anyhow!("cannot rebuild the key from these shares: {e}"))?;
    if key.len() != 32 {
        bail!("rebuilt key has the wrong length");
    }
    Ok(hex::encode(key))
}

/// The printable kit.
pub fn kit_text(vault_id: &str, key_hex: &str, shares: Option<(u8, Vec<Share>)>) -> Result<String> {
    let words = words_from_key(key_hex)?;
    let numbered: Vec<String> = words
        .split(' ')
        .enumerate()
        .map(|(i, w)| format!("{:>2}. {w}", i + 1))
        .collect();
    let mut t = String::new();
    t.push_str("VARSTO RECOVERY KIT\n");
    t.push_str(&format!("Vault {vault_id}\n"));
    t.push_str(
        "These 24 words are the vault key. Anyone who has them can read everything in the vault.\n",
    );
    t.push_str(
        "Keep this on paper or metal, in more than one place, never in a photo or a cloud note.\n",
    );
    t.push_str("Test it once a year: `varsto join --words \"...\"` on a spare device.\n\n");
    for row in numbered.chunks(4) {
        t.push_str(&row.join("   "));
        t.push('\n');
    }
    if let Some((threshold, shares)) = shares {
        t.push_str(&format!(
            "\nSHARES ({threshold} of {} rebuild the key; one alone reveals nothing). Give each to a different place or person.\n",
            shares.len()
        ));
        for s in shares {
            t.push_str(&format!("\nShare {}:\n", s.index));
            let n: Vec<String> = s
                .words
                .split(' ')
                .enumerate()
                .map(|(i, w)| format!("{:>2}. {w}", i + 1))
                .collect();
            for row in n.chunks(4) {
                t.push_str(&row.join("   "));
                t.push('\n');
            }
        }
        t.push_str(
            "\nRebuild: varsto recovery combine \"<index>: <24 words>\" \"<index>: <24 words>\"\n",
        );
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_roundtrip_and_catch_mistakes() {
        let key = hex::encode([7u8; 32]);
        let w = words_from_key(&key).unwrap();
        assert_eq!(w.split(' ').count(), 24);
        assert_eq!(key_from_words(&w).unwrap(), key);
        assert_eq!(key_from_words(&w.to_uppercase()).unwrap(), key);
        let mut bad: Vec<&str> = w.split(' ').collect();
        bad[3] = "zebra";
        assert!(key_from_words(&bad.join(" ")).is_err());
    }

    #[test]
    fn two_of_three_shares_rebuild_and_one_does_not() {
        let key = hex::encode([42u8; 32]);
        let shares = split(&key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        for pair in [(0, 1), (1, 2), (0, 2)] {
            let two = vec![shares[pair.0].clone(), shares[pair.1].clone()];
            assert_eq!(combine(&two, 2).unwrap(), key);
        }
        assert!(combine(&shares[..1], 2).is_err());
        let enc = shares[0].encode();
        assert_eq!(Share::decode(&enc).unwrap(), shares[0]);
        let text = kit_text("abcd", &key, Some((2, shares))).unwrap();
        assert!(text.contains("Share 1:") && text.contains("RECOVERY KIT"));
    }
}
