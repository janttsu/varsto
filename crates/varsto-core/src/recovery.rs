// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Recovery kit (F-042): the vault key on paper or metal. The 32-byte vault
//! key becomes 24 BIP-39 English words (with the standard checksum, so a
//! copying mistake is caught), and optionally three Shamir shares of which
//! any two rebuild the key, for people who keep copies in several places
//! and do not want any single place to hold the whole key.

use anyhow::{anyhow, bail, Result};
use bip39::Mnemonic;
use zeroize::{Zeroize, Zeroizing};

/// 24 words for a 32-byte key (hex in, words out). The words are the key:
/// the returned string is wiped when dropped.
pub fn words_from_key(key_hex: &str) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(hex::decode(key_hex)?);
    if bytes.len() != 32 {
        bail!("vault key must be 32 bytes");
    }
    let m = Mnemonic::from_entropy(&bytes).map_err(|e| anyhow!("mnemonic: {e}"))?;
    Ok(Zeroizing::new(m.words().collect::<Vec<_>>().join(" ")))
}

/// Words in (any spacing, any case), hex key out. Fails on a wrong word or a
/// checksum mismatch.
pub fn key_from_words(words: &str) -> Result<Zeroizing<String>> {
    let normalised = Zeroizing::new(
        words
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let m: Mnemonic = normalised
        .parse()
        .map_err(|e| anyhow!("these words are not a valid recovery phrase: {e}"))?;
    let entropy = Zeroizing::new(m.to_entropy());
    if entropy.len() != 32 {
        bail!("the phrase must have 24 words");
    }
    Ok(Zeroizing::new(hex::encode(&*entropy)))
}

/// One share: an index 1..=255 and 24 words. The words are wiped when the
/// share is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub words: String,
}

crate::redacted_debug!(Share { index ; words });

impl Drop for Share {
    fn drop(&mut self) {
        self.words.zeroize();
    }
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
    let sharks = blahaj::Sharks(threshold);
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

/// A short fingerprint of the key, printed on the kit as "Key check" so
/// that a key rebuilt from shares can be recognised as the right one: the
/// first 8 hex digits of a BLAKE3 key derivation over the key, under a
/// context of its own. It says nothing about the key itself.
pub fn key_check(key_hex: &str) -> Result<String> {
    let bytes = Zeroizing::new(hex::decode(key_hex)?);
    if bytes.len() != 32 {
        bail!("vault key must be 32 bytes");
    }
    let h = blake3::derive_key("varsto recovery key check v1", &bytes);
    Ok(hex::encode(&h[..4]))
}

/// Rebuild the key from enough shares. Two shares with the same index are
/// refused (the same share twice, or a miscopied index, would otherwise
/// give a wrong key without a word of warning). With `check`, the "Key
/// check" printed on the kit, a rebuilt key that does not match it is
/// refused: a share from another kit, or a copying mistake the word
/// checksums let through.
pub fn combine(shares: &[Share], threshold: u8, check: Option<&str>) -> Result<Zeroizing<String>> {
    let mut raw_shares = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for s in shares {
        if s.index == 0 {
            bail!("share index must be 1 or more");
        }
        if !seen.insert(s.index) {
            bail!(
                "share {} was given twice; each share has its own index",
                s.index
            );
        }
        let y = Zeroizing::new(hex::decode(key_from_words(&s.words)?.as_str())?);
        let mut raw = Zeroizing::new(vec![s.index]);
        raw.extend_from_slice(&y);
        let share = blahaj::Share::try_from(raw.as_slice()).map_err(|e| anyhow!("share: {e}"))?;
        raw_shares.push(share);
    }
    let key = Zeroizing::new(
        blahaj::Sharks(threshold)
            .recover(raw_shares.iter())
            .map_err(|e| anyhow!("cannot rebuild the key from these shares: {e}"))?,
    );
    if key.len() != 32 {
        bail!("rebuilt key has the wrong length");
    }
    let key_hex = Zeroizing::new(hex::encode(&*key));
    if let Some(expected) = check {
        let expected = expected.trim().to_ascii_lowercase();
        if expected.is_empty() {
            bail!("the key check is empty");
        }
        if !crate::crypto::ct_eq(key_check(&key_hex)?.as_bytes(), expected.as_bytes()) {
            bail!(
                "the rebuilt key does not match the key check {expected}: a share is from another kit or was copied wrong"
            );
        }
    }
    Ok(key_hex)
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
    t.push_str(&format!(
        "\nKey check: {}  (a key rebuilt from shares is right when `varsto recovery combine --check` accepts it with this value)\n",
        key_check(key_hex)?
    ));
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
            "\nRebuild: varsto recovery combine --check <key check> \"<index>: <24 words>\" \"<index>: <24 words>\"\n",
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
        assert_eq!(*key_from_words(&w).unwrap(), key);
        assert_eq!(*key_from_words(&w.to_uppercase()).unwrap(), key);
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
            assert_eq!(*combine(&two, 2, None).unwrap(), key);
            assert_eq!(
                *combine(&two, 2, Some(&key_check(&key).unwrap())).unwrap(),
                key
            );
        }
        assert!(combine(&shares[..1], 2, None).is_err());
        let enc = shares[0].encode();
        assert_eq!(Share::decode(&enc).unwrap(), shares[0]);
        let check = key_check(&key).unwrap();
        let text = kit_text("abcd", &key, Some((2, shares))).unwrap();
        assert!(text.contains("Share 1:") && text.contains("RECOVERY KIT"));
        assert!(text.contains(&format!("Key check: {check}")), "{text}");
        assert_eq!(check.len(), 8);
        assert!(!key.contains(&check));
    }

    #[test]
    fn the_same_share_twice_and_a_wrong_key_check_are_refused() {
        let key = hex::encode([42u8; 32]);
        let shares = split(&key, 2, 3).unwrap();
        // The same share twice: the library would interpolate a "key" from it.
        let twice = vec![shares[0].clone(), shares[0].clone()];
        let e = combine(&twice, 2, None).unwrap_err().to_string();
        assert!(e.contains("given twice"), "{e}");
        // A share of another kit gives a key that fails the check.
        let other = split(&hex::encode([7u8; 32]), 2, 3).unwrap();
        let mixed = vec![shares[0].clone(), other[1].clone()];
        assert!(combine(&mixed, 2, None).is_ok(), "no check: no way to tell");
        let e = combine(&mixed, 2, Some(&key_check(&key).unwrap()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not match the key check"), "{e}");
        let two = vec![shares[0].clone(), shares[1].clone()];
        assert!(combine(&two, 2, Some("00000000")).is_err());
        assert!(combine(&two, 2, Some("")).is_err());
        // Case and spaces around the check do not matter.
        let upper = key_check(&key).unwrap().to_uppercase();
        assert_eq!(*combine(&two, 2, Some(&format!(" {upper} "))).unwrap(), key);
    }

    #[test]
    fn shares_printed_before_the_library_change_still_combine() {
        // Produced by `split(hex([42; 32]), 2, 3)` with the sharks crate
        // (0.5.0): the share bytes are the x coordinate and 32 y bytes, and
        // the fork keeps that encoding.
        let key = hex::encode([42u8; 32]);
        let printed = [
            "1: stool toast salon circle blast fossil give retreat minute resource laugh cave kiss pink admit alpha arrow sense smart scale crash today employ bird",
            "2: sort cupboard place prosper bomb alone estate detect keep neglect glow rely adjust vivid width gift gravity ordinary allow language loan jeans bring sea",
            "3: critic maple mushroom spin provide elite marble scorpion team index network shine swim early fade castle dog attract doll trim because limit wise mom",
        ];
        let shares: Vec<Share> = printed.iter().map(|s| Share::decode(s).unwrap()).collect();
        for pair in [(0, 1), (1, 2), (0, 2)] {
            let two = vec![shares[pair.0].clone(), shares[pair.1].clone()];
            assert_eq!(
                *combine(&two, 2, Some(&key_check(&key).unwrap())).unwrap(),
                key
            );
        }
    }
}
