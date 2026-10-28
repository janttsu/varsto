// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Derivations and sealing of the rendezvous service (spec 83.3): the
//! vault tag, the device slots, the owner keys, the sealed peer blob and the
//! pairing tags and offers. Client side only: the server never derives
//! anything, it only compares bytes and checks Ed25519 signatures.

use super::proto::{self, PairOffer, Slot, Tag, Token, ID_LEN};
use crate::crypto::{self, SecretKey};
use crate::membership3::derive3;
use crate::record::{Id16, Parts};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;

fn first16(h: &[u8; 32]) -> [u8; ID_LEN] {
    let mut out = [0u8; ID_LEN];
    out.copy_from_slice(&h[..ID_LEN]);
    out
}

/// The keys of one vault for the rendezvous, all from K3₀ (the vault key of
/// epoch 0, `Engine::root_key`), which every full device of the vault holds
/// for good: devices of one vault compute the same tag whatever epoch they
/// are at, and nobody without K3₀ can.
pub struct VaultKeys {
    slot_key: SecretKey,
    blob_key: SecretKey,
    tag: Tag,
}

impl VaultKeys {
    /// `k3_0`: K3₀. `vault_id`: the vault id as text (as the LAN beacon tag
    /// takes it).
    pub fn new(k3_0: &SecretKey, vault_id: &str) -> VaultKeys {
        let tag_key = derive3(k3_0, "rendezvous-tag", &[]);
        let tag = first16(&crypto::keyed_hash(&tag_key, vault_id.as_bytes()));
        VaultKeys {
            slot_key: derive3(k3_0, "rendezvous-slot", &[]),
            blob_key: derive3(k3_0, "rendezvous-blob", &[]),
            tag,
        }
    }

    /// `keyed_hash(derive3(K3₀, "rendezvous-tag"), vault id)[..16]`.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// `keyed_hash(derive3(K3₀, "rendezvous-slot"), device id16)[..16]`.
    pub fn slot(&self, device: &Id16) -> Slot {
        first16(&crypto::keyed_hash(&self.slot_key, device))
    }

    /// Seal a peer record (its parts as a storage holds them, names and
    /// bytes) for the slot `slot`: `XChaCha20-Poly1305(derive3(K3₀,
    /// "rendezvous-blob"), aad3("rendezvous-blob", [tag, slot]),
    /// postcard(parts))`. The outer seal hides the envelope's plaintext
    /// header (vault id, device id) and the storage name from the server;
    /// the record inside is still signed and sealed under the registry key
    /// and is checked exactly as one read from a storage.
    pub fn seal_peer(&self, slot: &Slot, parts: &Parts) -> Result<Vec<u8>> {
        let plain = postcard::to_stdvec(parts).context("encode peer record parts")?;
        let blob = crypto::encrypt(&self.blob_key, &self.blob_aad(slot), &plain)?;
        if blob.len() > proto::MAX_BLOB {
            bail!(
                "peer record too large for the rendezvous ({} bytes)",
                blob.len()
            );
        }
        Ok(blob)
    }

    /// Open a blob of slot `slot`: the parts to hand to the record acceptor.
    /// A blob of another slot or vault, or one that was changed, fails.
    pub fn open_peer(&self, slot: &Slot, blob: &[u8]) -> Result<Parts> {
        if blob.len() > proto::MAX_BLOB {
            bail!("rendezvous blob too large");
        }
        let plain = crypto::decrypt(&self.blob_key, &self.blob_aad(slot), blob)?;
        let parts: Parts = postcard::from_bytes(&plain).context("decode peer record parts")?;
        if parts.is_empty() || parts.len() > 16 {
            bail!("rendezvous blob with {} parts", parts.len());
        }
        Ok(parts)
    }

    fn blob_aad(&self, slot: &Slot) -> Vec<u8> {
        crypto::aad_for_format(3, "rendezvous-blob", &[&self.tag, slot])
    }
}

/// The Ed25519 key that owns this device's slot under `tag`:
/// `blake3::derive_key("e2ee-sync-format/3/rendezvous-owner", K6 secret ||
/// tag)`. Only this device can make it (it comes from its own signing
/// secret, `SigningKey::to_bytes`), it is stable across restarts so the
/// slot stays this device's, and it is not K6: the server cannot link it to
/// the device registry.
pub fn owner_key(signer_secret: &[u8], tag: &Tag) -> SigningKey {
    let mut material = Vec::with_capacity(signer_secret.len() + ID_LEN);
    material.extend_from_slice(signer_secret);
    material.extend_from_slice(tag);
    let seed = blake3::derive_key("e2ee-sync-format/3/rendezvous-owner", &material);
    zeroize::Zeroize::zeroize(&mut material);
    SigningKey::from_bytes(&seed)
}

/// A fresh owner key for one pairing offer.
pub fn ephemeral_owner() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Argon2id parameters of the pairing-code tag: 19 MiB, two passes, one
/// lane (the OWASP minimum for Argon2id). About 40 ms on a laptop and
/// 150 ms on a phone, once per offer and once per join; a server that tries
/// every one of the 10⁹ codes needs on the order of 10⁷ CPU seconds per
/// offer, inside the offer's ten minutes.
pub const PAIR_ARGON2_M_KIB: u32 = 19 * 1024;
pub const PAIR_ARGON2_T: u32 = 2;
/// The fixed salt (16 bytes): the tag must be the same on both devices,
/// which share nothing but the digits.
pub const PAIR_ARGON2_SALT: &[u8; 16] = b"varsto-rv-pair/1";

/// What a pairing tag gives: where to look and the key of the blob.
pub struct PairKeys {
    pub tag: Tag,
    pub key: SecretKey,
}

/// The tag and blob key of a pairing code (nine digits, normalised):
/// `out = Argon2id(digits, PAIR_ARGON2_SALT, 19 MiB, t=2, p=1, 32 bytes)`,
/// tag = `out[..16]`, key = `blake3::derive_key("e2ee-sync-format/3/
/// rendezvous-pair-key", out)`.
pub fn pair_code_keys(digits: &str) -> Result<PairKeys> {
    check_digits(digits)?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(PAIR_ARGON2_M_KIB, PAIR_ARGON2_T, 1, Some(32))
            .map_err(|e| anyhow!("argon2 params: {e}"))?,
    );
    let mut out = [0u8; 32];
    argon
        .hash_password_into(digits.as_bytes(), PAIR_ARGON2_SALT, &mut out)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    let keys = PairKeys {
        tag: first16(&out),
        key: SecretKey(blake3::derive_key(
            "e2ee-sync-format/3/rendezvous-pair-key",
            &out,
        )),
    };
    zeroize::Zeroize::zeroize(&mut out);
    Ok(keys)
}

/// The tag and blob key of the random `rv=` token of a pairing link:
/// tag = `blake3::derive_key("e2ee-sync-format/3/rendezvous-pair-token-tag",
/// token)[..16]`, key = `blake3::derive_key("e2ee-sync-format/3/
/// rendezvous-pair-token-key", token || digits)`. The server learns nothing
/// of the code from it; a photo of the link gives what the code gives.
pub fn pair_token_keys(token: &Token, digits: &str) -> Result<PairKeys> {
    check_digits(digits)?;
    let tag = first16(&blake3::derive_key(
        "e2ee-sync-format/3/rendezvous-pair-token-tag",
        token,
    ));
    let mut material = token.to_vec();
    material.extend_from_slice(digits.as_bytes());
    let key = SecretKey(blake3::derive_key(
        "e2ee-sync-format/3/rendezvous-pair-token-key",
        &material,
    ));
    Ok(PairKeys { tag, key })
}

fn check_digits(digits: &str) -> Result<()> {
    if digits.len() != 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("a pairing code is nine digits");
    }
    Ok(())
}

impl PairKeys {
    /// Seal an offer: `XChaCha20-Poly1305(key, aad3("rendezvous-pair-offer",
    /// [tag]), JSON(offer))`.
    pub fn seal(&self, offer: &PairOffer) -> Result<Vec<u8>> {
        offer.check().map_err(|e| anyhow!("pairing offer: {e}"))?;
        let plain = serde_json::to_vec(offer)?;
        crypto::encrypt(&self.key, &self.aad(), &plain)
    }

    /// Open an offer found under this tag.
    pub fn open(&self, blob: &[u8]) -> Result<PairOffer> {
        if blob.len() > proto::MAX_BLOB {
            bail!("pairing blob too large");
        }
        let plain = crypto::decrypt(&self.key, &self.aad(), blob)?;
        let offer: PairOffer = serde_json::from_slice(&plain)?;
        offer.check().map_err(|e| anyhow!("pairing offer: {e}"))?;
        Ok(offer)
    }

    fn aad(&self) -> Vec<u8> {
        crypto::aad_for_format(3, "rendezvous-pair-offer", &[&self.tag])
    }
}

/// Parse the `rv=` value of a pairing link: 32 lowercase hex digits.
pub fn parse_token(s: &str) -> Option<Token> {
    let mut t = [0u8; ID_LEN];
    if s.len() != 32 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode_to_slice(s, &mut t).ok()?;
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k3() -> SecretKey {
        SecretKey([3u8; 32])
    }

    #[test]
    fn devices_of_one_vault_agree_and_other_vaults_differ() {
        let a = VaultKeys::new(&k3(), "vault-a");
        let a2 = VaultKeys::new(&SecretKey([3u8; 32]), "vault-a");
        let b = VaultKeys::new(&k3(), "vault-b");
        let c = VaultKeys::new(&SecretKey([4u8; 32]), "vault-a");
        assert_eq!(a.tag(), a2.tag());
        assert_ne!(a.tag(), b.tag());
        assert_ne!(a.tag(), c.tag());
        let d1 = [1u8; 16];
        let d2 = [2u8; 16];
        assert_eq!(a.slot(&d1), a2.slot(&d1));
        assert_ne!(a.slot(&d1), a.slot(&d2));
        assert_ne!(a.slot(&d1), c.slot(&d1));
        // Neither the tag nor a slot is a plain hash of what it hides.
        assert_ne!(&a.slot(&d1)[..], &blake3::hash(&d1).as_bytes()[..16]);
    }

    #[test]
    fn a_peer_blob_opens_only_for_its_vault_and_slot() {
        let v = VaultKeys::new(&k3(), "vault-a");
        let parts: Parts = vec![(
            "vault/peers/x/0000000000000001-0000.rec".into(),
            vec![7; 300],
        )];
        let s1 = v.slot(&[1; 16]);
        let blob = v.seal_peer(&s1, &parts).unwrap();
        assert!(!blob.windows(6).any(|w| w == b"vault/"), "names are sealed");
        assert_eq!(v.open_peer(&s1, &blob).unwrap(), parts);
        assert!(
            v.open_peer(&v.slot(&[2; 16]), &blob).is_err(),
            "moved to another slot"
        );
        let other = VaultKeys::new(&SecretKey([9; 32]), "vault-a");
        assert!(other.open_peer(&s1, &blob).is_err());
        let mut bad = blob.clone();
        let n = bad.len() - 1;
        bad[n] ^= 1;
        assert!(v.open_peer(&s1, &bad).is_err());
        assert!(v.open_peer(&s1, &vec![0; proto::MAX_BLOB + 1]).is_err());
        let huge: Parts = vec![("x".into(), vec![0; proto::MAX_BLOB])];
        assert!(v.seal_peer(&s1, &huge).is_err());
    }

    #[test]
    fn owner_keys_are_per_device_and_tag_and_stable() {
        let a = owner_key(&[1; 32], &[5; 16]);
        assert_eq!(a.to_bytes(), owner_key(&[1; 32], &[5; 16]).to_bytes());
        assert_ne!(a.to_bytes(), owner_key(&[2; 32], &[5; 16]).to_bytes());
        assert_ne!(a.to_bytes(), owner_key(&[1; 32], &[6; 16]).to_bytes());
        assert_ne!(ephemeral_owner().to_bytes(), ephemeral_owner().to_bytes());
    }

    #[test]
    fn pairing_tags_agree_on_the_code_and_seal_the_offer() {
        let a = pair_code_keys("123456789").unwrap();
        let b = pair_code_keys("123456789").unwrap();
        let c = pair_code_keys("123456780").unwrap();
        assert_eq!(a.tag, b.tag);
        assert_ne!(a.tag, c.tag);
        let offer = PairOffer {
            v: proto::VERSION,
            addrs: vec!["192.0.2.10:17894".into()],
            expires: 1_800_000_000,
            relay: true,
        };
        let blob = a.seal(&offer).unwrap();
        assert!(!blob.windows(9).any(|w| w == b"192.0.2.1"));
        assert_eq!(b.open(&blob).unwrap(), offer);
        assert!(c.open(&blob).is_err());
        assert!(pair_code_keys("12345678").is_err());
        assert!(pair_code_keys("12345678x").is_err());

        let t = [8u8; 16];
        let ta = pair_token_keys(&t, "123456789").unwrap();
        let tb = pair_token_keys(&t, "123456789").unwrap();
        assert_eq!(ta.tag, tb.tag);
        assert_ne!(ta.tag, a.tag);
        // The token's tag does not depend on the code; its key does.
        let tc = pair_token_keys(&t, "123456780").unwrap();
        assert_eq!(ta.tag, tc.tag);
        let blob = ta.seal(&offer).unwrap();
        assert_eq!(tb.open(&blob).unwrap(), offer);
        assert!(tc.open(&blob).is_err());
    }

    #[test]
    fn tokens_parse_only_as_32_lowercase_hex() {
        let t = proto::random_token();
        assert_eq!(parse_token(&hex::encode(t)), Some(t));
        assert_eq!(parse_token(&hex::encode(t).to_uppercase()), None);
        assert_eq!(parse_token("abc"), None);
    }
}
