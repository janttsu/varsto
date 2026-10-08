// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Hybrid key encapsulation: X25519 and ML-KEM-768 (FIPS 203) combined into
//! one shared secret, so that a secret sent to another party's public key
//! stays private unless both algorithms are broken. Used wherever a key must
//! travel to someone else's device; today that is the share token.
//!
//! Encoding. Public (encapsulation) key: X25519 key (32 bytes) followed by
//! the ML-KEM-768 encapsulation key (1184 bytes). Ciphertext: X25519 ephemeral
//! public key (32 bytes) followed by the ML-KEM ciphertext (1088 bytes). The
//! shared secret is `derive_key(context, x25519_ss || mlkem_ss || ciphertext
//! || encapsulation_key)`, binding the result to the transcript. The private
//! key is serialised as its two seeds (32 + 64 bytes).

use crate::crypto::{SecretKey, CONTEXT_PREFIX};
use anyhow::{anyhow, bail, Result};
use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use rand::RngCore;
use zeroize::Zeroize;

pub const KEM_ALG: &str = "x25519+ml-kem-768";

const X_LEN: usize = 32;
const PQ_SEED_LEN: usize = 64;
const PQ_EK_LEN: usize = 1184;
const PQ_CT_LEN: usize = 1088;
pub const ENCAPS_KEY_LEN: usize = X_LEN + PQ_EK_LEN;
pub const CIPHERTEXT_LEN: usize = X_LEN + PQ_CT_LEN;

/// Private half: can open secrets encapsulated to its public key.
pub struct DecapsKey {
    x: x25519_dalek::StaticSecret,
    pq_seed: [u8; PQ_SEED_LEN],
}

impl DecapsKey {
    pub fn generate() -> Self {
        let mut xs = [0u8; X_LEN];
        rand::rngs::OsRng.fill_bytes(&mut xs);
        let mut pq_seed = [0u8; PQ_SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut pq_seed);
        let k = DecapsKey {
            x: x25519_dalek::StaticSecret::from(xs),
            pq_seed,
        };
        xs.zeroize();
        k
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != X_LEN + PQ_SEED_LEN {
            bail!("decapsulation key must be {} bytes", X_LEN + PQ_SEED_LEN);
        }
        let xs: [u8; X_LEN] = b[..X_LEN].try_into().unwrap();
        let pq_seed: [u8; PQ_SEED_LEN] = b[X_LEN..].try_into().unwrap();
        Ok(DecapsKey {
            x: x25519_dalek::StaticSecret::from(xs),
            pq_seed,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.x.to_bytes().to_vec();
        out.extend_from_slice(&self.pq_seed);
        out
    }
    fn pq(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(self.pq_seed))
    }
    pub fn public(&self) -> EncapsKey {
        EncapsKey {
            x: x25519_dalek::PublicKey::from(&self.x),
            pq: self.pq().encapsulation_key().to_bytes().to_vec(),
        }
    }
    /// Recover the shared secret from a ciphertext made for this key.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SecretKey> {
        if ct.len() != CIPHERTEXT_LEN {
            bail!("kem ciphertext must be {CIPHERTEXT_LEN} bytes");
        }
        let eph: [u8; X_LEN] = ct[..X_LEN].try_into().unwrap();
        let x_ss = self.x.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
        let pq_ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ct[X_LEN..])
            .map_err(|_| anyhow!("ml-kem ciphertext length"))?;
        // ML-KEM decapsulation never fails: an invalid ciphertext yields an
        // implicit-rejection secret, so a tampered token simply fails to open.
        let pq_ss = self.pq().decapsulate(&pq_ct);
        Ok(combine(
            x_ss.as_bytes(),
            pq_ss.as_slice(),
            ct,
            &self.public().to_bytes(),
        ))
    }
}

impl Drop for DecapsKey {
    fn drop(&mut self) {
        self.pq_seed.zeroize();
    }
}

/// Public half: anyone holding it can encapsulate a secret for the owner.
#[derive(Clone)]
pub struct EncapsKey {
    x: x25519_dalek::PublicKey,
    pq: Vec<u8>,
}

impl EncapsKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != ENCAPS_KEY_LEN {
            bail!(
                "encapsulation key must be {ENCAPS_KEY_LEN} bytes, got {}",
                b.len()
            );
        }
        let xs: [u8; X_LEN] = b[..X_LEN].try_into().unwrap();
        // Validate the ML-KEM half now so a bad key fails here, not at use.
        Self::pq_key(&b[X_LEN..])?;
        Ok(EncapsKey {
            x: x25519_dalek::PublicKey::from(xs),
            pq: b[X_LEN..].to_vec(),
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.x.to_bytes().to_vec();
        out.extend_from_slice(&self.pq);
        out
    }
    fn pq_key(raw: &[u8]) -> Result<EncapsulationKey<MlKem768>> {
        let enc = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(raw)
            .map_err(|_| anyhow!("ml-kem encapsulation key length"))?;
        EncapsulationKey::<MlKem768>::new(&enc)
            .map_err(|_| anyhow!("ml-kem encapsulation key: invalid encoding"))
    }
    /// Produce a ciphertext for the owner and the shared secret it carries.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, SecretKey)> {
        let mut es = [0u8; X_LEN];
        rand::rngs::OsRng.fill_bytes(&mut es);
        let eph = x25519_dalek::StaticSecret::from(es);
        es.zeroize();
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let x_ss = eph.diffie_hellman(&self.x);
        // Fresh uniform randomness for ML-KEM's encapsulation message; this is
        // what the trait-based `encapsulate` does with a caller-supplied RNG.
        let mut m = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut m);
        let (pq_ct, pq_ss) =
            Self::pq_key(&self.pq)?.encapsulate_deterministic(&ml_kem::B32::from(m));
        m.zeroize();
        let mut ct = eph_pub.to_bytes().to_vec();
        ct.extend_from_slice(pq_ct.as_slice());
        let key = combine(x_ss.as_bytes(), pq_ss.as_slice(), &ct, &self.to_bytes());
        Ok((ct, key))
    }
}

fn combine(x_ss: &[u8], pq_ss: &[u8], ct: &[u8], ek: &[u8]) -> SecretKey {
    let context = format!("{CONTEXT_PREFIX}/hybrid-kem/{KEM_ALG}");
    let mut ikm = Vec::with_capacity(x_ss.len() + pq_ss.len() + ct.len() + ek.len());
    for part in [x_ss, pq_ss, ct, ek] {
        ikm.extend_from_slice(&(part.len() as u32).to_le_bytes());
        ikm.extend_from_slice(part);
    }
    let out = blake3::derive_key(&context, &ikm);
    ikm.zeroize();
    SecretKey::from_bytes(&out).expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let dk = DecapsKey::generate();
        let ek = EncapsKey::from_bytes(&dk.public().to_bytes()).unwrap();
        assert_eq!(ek.to_bytes().len(), ENCAPS_KEY_LEN);
        let (ct, k1) = ek.encapsulate().unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        let k2 = dk.decapsulate(&ct).unwrap();
        assert_eq!(k1.to_hex(), k2.to_hex());
        // Another key does not get the same secret, and a damaged ciphertext
        // (either half) yields a different secret or an error.
        let other = DecapsKey::generate();
        assert_ne!(other.decapsulate(&ct).unwrap().to_hex(), k1.to_hex());
        let mut bad = ct.clone();
        bad[5] ^= 1;
        assert_ne!(dk.decapsulate(&bad).unwrap().to_hex(), k1.to_hex());
        let mut bad = ct.clone();
        bad[X_LEN + 5] ^= 1;
        assert_ne!(dk.decapsulate(&bad).unwrap().to_hex(), k1.to_hex());
        // Private key round-trips through its seeds.
        let dk2 = DecapsKey::from_bytes(&dk.to_bytes()).unwrap();
        assert_eq!(dk2.decapsulate(&ct).unwrap().to_hex(), k1.to_hex());
    }
}
