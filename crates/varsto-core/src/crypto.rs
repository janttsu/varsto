// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Cryptographic primitives used by alpha-0.
//!
//! Choices (all recorded with algorithm identifiers in object headers so they
//! can change, see `docs/spec/key-hierarchy.md`):
//! - AEAD: XChaCha20-Poly1305 with a 192-bit nonce.
//! - Keyed hash and KDF: BLAKE3 (keyed mode and derive_key mode).
//! - Passphrase stretching: Argon2id with fixed minimum parameters.
//! - Signatures: Ed25519 only. The hybrid ML-DSA signature of the plan is
//!   not implemented yet; the algorithm identifier makes that visible.
//!
//! Every key has exactly one purpose; derivations carry a context string and
//! length-prefixed scope identifiers so that two scopes never share a key.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const AEAD_ALG: &str = "xchacha20poly1305";
pub const HASH_ALG: &str = "blake3";
pub const KDF_ALG: &str = "blake3-derive-key";
pub const SIG_ALG: &str = "ed25519";
pub const PASSPHRASE_KDF: &str = "argon2id";

/// Context prefix for key derivation. It is a format constant and must not
/// follow product renames (see the key hierarchy draft).
pub const CONTEXT_PREFIX: &str = "e2ee-sync-format/0";

/// Minimum Argon2id parameters (S-013: fixed minimums, only tightening allowed).
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;

pub const NONCE_LEN: usize = 24;

/// A 256-bit secret key. Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SecretKey(b)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 32 {
            bail!("key must be 32 bytes, got {}", b.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(b);
        Ok(SecretKey(k))
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&hex::decode(s.trim())?)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Derive a sub-key for one purpose, bound to the given scope identifiers.
    /// The context string is `<prefix>/<purpose>`; identifiers are fed into the
    /// key material with explicit lengths so that tuples cannot collide.
    pub fn derive(&self, purpose: &str, scope: &[&[u8]]) -> SecretKey {
        let context = format!("{CONTEXT_PREFIX}/{purpose}");
        let mut material = Vec::with_capacity(32 + scope.len() * 20);
        material.extend_from_slice(&self.0);
        for s in scope {
            material.extend_from_slice(&(s.len() as u32).to_le_bytes());
            material.extend_from_slice(s);
        }
        let out = blake3::derive_key(&context, &material);
        material.zeroize();
        SecretKey(out)
    }
}

/// Keyed BLAKE3 hash (used for chunk identifiers and file content hashes so
/// that storage never sees a plain hash of user content).
pub fn keyed_hash(key: &SecretKey, data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(&key.0, data).as_bytes()
}

/// Incremental keyed hasher for whole files.
pub struct KeyedHasher(blake3::Hasher);

impl KeyedHasher {
    pub fn new(key: &SecretKey) -> Self {
        KeyedHasher(blake3::Hasher::new_keyed(&key.0))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

/// Plain BLAKE3 hash of ciphertext or signed bodies (no secret involved).
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Build the associated data for an AEAD operation from labelled fields.
/// Fields are length-prefixed; the format version and the algorithm identifier
/// are always included first.
pub fn aad(object_type: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    };
    push(&mut out, &crate::FORMAT_VERSION.to_le_bytes());
    push(&mut out, AEAD_ALG.as_bytes());
    push(&mut out, object_type.as_bytes());
    for f in fields {
        push(&mut out, f);
    }
    out
}

/// Encrypt with a fresh random nonce. Output: nonce || ciphertext || tag.
pub fn encrypt(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    encrypt_with_nonce(key, &nonce, aad, plaintext)
}

/// Encrypt with a caller-chosen nonce. Only safe when the key is never used
/// with another nonce for a different plaintext (alpha-0 uses this for chunk
/// keys that are derived from the chunk's own keyed hash, so key and nonce are
/// unique per plaintext and the ciphertext is deterministic for deduplication).
pub fn encrypt_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key.0));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &SecretKey, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("ciphertext too short");
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key.0));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("decryption failed: wrong key, wrong context or tampered data"))
}

/// Parameters stored next to a passphrase-wrapped key so that the minimums
/// can only be tightened in later versions (the reader refuses weaker values).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PassphraseParams {
    pub kdf: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt_hex: String,
}

impl PassphraseParams {
    pub fn new() -> Self {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        PassphraseParams {
            kdf: PASSPHRASE_KDF.to_string(),
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
            salt_hex: hex::encode(salt),
        }
    }
}

impl Default for PassphraseParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Stretch a passphrase into a wrapping key. The passphrase is NFKC-normalised
/// by the caller (alpha-0: not yet, see plan 6.15) and may be any length.
pub fn passphrase_key(passphrase: &str, params: &PassphraseParams) -> Result<SecretKey> {
    if params.kdf != PASSPHRASE_KDF {
        bail!("unsupported passphrase KDF {}", params.kdf);
    }
    if params.m_kib < ARGON2_M_KIB || params.t < ARGON2_T || params.p < ARGON2_P {
        bail!("passphrase parameters below the specification minimum");
    }
    let salt = hex::decode(&params.salt_hex)?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|e| anyhow!("argon2 params: {e}"))?,
    );
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(SecretKey(out))
}

/// Ed25519 device signing key. The hybrid post-quantum signature is TBD.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        SigningKey(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
        Ok(SigningKey(ed25519_dalek::SigningKey::from_bytes(&arr)))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn public(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.0.sign(msg).to_bytes()
    }
}

#[derive(Clone)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"))?;
        Ok(VerifyingKey(
            ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|e| anyhow!("public key: {e}"))?,
        ))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| anyhow!("signature verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_and_aad_binding() {
        let k = SecretKey::random();
        let a = aad("chunk", &[b"folder1", b"id1"]);
        let ct = encrypt(&k, &a, b"hello").unwrap();
        assert_eq!(decrypt(&k, &a, &ct).unwrap(), b"hello");
        let other = aad("chunk", &[b"folder2", b"id1"]);
        assert!(decrypt(&k, &other, &ct).is_err());
        let mut tampered = ct.clone();
        tampered[NONCE_LEN + 1] ^= 1;
        assert!(decrypt(&k, &a, &tampered).is_err());
    }

    #[test]
    fn derivations_are_scoped() {
        let k = SecretKey::random();
        let a = k.derive("x", &[b"a", b"b"]);
        let b = k.derive("x", &[b"ab", b""]);
        let c = k.derive("y", &[b"a", b"b"]);
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, c.0);
        assert_eq!(a.0, k.derive("x", &[b"a", b"b"]).0);
    }

    #[test]
    fn signatures_verify() {
        let sk = SigningKey::generate();
        let sig = sk.sign(b"batch");
        sk.public().verify(b"batch", &sig).unwrap();
        assert!(sk.public().verify(b"other", &sig).is_err());
    }

    #[test]
    fn weak_passphrase_params_are_refused() {
        let mut p = PassphraseParams::new();
        p.m_kib = 1024;
        assert!(passphrase_key("x", &p).is_err());
    }
}
