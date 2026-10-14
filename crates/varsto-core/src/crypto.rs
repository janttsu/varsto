// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Cryptographic primitives used by alpha-0.
//!
//! Choices (all recorded with algorithm identifiers in object headers so they
//! can change, see `docs/spec/key-hierarchy.md`):
//! - AEAD: XChaCha20-Poly1305 with a 192-bit nonce.
//! - Keyed hash and KDF: BLAKE3 (keyed mode and derive_key mode).
//! - Passphrase stretching: Argon2id with fixed minimum parameters.
//! - Signatures: Ed25519 plus ML-DSA-65 (hybrid, both must verify). There
//!   is no Ed25519-only form (storage format 2).
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
/// Signature algorithm identifier carried by every signed object: an
/// Ed25519 signature and an ML-DSA-65 (FIPS 204) signature over the same
/// message, both of which must verify. It is the only one accepted.
pub const SIG_ALG: &str = "ed25519+ml-dsa-65";
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

crate::redacted_opaque!(SecretKey);

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

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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

/// Constant-time equality of two byte strings (unequal lengths differ in
/// constant time too). For MACs, confirmation values and tokens.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
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

/// Encrypt with a caller-chosen nonce. Only safe when a nonce is never used
/// twice with one key for different plaintexts. Chunk objects
/// (`crate::chunk_seal`) are the one user: the key is derived from the
/// chunk id and the nonce is a keyed hash of the exact bytes encrypted, so a
/// nonce repeats only for the same input and the ciphertext is
/// deterministic for deduplication.
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

/// The passphrase as it is stretched: Unicode NFKC, so that the same
/// characters typed on a keyboard that composes them differently (a macOS
/// "ä" versus a Windows "ä") give the same key (plan 6.15). There is no
/// fallback to the raw string.
pub fn normalize_passphrase(passphrase: &str) -> String {
    use unicode_normalization::UnicodeNormalization as _;
    passphrase.nfkc().collect()
}

/// Shortest device passphrase (characters after NFKC normalisation).
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Refuse a passphrase that is too short to protect the key file.
pub fn check_passphrase(passphrase: &str) -> Result<()> {
    if normalize_passphrase(passphrase).chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters long");
    }
    Ok(())
}

/// Stretch a passphrase into a wrapping key. The passphrase is NFKC-normalised
/// here and may be any length.
pub fn passphrase_key(passphrase: &str, params: &PassphraseParams) -> Result<SecretKey> {
    let passphrase = zeroize::Zeroizing::new(normalize_passphrase(passphrase));
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

const ED_SEED_LEN: usize = 32;
const ED_PK_LEN: usize = 32;
const ED_SIG_LEN: usize = 64;
const PQ_SEED_LEN: usize = 32;
const PQ_PK_LEN: usize = 1952;
const PQ_SIG_LEN: usize = 3309;

/// Device signing key: Ed25519 plus ML-DSA-65, a hybrid so that a break of
/// either algorithm alone does not let anyone forge what a device signs. The
/// serialised form is the Ed25519 seed followed by the ML-DSA seed (64
/// bytes); nothing else is accepted.
pub struct SigningKey {
    ed: ed25519_dalek::SigningKey,
    pq: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

crate::redacted_opaque!(SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut seed = [0u8; PQ_SEED_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let pq = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from(seed));
        seed.zeroize();
        SigningKey { ed, pq }
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != ED_SEED_LEN + PQ_SEED_LEN {
            bail!(
                "signing key must be {} bytes, got {}",
                ED_SEED_LEN + PQ_SEED_LEN,
                b.len()
            );
        }
        let ed_arr: [u8; ED_SEED_LEN] = b[..ED_SEED_LEN].try_into().unwrap();
        let pq_arr: [u8; PQ_SEED_LEN] = b[ED_SEED_LEN..].try_into().unwrap();
        Ok(SigningKey {
            ed: ed25519_dalek::SigningKey::from_bytes(&ed_arr),
            pq: ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from(pq_arr)),
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.ed.to_bytes().to_vec();
        out.extend_from_slice(self.pq.to_seed().as_slice());
        out
    }
    /// Algorithm identifier of the signatures this key produces.
    pub fn alg(&self) -> &'static str {
        SIG_ALG
    }
    pub fn public(&self) -> VerifyingKey {
        use ml_dsa::Keypair as _;
        VerifyingKey {
            ed: self.ed.verifying_key(),
            pq: self.pq.verifying_key(),
        }
    }
    /// Sign `msg`: the Ed25519 signature followed by the ML-DSA-65
    /// signature (64 + 3309 bytes).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        use ml_dsa::Signer as _;
        let mut out = self.ed.sign(msg).to_bytes().to_vec();
        let sig: ml_dsa::Signature<ml_dsa::MlDsa65> = self.pq.sign(msg);
        out.extend_from_slice(sig.encode().as_slice());
        out
    }
}

/// Device public key: Ed25519 key followed by the ML-DSA-65 key (32 + 1952
/// bytes). Only that length is accepted.
#[derive(Clone)]
pub struct VerifyingKey {
    ed: ed25519_dalek::VerifyingKey,
    pq: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
}

/// Length of a public key in bytes.
pub const PUBLIC_KEY_LEN: usize = ED_PK_LEN + PQ_PK_LEN;

impl VerifyingKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            bail!("public key must be {PUBLIC_KEY_LEN} bytes, got {}", b.len());
        }
        let arr: [u8; ED_PK_LEN] = b[..ED_PK_LEN].try_into().unwrap();
        let ed = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow!("public key: {e}"))?;
        let enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&b[ED_PK_LEN..])
            .map_err(|_| anyhow!("ml-dsa public key length"))?;
        let pq = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc);
        Ok(VerifyingKey { ed, pq })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.ed.to_bytes().to_vec();
        out.extend_from_slice(self.pq.encode().as_slice());
        out
    }
    /// Verify `sig` produced under algorithm `alg`: only the hybrid
    /// algorithm, and both parts must verify, so an attacker who breaks one
    /// algorithm cannot strip the other or downgrade to Ed25519 alone.
    pub fn verify(&self, alg: &str, msg: &[u8], sig: &[u8]) -> Result<()> {
        if alg != SIG_ALG {
            bail!("unsupported signature algorithm {alg}");
        }
        if sig.len() != ED_SIG_LEN + PQ_SIG_LEN {
            bail!("hybrid signature must be {} bytes", ED_SIG_LEN + PQ_SIG_LEN);
        }
        self.verify_ed(msg, &sig[..ED_SIG_LEN])?;
        let pq_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(&sig[ED_SIG_LEN..])
            .map_err(|_| anyhow!("ml-dsa signature: invalid encoding"))?;
        use ml_dsa::Verifier as _;
        self.pq
            .verify(msg, &pq_sig)
            .map_err(|_| anyhow!("ml-dsa signature verification failed"))
    }
    fn verify_ed(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let arr: [u8; ED_SIG_LEN] = sig.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        self.ed
            .verify_strict(msg, &sig)
            .map_err(|_| anyhow!("ed25519 signature verification failed"))
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
        assert_eq!(sk.alg(), SIG_ALG);
        let sig = sk.sign(b"batch");
        assert_eq!(sig.len(), ED_SIG_LEN + PQ_SIG_LEN);
        sk.public().verify(SIG_ALG, b"batch", &sig).unwrap();
        assert!(sk.public().verify(SIG_ALG, b"other", &sig).is_err());
        // Both halves are required: a valid Ed25519 part with a damaged
        // ML-DSA part fails, and so does the reverse.
        let mut t = sig.clone();
        t[ED_SIG_LEN + 10] ^= 1;
        assert!(sk.public().verify(SIG_ALG, b"batch", &t).is_err());
        let mut t = sig.clone();
        t[3] ^= 1;
        assert!(sk.public().verify(SIG_ALG, b"batch", &t).is_err());
        // Downgrade: the Ed25519 half alone is not accepted.
        assert!(sk
            .public()
            .verify("ed25519", b"batch", &sig[..ED_SIG_LEN])
            .is_err());
        assert!(sk
            .public()
            .verify(SIG_ALG, b"batch", &sig[..ED_SIG_LEN])
            .is_err());
        // Keys and public keys round-trip through their byte forms.
        let sk2 = SigningKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk2.public().to_bytes(), sk.public().to_bytes());
        let pk = VerifyingKey::from_bytes(&sk.public().to_bytes()).unwrap();
        pk.verify(SIG_ALG, b"batch", &sk2.sign(b"batch")).unwrap();
    }

    #[test]
    fn ed25519_only_keys_are_refused() {
        // Format 2 has no Ed25519-only keys: neither a 32-byte signing key
        // nor a 32-byte public key is accepted.
        assert!(SigningKey::from_bytes(&[7u8; 32]).is_err());
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(VerifyingKey::from_bytes(ed.verifying_key().as_bytes()).is_err());
        let sk = SigningKey::generate();
        assert_eq!(sk.public().to_bytes().len(), PUBLIC_KEY_LEN);
        assert!(VerifyingKey::from_bytes(&sk.public().to_bytes()[..PUBLIC_KEY_LEN - 1]).is_err());
    }

    #[test]
    fn passphrases_are_nfkc_normalised() {
        // "ä" composed (U+00E4) and decomposed (a + U+0308) give the same key.
        let p = PassphraseParams::new();
        let a = passphrase_key("p\u{e4}ss", &p).unwrap();
        let b = passphrase_key("pa\u{308}ss", &p).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(normalize_passphrase("\u{fb01}"), "fi");
    }

    #[test]
    fn weak_passphrase_params_are_refused() {
        let mut p = PassphraseParams::new();
        p.m_kib = 1024;
        assert!(passphrase_key("x", &p).is_err());
    }
}
