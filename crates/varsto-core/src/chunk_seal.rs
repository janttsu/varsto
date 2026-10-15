// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Sealing and opening chunk objects (format 2).
//!
//! Every chunk object is made by [`seal_chunk`] and read by [`open_chunk`],
//! whatever writes or reads it (a push, the block cache, an import, a data
//! move, a Strongroom conversion, a peer serving the object again):
//!
//! - the plaintext is packed (`crate::pack`: method byte and payload);
//! - the key is the chunk key of the folder, epoch and chunk id;
//! - the nonce is a keyed hash of the packed bytes
//!   (`FolderKeys::chunk_nonce`), so a nonce is never used for two
//!   different inputs under one key, even when two devices pack the same
//!   chunk differently;
//! - the associated data binds vault, folder, epoch, chunk id, plaintext
//!   length and packed length.
//!
//! The result is `nonce || ciphertext || tag`, named by its plain BLAKE3
//! hash (the object name).

use crate::crypto::{self, NONCE_LEN};
use crate::ids::{ChunkId, VaultId};
use crate::vault::FolderKeys;
use anyhow::{anyhow, bail, Result};

/// Bytes an object adds to its packed chunk: nonce and tag.
pub const OBJECT_OVERHEAD: usize = NONCE_LEN + 16;

/// The object of one chunk: deterministic, so every device that seals the
/// same chunk under the same epoch (and packs it the same way) gets the
/// same bytes.
pub fn seal_chunk(
    fk: &FolderKeys,
    vault: &VaultId,
    chunk: &ChunkId,
    epoch: u32,
    plain: &[u8],
) -> Result<Vec<u8>> {
    seal_packed(
        fk,
        vault,
        chunk,
        epoch,
        plain.len() as u64,
        &crate::pack::pack(plain),
    )
}

/// `seal_chunk` for bytes already packed (`crate::pack::pack`).
pub fn seal_packed(
    fk: &FolderKeys,
    vault: &VaultId,
    chunk: &ChunkId,
    epoch: u32,
    plain_len: u64,
    packed: &[u8],
) -> Result<Vec<u8>> {
    crypto::encrypt_with_nonce(
        &fk.chunk_key(epoch, chunk)?,
        &fk.chunk_nonce(epoch, packed)?,
        &fk.chunk_aad(vault, epoch, chunk, plain_len, packed.len() as u64),
        packed,
    )
}

/// Decrypt one object of chunk `chunk` (`size` plaintext bytes, key epoch
/// `epoch`), check that its nonce is the one the packed bytes give, unpack
/// it and check the plaintext against the chunk id.
pub fn open_chunk(
    fk: &FolderKeys,
    vault: &VaultId,
    chunk: &ChunkId,
    epoch: u32,
    size: u64,
    object: &[u8],
) -> Result<Vec<u8>> {
    let packed_len = object
        .len()
        .checked_sub(OBJECT_OVERHEAD)
        .ok_or_else(|| anyhow!("chunk object too short"))?;
    let packed = crypto::decrypt(
        &fk.chunk_key(epoch, chunk)?,
        &fk.chunk_aad(vault, epoch, chunk, size, packed_len as u64),
        object,
    )?;
    // A writer that chose its own nonce is not following the format: its
    // object would not be the one every other device makes.
    if fk.chunk_nonce(epoch, &packed)?[..] != object[..NONCE_LEN] {
        bail!(
            "chunk {} has a nonce the format does not give",
            chunk.short()
        );
    }
    let plain = crate::pack::unpack(&packed, size)?;
    if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain)) != *chunk {
        bail!("chunk {} failed its content check", chunk.short());
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::ids::FolderId;
    use std::collections::BTreeSet;

    fn keys() -> FolderKeys {
        FolderKeys::from_folder_key(&FolderId::from_bytes(&[3; 16]), SecretKey([7; 32])).unwrap()
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Property: over many chunks and many encodings of each (raw, the
    /// format's zstd, other zstd levels standing in for another library
    /// version), two different packed byte strings never get the same
    /// nonce, and the same bytes always get the same nonce.
    #[test]
    fn different_encodings_never_share_a_nonce() {
        let fk = keys();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut seen: std::collections::HashMap<[u8; NONCE_LEN], Vec<u8>> = Default::default();
        for round in 0..200 {
            let len = 1 + (rng.next() % 20_000) as usize;
            let plain = if round % 2 == 0 {
                rng.bytes(len)
            } else {
                // Compressible: repeated words.
                b"lorem ipsum dolor sit amet "
                    .iter()
                    .cycle()
                    .take(len)
                    .copied()
                    .collect()
            };
            let mut encodings: BTreeSet<Vec<u8>> = BTreeSet::new();
            encodings.insert([&[crate::pack::METHOD_RAW][..], &plain].concat());
            encodings.insert(crate::pack::pack(&plain));
            for level in [1, 3, 9, 19] {
                let z = zstd::bulk::compress(&plain, level).unwrap();
                encodings.insert([&[crate::pack::METHOD_ZSTD][..], &z].concat());
            }
            for packed in encodings {
                let n = fk.chunk_nonce(0, &packed).unwrap();
                assert_eq!(n, fk.chunk_nonce(0, &packed).unwrap(), "same bytes");
                if let Some(prev) = seen.insert(n, packed.clone()) {
                    assert_eq!(prev, packed, "two encodings share a nonce");
                }
            }
        }
        // Another epoch's key gives other nonces for the same bytes.
        let later = keys().with_epochs([(1u32, SecretKey([9; 32]))].into());
        let packed = crate::pack::pack(b"same bytes in two epochs");
        assert_ne!(
            later.chunk_nonce(0, &packed).unwrap(),
            later.chunk_nonce(1, &packed).unwrap()
        );
    }

    #[test]
    fn sealed_chunks_open_and_are_deterministic() {
        let fk = keys();
        let vault = VaultId::from_bytes(&[1; 16]);
        for plain in [
            b"x".to_vec(),
            b"compressible text, ".repeat(5000),
            Rng(5).bytes(70_000),
        ] {
            let chunk = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain));
            let a = seal_chunk(&fk, &vault, &chunk, 0, &plain).unwrap();
            assert_eq!(a, seal_chunk(&fk, &vault, &chunk, 0, &plain).unwrap());
            let n = plain.len() as u64;
            assert_eq!(open_chunk(&fk, &vault, &chunk, 0, n, &a).unwrap(), plain);
            // Wrong size, wrong epoch, damaged bytes: refused.
            assert!(open_chunk(&fk, &vault, &chunk, 0, n + 1, &a).is_err());
            assert!(open_chunk(&fk, &vault, &chunk, 1, n, &a).is_err());
            let mut bad = a.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(open_chunk(&fk, &vault, &chunk, 0, n, &bad).is_err());
        }
    }

    #[test]
    fn an_object_with_a_chosen_nonce_is_refused() {
        let fk = keys();
        let vault = VaultId::from_bytes(&[1; 16]);
        let plain = b"chosen nonce".to_vec();
        let chunk = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain));
        let packed = crate::pack::pack(&plain);
        let forged = crypto::encrypt_with_nonce(
            &fk.chunk_key(0, &chunk).unwrap(),
            &[0u8; NONCE_LEN],
            &fk.chunk_aad(&vault, 0, &chunk, plain.len() as u64, packed.len() as u64),
            &packed,
        )
        .unwrap();
        let err = open_chunk(&fk, &vault, &chunk, 0, plain.len() as u64, &forged).unwrap_err();
        assert!(format!("{err:#}").contains("nonce"), "{err:#}");
    }
}
