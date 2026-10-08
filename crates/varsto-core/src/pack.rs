// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Chunk payload packing: compression before encryption. Ciphertext does not
//! compress, so a chunk is compressed once, here, and every stored copy and
//! every transfer (cloud, disk, peer on the LAN or across the internet)
//! carries the small form. The level is a format constant: devices must
//! produce byte-identical objects for the same chunk, or deduplication and
//! content addressing break.
//!
//! Payload = one method byte followed by the data: `0` raw, `1` zstd.
//! Compression is skipped when it would save less than 5 %, so already
//! compressed media costs nothing but the byte.

use anyhow::{anyhow, bail, Result};

pub const METHOD_RAW: u8 = 0;
pub const METHOD_ZSTD: u8 = 1;
/// zstd level used for every chunk (format constant, see module docs).
pub const ZSTD_LEVEL: i32 = 12;

pub fn pack(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len() + 1);
    if plain.len() >= 64 {
        if let Ok(z) = zstd::bulk::compress(plain, ZSTD_LEVEL) {
            if z.len() + 1 < plain.len() - plain.len() / 20 {
                out.push(METHOD_ZSTD);
                out.extend_from_slice(&z);
                return out;
            }
        }
    }
    out.push(METHOD_RAW);
    out.extend_from_slice(plain);
    out
}

pub fn unpack(payload: &[u8], expected_len: u64) -> Result<Vec<u8>> {
    let (method, data) = payload
        .split_first()
        .ok_or_else(|| anyhow!("empty chunk payload"))?;
    let plain = match *method {
        METHOD_RAW => data.to_vec(),
        METHOD_ZSTD => zstd::bulk::decompress(data, expected_len as usize)
            .map_err(|e| anyhow!("chunk decompression failed: {e}"))?,
        m => bail!("unknown chunk packing method {m}"),
    };
    if plain.len() as u64 != expected_len {
        bail!(
            "chunk length {} does not match the manifest ({expected_len})",
            plain.len()
        );
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_data_shrinks_and_roundtrips() {
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog. ".repeat(2000);
        let p = pack(&text);
        assert_eq!(p[0], METHOD_ZSTD);
        assert!(p.len() < text.len() / 10, "{} vs {}", p.len(), text.len());
        assert_eq!(unpack(&p, text.len() as u64).unwrap(), text);
        assert!(unpack(&p, text.len() as u64 + 1).is_err());
        // Deterministic: the same bytes every time (content addressing relies on it).
        assert_eq!(pack(&text), p);
    }

    #[test]
    fn incompressible_data_is_stored_raw() {
        let mut rnd = vec![0u8; 100_000];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        let p = pack(&rnd);
        assert_eq!(p[0], METHOD_RAW);
        assert_eq!(p.len(), rnd.len() + 1);
        assert_eq!(unpack(&p, rnd.len() as u64).unwrap(), rnd);
        assert!(unpack(&[9, 1, 2], 2).is_err());
    }
}
