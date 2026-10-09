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
use std::cell::RefCell;

pub const METHOD_RAW: u8 = 0;
pub const METHOD_ZSTD: u8 = 1;
/// zstd level used for every chunk (format constant, see module docs).
pub const ZSTD_LEVEL: i32 = 12;

thread_local! {
    // One zstd context per thread, reused for every chunk. A fresh context
    // costs more than compressing a 256 KiB chunk at this level: its tables
    // are allocated and zeroed every time (four times the work for random
    // data, more for text, measured with the musl allocator of the Linux
    // build). Reuse changes no output byte: zstd resets the context per frame.
    static COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

fn compress(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    COMPRESSOR.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            *c = Some(zstd::bulk::Compressor::new(ZSTD_LEVEL)?);
        }
        c.as_mut().expect("compressor just created").compress(plain)
    })
}

fn decompress(data: &[u8], capacity: usize) -> std::io::Result<Vec<u8>> {
    DECOMPRESSOR.with(|d| {
        let mut d = d.borrow_mut();
        if d.is_none() {
            *d = Some(zstd::bulk::Decompressor::new()?);
        }
        d.as_mut()
            .expect("decompressor just created")
            .decompress(data, capacity)
    })
}

pub fn pack(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len() + 1);
    if plain.len() >= 64 {
        if let Ok(z) = compress(plain) {
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
        METHOD_ZSTD => decompress(data, expected_len as usize)
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
    fn reused_context_matches_a_fresh_one() {
        // Objects are content-addressed: the reused per-thread context must
        // produce exactly the bytes of a one-off compression, whatever it
        // compressed before (larger, smaller, incompressible).
        let mut rnd = vec![0u8; 300_000];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        let inputs: Vec<Vec<u8>> = vec![
            b"log line 200 GET /api/v1/items ".repeat(30_000),
            rnd.clone(),
            b"short but compressible text, ".repeat(10),
            [b"x".repeat(70_000), rnd[..50_000].to_vec()].concat(),
            b"the quick brown fox jumps over the lazy dog. ".repeat(2000),
        ];
        for round in 0..2 {
            for (i, input) in inputs.iter().enumerate() {
                let fresh = zstd::bulk::compress(input, ZSTD_LEVEL).unwrap();
                assert_eq!(compress(input).unwrap(), fresh, "input {i}, round {round}");
                let p = pack(input);
                assert_eq!(unpack(&p, input.len() as u64).unwrap(), *input);
            }
        }
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
