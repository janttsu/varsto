// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Chunk payload packing: compression before encryption. Ciphertext does not
//! compress, so a chunk is compressed once, here, and every stored copy and
//! every transfer (cloud, disk, peer on the LAN or across the internet)
//! carries the small form.
//!
//! Payload = one method byte followed by the data: `0` raw, `1` zstd at
//! level 3 (format 2). Whether a chunk is compressed depends on its content
//! alone: its first 64 KiB are compressed at level 1 as a probe, and only
//! when the probe saves at least 5 % is the whole chunk compressed; the
//! result is kept when it saves at least 5 % too. Media and other
//! compressed content therefore cost a cheap probe and the byte.
//!
//! The bytes are not required to be identical across zstd versions: the
//! nonce of a chunk object follows the packed bytes (`crate::chunk_seal`),
//! so another encoding is another object, never the same nonce over other
//! bytes.

use anyhow::{anyhow, bail, Result};
use std::cell::RefCell;

pub const METHOD_RAW: u8 = 0;
pub const METHOD_ZSTD: u8 = 1;
/// zstd level of every compressed chunk (format 2).
pub const ZSTD_LEVEL: i32 = 3;
/// Level and length of the probe that decides whether to compress.
pub const PROBE_LEVEL: i32 = 1;
pub const PROBE_BYTES: usize = 64 << 10;
/// Chunks shorter than this are stored raw.
const MIN_COMPRESS: usize = 64;

thread_local! {
    // One zstd context per thread and level, reused for every chunk. A
    // fresh context costs about as much as compressing a chunk: its tables
    // are allocated and zeroed every time. Reuse changes no output byte:
    // zstd resets the context per frame.
    static COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static PROBE: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

fn compress_with(
    slot: &'static std::thread::LocalKey<RefCell<Option<zstd::bulk::Compressor<'static>>>>,
    level: i32,
    plain: &[u8],
) -> std::io::Result<Vec<u8>> {
    slot.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            *c = Some(zstd::bulk::Compressor::new(level)?);
        }
        c.as_mut().expect("compressor just created").compress(plain)
    })
}

fn compress(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    compress_with(&COMPRESSOR, ZSTD_LEVEL, plain)
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

/// Whether `compressed` bytes save at least 5 % of `plain` bytes.
fn saves(compressed: usize, plain: usize) -> bool {
    compressed + 1 < plain - plain / 20
}

/// Whether the chunk's first 64 KiB compress at all (level 1).
fn worth_compressing(plain: &[u8]) -> bool {
    let head = &plain[..plain.len().min(PROBE_BYTES)];
    compress_with(&PROBE, PROBE_LEVEL, head).is_ok_and(|z| saves(z.len(), head.len()))
}

pub fn pack(plain: &[u8]) -> Vec<u8> {
    if plain.len() >= MIN_COMPRESS && worth_compressing(plain) {
        if let Ok(z) = compress(plain) {
            if saves(z.len(), plain.len()) {
                let mut out = Vec::with_capacity(z.len() + 1);
                out.push(METHOD_ZSTD);
                out.extend_from_slice(&z);
                return out;
            }
        }
    }
    let mut out = Vec::with_capacity(plain.len() + 1);
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
        METHOD_ZSTD => {
            if expected_len > crate::manifest::MAX_CHUNK_SIZE {
                bail!("chunk of {expected_len} bytes is larger than any chunk can be");
            }
            decompress(data, expected_len as usize)
                .map_err(|e| anyhow!("chunk decompression failed: {e}"))?
        }
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
    fn the_probe_decides_by_the_first_64_kib() {
        let mut rnd = vec![0u8; 2_000_000];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        let text = b"2026-10-14 12:00:01 GET /api/v1/items 200 ".repeat(5000);
        // Random head, compressible tail: stored raw, whatever the tail.
        let random_head = [&rnd[..PROBE_BYTES], &text[..]].concat();
        assert_eq!(pack(&random_head)[0], METHOD_RAW);
        // Compressible head, random tail: compressed when the whole saves 5 %.
        let text_head = [&text[..], &rnd[..50_000]].concat();
        let p = pack(&text_head);
        assert_eq!(p[0], METHOD_ZSTD);
        assert_eq!(unpack(&p, text_head.len() as u64).unwrap(), text_head);
        // Compressible head but mostly random (64 KiB of text in 2 MB): the
        // probe says yes, the whole saves too little, so raw.
        let mostly_random = [&text[..PROBE_BYTES], &rnd[..]].concat();
        assert_eq!(pack(&mostly_random)[0], METHOD_RAW);
        // Short chunks are raw.
        assert_eq!(pack(&[b'a'; 63])[0], METHOD_RAW);
        assert_eq!(pack(&[b'a'; 64])[0], METHOD_ZSTD);
    }

    /// Ad-hoc throughput comparison of the format-1 packing (zstd 12, no
    /// probe) and this one, on text and on random data:
    /// `cargo test --release -p varsto-core --lib pack::tests::throughput -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn throughput() {
        fn old_pack(plain: &[u8]) -> Vec<u8> {
            let z = zstd::bulk::compress(plain, 12).unwrap();
            if z.len() + 1 < plain.len() - plain.len() / 20 {
                [&[METHOD_ZSTD][..], &z].concat()
            } else {
                [&[METHOD_RAW][..], plain].concat()
            }
        }
        let chunk = 1 << 20;
        let total = 64 << 20;
        let mut text = Vec::with_capacity(total);
        let mut i = 0u64;
        while text.len() < total {
            text.extend_from_slice(
                format!(
                    "2026-10-14T12:{:02}:{:02}Z host-{} GET /api/v1/items/{} 200 {} ms user={}\n",
                    i % 60,
                    (i * 7) % 60,
                    i % 13,
                    i * 31 % 100_000,
                    i % 997,
                    i % 41
                )
                .as_bytes(),
            );
            i += 1;
        }
        text.truncate(total);
        let mut rnd = vec![0u8; total];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        for (label, data) in [("text", &text), ("random", &rnd)] {
            for (name, f) in [
                ("format 1 (zstd 12)", old_pack as fn(&[u8]) -> Vec<u8>),
                ("format 2 (probe, zstd 3)", pack as fn(&[u8]) -> Vec<u8>),
            ] {
                let t = std::time::Instant::now();
                let out: usize = data.chunks(chunk).map(|c| f(c).len()).sum();
                let secs = t.elapsed().as_secs_f64();
                println!(
                    "{label:6} {name:26} {:7.1} MB/s, stored {:5.1} % of {} MiB",
                    data.len() as f64 / secs / 1e6,
                    out as f64 * 100.0 / data.len() as f64,
                    data.len() >> 20
                );
            }
        }
    }

    #[test]
    fn every_length_round_trips() {
        for n in [1usize, 63, 64, 4095, 4096, 300_000, 16 << 20] {
            let text: Vec<u8> = b"round trip ".iter().cycle().take(n).copied().collect();
            let mut rnd = vec![0u8; n];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
            for plain in [text, rnd] {
                let p = pack(&plain);
                assert!(p.len() <= plain.len() + 1, "{n}: packed {}", p.len());
                assert_eq!(unpack(&p, n as u64).unwrap(), plain, "{n}");
                assert_eq!(pack(&plain), p, "{n}: deterministic");
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
