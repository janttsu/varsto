// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Content-defined chunking (Gear rolling hash with FastCDC-style
//! normalisation). A chunk boundary depends only on content, so inserting
//! bytes in the middle of a file shifts only nearby chunks.
//!
//! The chunker streams from any `Read`, holding at most `max` bytes in memory.

use std::io::{self, Read};

#[derive(Clone, Copy, Debug)]
pub struct ChunkerParams {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl ChunkerParams {
    /// Alpha-0 default: 64 KiB minimum, 256 KiB average, 1 MiB maximum.
    /// The plan's target (256 KiB to 4 MiB) will be measured with a prototype.
    pub const DEFAULT: ChunkerParams = ChunkerParams {
        min: 64 * 1024,
        avg: 256 * 1024,
        max: 1024 * 1024,
    };

    /// Small sizes for tests.
    pub const SMALL: ChunkerParams = ChunkerParams {
        min: 1024,
        avg: 4096,
        max: 16384,
    };

    fn validate(&self) -> io::Result<()> {
        if self.min == 0
            || self.min > self.avg
            || self.avg > self.max
            || !self.avg.is_power_of_two()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunker params need 0 < min <= avg <= max and avg a power of two",
            ));
        }
        Ok(())
    }
}

/// Deterministic Gear table (splitmix64 from a fixed seed). Part of the format:
/// changing it changes every chunk boundary.
fn gear_table() -> &'static [u64; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        let mut state: u64 = 0x5f3b_e2a1_c0de_0001;
        for slot in t.iter_mut() {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *slot = z ^ (z >> 31);
        }
        t
    })
}

/// Find the cut point in `buf` (which holds at most `max` bytes and may end
/// at end of file). Returns the length of the next chunk.
pub fn find_cut(buf: &[u8], p: &ChunkerParams) -> usize {
    let n = buf.len().min(p.max);
    if n <= p.min {
        return n;
    }
    let bits = p.avg.trailing_zeros();
    let mask_small: u64 = !0u64 << (64 - (bits + 1)); // stricter before avg
    let mask_large: u64 = !0u64 << (64 - (bits.saturating_sub(1)).max(1)); // looser after avg
    let table = gear_table();
    let mut fp: u64 = 0;
    let avg = p.avg.min(n);
    let mut i = p.min;
    while i < avg {
        fp = (fp << 1).wrapping_add(table[buf[i] as usize]);
        if fp & mask_small == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < n {
        fp = (fp << 1).wrapping_add(table[buf[i] as usize]);
        if fp & mask_large == 0 {
            return i + 1;
        }
        i += 1;
    }
    n
}

/// Streaming chunker: yields consecutive chunks of the reader.
pub struct Chunker<R: Read> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    params: ChunkerParams,
}

impl<R: Read> Chunker<R> {
    pub fn new(reader: R, params: ChunkerParams) -> io::Result<Self> {
        params.validate()?;
        Ok(Chunker {
            reader,
            buf: Vec::with_capacity(params.max * 2),
            eof: false,
            params,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut tmp = vec![0u8; 64 * 1024];
        while !self.eof && self.buf.len() < self.params.max {
            let n = self.reader.read(&mut tmp)?;
            if n == 0 {
                self.eof = true;
            } else {
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }
        Ok(())
    }
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.fill() {
            return Some(Err(e));
        }
        if self.buf.is_empty() {
            return None;
        }
        let cut = find_cut(&self.buf, &self.params);
        let chunk: Vec<u8> = self.buf.drain(..cut).collect();
        Some(Ok(chunk))
    }
}

/// Convenience: chunk a byte slice fully.
pub fn chunk_bytes(data: &[u8], params: ChunkerParams) -> Vec<Vec<u8>> {
    Chunker::new(data, params)
        .expect("valid params")
        .map(|c| c.expect("in-memory read cannot fail"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn chunks_reassemble_and_respect_bounds() {
        let data = pseudo_random(200_000, 7);
        let chunks = chunk_bytes(&data, ChunkerParams::SMALL);
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(joined, data);
        for c in &chunks[..chunks.len() - 1] {
            assert!(c.len() >= ChunkerParams::SMALL.min && c.len() <= ChunkerParams::SMALL.max);
        }
        assert!(
            chunks.len() > 10,
            "expected many chunks, got {}",
            chunks.len()
        );
    }

    #[test]
    fn insertion_shifts_only_local_chunks() {
        let data = pseudo_random(300_000, 11);
        let a = chunk_bytes(&data, ChunkerParams::SMALL);
        let mut modified = data.clone();
        modified.splice(150_000..150_000, b"INSERTED BYTES".iter().cloned());
        let b = chunk_bytes(&modified, ChunkerParams::SMALL);
        let set_a: std::collections::HashSet<Vec<u8>> = a.into_iter().collect();
        let common = b.iter().filter(|c| set_a.contains(*c)).count();
        assert!(
            common * 10 >= b.len() * 8,
            "only {common} of {} chunks shared",
            b.len()
        );
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(chunk_bytes(b"", ChunkerParams::SMALL).is_empty());
    }
}
