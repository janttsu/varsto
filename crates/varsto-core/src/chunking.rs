// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Content-defined chunking (Gear rolling hash with FastCDC-style
//! normalisation). A chunk boundary depends only on content, so inserting
//! bytes in the middle of a file shifts only nearby chunks.
//!
//! Format 2 keys the Gear table: it is derived from a seed of the folder
//! (`FolderKeys::chunker_seed`, from the folder hash key K11), so where a
//! file is cut is secret per folder, and the same file pushed to two
//! folders is cut differently. K11 does not change with key epochs, so the
//! cuts (and with them deduplication) survive a rotation.
//!
//! The chunker streams from any `Read`, holding at most `max` bytes in memory.

use std::io::{self, Read};

/// The chunking a file entry was cut with (`FileState::chunking`): the
/// size tiers of [`ChunkerParams::for_size`] and a keyed Gear table.
pub const CHUNKING: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkerParams {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
    /// Seed of the Gear table (format 2: per folder).
    pub seed: [u8; 32],
}

impl ChunkerParams {
    /// Files under 1 MiB: one block (a file is never larger than `min`).
    pub const ONE_BLOCK: ChunkerParams = ChunkerParams {
        min: 1 << 20,
        avg: 1 << 20,
        max: 1 << 20,
        seed: [0; 32],
    };

    /// Files from 1 MiB to 32 MiB (and content of unknown size): 256 KiB
    /// minimum, 1 MiB average, 4 MiB maximum.
    pub const DEFAULT: ChunkerParams = ChunkerParams {
        min: 256 << 10,
        avg: 1 << 20,
        max: 4 << 20,
        seed: [0; 32],
    };

    /// Files from 32 MiB to 1 GiB: 1 MiB minimum, 4 MiB average, 16 MiB
    /// maximum.
    pub const MEDIUM: ChunkerParams = ChunkerParams {
        min: 1 << 20,
        avg: 4 << 20,
        max: 16 << 20,
        seed: [0; 32],
    };

    /// Files from 1 GiB: 2 MiB minimum, 8 MiB average, 16 MiB maximum. A
    /// 50 GB file is about 6 000 blocks: a short file list, few ledger
    /// events and requests, while a change in the middle still rewrites
    /// only a few megabytes.
    pub const LARGE: ChunkerParams = ChunkerParams {
        min: 2 << 20,
        avg: 8 << 20,
        max: 16 << 20,
        seed: [0; 32],
    };

    /// The block sizes for a file of `size` bytes in a folder with chunker
    /// seed `seed` (format 2, `chunking: 2` in the file entry). Depends on
    /// the size and the folder alone, so the same content in one folder
    /// gives the same blocks on every device. Photos and other files that
    /// never deduplicate inside themselves stay a handful of blocks.
    pub fn for_size(size: u64, seed: &[u8; 32]) -> ChunkerParams {
        let tier = if size >= 1 << 30 {
            Self::LARGE
        } else if size >= 32 << 20 {
            Self::MEDIUM
        } else if size >= 1 << 20 {
            Self::DEFAULT
        } else {
            Self::ONE_BLOCK
        };
        tier.with_seed(seed)
    }

    /// The same sizes with another Gear table seed.
    pub fn with_seed(mut self, seed: &[u8; 32]) -> ChunkerParams {
        self.seed = *seed;
        self
    }

    /// Whether these are the sizes of a tier (seed aside): what an engine
    /// left at its default uses.
    pub fn same_sizes(&self, other: &ChunkerParams) -> bool {
        (self.min, self.avg, self.max) == (other.min, other.avg, other.max)
    }

    /// Small sizes for tests.
    pub const SMALL: ChunkerParams = ChunkerParams {
        min: 1024,
        avg: 4096,
        max: 16384,
        seed: [0; 32],
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

/// The Gear table of a seed: 256 words of BLAKE3 output keyed by the seed.
/// Part of the format: another table cuts every file elsewhere.
pub fn gear_table(seed: &[u8; 32]) -> Box<[u64; 256]> {
    let mut bytes = [0u8; 256 * 8];
    blake3::Hasher::new_keyed(seed)
        .update(b"varsto gear table")
        .finalize_xof()
        .fill(&mut bytes);
    let mut t = Box::new([0u64; 256]);
    for (slot, b) in t.iter_mut().zip(bytes.chunks_exact(8)) {
        *slot = u64::from_le_bytes(b.try_into().expect("8 bytes"));
    }
    t
}

/// Find the cut point in `buf` (which holds at most `max` bytes and may end
/// at end of file) with Gear table `table`. Returns the length of the next
/// chunk.
pub fn find_cut(buf: &[u8], p: &ChunkerParams, table: &[u64; 256]) -> usize {
    let n = buf.len().min(p.max);
    if n <= p.min {
        return n;
    }
    let bits = p.avg.trailing_zeros();
    let mask_small: u64 = !0u64 << (64 - (bits + 1)); // stricter before avg
    let mask_large: u64 = !0u64 << (64 - (bits.saturating_sub(1)).max(1)); // looser after avg
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
    table: Box<[u64; 256]>,
}

impl<R: Read> Chunker<R> {
    pub fn new(reader: R, params: ChunkerParams) -> io::Result<Self> {
        params.validate()?;
        Ok(Chunker {
            reader,
            buf: Vec::with_capacity(params.max * 2),
            eof: false,
            table: gear_table(&params.seed),
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
        let cut = find_cut(&self.buf, &self.params, &self.table);
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
    fn the_seed_decides_the_cuts() {
        let data = pseudo_random(400_000, 13);
        let seeded = |b: u8| chunk_bytes(&data, ChunkerParams::SMALL.with_seed(&[b; 32]));
        let lens = |c: &Vec<Vec<u8>>| c.iter().map(Vec::len).collect::<Vec<_>>();
        // The same seed cuts the same way every time.
        assert_eq!(seeded(1), seeded(1));
        // Other seeds cut elsewhere: no two of these share their sizes.
        let all: Vec<Vec<usize>> = (1..=8).map(|b| lens(&seeded(b))).collect();
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j], "seeds {} and {} cut alike", i + 1, j + 1);
            }
        }
        for b in 1..=8 {
            assert_eq!(seeded(b).concat(), data);
        }
    }

    #[test]
    fn size_tiers() {
        let seed = [5; 32];
        let tier = |n: u64| ChunkerParams::for_size(n, &seed);
        assert!(tier(0).same_sizes(&ChunkerParams::ONE_BLOCK));
        assert!(tier((1 << 20) - 1).same_sizes(&ChunkerParams::ONE_BLOCK));
        assert!(tier(1 << 20).same_sizes(&ChunkerParams::DEFAULT));
        assert!(tier((32 << 20) - 1).same_sizes(&ChunkerParams::DEFAULT));
        assert!(tier(32 << 20).same_sizes(&ChunkerParams::MEDIUM));
        assert!(tier(1 << 30).same_sizes(&ChunkerParams::LARGE));
        assert_eq!(tier(1 << 30).seed, seed);
        // A file under 1 MiB is one block.
        let data = pseudo_random((1 << 20) - 1, 3);
        assert_eq!(chunk_bytes(&data, tier(data.len() as u64)).len(), 1);
        for p in [
            ChunkerParams::ONE_BLOCK,
            ChunkerParams::DEFAULT,
            ChunkerParams::MEDIUM,
            ChunkerParams::LARGE,
        ] {
            p.validate().unwrap();
            assert!(p.max as u64 <= crate::manifest::MAX_CHUNK_SIZE);
        }
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(chunk_bytes(b"", ChunkerParams::SMALL).is_empty());
    }
}
