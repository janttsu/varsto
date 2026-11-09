// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Reuse the unchanged prefix of a file that already has blocks.
//!
//! A gear cut depends only on the bytes since the previous cut, so a change
//! leaves every block before it valid. Hashing those blocks and keeping
//! their ids avoids walking the gear table, and compressing and encrypting,
//! over the prefix. The tail, from the first block that differs (and from
//! the last block when the file grew), is cut again.

use crate::crypto::{self, KeyedHasher, SecretKey};
use crate::ids::ChunkId;
use crate::manifest::{ChunkRef, MAX_CHUNK_SIZE};
use std::io::{self, Read, Seek, SeekFrom};

/// Blocks of `old` that still occupy the start of `file`, in order.
/// `file` is left at the first byte that has to be cut again.
pub(super) fn keep_prefix<R: Read + Seek>(
    file: &mut R,
    old: &[ChunkRef],
    key: &SecretKey,
    hasher: &mut KeyedHasher,
) -> io::Result<Vec<ChunkRef>> {
    let mut kept = Vec::new();
    let mut offset = 0u64;
    for (i, chunk) in old.iter().enumerate() {
        if chunk.size == 0 || chunk.size > MAX_CHUNK_SIZE {
            file.seek(SeekFrom::Start(offset))?;
            return Ok(kept);
        }
        let mut buf = vec![0u8; chunk.size as usize];
        match file.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                file.seek(SeekFrom::Start(offset))?;
                return Ok(kept);
            }
            Err(e) => return Err(e),
        }
        if ChunkId::from_bytes(&crypto::keyed_hash(key, &buf)) != chunk.chunk {
            file.seek(SeekFrom::Start(offset))?;
            return Ok(kept);
        }
        // The last block of a file may end because the file ended, not
        // because the gear hash cut there. Bytes appended after it belong
        // to a new cut of that same block.
        if i + 1 == old.len() {
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? > 0 {
                file.seek(SeekFrom::Start(offset))?;
                return Ok(kept);
            }
        }
        hasher.update(&buf);
        kept.push(chunk.clone());
        offset += chunk.size;
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::{chunk_bytes, Chunker, ChunkerParams};
    use crate::ids::ObjectName;
    use std::io::Cursor;

    fn refs(parts: &[Vec<u8>], key: &SecretKey) -> Vec<ChunkRef> {
        parts
            .iter()
            .map(|p| ChunkRef {
                chunk: ChunkId::from_bytes(&crypto::keyed_hash(key, p)),
                object: ObjectName::from_bytes(&crypto::hash(p)),
                size: p.len() as u64,
                epoch: 0,
            })
            .collect()
    }

    fn cut_all(data: &[u8], params: ChunkerParams, key: &SecretKey) -> Vec<ChunkRef> {
        let mut hasher = KeyedHasher::new(key);
        let mut file = Cursor::new(data.to_vec());
        let old = refs(&chunk_bytes(data, params), key);
        let kept = keep_prefix(&mut file, &old, key, &mut hasher).unwrap();
        assert_eq!(kept.len(), old.len());
        assert_eq!(hasher.finalize(), *blake3::keyed_hash(&key.0, data).as_bytes());
        kept
    }

    #[test]
    fn an_unchanged_file_keeps_every_block() {
        let key = SecretKey([3u8; 32]);
        let params = ChunkerParams::SMALL.with_seed(&[9u8; 32]);
        let mut data = vec![0u8; 80_000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 17) as u8;
        }
        let kept = cut_all(&data, params, &key);
        assert!(kept.len() > 2);
    }

    #[test]
    fn a_change_in_the_middle_keeps_the_prefix_and_recuts_the_tail() {
        let key = SecretKey([3u8; 32]);
        let params = ChunkerParams::SMALL.with_seed(&[9u8; 32]);
        let mut data = vec![0u8; 80_000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 17) as u8;
        }
        let old = refs(&chunk_bytes(&data, params), &key);
        data[40_000] ^= 0xff;
        let mut hasher = KeyedHasher::new(&key);
        let mut file = Cursor::new(data.clone());
        let kept = keep_prefix(&mut file, &old, &key, &mut hasher).unwrap();
        assert!(!kept.is_empty());
        assert!(kept.len() < old.len());
        let tail: Vec<Vec<u8>> = Chunker::new(file, params)
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        for part in &tail {
            hasher.update(part);
        }
        let fresh = refs(&tail, &key);
        assert_ne!(fresh[0].chunk, old[kept.len()].chunk);
        assert_eq!(hasher.finalize(), *blake3::keyed_hash(&key.0, &data).as_bytes());
        let whole = refs(&chunk_bytes(&data, params), &key);
        let mut got = kept;
        got.extend(fresh);
        assert_eq!(got, whole);
    }
}
