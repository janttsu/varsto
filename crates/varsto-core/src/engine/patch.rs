// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Applying a new version of a file onto the bytes already on disk.
//!
//! A small edit of a large file used to be written as a new file: every
//! unchanged block was read, checked and copied. When the new version shares
//! long runs of blocks at the same offsets, those runs stay and only the
//! runs that differ are written.

use crate::manifest::ChunkRef;
use std::path::{Path, PathBuf};

/// How far a resync looks past a difference, in blocks. An edit that moves
/// the cut by more than this is written out again from there.
const WINDOW: usize = 64;

/// Unchanged bytes at or below this are hashed before they are trusted, so
/// a small file that changed under a preserved modification time is still
/// fetched. Above it, a file whose size and modification time still match
/// the index keeps those bytes unread: the scanner uses the same check, and
/// the bit-rot scrub re-hashes large files on its own schedule.
pub const VERIFY_KEEP_UNTIL: u64 = 8 << 20;

/// A write larger than this is not patched in place (the ordinary download
/// copies the blocks into a new file). Keeps the patched ranges small
/// enough to fetch before anything is overwritten.
const MAX_WRITE: u64 = 32 << 20;

/// One run of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Span {
    /// Bytes already at `off` that equal the new version.
    Keep { off: u64, len: u64 },
    /// Blocks to write at `off`.
    Write { off: u64, chunks: Vec<ChunkRef> },
}

/// How to turn `old` into `new` without moving bytes that already sit at
/// the right offset. `None` when keeping them would not be cheaper than
/// writing the file again.
pub(super) fn plan(old: &[ChunkRef], new: &[ChunkRef]) -> Option<Vec<Span>> {
    if old.is_empty() || new.is_empty() {
        return None;
    }
    let old_off = offsets(old);
    let new_off = offsets(new);
    let mut spans: Vec<Span> = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while j < new.len() {
        if i < old.len() && same_place(&old[i], &new[j], old_off[i], new_off[j]) {
            push_keep(&mut spans, new_off[j], new[j].size);
            i += 1;
            j += 1;
            continue;
        }
        let mut found = None;
        for b in 0..WINDOW {
            if j + b >= new.len() {
                break;
            }
            for a in 0..WINDOW {
                if i + a >= old.len() {
                    break;
                }
                if same_place(&old[i + a], &new[j + b], old_off[i + a], new_off[j + b]) {
                    found = Some((a, b));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some((a, b)) = found else {
            push_write(&mut spans, new_off[j], &new[j..]);
            break;
        };
        if b > 0 {
            push_write(&mut spans, new_off[j], &new[j..j + b]);
        }
        i += a;
        j += b;
    }
    let kept = kept_len(&spans);
    let write = write_len(&spans);
    let new_len: u64 = new.iter().map(|c| c.size).sum();
    if kept == 0 || write > MAX_WRITE || (kept < new_len / 2 && kept < VERIFY_KEEP_UNTIL) {
        return None;
    }
    Some(spans)
}

pub(super) fn kept_len(spans: &[Span]) -> u64 {
    spans
        .iter()
        .map(|s| match s {
            Span::Keep { len, .. } => *len,
            Span::Write { .. } => 0,
        })
        .sum()
}

pub(super) fn write_len(spans: &[Span]) -> u64 {
    spans
        .iter()
        .map(|s| match s {
            Span::Write { chunks, .. } => chunks.iter().map(|c| c.size).sum(),
            Span::Keep { .. } => 0,
        })
        .sum()
}

/// The same block at the same offset: nothing to move.
fn same_place(old: &ChunkRef, new: &ChunkRef, old_at: u64, new_at: u64) -> bool {
    old_at == new_at && old.size == new.size && old.chunk == new.chunk
}

fn offsets(chunks: &[ChunkRef]) -> Vec<u64> {
    let mut at = 0u64;
    chunks
        .iter()
        .map(|c| {
            let o = at;
            at += c.size;
            o
        })
        .collect()
}

fn push_keep(spans: &mut Vec<Span>, off: u64, len: u64) {
    if let Some(Span::Keep { len: n, .. }) = spans.last_mut() {
        *n += len;
        return;
    }
    spans.push(Span::Keep { off, len });
}

fn push_write(spans: &mut Vec<Span>, off: u64, chunks: &[ChunkRef]) {
    if chunks.is_empty() {
        return;
    }
    if let Some(Span::Write { chunks: have, .. }) = spans.last_mut() {
        have.extend(chunks.iter().cloned());
        return;
    }
    spans.push(Span::Write {
        off,
        chunks: chunks.to_vec(),
    });
}

/// Same blocks, in order. Object names are not compared: a block can be
/// stored again under a new name and still be the same plaintext.
pub(super) fn same_blocks(a: &[ChunkRef], b: &[ChunkRef]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.chunk == y.chunk && x.size == y.size)
}

/// Folder names whose directories contain `paths`, longest mount first.
/// `None` when any path is outside every mount: the caller syncs everything.
pub fn folder_names_for_paths(
    mounts: &[(String, PathBuf)],
    paths: &[PathBuf],
) -> Option<Vec<String>> {
    if mounts.is_empty() || paths.is_empty() {
        return None;
    }
    let mut names = std::collections::BTreeSet::new();
    for path in paths {
        let mut best: Option<(usize, &str)> = None;
        for (name, root) in mounts {
            if path_under(path, root) {
                let n = root.as_os_str().len();
                if best.map(|(len, _)| n > len).unwrap_or(true) {
                    best = Some((n, name));
                }
            }
        }
        names.insert(best?.1.to_string());
    }
    Some(names.into_iter().collect())
}

fn path_under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ChunkId, ObjectName};

    fn block(n: u8, size: u64) -> ChunkRef {
        ChunkRef {
            chunk: ChunkId::from_bytes(&[n; 16]),
            object: ObjectName::from_bytes(&[n.wrapping_add(9); 16]),
            size,
            epoch: 0,
        }
    }

    #[test]
    fn an_append_keeps_the_old_bytes() {
        let old = vec![block(1, 1000), block(2, 1000)];
        let mut new = old.clone();
        new.push(block(3, 50));
        let spans = plan(&old, &new).unwrap();
        assert_eq!(
            spans,
            vec![
                Span::Keep { off: 0, len: 2000 },
                Span::Write {
                    off: 2000,
                    chunks: vec![block(3, 50)],
                },
            ]
        );
    }

    #[test]
    fn a_middle_edit_keeps_both_ends() {
        let old = vec![block(1, 100), block(2, 100), block(3, 100)];
        let new = vec![block(1, 100), block(9, 100), block(3, 100)];
        let spans = plan(&old, &new).unwrap();
        assert_eq!(kept_len(&spans), 200);
        assert_eq!(write_len(&spans), 100);
        assert!(matches!(spans[1], Span::Write { off: 100, .. }));
    }

    #[test]
    fn a_file_that_shares_nothing_is_written_again() {
        let old = vec![block(1, 100), block(2, 100)];
        let new = vec![block(3, 100), block(4, 100)];
        assert!(plan(&old, &new).is_none());
    }

    #[test]
    fn a_write_past_the_limit_is_not_patched() {
        let keep = block(1, 40 << 20);
        let old_tail: Vec<_> = (0..33).map(|i| block(10 + i, 1 << 20)).collect();
        let new_tail: Vec<_> = (0..33).map(|i| block(80 + i, 1 << 20)).collect();
        let mut old = vec![keep.clone()];
        old.extend(old_tail);
        let mut new = vec![keep];
        new.extend(new_tail);
        assert!(plan(&old, &new).is_none());
    }

    #[test]
    fn a_path_outside_every_folder_syncs_everything() {
        let mounts = vec![("docs".into(), PathBuf::from("/data/docs"))];
        assert!(folder_names_for_paths(&mounts, &[PathBuf::from("/other/a")]).is_none());
        let got = folder_names_for_paths(
            &mounts,
            &[PathBuf::from("/data/docs/a"), PathBuf::from("/data/docs/b")],
        )
        .unwrap();
        assert_eq!(got, vec!["docs".to_string()]);
    }

    #[test]
    fn the_longest_mount_wins() {
        let mounts = vec![
            ("docs".into(), PathBuf::from("/data/docs")),
            ("nested".into(), PathBuf::from("/data/docs/nested")),
        ];
        let got = folder_names_for_paths(&mounts, &[PathBuf::from("/data/docs/nested/a")]).unwrap();
        assert_eq!(got, vec!["nested".to_string()]);
    }
}
