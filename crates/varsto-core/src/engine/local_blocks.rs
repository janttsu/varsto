// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Blocks a pull takes from this device instead of a peer or a storage.
//!
//! A block is named by its chunk id, the folder's keyed hash of its
//! plaintext, so any file of the folder on this device whose recorded
//! version lists that chunk can supply it: the previous version of a file
//! that changed (only the changed blocks are new), a file that was renamed
//! or moved, a copy of the same content, and every file this pull has
//! already written (blocks fetched earlier in the same pull, also earlier
//! in the same file). The index is built from the folder state after the
//! pull's scan and is only a hint: every block read is hashed again and
//! used only when it matches its chunk id, so a file that changed under
//! the index costs a read and falls back to the network.
//!
//! Sources are files under the folder's directory and, for files the pull
//! moved to the trash (a deletion that is the other half of a rename), the
//! trash copy. A source is opened only when it is a regular file (not a
//! link, not a pipe) whose real directory lies under the directory it was
//! registered under, so no link leads a read out of the folder. Nothing is
//! kept in memory but the index (about 24 bytes per block) and the block
//! being copied.
//!
//! Chunk ids are keyed per folder (K11 is derived with the folder id), so a
//! block of one folder never has the id of a block of another: the sources
//! are the files of the folder being pulled.

use crate::crypto;
use crate::ids::ChunkId;
use crate::manifest::{ChunkRef, MAX_CHUNK_SIZE};
use crate::vault::FolderKeys;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Places kept per block: copies of one block in many files need only a
/// few candidates (a source that went stale gives way to a live one).
const CANDIDATES: usize = 4;

/// Where one block lies in one source.
#[derive(Clone, Copy, Debug)]
struct Loc {
    offset: u64,
    src: u32,
    size: u32,
}

#[derive(Debug)]
struct Source {
    disk: PathBuf,
    /// Index into `LocalBlocks::bases`: the directory the file must be in.
    base: usize,
    /// False once the file is known to hold something else (overwritten,
    /// failed its check, a download that did not finish).
    live: bool,
}

/// What a pull can copy locally, by chunk id (see the module comment).
#[derive(Debug, Default)]
pub(super) struct LocalBlocks {
    /// Canonical directories sources may be in.
    bases: Vec<PathBuf>,
    /// `bases` by the path they were given as.
    base_of: HashMap<PathBuf, usize>,
    sources: Vec<Source>,
    /// The live source at each disk path.
    at: HashMap<PathBuf, u32>,
    /// Candidates by the first 8 bytes of the chunk id (a collision only
    /// costs a read that fails its check).
    blocks: HashMap<u64, Vec<Loc>>,
    /// The temporary file a download is writing (its blocks so far).
    temp: Option<u32>,
    /// The source opened last: consecutive blocks of one file are read
    /// through one handle.
    open: Option<(u32, fs::File)>,
}

fn key(chunk: &ChunkId) -> u64 {
    let s = chunk.as_str();
    u64::from_str_radix(s.get(..16).unwrap_or(s), 16).unwrap_or(0)
}

/// Open `disk` for reading without following a link at the last component
/// and without blocking on a pipe; `None` unless it is a regular file and
/// the file opened is the one looked at.
fn open_regular(disk: &Path) -> Option<fs::File> {
    let md = fs::symlink_metadata(disk).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = opts.open(disk).ok()?;
    let fmd = f.metadata().ok()?;
    if !fmd.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fmd.ino() != md.ino() || fmd.dev() != md.dev() {
            return None;
        }
    }
    Some(f)
}

impl LocalBlocks {
    /// Register `dir` as a directory sources may be in; its index.
    fn base(&mut self, dir: &Path) -> Option<usize> {
        if let Some(i) = self.base_of.get(dir) {
            return Some(*i);
        }
        let real = fs::canonicalize(dir).ok()?;
        let i = match self.bases.iter().position(|b| *b == real) {
            Some(i) => i,
            None => {
                self.bases.push(real);
                self.bases.len() - 1
            }
        };
        self.base_of.insert(dir.to_path_buf(), i);
        Some(i)
    }

    /// A file at `disk` (under `dir`) whose content is `chunks`, in order.
    /// Replaces what was known at `disk`. Returns the source.
    pub(super) fn add_file(&mut self, dir: &Path, disk: &Path, chunks: &[ChunkRef]) -> Option<u32> {
        let src = self.add_source(dir, disk)?;
        self.at.insert(disk.to_path_buf(), src);
        let mut offset = 0u64;
        for c in chunks {
            self.add_loc(src, c, offset);
            offset += c.size;
        }
        Some(src)
    }

    fn add_source(&mut self, dir: &Path, disk: &Path) -> Option<u32> {
        let base = self.base(dir)?;
        if let Some(old) = self.at.remove(disk) {
            self.kill(old);
        }
        let src = u32::try_from(self.sources.len()).ok()?;
        self.sources.push(Source {
            disk: disk.to_path_buf(),
            base,
            live: true,
        });
        Some(src)
    }

    fn add_loc(&mut self, src: u32, c: &ChunkRef, offset: u64) {
        let Ok(size) = u32::try_from(c.size) else {
            return;
        };
        if c.size == 0 || c.size > MAX_CHUNK_SIZE {
            return;
        }
        let loc = Loc { offset, src, size };
        let list = self.blocks.entry(key(&c.chunk)).or_default();
        if list.iter().any(|l| l.src == src && l.size == size) {
            return; // one place per file is enough
        }
        if list.len() < CANDIDATES {
            list.push(loc);
        } else if let Some(slot) = list.iter_mut().find(|l| !self.sources[l.src as usize].live) {
            *slot = loc;
        }
    }

    fn kill(&mut self, src: u32) {
        if let Some(s) = self.sources.get_mut(src as usize) {
            s.live = false;
        }
        if self.open.as_ref().is_some_and(|(o, _)| *o == src) {
            self.open = None;
        }
    }

    /// The file at `from` is now at `to` (under `dir`), unchanged: moved to
    /// the trash or to its conflict copy.
    pub(super) fn moved(&mut self, from: &Path, dir: &Path, to: &Path) {
        let Some(src) = self.at.remove(from) else {
            return;
        };
        match self.base(dir) {
            Some(base) => {
                if let Some(old) = self.at.insert(to.to_path_buf(), src) {
                    if old != src {
                        self.kill(old);
                    }
                }
                let s = &mut self.sources[src as usize];
                s.disk = to.to_path_buf();
                s.base = base;
                if self.open.as_ref().is_some_and(|(o, _)| *o == src) {
                    self.open = None;
                }
            }
            None => self.kill(src),
        }
    }

    /// A download starts writing `tmp` (under `dir`): its blocks become
    /// sources as they are written (`wrote`).
    pub(super) fn begin_temp(&mut self, dir: &Path, tmp: &Path) {
        self.end_temp();
        self.temp = self.add_source(dir, tmp);
    }

    /// Block `c` is now in the temporary file at `offset`.
    pub(super) fn wrote(&mut self, c: &ChunkRef, offset: u64) {
        if let Some(src) = self.temp {
            self.add_loc(src, c, offset);
        }
    }

    /// The temporary file became `disk` (renamed over whatever was there).
    pub(super) fn finish_temp(&mut self, disk: &Path) {
        if let Some(src) = self.temp.take() {
            if let Some(old) = self.at.insert(disk.to_path_buf(), src) {
                self.kill(old);
            }
            self.sources[src as usize].disk = disk.to_path_buf();
            if self.open.as_ref().is_some_and(|(o, _)| *o == src) {
                self.open = None;
            }
        }
    }

    /// The download stopped: its temporary file is no source.
    pub(super) fn end_temp(&mut self) {
        if let Some(src) = self.temp.take() {
            self.kill(src);
        }
    }

    /// Whether some live source is thought to hold `c` (not checked).
    pub(super) fn has(&self, c: &ChunkRef) -> bool {
        self.blocks.get(&key(&c.chunk)).is_some_and(|l| {
            l.iter()
                .any(|l| l.size as u64 == c.size && self.sources[l.src as usize].live)
        })
    }

    /// The plaintext of `c` read from a source here, checked against its
    /// chunk id; `None` when no source has it (any more).
    pub(super) fn read(&mut self, fk: &FolderKeys, c: &ChunkRef) -> Option<Vec<u8>> {
        let cands: Vec<Loc> = self
            .blocks
            .get(&key(&c.chunk))?
            .iter()
            .filter(|l| l.size as u64 == c.size && self.sources[l.src as usize].live)
            .copied()
            .collect();
        for loc in cands {
            match self.read_at(loc) {
                Some(buf)
                    if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &buf)) == c.chunk =>
                {
                    return Some(buf);
                }
                // Unreadable, or not what the index says (changed since):
                // nothing more is taken from this file.
                _ if self.temp != Some(loc.src) => self.kill(loc.src),
                // A first-key collision in the file being written.
                _ => {}
            }
        }
        None
    }

    fn read_at(&mut self, loc: Loc) -> Option<Vec<u8>> {
        if !self.open.as_ref().is_some_and(|(o, _)| *o == loc.src) {
            let s = &self.sources[loc.src as usize];
            // Every directory between the base and the file is a real one
            // under the base: a link swapped in for a directory is not
            // followed out of it.
            let parent = fs::canonicalize(s.disk.parent()?).ok()?;
            if !parent.starts_with(&self.bases[s.base]) {
                return None;
            }
            self.open = Some((loc.src, open_regular(&s.disk)?));
        }
        let (_, f) = self.open.as_mut()?;
        let len = f.metadata().ok()?.len();
        if loc.offset.checked_add(loc.size as u64)? > len {
            return None;
        }
        f.seek(SeekFrom::Start(loc.offset)).ok()?;
        let mut buf = vec![0u8; loc.size as usize];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::ids::{FolderId, ObjectName};

    fn keys() -> FolderKeys {
        FolderKeys::from_folder_key(&FolderId::from_bytes(&[3; 16]), SecretKey([7; 32])).unwrap()
    }

    fn cref(fk: &FolderKeys, plain: &[u8]) -> ChunkRef {
        ChunkRef {
            chunk: ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, plain)),
            object: ObjectName::from_bytes(&[0; 32]),
            size: plain.len() as u64,
            epoch: 0,
        }
    }

    #[test]
    fn blocks_are_read_checked_and_dropped_when_the_file_changes() {
        let fk = keys();
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (vec![1u8; 100], vec![2u8; 50]);
        let file = dir.path().join("f.bin");
        fs::write(&file, [a.clone(), b.clone()].concat()).unwrap();
        let (ca, cb) = (cref(&fk, &a), cref(&fk, &b));
        let mut lb = LocalBlocks::default();
        lb.add_file(dir.path(), &file, &[ca.clone(), cb.clone()]);
        assert!(lb.has(&cb));
        assert_eq!(lb.read(&fk, &cb), Some(b.clone()));
        assert_eq!(lb.read(&fk, &ca), Some(a.clone()));
        // Changed under the index: the check fails and the file is dropped.
        fs::write(&file, vec![9u8; 150]).unwrap();
        lb.open = None;
        assert_eq!(lb.read(&fk, &ca), None);
        assert!(!lb.has(&cb));
    }

    #[test]
    fn a_moved_file_is_read_where_it_went() {
        let fk = keys();
        let dir = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let a = vec![5u8; 64];
        let file = dir.path().join("f.bin");
        fs::write(&file, &a).unwrap();
        let ca = cref(&fk, &a);
        let mut lb = LocalBlocks::default();
        lb.add_file(dir.path(), &file, std::slice::from_ref(&ca));
        let to = trash.path().join("f.bin.123");
        fs::rename(&file, &to).unwrap();
        lb.moved(&file, trash.path(), &to);
        assert_eq!(lb.read(&fk, &ca), Some(a));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_folder_is_not_followed() {
        let fk = keys();
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let a = vec![7u8; 64];
        fs::write(outside.path().join("f.bin"), &a).unwrap();
        let ca = cref(&fk, &a);
        // A directory of the folder replaced by a link after the scan.
        let sub = dir.path().join("sub");
        std::os::unix::fs::symlink(outside.path(), &sub).unwrap();
        let mut lb = LocalBlocks::default();
        lb.add_file(dir.path(), &sub.join("f.bin"), std::slice::from_ref(&ca));
        assert_eq!(lb.read(&fk, &ca), None);
        // The file itself a link.
        let link = dir.path().join("l.bin");
        std::os::unix::fs::symlink(outside.path().join("f.bin"), &link).unwrap();
        lb.add_file(dir.path(), &link, std::slice::from_ref(&ca));
        assert_eq!(lb.read(&fk, &ca), None);
    }
}
