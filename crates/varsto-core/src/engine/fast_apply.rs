// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Faster ways to put a pulled file on disk: patch a large file in place,
//! rename a moved file, and journal a run of new small files together.
//! Each one falls back to the ordinary download when it does not apply.

use super::patch::{self, Span};
use super::{disk_matches_index, mtime_ns_of, present, remove_empty_parents, Engine, FolderState};
use crate::ids::ChunkId;
use crate::ledger::Event;
use crate::manifest::{ChunkRef, FileState, Merge};
use crate::storage::{Storage, StorageSpec};
use crate::vault::{FolderKeys, FolderRecord};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const SMALL_RUN_MIN: usize = 8;
/// One journal for the whole run. Syncing every temp, or a wider wave of
/// those syncs, made a 10 000-file pull wait on the disk.
const SMALL_RUN_MAX: usize = 512;
/// Plaintext held for one run. The bytes are in memory until the barrier.
const SMALL_RUN_BYTES: u64 = 256 << 20;
const SMALL_CHUNK_MAX: u64 = 256 << 10;

struct Taken {
    bytes: Vec<u8>,
    reused: bool,
    from_peer: bool,
}

struct Piece {
    off: u64,
    chunk: ChunkRef,
    taken: Taken,
}

impl Engine {
    /// Index the non-deleted files this pull is about to add, by content
    /// hash, so a deletion of the same blocks can become a rename.
    pub(super) fn prepare_rename_offers(
        &mut self,
        root: &Path,
        state: &FolderState,
        entries: &[(&String, &FileState)],
    ) {
        self.rename_offers.clear();
        for (path, remote) in entries {
            if remote.deleted || remote.is_symlink() || remote.chunks.is_empty() {
                continue;
            }
            if !manifest_take(state, path, remote) {
                continue;
            }
            if present(&self.disk_of(root, state, path)) {
                continue;
            }
            self.rename_offers
                .entry(remote.content_hash.clone())
                .or_default()
                .push(((*path).clone(), (*remote).clone()));
        }
    }

    /// When `remote` deletes a file whose blocks are an add in this pull,
    /// rename it there instead of moving it to the trash. `Ok(false)` leaves
    /// the deletion to the trash path.
    pub(super) fn rename_onto_add(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
        remote: &FileState,
        disk: &Path,
        report: &mut super::PullReport,
    ) -> Result<bool> {
        let Some(local) = state.files.get(&remote.path).cloned() else {
            return Ok(false);
        };
        if local.deleted || local.is_symlink() || local.chunks.is_empty() {
            return Ok(false);
        }
        let Some(offers) = self.rename_offers.get(&local.content_hash).cloned() else {
            return Ok(false);
        };
        for (dest_path, add) in offers {
            if dest_path == remote.path || !patch::same_blocks(&local.chunks, &add.chunks) {
                continue;
            }
            let dest = match self.place(root, state, &dest_path, Some(&mut report.renamed_locally))
            {
                Ok(d) => d,
                Err(_) => continue,
            };
            if dest == disk || present(&dest) {
                continue;
            }
            if let Some(parent) = dest.parent() {
                if fs::create_dir_all(parent).is_err() {
                    continue;
                }
            }
            self.ensure_local_blocks(rec, root, state);
            match fs::rename(disk, &dest) {
                Ok(()) => {
                    if let Some(list) = self.rename_offers.get_mut(&local.content_hash) {
                        list.retain(|(p, _)| p != &dest_path);
                    }
                    self.placed_early.insert(dest_path.clone());
                    if let Some((folder, lb)) = self.local_blocks.as_mut() {
                        if *folder == rec.folder_id {
                            if let Some(parent) = dest.parent() {
                                lb.moved(disk, parent, &dest);
                            }
                        }
                    }
                    if add.mtime > 0 {
                        let t = std::time::UNIX_EPOCH
                            + std::time::Duration::from_nanos(add.mtime as u64);
                        if let Ok(f) = fs::File::options().write(true).open(&dest) {
                            let _ = f.set_modified(t);
                        }
                    }
                    let seen = self.settle_meta(
                        &rec.folder_id,
                        &dest,
                        &add,
                        &mut report.metadata_problems,
                    );
                    let md = fs::symlink_metadata(&dest)?;
                    let rules = self.local_rules(root);
                    state.local_names.forget(rules, &remote.path);
                    state.local_index.remove(&remote.path);
                    state.pending_remote.remove(&remote.path);
                    state.files.insert(remote.path.clone(), remote.clone());
                    state.local_index.insert(
                        dest_path.clone(),
                        super::LocalIndexEntry {
                            size: md.len(),
                            mtime: mtime_ns_of(&md),
                            content_hash: add.content_hash.clone(),
                            meta_seen: seen,
                        },
                    );
                    state.pending_remote.remove(&dest_path);
                    state.files.insert(dest_path.clone(), add.clone());
                    report.files_deleted += 1;
                    report.files_updated += 1;
                    report.bytes_reused_local += add.size;
                    report.chunks_reused_local += add.chunks.len() as u64;
                    remove_empty_parents(root, disk);
                    if self.share_read_only(rec) {
                        super::share_roles::set_read_only(&dest, true);
                    }
                    self.note_fresh(rec, root, state, &dest_path, &add);
                    return Ok(true);
                }
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => return Ok(false),
                Err(_) => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Write `remote` over the file at `disk` when long runs already sit at
    /// the right offsets. `Ok(true)` is done (the caller records the index).
    /// `Ok(false)` means the ordinary download should run. `Err` only after
    /// the file was changed: the path stays in `state.patching`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_inplace(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        root: &Path,
        state: &mut FolderState,
        remote: &FileState,
        disk: &Path,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut super::PullReport,
    ) -> Result<bool> {
        if state.patching.contains(&remote.path) {
            let ix = state.local_index.get(&remote.path);
            if !disk_matches_index(disk, ix) {
                let _ = fs::remove_file(disk);
                state.local_index.remove(&remote.path);
                state.patching.remove(&remote.path);
                return Ok(false);
            }
            state.patching.remove(&remote.path);
        }
        if remote.is_symlink() || remote.chunks.is_empty() || remote.deleted {
            return Ok(false);
        }
        let Some(old) = state
            .files
            .get(&remote.path)
            .filter(|f| !f.deleted && !f.is_symlink() && !f.chunks.is_empty())
            .cloned()
        else {
            return Ok(false);
        };
        let Some(ix) = state.local_index.get(&remote.path).cloned() else {
            return Ok(false);
        };
        if ix.content_hash != old.content_hash || ix.size != old.size {
            return Ok(false);
        }
        let Ok(md) = fs::symlink_metadata(disk) else {
            return Ok(false);
        };
        if !md.file_type().is_file() || md.len() != ix.size || mtime_ns_of(&md) != ix.mtime {
            return Ok(false);
        }
        let Some(spans) = patch::plan(&old.chunks, &remote.chunks) else {
            return Ok(false);
        };
        let new_len: u64 = remote.chunks.iter().map(|c| c.size).sum();
        if patch::kept_len(&spans) + patch::write_len(&spans) != new_len {
            return Ok(false);
        }
        if patch::kept_len(&spans) <= patch::VERIFY_KEEP_UNTIL
            && !verify_keeps(disk, &old.chunks, &spans, &fk.hash).unwrap_or(false)
        {
            return Ok(false);
        }
        self.ensure_local_blocks(rec, root, state);
        let folder_id = rec.folder_id.clone();
        let mut local = self
            .local_blocks
            .take()
            .map(|(_, lb)| lb)
            .unwrap_or_default();
        let loaded = self.load_writes(fk, rec, &spans, storages, &mut local);
        self.local_blocks = Some((folder_id, local));
        let pieces = match loaded {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        state.patching.insert(remote.path.clone());
        if self.save_state(&rec.folder_id, state).is_err() {
            state.patching.remove(&remote.path);
            return Ok(false);
        }
        self.note_replace_hook(disk);
        if !disk_matches_index(disk, Some(&ix)) {
            state.patching.remove(&remote.path);
            let _ = self.save_state(&rec.folder_id, state);
            return Ok(false);
        }
        crate::fsmeta::make_replaceable(disk);
        let mut modified = false;
        let written = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new().read(true).write(true).open(disk)?;
            for piece in &pieces {
                file.seek(SeekFrom::Start(piece.off))?;
                file.write_all(&piece.taken.bytes)?;
                modified = true;
            }
            file.set_len(new_len)?;
            modified = true;
            if remote.mtime > 0 {
                let t =
                    std::time::UNIX_EPOCH + std::time::Duration::from_nanos(remote.mtime as u64);
                let _ = file.set_modified(t);
            }
            file.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written {
            if modified {
                return Err(e);
            }
            state.patching.remove(&remote.path);
            let _ = self.save_state(&rec.folder_id, state);
            return Ok(false);
        }
        state.patching.remove(&remote.path);
        if let Some(log) = &self.download_log {
            log.lock().unwrap().push(remote.path.clone());
        }
        self.account(rec, report, &pieces);
        let keep_chunks = chunks_kept(&remote.chunks, &spans);
        report.chunks_reused_local += keep_chunks;
        report.bytes_reused_local += patch::kept_len(&spans);
        if let Some((folder, lb)) = self.local_blocks.as_mut() {
            if *folder == rec.folder_id {
                lb.add_file(root, disk, &remote.chunks);
            }
        }
        if self.share_read_only(rec) {
            super::share_roles::set_read_only(disk, true);
        }
        Ok(true)
    }

    /// Write a contiguous run of at least eight new single-block files,
    /// making them durable together, then rename them into place. Returns
    /// how many entries were handled (0 when this is not such a run).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_small_run(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        root: &Path,
        state: &mut FolderState,
        entries: &[(&String, &FileState)],
        from: usize,
        ignore: &mut Option<crate::ignore_rules::Matcher>,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut super::PullReport,
    ) -> usize {
        if self.mount_is_encrypted(&rec.folder_id) || self.mount_is_selective(&rec.folder_id) {
            return 0;
        }
        let mut n = 0;
        let mut bytes = 0u64;
        while from + n < entries.len() && n < SMALL_RUN_MAX && bytes < SMALL_RUN_BYTES {
            let (path, remote) = entries[from + n];
            if self.placed_early.contains(path)
                || !self.simple_new(root, state, ignore, path, remote)
            {
                break;
            }
            bytes += remote.size;
            n += 1;
        }
        if n < SMALL_RUN_MIN {
            return 0;
        }
        self.ensure_local_blocks(rec, root, state);
        let folder_id = rec.folder_id.clone();
        let mut local = self
            .local_blocks
            .take()
            .map(|(_, lb)| lb)
            .unwrap_or_default();
        let mut have: HashMap<ChunkId, Vec<u8>> = HashMap::new();
        let mut staged: Vec<Staged> = Vec::with_capacity(n);
        for (path, remote) in entries.iter().skip(from).take(n) {
            let disk = match self.place(root, state, path, Some(&mut report.renamed_locally)) {
                Ok(d) if !present(&d) => d,
                _ => break,
            };
            if self.space_for(rec, &disk, remote.size).is_err() {
                break;
            }
            if let Some(parent) = disk.parent() {
                if fs::create_dir_all(parent).is_err() {
                    break;
                }
            }
            let chunk = &remote.chunks[0];
            let taken = if let Some(bytes) = have
                .get(&chunk.chunk)
                .filter(|b| b.len() as u64 == chunk.size)
            {
                Taken {
                    bytes: bytes.clone(),
                    reused: true,
                    from_peer: false,
                }
            } else {
                match self.load_chunk(fk, rec, chunk, storages, &mut local) {
                    Ok(t) => t,
                    Err(_) => break,
                }
            };
            if !taken.reused {
                have.insert(chunk.chunk.clone(), taken.bytes.clone());
            }
            let (tmp, tmp_file) = match crate::util::temp_beside(&disk, "tmp") {
                Ok(t) => t,
                Err(_) => break,
            };
            let cleanup = crate::util::RemoveOnDrop::new(&tmp);
            let mut file = tmp_file;
            if file.write_all(&taken.bytes).is_err() {
                break;
            }
            if remote.mtime > 0 {
                let t =
                    std::time::UNIX_EPOCH + std::time::Duration::from_nanos(remote.mtime as u64);
                let _ = file.set_modified(t);
            }
            let settings = self.meta_settings(&rec.folder_id);
            let mode =
                if settings.permissions && self.meta_caps.mode == crate::fsmeta::ModeCap::Full {
                    remote.meta.as_ref().and_then(|m| m.mode)
                } else {
                    None
                };
            crate::util::set_final_mode(&file, mode);
            staged.push(Staged {
                path: (*path).clone(),
                remote: (*remote).clone(),
                disk,
                tmp,
                cleanup,
                reused: taken.reused,
                from_peer: taken.from_peer,
                chunk: chunk.clone(),
                mode,
            });
        }
        // A file that did not fit (the process ran out of open files, or a
        // block was missing) is left for the next pass. The files already
        // written are committed. Discarding them made the next file try the
        // same oversized run again, and a 10 000-file pull never finished.
        if staged.len() < SMALL_RUN_MIN {
            drop(staged);
            self.local_blocks = Some((folder_id, local));
            return 0;
        }
        // One journal sync for the run, overlapped with the next download.
        // Syncing each temp, or the whole volume, stalled the disk. A failed
        // journal leaves these files for the ordinary path, which syncs
        // each one itself.
        let planned: Vec<super::apply_journal::Planned> = staged
            .iter()
            .map(|item| super::apply_journal::Planned {
                dest: item.disk.clone(),
                src: item.tmp.clone(),
                mtime_ns: item.remote.mtime,
                mode: item.mode,
            })
            .collect();
        let journal_home = self.home().to_path_buf();
        self.local_blocks = Some((folder_id.clone(), local));
        let commit =
            std::thread::spawn(move || super::apply_journal::commit(&journal_home, &planned));
        self.prefetch_following(rec, root, entries, from + staged.len(), state, storages);
        let _journal_path = match commit.join() {
            Ok(Ok(path)) => path,
            Ok(Err(err)) => {
                log::warn!(
                    "apply journal was not synced ({err}); this run is left for the ordinary path"
                );
                drop(staged);
                return 0;
            }
            Err(_) => {
                log::warn!("apply journal thread panicked; this run is left for the ordinary path");
                drop(staged);
                return 0;
            }
        };
        let mut local = self
            .local_blocks
            .take()
            .map(|(_, lb)| lb)
            .unwrap_or_default();
        for item in &mut staged {
            crate::fsmeta::make_replaceable(&item.disk);
            if fs::rename(&item.tmp, &item.disk).is_err() {
                report.files_unavailable.push(format!(
                    "{}: the new file could not be put in place",
                    item.path
                ));
                state
                    .pending_remote
                    .entry(item.path.clone())
                    .or_insert_with(|| item.remote.clone());
                continue;
            }
            item.cleanup.keep();
            if let Some(log) = &self.download_log {
                log.lock().unwrap().push(item.path.clone());
            }
            self.prefetched.remove(&item.chunk.object);
            let progress =
                crate::progress::Download::begin(&rec.name, &item.path, item.remote.size);
            progress.advance(item.chunk.size);
            if item.reused {
                report.chunks_reused_local += 1;
                report.bytes_reused_local += item.chunk.size;
            } else {
                report.chunks_downloaded += 1;
                report.bytes_downloaded += item.chunk.size;
                if item.from_peer {
                    report.chunks_from_peers += 1;
                    report.bytes_from_peers += item.chunk.size;
                }
            }
            if !rec.is_backup() {
                self.pending.push(Event::ChunkOnDevice {
                    folder: rec.folder_id.clone(),
                    chunk: item.chunk.chunk.clone(),
                    object: item.chunk.object.clone(),
                    size: item.chunk.size,
                });
            }
            let seen = self.settle_meta(
                &rec.folder_id,
                &item.disk,
                &item.remote,
                &mut report.metadata_problems,
            );
            if let Ok(md) = fs::metadata(&item.disk) {
                state.local_index.insert(
                    item.path.clone(),
                    super::LocalIndexEntry {
                        size: md.len(),
                        mtime: mtime_ns_of(&md),
                        content_hash: item.remote.content_hash.clone(),
                        meta_seen: seen,
                    },
                );
            }
            state.pending_remote.remove(&item.path);
            state.files.insert(item.path.clone(), item.remote.clone());
            report.files_updated += 1;
            local.add_file(
                item.disk.parent().unwrap_or(root),
                &item.disk,
                &item.remote.chunks,
            );
            if self.share_read_only(rec) {
                super::share_roles::set_read_only(&item.disk, true);
            }
            self.note_fresh(rec, root, state, &item.path, &item.remote);
        }
        // The journal stays until the pull returns. Syncing these names now
        // would fill the disk queue the next batch still needs. The pull
        // drops a guard that syncs them afterwards; a crash before that
        // restores them from the journal.
        let done = staged.len();
        self.local_blocks = Some((folder_id, local));
        done
    }

    /// Download the next small-file run while the journal of this one syncs.
    fn prefetch_following(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        entries: &[(&String, &FileState)],
        mut at: usize,
        state: &FolderState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
    ) {
        let end = (at + SMALL_RUN_MAX).min(entries.len());
        while at < end {
            let next = self.prefetch_small(rec, root, entries, at, state, storages);
            if next <= at {
                break;
            }
            at = next;
        }
    }

    fn simple_new(
        &self,
        root: &Path,
        state: &FolderState,
        ignore: &mut Option<crate::ignore_rules::Matcher>,
        path: &str,
        remote: &FileState,
    ) -> bool {
        if remote.deleted || remote.is_symlink() || remote.chunks.len() != 1 {
            return false;
        }
        if remote.chunks[0].size > SMALL_CHUNK_MAX || remote.chunks[0].size == 0 {
            return false;
        }
        if ignore.as_mut().is_some_and(|m| m.is_ignored(path, false)) {
            return false;
        }
        if !manifest_take(state, path, remote) {
            return false;
        }
        if self.check_no_link_above(root, state, path).is_err() {
            return false;
        }
        let disk = self.disk_of(root, state, path);
        !present(&disk)
    }

    fn load_writes(
        &mut self,
        fk: &FolderKeys,
        rec: &FolderRecord,
        spans: &[Span],
        storages: &[(StorageSpec, Box<dyn Storage>)],
        local: &mut super::local_blocks::LocalBlocks,
    ) -> Result<Vec<Piece>> {
        let mut pieces = Vec::new();
        for span in spans {
            let Span::Write { off, chunks } = span else {
                continue;
            };
            let mut at = *off;
            for c in chunks {
                let taken = self.load_chunk(fk, rec, c, storages, local)?;
                if taken.bytes.len() as u64 != c.size {
                    return Err(anyhow!("chunk {} has the wrong length", c.chunk.short()));
                }
                pieces.push(Piece {
                    off: at,
                    chunk: c.clone(),
                    taken,
                });
                at += c.size;
            }
        }
        Ok(pieces)
    }

    /// Plaintext of `chunk` from this device, from a block fetched ahead,
    /// from a staged pool disk, or from the network. Read before any byte
    /// of an in-place patch is written.
    fn load_chunk(
        &mut self,
        fk: &FolderKeys,
        rec: &FolderRecord,
        chunk: &ChunkRef,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        local: &mut super::local_blocks::LocalBlocks,
    ) -> Result<Taken> {
        if let Some(bytes) = local.read(fk, chunk) {
            return Ok(Taken {
                bytes,
                reused: true,
                from_peer: false,
            });
        }
        if let Some(super::fetch::Fetched::Got { bytes, from_peer }) =
            self.prefetched.get(&chunk.object)
        {
            let plain = crate::chunk_seal::open_chunk(
                fk,
                &self.vault.vault_id,
                &chunk.chunk,
                chunk.epoch,
                chunk.size,
                bytes,
            )?;
            return Ok(Taken {
                bytes: plain,
                reused: false,
                from_peer: *from_peer,
            });
        }
        let staging = self.staging_roots();
        if let Some((path, _)) = super::disk_fetch::staged_object(&staging, &chunk.object) {
            if let Ok(bytes) = fs::read(&path) {
                if crate::ids::ObjectName::from_bytes(&crate::crypto::hash(&bytes)) == chunk.object
                {
                    let plain = crate::chunk_seal::open_chunk(
                        fk,
                        &self.vault.vault_id,
                        &chunk.chunk,
                        chunk.epoch,
                        chunk.size,
                        &bytes,
                    )?;
                    return Ok(Taken {
                        bytes: plain,
                        reused: false,
                        from_peer: false,
                    });
                }
            }
        }
        let peers = if rec.is_backup() {
            None
        } else {
            self.peers.clone()
        };
        let stats = self.fetch_stats.clone();
        let fetched = super::fetch::fetch_object(peers.as_deref(), &chunk.object, storages, &stats);
        match fetched {
            super::fetch::Fetched::Got { bytes, from_peer } => {
                let plain = crate::chunk_seal::open_chunk(
                    fk,
                    &self.vault.vault_id,
                    &chunk.chunk,
                    chunk.epoch,
                    chunk.size,
                    &bytes,
                )?;
                Ok(Taken {
                    bytes: plain,
                    reused: false,
                    from_peer,
                })
            }
            super::fetch::Fetched::Failed(e) => Err(e),
            super::fetch::Fetched::Missing(Some(nd)) => Err(anyhow::Error::new(nd)),
            super::fetch::Fetched::Missing(None) => Err(anyhow!(
                "chunk {} is not available on any readable storage",
                chunk.chunk.short()
            )),
        }
    }

    fn account(&mut self, rec: &FolderRecord, report: &mut super::PullReport, pieces: &[Piece]) {
        for piece in pieces {
            let n = piece.taken.bytes.len() as u64;
            if piece.taken.reused {
                report.chunks_reused_local += 1;
                report.bytes_reused_local += n;
            } else {
                report.chunks_downloaded += 1;
                report.bytes_downloaded += n;
                if piece.taken.from_peer {
                    report.chunks_from_peers += 1;
                    report.bytes_from_peers += n;
                }
            }
            self.prefetched.remove(&piece.chunk.object);
            if !rec.is_backup() {
                self.pending.push(Event::ChunkOnDevice {
                    folder: rec.folder_id.clone(),
                    chunk: piece.chunk.chunk.clone(),
                    object: piece.chunk.object.clone(),
                    size: piece.chunk.size,
                });
            }
        }
    }
}

struct Staged {
    path: String,
    remote: FileState,
    disk: PathBuf,
    tmp: PathBuf,
    cleanup: crate::util::RemoveOnDrop,
    reused: bool,
    from_peer: bool,
    chunk: ChunkRef,
    mode: Option<u32>,
}

fn manifest_take(state: &FolderState, path: &str, remote: &FileState) -> bool {
    matches!(
        crate::manifest::merge(state.files.get(path), remote),
        Merge::TakeRemote
    )
}

fn verify_keeps(
    disk: &Path,
    old: &[ChunkRef],
    spans: &[Span],
    key: &crate::crypto::SecretKey,
) -> Result<bool> {
    let mut file = fs::File::open(disk)?;
    let mut at = 0u64;
    for c in old {
        let start = at;
        at += c.size;
        let kept = spans
            .iter()
            .any(|s| matches!(s, Span::Keep { off, len } if start >= *off && at <= *off + *len));
        if !kept {
            continue;
        }
        file.seek(SeekFrom::Start(start))?;
        let mut buf = vec![0u8; c.size as usize];
        if file.read_exact(&mut buf).is_err() {
            return Ok(false);
        }
        if ChunkId::from_bytes(&crate::crypto::keyed_hash(key, &buf)) != c.chunk {
            return Ok(false);
        }
    }
    Ok(true)
}

fn chunks_kept(chunks: &[ChunkRef], spans: &[Span]) -> u64 {
    let mut n = 0u64;
    let mut at = 0u64;
    for c in chunks {
        let start = at;
        at += c.size;
        if spans
            .iter()
            .any(|s| matches!(s, Span::Keep { off, len } if start >= *off && at <= *off + *len))
        {
            n += 1;
        }
    }
    n
}
