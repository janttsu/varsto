// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folders kept "encrypted on this device" (phones).
//!
//! Such a folder keeps no plaintext on the device. Its files are kept as the
//! very objects the storages hold (content-addressed, named by the hash of
//! their ciphertext) in a block cache inside the device directory:
//! `<home>/block-cache/chunks/<xx>/<object>`, the storage layout. Selective
//! sync works as in every other folder; the local index of the folder state
//! names the files whose blocks are all in the cache ("local"), the others
//! are placeholders. Files are read through the app only: the viewer
//! decrypts in memory, and "open in another app" writes a decrypted copy to
//! `<home>/exports`, which is emptied when the vault locks and at start.
//!
//! Files added on the device are chunked and encrypted as they arrive (the
//! same deterministic chunking and encryption as a push of a plain file), go
//! into the cache, and are uploaded from there. Peers are served the cached
//! objects verbatim.

use super::*;
use std::io::Read;

/// Block cache directory inside the device directory.
pub const BLOCK_CACHE_DIR: &str = "block-cache";
/// Decrypted copies handed to other apps on request ("open in another app").
pub const EXPORT_DIR: &str = "exports";
/// Objects the ledger does not know yet (an upload being encrypted right now)
/// and temporary files are left alone this long by the cache cleanup.
const STAGING_GRACE_SECS: u64 = 3600;
/// Largest picture whose thumbnail is made from the block cache (in memory).
const THUMB_MAX_BYTES: u64 = 64 << 20;

/// Encrypts the content of one file into the block cache. It holds a copy of
/// the folder keys, so an upload can be read and encrypted without holding
/// the engine (`Engine::block_writer`, then `Engine::commit_staged`).
pub struct BlockWriter {
    folder: FolderId,
    vault: VaultId,
    fk: FolderKeys,
    /// Chunks the folder already references keep their key epoch (and so
    /// their object), as in a scan of a plain folder.
    known: HashMap<ChunkId, ChunkRef>,
    cache: PathBuf,
    chunker: ChunkerParams,
}

/// The content of a file, encrypted into the block cache, not yet recorded.
pub struct StagedFile {
    folder: FolderId,
    size: u64,
    content_hash: String,
    chunks: Vec<ChunkRef>,
}

impl StagedFile {
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl BlockWriter {
    /// Chunk, hash and encrypt everything `reader` yields; only ciphertext is
    /// written (to the block cache). Memory use is bounded by the chunk size.
    pub fn write(&self, reader: impl Read) -> Result<StagedFile> {
        let mut hasher = KeyedHasher::new(&self.fk.hash);
        let mut chunks = Vec::new();
        let mut size = 0u64;
        for chunk in Chunker::new(reader, self.chunker)? {
            let chunk = chunk?;
            let len = chunk.len() as u64;
            hasher.update(&chunk);
            size += len;
            let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&self.fk.hash, &chunk));
            let epoch = match self.known.get(&chunk_id) {
                Some(c) if c.size == len => c.epoch,
                _ => self.fk.epoch,
            };
            let ct = seal_chunk(&self.fk, &self.vault, &chunk_id, epoch, &chunk)?;
            let object = ObjectName::from_bytes(&crypto::hash(&ct));
            put_cached(&self.cache, &object, &ct)?;
            chunks.push(ChunkRef {
                chunk: chunk_id,
                object,
                size: len,
                epoch,
            });
        }
        Ok(StagedFile {
            folder: self.folder.clone(),
            size,
            content_hash: hex::encode(hasher.finalize()),
            chunks,
        })
    }
}

/// The object of one chunk: deterministic, so every device that encrypts the
/// same chunk under the same epoch gets the same bytes.
fn seal_chunk(
    fk: &FolderKeys,
    vault: &VaultId,
    chunk: &ChunkId,
    epoch: u32,
    plain: &[u8],
) -> Result<Vec<u8>> {
    crypto::encrypt_with_nonce(
        &fk.chunk_key(epoch, chunk)?,
        &fk.chunk_nonce(epoch, chunk)?,
        &fk.chunk_aad(vault, chunk, plain.len() as u64),
        &crate::pack::pack(plain),
    )
}

/// Decrypt one object and check it against its chunk id and size.
pub(super) fn open_chunk(
    fk: &FolderKeys,
    vault: &VaultId,
    cref: &ChunkRef,
    ct: &[u8],
) -> Result<Vec<u8>> {
    let plain = crate::pack::unpack(
        &crypto::decrypt(
            &fk.chunk_key(cref.epoch, &cref.chunk)?,
            &fk.chunk_aad(vault, &cref.chunk, cref.size),
            ct,
        )?,
        cref.size,
    )?;
    if ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &plain)) != cref.chunk
        || plain.len() as u64 != cref.size
    {
        bail!("chunk {} failed its content check", cref.chunk.short());
    }
    Ok(plain)
}

fn cache_path(root: &Path, object: &ObjectName) -> PathBuf {
    root.join(chunk_storage_key(object))
}

/// Store an object in the cache (atomically; nothing if it is there already).
fn put_cached(root: &Path, object: &ObjectName, ct: &[u8]) -> Result<()> {
    let path = cache_path(root, object);
    if path.is_file() {
        return Ok(());
    }
    let dir = path.parent().ok_or_else(|| anyhow!("bad cache path"))?;
    fs::create_dir_all(dir)?;
    // A name of its own: an upload may be encrypting while a sync writes.
    let tmp = dir.join(format!(".{}.tmp-{:016x}", object, rand::random::<u64>()));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("create temporary file {}", tmp.display()))?;
        f.write_all(ct)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// The local index entry of a file whose blocks are all in the cache.
fn cached_entry(f: &FileState) -> LocalIndexEntry {
    LocalIndexEntry {
        size: f.size,
        mtime: f.mtime,
        content_hash: f.content_hash.clone(),
    }
}

fn mtime_ns(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A path relative to the folder that stays inside it.
pub(super) fn check_rel_path(path: &str) -> Result<()> {
    util::check_rel_path(path)
}

impl Engine {
    pub(super) fn block_cache_root(&self) -> PathBuf {
        self.home.join(BLOCK_CACHE_DIR)
    }

    /// A cached object, if this device has an intact copy.
    pub(super) fn cached_object(&self, object: &ObjectName) -> Option<Vec<u8>> {
        let bytes = fs::read(cache_path(&self.block_cache_root(), object)).ok()?;
        (ObjectName::from_bytes(&crypto::hash(&bytes)) == *object).then_some(bytes)
    }

    fn cache_has(&self, object: &ObjectName) -> bool {
        cache_path(&self.block_cache_root(), object).is_file()
    }

    fn writer_for(&self, rec: &FolderRecord, state: &FolderState) -> Result<BlockWriter> {
        Ok(BlockWriter {
            folder: rec.folder_id.clone(),
            vault: self.vault.vault_id.clone(),
            fk: self.folder_keys(rec)?,
            known: state
                .files
                .values()
                .chain(state.pending_remote.values())
                .flat_map(|f| f.chunks.iter())
                .map(|c| (c.chunk.clone(), c.clone()))
                .collect(),
            cache: self.block_cache_root(),
            chunker: self.chunker,
        })
    }

    /// A writer that encrypts a new file of `folder` into the block cache, or
    /// `None` when the folder keeps plain files on this device.
    pub fn block_writer(&self, folder: &str) -> Result<Option<BlockWriter>> {
        let (rec, _) = self.resolve_folder(folder)?;
        if !self.mount_is_encrypted(&rec.folder_id) {
            return Ok(None);
        }
        let state = self.load_state(&rec.folder_id)?;
        Ok(Some(self.writer_for(&rec, &state)?))
    }

    /// Record a staged file as the content of `path` (created or replaced),
    /// then push: its blocks go from the cache to the storages and the new
    /// file list is published.
    pub fn commit_staged(
        &mut self,
        folder: &str,
        path: &str,
        staged: StagedFile,
    ) -> Result<PushReport> {
        check_rel_path(path)?;
        let (rec, _) = self.resolve_folder(folder)?;
        if staged.folder != rec.folder_id {
            bail!("the staged file belongs to another folder");
        }
        let mut state = self.load_state(&rec.folder_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.record_cached(&rec, &mut state, path, staged, now)?;
        self.save_state(&rec.folder_id, &state)?;
        self.push(folder)
    }

    /// Make `staged` the content of `path`: a new version unless the content
    /// is what the folder already has. Returns whether a version was made.
    fn record_cached(
        &mut self,
        rec: &FolderRecord,
        state: &mut FolderState,
        path: &str,
        staged: StagedFile,
        mtime: i64,
    ) -> Result<bool> {
        for c in &staged.chunks {
            self.pending.push(Event::ChunkOnDevice {
                folder: rec.folder_id.clone(),
                chunk: c.chunk.clone(),
                object: c.object.clone(),
                size: c.size,
            });
        }
        let me = self.vault.device_id.clone();
        let previous = state.files.get(path);
        let changed =
            !matches!(previous, Some(p) if !p.deleted && p.content_hash == staged.content_hash);
        if changed {
            let clock = self.tick()?;
            let mut version = previous.map(|p| p.version.clone()).unwrap_or_default();
            version.insert(me.clone(), clock);
            state.files.insert(
                path.to_string(),
                FileState {
                    path: path.to_string(),
                    version,
                    deleted: false,
                    size: staged.size,
                    mtime,
                    content_hash: staged.content_hash,
                    chunks: staged.chunks,
                    modified_by: me,
                    modified_clock: clock,
                },
            );
        }
        let file = &state.files[path];
        if file.chunks.iter().all(|c| self.cache_has(&c.object)) {
            state
                .local_index
                .insert(path.to_string(), cached_entry(file));
        }
        state.pending_remote.remove(path);
        state.accessed.insert(path.to_string(), now_secs());
        Ok(changed)
    }

    /// The scan of a folder kept encrypted here. Nothing in its directory is
    /// expected: files come and go through the app. A plain file found there
    /// (left from before the block cache, when such folders held plaintext
    /// while unlocked) is encrypted into the cache, recorded (as a new
    /// version when it differs from the synced one) and only then deleted;
    /// placeholder files of that layout are removed. Returns (files, changed).
    pub(super) fn scan_cached(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
    ) -> Result<(u64, u64)> {
        let mut changed = 0u64;
        let mut converted: Vec<(String, PathBuf)> = Vec::new();
        let mut placeholders: Vec<PathBuf> = Vec::new();
        if root.is_dir() {
            let mut found: Vec<(String, PathBuf)> = Vec::new();
            let walker = walkdir::WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    !(e.depth() > 0 && e.file_name().to_string_lossy().starts_with(".varsto"))
                });
            for entry in walker {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let Some(path) = util::manifest_path(entry.path().strip_prefix(root)?) else {
                    continue;
                };
                if path.ends_with(PLACEHOLDER_SUFFIX) {
                    placeholders.push(entry.path().to_path_buf());
                } else {
                    found.push((path, entry.path().to_path_buf()));
                }
            }
            if !found.is_empty() {
                let writer = self.writer_for(rec, state)?;
                for (path, disk) in found {
                    let md = fs::metadata(&disk)?;
                    let staged = writer.write(std::io::BufReader::new(fs::File::open(&disk)?))?;
                    // Changed while it was read: the next scan takes it.
                    let now = fs::metadata(&disk)?;
                    if now.len() != md.len() || mtime_ns(&now) != mtime_ns(&md) {
                        continue;
                    }
                    if self.record_cached(rec, state, &path, staged, mtime_ns(&md))? {
                        changed += 1;
                    }
                    converted.push((path, disk));
                }
            }
        }
        if !state.block_cache {
            // Until now the index may have described plain files in the
            // directory: it keeps what is cached now.
            let kept: BTreeSet<&String> = converted.iter().map(|(p, _)| p).collect();
            let files = &state.files;
            state.local_index.retain(|p, _| {
                kept.contains(p)
                    || files.get(p).is_some_and(|f| {
                        !f.deleted && f.chunks.iter().all(|c| self.cache_has(&c.object))
                    })
            });
            state.block_cache = true;
        }
        if !converted.is_empty() || !placeholders.is_empty() {
            // The state names every converted file before its plaintext goes.
            self.save_state(&rec.folder_id, state)?;
            for (_, disk) in &converted {
                fs::remove_file(disk)?;
            }
            for p in &placeholders {
                let _ = fs::remove_file(p);
            }
            for e in walkdir::WalkDir::new(root)
                .follow_links(false)
                .contents_first(true)
                .min_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_dir())
            {
                let _ = fs::remove_dir(e.path()); // only empty ones go
            }
        }
        let files = state.files.values().filter(|f| !f.deleted).count() as u64;
        Ok((files, changed))
    }

    /// One object from a peer or the first readable storage with an intact
    /// copy. Returns where it came from ("peer:<device>" or a storage name).
    pub(super) fn fetch_object(
        &self,
        cref: &ChunkRef,
        storages: &[(StorageSpec, Box<dyn Storage>)],
    ) -> Result<(String, Vec<u8>)> {
        if let Some((dev, ct)) = self.peers.as_ref().and_then(|p| p.get(&cref.object)) {
            if ObjectName::from_bytes(&crypto::hash(&ct)) == cref.object {
                return Ok((format!("peer:{}", dev.short()), ct));
            }
        }
        let key = chunk_storage_key(&cref.object);
        let mut needs_disk: Option<PoolError> = None;
        for (spec, backend) in storages {
            match backend.get(&key) {
                Ok(Some(ct)) if ObjectName::from_bytes(&crypto::hash(&ct)) == cref.object => {
                    return Ok((spec.name().to_string(), ct));
                }
                Ok(_) => {} // absent, or a corrupt copy: try the next storage
                Err(e) => match pool::pool_error(&e) {
                    Some(nd @ PoolError::NeedsDisk { .. }) => {
                        needs_disk.get_or_insert(nd.clone());
                    }
                    _ => return Err(e),
                },
            }
        }
        if let Some(nd) = needs_disk {
            return Err(anyhow::Error::new(nd));
        }
        bail!(
            "chunk {} is not available on any readable storage",
            cref.chunk.short()
        )
    }

    /// Put every block of `file` into the cache: the ones missing are fetched,
    /// checked by name and by decrypting them (in memory), and stored as they
    /// came. Nothing is decrypted to disk.
    pub(super) fn cache_file(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        file: &FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let progress = crate::progress::Download::begin(&rec.name, &file.path, file.size);
        let root = self.block_cache_root();
        for cref in &file.chunks {
            if self.cache_has(&cref.object) {
                progress.advance(cref.size);
                continue;
            }
            let (source, ct) = self.fetch_object(cref, storages)?;
            open_chunk(fk, &self.vault.vault_id, cref, &ct)?;
            put_cached(&root, &cref.object, &ct)?;
            if source.starts_with("peer:") {
                report.chunks_from_peers += 1;
            }
            report.chunks_downloaded += 1;
            report.bytes_downloaded += cref.size;
            progress.advance(cref.size);
            self.pending.push(Event::ChunkVerified {
                folder: rec.folder_id.clone(),
                chunk: cref.chunk.clone(),
                object: cref.object.clone(),
                storage: source,
            });
            self.pending.push(Event::ChunkOnDevice {
                folder: rec.folder_id.clone(),
                chunk: cref.chunk.clone(),
                object: cref.object.clone(),
                size: cref.size,
            });
        }
        Ok(())
    }

    /// `apply_remote` for a folder kept encrypted here: the new version's
    /// blocks are cached when the folder is not selective, or when the file
    /// is pinned or its previous version was cached; otherwise it is a
    /// placeholder.
    pub(super) fn apply_remote_cached(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        state: &mut FolderState,
        remote: FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let path = remote.path.clone();
        if remote.deleted {
            if state.local_index.remove(&path).is_some() {
                report.files_deleted += 1;
            }
            state.pending_remote.remove(&path);
            state.files.insert(path, remote);
            return Ok(());
        }
        let wanted = !self.mount_is_selective(&rec.folder_id)
            || state.pinned.contains(&path)
            || state.local_index.contains_key(&path);
        if !wanted {
            state.local_index.remove(&path);
            state.pending_remote.remove(&path);
            state.files.insert(path, remote);
            report.files_updated += 1;
            return Ok(());
        }
        match self.cache_file(rec, fk, &remote, storages, report) {
            Ok(()) => {
                state
                    .local_index
                    .insert(path.clone(), cached_entry(&remote));
                state.pending_remote.remove(&path);
                state.files.insert(path, remote);
                report.files_updated += 1;
            }
            Err(e) => {
                if let Some(PoolError::NeedsDisk { label, place, .. }) = pool::pool_error(&e) {
                    let d = format!("{label} ({place})");
                    if !report.disks_needed.contains(&d) {
                        report.disks_needed.push(d);
                    }
                }
                report.files_unavailable.push(format!("{path}: {e}"));
                state.pending_remote.insert(path, remote);
            }
        }
        Ok(())
    }

    /// The conflict copy of a folder kept encrypted here: the losing version
    /// under a new path, sharing its blocks.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn conflict_copy_cached(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        state: &mut FolderState,
        path: &str,
        loser: &FileState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let me = self.vault.device_id.clone();
        let cpath = manifest::conflict_path(path, loser);
        let was_cached = state
            .files
            .get(path)
            .is_some_and(|l| l.content_hash == loser.content_hash)
            && state.local_index.contains_key(path);
        let clock = self.tick()?;
        let mut cstate = loser.clone();
        cstate.path = cpath.clone();
        cstate.version = BTreeMap::from([(me.clone(), clock)]);
        cstate.modified_by = me;
        cstate.modified_clock = clock;
        let cached = was_cached
            || (!self.mount_is_selective(&rec.folder_id)
                && self.cache_file(rec, fk, &cstate, storages, report).is_ok());
        if cached {
            state
                .local_index
                .insert(cpath.clone(), cached_entry(&cstate));
        }
        state.files.insert(cpath, cstate);
        Ok(())
    }

    /// After a pull: a folder that is not selective has every current file
    /// cached, a selective one its pinned files. Files that cannot be read
    /// now are reported and tried again on the next sync.
    pub(super) fn cache_wanted(
        &mut self,
        rec: &FolderRecord,
        fk: &FolderKeys,
        state: &mut FolderState,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        report: &mut PullReport,
    ) -> Result<()> {
        let selective = self.mount_is_selective(&rec.folder_id);
        let wanted: Vec<FileState> = state
            .files
            .values()
            .filter(|f| {
                !f.deleted
                    && !state.local_index.contains_key(&f.path)
                    && !state.pending_remote.contains_key(&f.path)
                    && (!selective || state.pinned.contains(&f.path))
            })
            .cloned()
            .collect();
        for f in wanted {
            match self.cache_file(rec, fk, &f, storages, report) {
                Ok(()) => {
                    state.local_index.insert(f.path.clone(), cached_entry(&f));
                }
                Err(e) => report.files_unavailable.push(format!("{}: {e}", f.path)),
            }
        }
        Ok(())
    }

    /// `fetch_file` for a folder kept encrypted here: cache and pin.
    pub(super) fn fetch_cached(&mut self, rec: &FolderRecord, path: &str) -> Result<PullReport> {
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("unknown file {path}"))?;
        if file.deleted {
            bail!("{path} is deleted");
        }
        let fk = self.folder_keys(rec)?;
        let storages = self.open_storages(false)?;
        let mut report = PullReport {
            folder: rec.name.clone(),
            ..Default::default()
        };
        self.cache_file(rec, &fk, &file, &storages, &mut report)?;
        state
            .local_index
            .insert(path.to_string(), cached_entry(&file));
        state.accessed.insert(path.to_string(), now_secs());
        state.pinned.insert(path.to_string());
        report.files_updated += 1;
        self.commit_batch()?;
        self.save_state(&rec.folder_id, &state)?;
        Ok(report)
    }

    /// `move_file` for a folder kept encrypted here: the file list changes,
    /// the blocks stay.
    pub(super) fn move_cached(
        &mut self,
        rec: &FolderRecord,
        folder: &str,
        from: &str,
        to: &str,
    ) -> Result<PushReport> {
        let mut state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(from)
            .filter(|f| !f.deleted)
            .cloned()
            .ok_or_else(|| anyhow!("unknown file {from}"))?;
        let me = self.vault.device_id.clone();
        let clock = self.tick()?;
        let mut version = file.version.clone();
        version.insert(me.clone(), clock);
        state.files.insert(
            from.to_string(),
            FileState {
                path: from.to_string(),
                version,
                deleted: true,
                size: 0,
                mtime: 0,
                content_hash: String::new(),
                chunks: vec![],
                modified_by: me.clone(),
                modified_clock: clock,
            },
        );
        let clock = self.tick()?;
        let mut version = state
            .files
            .get(to)
            .map(|p| p.version.clone())
            .unwrap_or_default();
        version.insert(me.clone(), clock);
        state.files.insert(
            to.to_string(),
            FileState {
                path: to.to_string(),
                version,
                modified_by: me,
                modified_clock: clock,
                ..file
            },
        );
        if let Some(ix) = state.local_index.remove(from) {
            state.local_index.insert(to.to_string(), ix);
        }
        if state.pinned.remove(from) {
            state.pinned.insert(to.to_string());
        }
        if let Some(t) = state.accessed.remove(from) {
            state.accessed.insert(to.to_string(), t);
        }
        self.save_state(&rec.folder_id, &state)?;
        self.push(folder)
    }

    /// Thumbnail of a picture of a folder kept encrypted here, made in
    /// memory from its cached blocks. `None` when it cannot be made now.
    pub(super) fn thumbnail_from_cache(
        &self,
        fk: &FolderKeys,
        state: &FolderState,
        path: &str,
    ) -> Option<Vec<u8>> {
        let file = state.files.get(path).filter(|f| !f.deleted)?;
        if !thumbs::is_image(path)
            || file.size > THUMB_MAX_BYTES
            || !state.local_index.contains_key(path)
        {
            return None;
        }
        let mut bytes = Vec::with_capacity(file.size as usize);
        for cref in &file.chunks {
            let ct = self.cached_object(&cref.object)?;
            bytes.extend(open_chunk(fk, &self.vault.vault_id, cref, &ct).ok()?);
        }
        thumbs::make_from_bytes(&bytes, path)
    }

    /// Plaintext of one chunk: from the block cache, else from a peer or a
    /// storage (opened on first need), decrypted and checked in memory.
    pub(super) fn chunk_plain(
        &self,
        fk: &FolderKeys,
        cref: &ChunkRef,
        storages: &mut Option<OpenStorages>,
    ) -> Result<Vec<u8>> {
        if let Some(ct) = self.cached_object(&cref.object) {
            return open_chunk(fk, &self.vault.vault_id, cref, &ct);
        }
        if storages.is_none() {
            *storages = Some(self.open_storages(false)?);
        }
        let (_, ct) = self.fetch_object(cref, storages.as_deref().unwrap_or_default())?;
        open_chunk(fk, &self.vault.vault_id, cref, &ct)
    }

    /// Write a decrypted copy of a file to `<home>/exports/<random>/<name>`
    /// for handing it to another app, on the user's explicit request. The
    /// copies are removed when the vault locks and when the service starts
    /// (`clear_exports`). Counts as an access.
    pub fn export_file(&mut self, folder: &str, path: &str) -> Result<PathBuf> {
        check_rel_path(path)?;
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let file = match state.files.get(path) {
            Some(f) if !f.deleted => f.clone(),
            _ => bail!("unknown file {path}"),
        };
        let fk = self.folder_keys(&rec)?;
        let dir = self
            .home
            .join(EXPORT_DIR)
            .join(format!("{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&dir)?;
        let name = path.rsplit('/').next().unwrap_or("file");
        let out = dir.join(name);
        let written = (|| -> Result<()> {
            let mut f = fs::File::create(&out)?;
            let mut storages = None;
            for cref in &file.chunks {
                f.write_all(&self.chunk_plain(&fk, cref, &mut storages)?)?;
            }
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written {
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }
        self.touch_access(folder, path)?;
        Ok(out)
    }

    /// Remove every decrypted copy made by `export_file`. Returns how many
    /// files were removed.
    pub fn clear_exports(home: &Path) -> u64 {
        let dir = home.join(EXPORT_DIR);
        let n = walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count() as u64;
        let _ = fs::remove_dir_all(&dir);
        n
    }

    /// Storages whose copy lets a device drop its own: every storage that is
    /// not a transferrer, and replicas.
    pub(super) fn durable_copy(&self, view: &LedgerView, folder: &FolderId, c: &ChunkRef) -> bool {
        let durable: HashSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| s.name())
            .collect();
        view.locate(folder, &c.chunk)
            .filter(|r| r.object == c.object)
            .map(|r| {
                r.storages
                    .keys()
                    .any(|k| durable.contains(k.as_str()) || k.starts_with("replica:"))
            })
            .unwrap_or(false)
    }

    /// Drop the cached blocks of `paths` of a folder kept encrypted here.
    /// A file is freed only when every block is on a storage; the others are
    /// returned with the reason. Freeing makes the folder selective, as
    /// everywhere.
    pub(super) fn free_cached(
        &mut self,
        rec: &FolderRecord,
        paths: &[String],
    ) -> Result<Vec<(String, String)>> {
        let view = self.view()?;
        let mut state = self.load_state(&rec.folder_id)?;
        let mut kept = Vec::new();
        let mut freed = 0usize;
        for p in paths {
            let Some(file) = state.files.get(p).filter(|f| !f.deleted) else {
                kept.push((p.clone(), format!("unknown file {p}")));
                continue;
            };
            if !file
                .chunks
                .iter()
                .all(|c| self.durable_copy(&view, &rec.folder_id, c))
            {
                kept.push((
                    p.clone(),
                    format!("{p} is not fully stored elsewhere yet; sync first"),
                ));
                continue;
            }
            state.local_index.remove(p);
            state.pinned.remove(p);
            freed += 1;
        }
        self.save_state(&rec.folder_id, &state)?;
        if freed > 0 {
            for m in self
                .config
                .folders
                .iter_mut()
                .filter(|m| m.folder_id == rec.folder_id)
            {
                m.selective = true;
            }
            self.config.save(&self.home)?;
            self.gc_block_cache(&view)?;
        }
        Ok(kept)
    }

    /// Remove cached objects no file needs here any more. Kept: the blocks of
    /// cached files, and every block whose only copy may be this one (no
    /// storage holds it). Objects the ledger does not know at all (an upload
    /// being encrypted) are left alone for a while. Returns objects removed.
    pub(super) fn gc_block_cache(&self, view: &LedgerView) -> Result<u64> {
        let dir = self.block_cache_root().join("chunks");
        if !dir.is_dir() {
            return Ok(0);
        }
        // Object name -> some storage that is not a transferrer holds it.
        let durable_names: HashSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .map(|s| s.name())
            .collect();
        let mut stored: HashMap<String, bool> = HashMap::new();
        for r in view.chunks.values() {
            let d = r
                .storages
                .keys()
                .any(|k| durable_names.contains(k.as_str()) || k.starts_with("replica:"));
            *stored.entry(r.object.to_string()).or_insert(false) |= d;
        }
        let mut keep: HashSet<String> = HashSet::new();
        for m in &self.config.folders {
            let state = self.load_state(&m.folder_id)?;
            for f in state
                .files
                .values()
                .chain(state.pending_remote.values())
                .filter(|f| !f.deleted)
            {
                let cached = m.encrypted && state.local_index.contains_key(&f.path);
                for c in &f.chunks {
                    let name = c.object.to_string();
                    if cached || !stored.get(&name).copied().unwrap_or(false) {
                        keep.insert(name);
                    }
                }
            }
        }
        let old = |e: &walkdir::DirEntry| {
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > STAGING_GRACE_SECS)
        };
        let mut removed = 0u64;
        for e in walkdir::WalkDir::new(&dir)
            .min_depth(2)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = e.file_name().to_string_lossy().to_string();
            let drop = if name.starts_with('.') {
                old(&e) // a temporary file left by an interrupted write
            } else if keep.contains(&name) {
                false
            } else {
                match stored.get(&name) {
                    Some(true) => true,
                    Some(false) => false, // known, on no storage: maybe the only copy
                    None => old(&e),
                }
            };
            if drop && fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}
