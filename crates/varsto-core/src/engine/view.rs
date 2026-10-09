// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Reading a file for the in-app viewer without writing its plaintext to the
//! device. A file whose plaintext is already on this device is read from
//! there; otherwise only the chunks that cover the requested byte range are
//! fetched, verified and decrypted in memory. Nothing is written: no temporary
//! file, no plaintext cache, no change to the local index.

use super::*;

impl Engine {
    /// Size in bytes of a file as the viewer sees it: the local copy if this
    /// device has the plaintext, otherwise the size recorded in the manifest.
    pub fn view_size(&self, folder: &str, path: &str) -> Result<u64> {
        let (rec, root) = self.resolve_folder(folder)?;
        check_view_path(path)?;
        let disk = root.join(path);
        if disk.is_file() {
            return Ok(fs::metadata(&disk)?.len());
        }
        let state = self.load_state(&rec.folder_id)?;
        match state.files.get(path) {
            Some(f) if !f.deleted => Ok(f.size),
            _ => bail!("unknown file {path}"),
        }
    }

    /// Plaintext bytes `start..end` of a file (`end` is exclusive and clamped
    /// to the file size), decrypted in memory when the device holds only a
    /// placeholder. The result is never written anywhere.
    pub fn view_range(&self, folder: &str, path: &str, start: u64, end: u64) -> Result<Vec<u8>> {
        let (rec, root) = self.resolve_folder(folder)?;
        check_view_path(path)?;
        let disk = root.join(path);
        if disk.is_file() {
            use std::io::{Read, Seek, SeekFrom};
            let mut f =
                fs::File::open(&disk).with_context(|| format!("read {}", disk.display()))?;
            let len = f.metadata()?.len();
            let end = end.min(len);
            if start >= end {
                return Ok(Vec::new());
            }
            f.seek(SeekFrom::Start(start))?;
            let mut out = Vec::with_capacity((end - start) as usize);
            f.take(end - start).read_to_end(&mut out)?;
            return Ok(out);
        }
        let state = self.load_state(&rec.folder_id)?;
        let file = match state.files.get(path) {
            Some(f) if !f.deleted => f.clone(),
            _ => bail!("unknown file {path}"),
        };
        let end = end.min(file.size);
        if start >= end {
            return Ok(Vec::new());
        }
        let fk = self.folder_keys(&rec)?;
        let storages = self.open_storages(false)?;
        let mut out = Vec::with_capacity((end - start) as usize);
        let mut offset = 0u64;
        for cref in &file.chunks {
            let (c_start, c_end) = (offset, offset + cref.size);
            offset = c_end;
            if c_end <= start {
                continue;
            }
            if c_start >= end {
                break;
            }
            let plain = self.chunk_plaintext(&fk, cref, &storages)?;
            let from = start.saturating_sub(c_start) as usize;
            let to = (end.min(c_end) - c_start) as usize;
            out.extend_from_slice(&plain[from..to]);
        }
        Ok(out)
    }

    /// One chunk, fetched from a peer or the first readable storage that has
    /// an intact copy, decrypted and checked against its id.
    fn chunk_plaintext(
        &self,
        fk: &FolderKeys,
        cref: &ChunkRef,
        storages: &[(StorageSpec, Box<dyn Storage>)],
    ) -> Result<Vec<u8>> {
        let key = chunk_storage_key(&cref.object);
        let mut got = self
            .peers
            .as_ref()
            .and_then(|p| p.get(&cref.object))
            .map(|(_, ct)| ct);
        let mut needs_disk: Option<PoolError> = None;
        for (_, backend) in storages {
            if got.is_some() {
                break;
            }
            match backend.get(&key) {
                Ok(Some(ct)) if ObjectName::from_bytes(&crypto::hash(&ct)) == cref.object => {
                    got = Some(ct);
                }
                Ok(_) => {}
                Err(e) => match pool::pool_error(&e) {
                    Some(nd @ PoolError::NeedsDisk { .. }) => {
                        needs_disk.get_or_insert(nd.clone());
                    }
                    _ => return Err(e),
                },
            }
        }
        let Some(ct) = got else {
            if let Some(nd) = needs_disk {
                return Err(anyhow::Error::new(nd));
            }
            bail!(
                "chunk {} is not available on any readable storage",
                cref.chunk.short()
            );
        };
        let plain = crate::pack::unpack(
            &crypto::decrypt(
                &fk.chunk_key(cref.epoch, &cref.chunk)?,
                &fk.chunk_aad(&self.vault.vault_id, &cref.chunk, cref.size),
                &ct,
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
}

fn check_view_path(path: &str) -> Result<()> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || path.split('/').any(|c| c == ".." || c.is_empty())
    {
        bail!("path must be relative to the folder and must not contain '..': {path}");
    }
    Ok(())
}
