// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Reading a file for the in-app viewer without writing its plaintext to the
//! device. A file whose plaintext is already on this device (a plain folder)
//! is read from there; otherwise only the chunks that cover the requested
//! byte range are read from the block cache (folders kept encrypted here) or
//! fetched, verified and decrypted in memory. Nothing is written: no
//! temporary file, no plaintext cache, no change to the local index.

use super::*;

impl Engine {
    /// Size in bytes of a file as the viewer sees it: the local copy if this
    /// device has the plaintext, otherwise the size recorded in the manifest.
    pub fn view_size(&self, folder: &str, path: &str) -> Result<u64> {
        let (rec, root) = self.resolve_folder(folder)?;
        block_cache::check_rel_path(path)?;
        let disk = root.join(path);
        if !self.mount_is_encrypted(&rec.folder_id) && disk.is_file() {
            return Ok(fs::metadata(&disk)?.len());
        }
        let state = self.load_state(&rec.folder_id)?;
        match state.files.get(path) {
            Some(f) if !f.deleted => Ok(f.size),
            _ => bail!("unknown file {path}"),
        }
    }

    /// Plaintext bytes `start..end` of a file (`end` is exclusive and clamped
    /// to the file size), decrypted in memory when the device holds no plain
    /// copy. The result is never written anywhere.
    pub fn view_range(&self, folder: &str, path: &str, start: u64, end: u64) -> Result<Vec<u8>> {
        let (rec, root) = self.resolve_folder(folder)?;
        block_cache::check_rel_path(path)?;
        let disk = root.join(path);
        if !self.mount_is_encrypted(&rec.folder_id) && disk.is_file() {
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
        // Storages are opened only for a chunk the block cache lacks.
        let mut storages = None;
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
            let plain = self.chunk_plain(&fk, cref, &mut storages)?;
            let from = start.saturating_sub(c_start) as usize;
            let to = (end.min(c_end) - c_start) as usize;
            out.extend_from_slice(&plain[from..to]);
        }
        Ok(out)
    }
}
