// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Which blocks this device holds in its files, as the ledger says
//! (`ChunkOnDevice` and `ChunkOffDevice`). Downloads and scans record what
//! arrives; the reconcile step of every sync records the rest: blocks of
//! files deleted or freed here, and of folders no longer attached here. Each
//! step writes only the differences between the files on disk and what the
//! ledger already says, so an unchanged folder records nothing.
//!
//! Durability policies count these copies at place "home"
//! (`Engine::policy_check_at`); nothing that lets a storage copy go does.

use super::*;

impl Engine {
    /// Record which blocks of an attached folder this device holds now: the
    /// blocks of current files whose content on disk (or in the block cache)
    /// is the version the folder has. Placeholders, deleted files and files
    /// changed since the last scan do not count. A backup's blocks are never
    /// held by a device.
    pub(super) fn reconcile_device_copies(
        &mut self,
        rec: &FolderRecord,
        state: &FolderState,
    ) -> Result<()> {
        let mut held: HashMap<&ChunkId, &ChunkRef> = HashMap::new();
        if !rec.is_backup() {
            for f in state.files.values().filter(|f| !f.deleted) {
                let on_disk = state
                    .local_index
                    .get(&f.path)
                    .is_some_and(|ix| ix.content_hash == f.content_hash);
                if on_disk {
                    for c in &f.chunks {
                        held.entry(&c.chunk).or_insert(c);
                    }
                }
            }
        }
        let view = self.view()?;
        let me = &self.vault.device_id;
        let mut claimed: HashSet<&ChunkId> = HashSet::new();
        let mut events = Vec::new();
        for ((folder, chunk), r) in &view.chunks {
            if folder != &rec.folder_id || !r.held_by(me) {
                continue;
            }
            claimed.insert(chunk);
            if !held.contains_key(chunk) {
                events.push(Event::ChunkOffDevice {
                    folder: folder.clone(),
                    chunk: chunk.clone(),
                });
            }
        }
        for (chunk, c) in held {
            if !claimed.contains(chunk) {
                events.push(Event::ChunkOnDevice {
                    folder: rec.folder_id.clone(),
                    chunk: chunk.clone(),
                    object: c.object.clone(),
                    size: c.size,
                });
            }
        }
        self.pending.extend(events);
        Ok(())
    }

    /// Record that this device holds no block of the folders that are not
    /// attached here (detached, removed, or never attached), or of `only`.
    pub(super) fn release_device_copies(&mut self, only: Option<&FolderId>) -> Result<()> {
        let attached: HashSet<&FolderId> =
            self.config.folders.iter().map(|m| &m.folder_id).collect();
        let view = self.view()?;
        let me = &self.vault.device_id;
        let events: Vec<Event> = view
            .chunks
            .iter()
            .filter(|((folder, _), r)| {
                let gone = match only {
                    Some(f) => folder == f,
                    None => !attached.contains(folder),
                };
                gone && r.held_by(me)
            })
            .map(|((folder, chunk), _)| Event::ChunkOffDevice {
                folder: folder.clone(),
                chunk: chunk.clone(),
            })
            .collect();
        self.pending.extend(events);
        Ok(())
    }
}
