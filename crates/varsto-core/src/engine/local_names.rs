// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Where the vault paths of a folder are on this device's disk: the
//! folder state's local name map and the filesystem's rules
//! (`crate::names`).

use super::{Engine, FolderState};
use crate::ids::FolderId;
use crate::names::{LocalRules, Placed};
use anyhow::Result;
use std::path::{Path, PathBuf};

impl Engine {
    /// Assume these filesystem rules for every folder instead of probing
    /// them; `None` probes again. Tests simulate Windows names or a
    /// case-insensitive disk with it on Linux.
    pub fn set_local_rules(&mut self, rules: Option<LocalRules>) {
        self.local_rules = rules;
    }

    /// The rules of the filesystem a folder's directory is on.
    pub(super) fn local_rules(&self, root: &Path) -> LocalRules {
        self.local_rules.unwrap_or_else(|| LocalRules::detect(root))
    }

    /// Where vault path `path` is (or would be) on disk, for reading and
    /// checks.
    pub(super) fn disk_of(&self, root: &Path, state: &FolderState, path: &str) -> PathBuf {
        state.local_names.disk(root, self.local_rules(root), path)
    }

    /// Where to write vault path `path`: its local name, chosen (and
    /// recorded) now if it has none. A name that had to change because of
    /// a case collision is reported in `renamed`.
    pub(super) fn place(
        &self,
        root: &Path,
        state: &mut FolderState,
        path: &str,
        renamed: Option<&mut Vec<String>>,
    ) -> Result<PathBuf> {
        let rules = self.local_rules(root);
        let (disk, placed) = state.local_names.place(root, rules, path)?;
        if let (Placed::Disambiguated(local), Some(r)) = (placed, renamed) {
            r.push(format!(
                "{} -> {}",
                crate::names::display(path),
                crate::names::display(&local)
            ));
        }
        Ok(disk)
    }

    /// [`Engine::disk_of`] for callers that do not hold the folder state.
    /// Refuse vault path `path` when a directory above its local name
    /// inside the folder is a symbolic link (`crate::fsmeta`).
    pub(super) fn check_no_link_above(
        &self,
        root: &Path,
        state: &FolderState,
        path: &str,
    ) -> Result<()> {
        let local = state.local_names.local_rel(self.local_rules(root), path);
        crate::fsmeta::check_no_link_above(root, &local)
    }

    pub(super) fn disk_path(&self, folder: &FolderId, root: &Path, path: &str) -> PathBuf {
        match self.load_state(folder) {
            Ok(state) => self.disk_of(root, &state, path),
            Err(_) => crate::names::join(root, &self.local_rules(root).default_local(path)),
        }
    }
}
