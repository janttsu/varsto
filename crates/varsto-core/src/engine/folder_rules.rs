// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Per-folder ignore rules and metadata settings on this device: reading
//! and changing them (`ignore_rules`, `fsmeta`; spec sections "Ignore
//! rules" and "File metadata").

use super::{Engine, FolderId};
use crate::fsmeta::{Caps, MetaSettings};
use crate::ignore_rules::{self, Matcher, Verdict, IGNORE_FILE};
use crate::util;
use anyhow::{bail, Result};
use serde::Serialize;
use std::fs;

/// A folder's ignore rules as this device sees them.
#[derive(Clone, Debug, Serialize)]
pub struct IgnoreInfo {
    pub folder: String,
    /// The folder's root `.varstoignore` (synced), as text.
    pub synced: String,
    /// `.varstoignore` files in subdirectories (manifest paths).
    pub nested: Vec<String>,
    /// This device's own patterns (not synced).
    pub local: Vec<String>,
    /// Common junk patterns the interface offers to add.
    pub suggested: Vec<String>,
    /// Rules apply only where the folder has plain files on this device.
    pub applies_here: bool,
}

impl Engine {
    pub(super) fn ignore_local(&self, folder: &FolderId) -> Vec<String> {
        self.config
            .folders
            .iter()
            .find(|m| &m.folder_id == folder)
            .map(|m| m.ignore_local.clone())
            .unwrap_or_default()
    }

    pub(super) fn meta_settings(&self, folder: &FolderId) -> MetaSettings {
        self.config
            .folders
            .iter()
            .find(|m| &m.folder_id == folder)
            .map(|m| m.meta)
            .unwrap_or_default()
    }

    /// What file metadata this system can represent.
    pub fn meta_caps(&self) -> Caps {
        self.meta_caps
    }

    /// Treat this device as one that can represent less (or more) than the
    /// running system: tests, and front ends that know their filesystem.
    pub fn set_meta_caps(&mut self, caps: Caps) {
        self.meta_caps = caps;
    }

    pub fn folder_ignore(&self, folder: &str) -> Result<IgnoreInfo> {
        let (rec, root) = self.resolve_folder(folder)?;
        let applies_here = !self.mount_is_encrypted(&rec.folder_id);
        let synced = if applies_here {
            read_ignore_file(&root.join(IGNORE_FILE))
        } else {
            String::new()
        };
        let state = self.load_state(&rec.folder_id)?;
        let suffix = format!("/{IGNORE_FILE}");
        let nested = state
            .files
            .values()
            .filter(|f| !f.deleted && f.path.ends_with(&suffix))
            .map(|f| f.path.clone())
            .collect();
        Ok(IgnoreInfo {
            folder: rec.name,
            synced,
            nested,
            local: self.ignore_local(&rec.folder_id),
            suggested: ignore_rules::SUGGESTED
                .iter()
                .map(|s| s.to_string())
                .collect(),
            applies_here,
        })
    }

    /// Replace the folder's root `.varstoignore` (synced on the next push;
    /// an empty text removes the file) and/or this device's own patterns.
    pub fn set_folder_ignore(
        &mut self,
        folder: &str,
        synced: Option<&str>,
        local: Option<Vec<String>>,
    ) -> Result<()> {
        let (rec, root) = self.resolve_for_write(folder)?;
        if let Some(text) = synced {
            if self.mount_is_encrypted(&rec.folder_id) {
                bail!(
                    "{} keeps its files encrypted on this device; edit its .varstoignore on a device with plain files",
                    rec.name
                );
            }
            if text.len() > 256 * 1024 {
                bail!("an ignore file is at most 256 KiB");
            }
            let file = root.join(IGNORE_FILE);
            if fs::symlink_metadata(&file).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!("{} is a symbolic link; it is not written", file.display());
            }
            if text.trim().is_empty() {
                if file.exists() {
                    fs::remove_file(&file)?;
                }
            } else {
                let mut t = text.replace("\r\n", "\n");
                if !t.ends_with('\n') {
                    t.push('\n');
                }
                util::write_atomic(&file, t.as_bytes())?;
            }
        }
        if let Some(lines) = local {
            for l in &lines {
                ignore_rules::check_pattern(l)?;
            }
            for m in self
                .config
                .folders
                .iter_mut()
                .filter(|m| m.folder_id == rec.folder_id)
            {
                m.ignore_local = lines.clone();
            }
            self.config.save(&self.home)?;
        }
        Ok(())
    }

    /// Add a pattern to the synced file or (`local`) to this device's list.
    /// False when it was there already.
    pub fn ignore_add(&mut self, folder: &str, pattern: &str, local: bool) -> Result<bool> {
        ignore_rules::check_pattern(pattern)?;
        let info = self.folder_ignore(folder)?;
        if local {
            if info.local.iter().any(|p| p == pattern) {
                return Ok(false);
            }
            let mut l = info.local;
            l.push(pattern.to_string());
            self.set_folder_ignore(folder, None, Some(l))?;
            return Ok(true);
        }
        let (text, added) = ignore_rules::add_line(&info.synced, pattern);
        if added {
            self.set_folder_ignore(folder, Some(&text), None)?;
        }
        Ok(added)
    }

    /// Remove a pattern; false when it was not there.
    pub fn ignore_remove(&mut self, folder: &str, pattern: &str, local: bool) -> Result<bool> {
        let info = self.folder_ignore(folder)?;
        if local {
            let before = info.local.len();
            let l: Vec<String> = info.local.into_iter().filter(|p| p != pattern).collect();
            if l.len() == before {
                return Ok(false);
            }
            self.set_folder_ignore(folder, None, Some(l))?;
            return Ok(true);
        }
        let (text, removed) = ignore_rules::remove_line(&info.synced, pattern);
        if removed {
            self.set_folder_ignore(folder, Some(&text), None)?;
        }
        Ok(removed)
    }

    /// Whether `path` (relative to the folder; a trailing `/` means a
    /// directory, as does an existing directory) is ignored here, and why.
    /// With `synced_text`, that text stands for the root file (a preview).
    pub fn check_ignore(
        &self,
        folder: &str,
        path: &str,
        synced_text: Option<&str>,
        local: Option<&[String]>,
    ) -> Result<Verdict> {
        let (rec, root) = self.resolve_folder(folder)?;
        let rel = path.trim().trim_start_matches("./").replace('\\', "/");
        let is_dir = rel.ends_with('/')
            || fs::symlink_metadata(root.join(rel.trim_end_matches('/'))).is_ok_and(|m| m.is_dir());
        let rel = rel.trim_matches('/').to_string();
        if rel.is_empty() {
            bail!("give a path inside the folder");
        }
        let own = self.ignore_local(&rec.folder_id);
        let local = local.unwrap_or(&own);
        let mut m = match synced_text {
            Some(t) => {
                // The text replaces the root file; files further down are read.
                let mut m = Matcher::new(Some(&root), local);
                m.override_root(t);
                m
            }
            None => Matcher::new(Some(&root), local),
        };
        Ok(m.explain(&rel, is_dir))
    }

    pub fn folder_settings(&self, folder: &str) -> Result<MetaSettings> {
        let (rec, _) = self.resolve_folder(folder)?;
        Ok(self.meta_settings(&rec.folder_id))
    }

    pub fn set_folder_settings(&mut self, folder: &str, settings: MetaSettings) -> Result<()> {
        let (rec, _) = self.resolve_for_write(folder)?;
        for m in self
            .config
            .folders
            .iter_mut()
            .filter(|m| m.folder_id == rec.folder_id)
        {
            m.meta = settings;
        }
        self.config.save(&self.home)
    }
}

fn read_ignore_file(path: &std::path::Path) -> String {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => fs::read_to_string(path).unwrap_or_default(),
        _ => String::new(),
    }
}
