// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The spool directory of a YouTube job as an import source
//! (`engine::youtube`). It holds downloaded videos under the names they get
//! in the folder (`<channel>/<date> <title> [<id>].<ext>`); a file's
//! content id is `youtube:<video id>:<suffix>` (`crate::youtube::content_id`),
//! so the import book says which videos are in the folder whatever their
//! titles became. The source's identity is the job's canonical address:
//! two devices following the same channel fill the same folder.
//!
//! Only the files the job names are listed (completed downloads); yt-dlp's
//! work directory (`.varsto-work`) is never listed.

use super::{dir, Delivery, ImportSource, ListedItem, Listing, Note, SourceInfo, Verdict, Wanted};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct SpoolSource {
    root: PathBuf,
    info: SourceInfo,
    only: BTreeSet<String>,
    /// (size, mtime) of each listed path, checked again when it is read.
    listed: BTreeMap<String, (u64, i64)>,
}

/// The identity of a job's source.
pub fn identity(canonical_url: &str) -> String {
    format!("youtube:{canonical_url}")
}

impl SpoolSource {
    /// `only`: the paths (relative to `dir`) to list.
    pub fn open(
        dir: &Path,
        canonical_url: &str,
        label: &str,
        only: BTreeSet<String>,
    ) -> Result<SpoolSource> {
        let root = dir.canonicalize().map_err(|e| {
            anyhow::anyhow!("the download directory {} is not there: {e}", dir.display())
        })?;
        if !root.is_dir() {
            bail!("{} is not a directory", root.display());
        }
        let id = identity(canonical_url);
        Ok(SpoolSource {
            info: SourceInfo {
                kind: super::KIND_YOUTUBE,
                identity: vec![id.clone()],
                display: canonical_url.to_string(),
                default_folder: super::folder_name_from(label),
                instance: id,
                instance_name: root.display().to_string(),
                repositories: BTreeMap::new(),
                dead: Default::default(),
                local_path: Some(root.clone()),
            },
            root,
            only,
            listed: BTreeMap::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// The content id of a path in the spool, from the `[<id>]` in its name.
pub fn path_content_id(path: &str) -> Option<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let vid = crate::youtube::id_from_filename(name)?;
    let suffix = crate::youtube::suffix_after_id(name, &vid)?;
    Some(crate::youtube::content_id(&vid, suffix))
}

impl ImportSource for SpoolSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn list(&mut self) -> Result<Listing> {
        let mut listing = Listing {
            tree_ref: format!("listed {}", crate::util::now_utc()),
            ..Default::default()
        };
        self.listed.clear();
        for path in &self.only {
            if let Err(e) = crate::util::check_rel_path(path) {
                listing.skipped.push(Note {
                    path: path.clone(),
                    reason: format!("the name cannot be used in Varsto: {e}"),
                });
                continue;
            }
            let Some(id) = path_content_id(path) else {
                listing.skipped.push(Note {
                    path: path.clone(),
                    reason: "no video id in the name".into(),
                });
                continue;
            };
            let p = crate::util::safe_join(&self.root, path)?;
            let md = match std::fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_file() => m,
                Ok(_) => {
                    listing.skipped.push(Note {
                        path: path.clone(),
                        reason: "not a regular file".into(),
                    });
                    continue;
                }
                Err(_) => continue,
            };
            let mtime = dir::mtime_ns(&md);
            self.listed.insert(path.clone(), (md.len(), mtime));
            listing.items.push(ListedItem {
                path: path.clone(),
                id,
                size: Some(md.len()),
                mtime_ns: Some(mtime),
                check: None,
                present: true,
            });
        }
        Ok(listing)
    }

    fn deliver(&mut self, wanted: &[Wanted], sink: &mut super::Sink) -> Result<()> {
        let mut order: Vec<usize> = (0..wanted.len()).collect();
        order.sort_by(|a, b| wanted[*a].path.cmp(&wanted[*b].path));
        for i in order {
            let w = &wanted[i];
            let verdict = match dir::open_inside(&self.root, &w.path) {
                Ok(Some((mut f, md))) => {
                    let same = self
                        .listed
                        .get(&w.path)
                        .is_some_and(|(s, m)| *s == md.len() && *m == dir::mtime_ns(&md));
                    if !same {
                        sink(
                            i,
                            Delivery::Failed("changed while importing; it is read again".into()),
                        )?
                    } else {
                        sink(
                            i,
                            Delivery::Content {
                                reader: &mut f,
                                mtime_ns: Some(dir::mtime_ns(&md)),
                                retry: false,
                            },
                        )?
                    }
                }
                Ok(None) => sink(i, Delivery::Missing)?,
                Err(e) => sink(i, Delivery::Failed(format!("cannot be read: {e:#}")))?,
            };
            if verdict == Verdict::Stop {
                break;
            }
        }
        Ok(())
    }

    fn wants_source_hash(&self) -> bool {
        true
    }
}
