// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A local directory as an import source. Files are read in path order
//! (one after the other: on a rotating disk that is the fastest); symbolic
//! links are never followed, special files (sockets, devices, pipes) and
//! unreadable entries are named in the report. A file's id is its path,
//! size and modification time, so a changed file is imported again as a
//! new version. The SHA-256 of what was read is kept in the import book:
//! removing the source files afterwards (`import cleanup`) checks it again.

use super::{Delivery, ImportSource, ListedItem, Listing, Note, SourceInfo, Verdict, Wanted};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct DirSource {
    root: PathBuf,
    info: SourceInfo,
}

pub fn mtime_ns(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// The id of a file version of a local source.
pub fn file_id(path: &str, size: u64, mtime_ns: i64) -> String {
    format!("dir:{size}:{mtime_ns}:{path}")
}

impl DirSource {
    pub fn open(path: &Path) -> Result<DirSource> {
        let root = path
            .canonicalize()
            .with_context(|| format!("no directory {}", path.display()))?;
        if !root.is_dir() {
            bail!("{} is not a directory", root.display());
        }
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "import".into());
        let identity = format!("dir:{}", root.display());
        Ok(DirSource {
            info: SourceInfo {
                kind: super::KIND_DIR,
                identity: vec![identity.clone()],
                display: root.display().to_string(),
                default_folder: super::folder_name_from(&name),
                instance: identity,
                instance_name: root.display().to_string(),
                repositories: BTreeMap::new(),
                dead: Default::default(),
                local_path: Some(root.clone()),
            },
            root,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl ImportSource for DirSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn list(&mut self) -> Result<Listing> {
        let mut listing = Listing {
            tree_ref: format!("listed {}", crate::util::now_utc()),
            ..Default::default()
        };
        let mut lower: BTreeMap<String, String> = BTreeMap::new();
        let walker = walkdir::WalkDir::new(&self.root)
            .follow_links(false)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".varsto"));
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let path = e
                        .path()
                        .and_then(|p| p.strip_prefix(&self.root).ok())
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default();
                    listing.skipped.push(Note {
                        path,
                        reason: format!("cannot be read: {e}"),
                    });
                    continue;
                }
            };
            let rel = entry.path().strip_prefix(&self.root)?;
            let ft = entry.file_type();
            if ft.is_dir() {
                continue;
            }
            let Some(path) = crate::util::manifest_path(rel) else {
                listing.skipped.push(Note {
                    path: rel.to_string_lossy().to_string(),
                    reason: "the name is not valid UTF-8".into(),
                });
                continue;
            };
            if ft.is_symlink() {
                listing.skipped.push(Note {
                    path,
                    reason: "a symbolic link: not followed".into(),
                });
                continue;
            }
            if !ft.is_file() {
                listing.skipped.push(Note {
                    path,
                    reason: "a special file (socket, device or pipe)".into(),
                });
                continue;
            }
            // Names are kept as they are (`crate::names`); only what
            // could leave the folder is refused.
            if let Err(e) = crate::util::check_rel_path(&path) {
                listing.skipped.push(Note {
                    path,
                    reason: format!("the name cannot be used in Varsto: {e}"),
                });
                continue;
            }
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    listing.skipped.push(Note {
                        path,
                        reason: format!("cannot be read: {e}"),
                    });
                    continue;
                }
            };
            if let Some(other) = lower.insert(path.to_lowercase(), path.clone()) {
                listing.warnings.push(Note {
                    path: path.clone(),
                    reason: format!(
                        "differs from {other} only by case: both are imported; on Windows and macOS one of them is kept under a local name with \" (2)\""
                    ),
                });
            }
            let mtime = mtime_ns(&md);
            listing.items.push(ListedItem {
                id: file_id(&path, md.len(), mtime),
                path,
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
            let verdict = match open_inside(&self.root, &w.path) {
                Ok(Some((mut f, md))) => {
                    let id = file_id(&w.path, md.len(), mtime_ns(&md));
                    if id != w.id {
                        sink(
                            i,
                            Delivery::Failed(
                                "changed while importing; run the import again".into(),
                            ),
                        )?
                    } else {
                        sink(
                            i,
                            Delivery::Content {
                                reader: &mut f,
                                mtime_ns: Some(mtime_ns(&md)),
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

/// Open `root/rel` for reading when it is a regular file reached without
/// passing any symbolic link; `None` when it is gone.
pub fn open_inside(root: &Path, rel: &str) -> Result<Option<(std::fs::File, std::fs::Metadata)>> {
    let p = match crate::util::safe_join(root, rel) {
        Ok(p) => p,
        Err(e) => bail!("{e}"),
    };
    let md = match std::fs::symlink_metadata(&p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !md.file_type().is_file() {
        bail!("no longer a regular file");
    }
    let f = std::fs::File::open(&p)?;
    let md = f.metadata()?;
    Ok(Some((f, md)))
}
