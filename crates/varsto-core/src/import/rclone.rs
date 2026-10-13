// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Any rclone remote as an import source: Dropbox, OneDrive, Google Drive,
//! and every other backend rclone knows. Varsto runs the user's own
//! `rclone` (`VARSTO_RCLONE`, else `rclone` on the path) with the user's own
//! configuration (`RCLONE_CONFIG` is passed through); the remote's tokens
//! are never read by Varsto: of `rclone config dump` only each remote's
//! `type` is kept.
//!
//! Listing: `rclone lsjson -R --files-only --no-mimetype`, read line by
//! line as rclone writes it, with the provider's own hash where the remote
//! has one (Dropbox content hash, OneDrive QuickXorHash, MD5, SHA-1, ...).
//! Reading: `rclone copy --files-from-raw` of a batch of files into a
//! temporary directory (one rclone process per batch keeps its
//! connections and parallel transfers, much faster than one `rclone cat`
//! per file), then each file is handed over and deleted. A file whose
//! content does not match the provider's hash is downloaded once more.

use super::{
    Check, Delivery, ImportSource, ListedItem, Listing, Note, SourceInfo, Verdict, Wanted,
};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> String {
    std::env::var("VARSTO_RCLONE").unwrap_or_else(|_| "rclone".to_string())
}

fn rclone() -> Command {
    let mut c = Command::new(binary());
    c.stdin(Stdio::null());
    c
}

/// `remote:path` split into the remote's name and the path. On-the-fly
/// remotes (`:local:/tmp`) are named by their backend.
pub fn split_remote(spec: &str) -> Result<(String, String)> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix(':') {
        let (backend, path) = rest
            .split_once(':')
            .ok_or_else(|| anyhow!("a remote looks like `name:path` (see `rclone listremotes`)"))?;
        return Ok((
            format!(":{backend}"),
            path.trim_end_matches('/').to_string(),
        ));
    }
    let (name, path) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("a remote looks like `name:path` (see `rclone listremotes`)"))?;
    if name.is_empty() || name.contains('/') {
        bail!("a remote looks like `name:path` (see `rclone listremotes`)");
    }
    Ok((name.to_string(), path.trim_end_matches('/').to_string()))
}

/// The type of every configured remote (`dropbox`, `onedrive`, `drive`, ...)
/// from `rclone config dump`; everything else in it (tokens) is dropped
/// unread.
pub fn remote_types() -> Result<BTreeMap<String, String>> {
    let out = rclone()
        .args(["config", "dump"])
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run {} (install rclone or set VARSTO_RCLONE)", binary()))?;
    if !out.status.success() {
        bail!(
            "rclone config dump failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("read rclone's remote list")?;
    let mut types = BTreeMap::new();
    if let Some(map) = v.as_object() {
        for (name, conf) in map {
            if let Some(t) = conf.get("type").and_then(|t| t.as_str()) {
                types.insert(name.clone(), t.to_string());
            }
        }
    }
    Ok(types)
}

/// How to set a remote of `kind` up, for the message when it is missing.
pub fn setup_help(kind: &str, name: &str) -> String {
    let label = match kind {
        "dropbox" => "Dropbox",
        "onedrive" => "OneDrive",
        "drive" => "Google Drive",
        other => other,
    };
    format!(
        "no rclone remote named {name:?} of type {kind}. Set one up with rclone first (the {label} sign-in happens in your browser, between you and {label}):\n  rclone config create {name} {kind}\nthen run the import again with {name}:<path>"
    )
}

/// The hash to ask for, by remote type: the provider's own where it has
/// one. A local remote would have to read every file to hash it, so none
/// unless asked for.
fn default_hash(remote_type: &str, spec: &str) -> Option<String> {
    let fixed = match remote_type {
        "dropbox" => Some("dropbox"),
        "onedrive" => Some("quickxor"),
        "drive" => Some("sha256"),
        "s3" | "gcs" | "azureblob" | "swift" | "hidrive" => Some("md5"),
        "b2" | "box" | "pcloud" | "mega" => Some("sha1"),
        "local" | "alias" | "crypt" | "union" | "combine" | "chunker" | "compress" => None,
        _ => return features_hash(spec),
    };
    fixed.map(str::to_string)
}

/// For other backends: the first hash `rclone backend features` lists that
/// Varsto can check.
fn features_hash(spec: &str) -> Option<String> {
    let out = rclone()
        .args(["backend", "features", spec])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let hashes: Vec<String> = v
        .get("Hashes")?
        .as_array()?
        .iter()
        .filter_map(|h| h.as_str().map(str::to_string))
        .collect();
    ["dropbox", "quickxor", "sha256", "sha1", "md5", "blake3"]
        .into_iter()
        .find(|h| hashes.iter().any(|x| x == h))
        .map(str::to_string)
}

pub struct RcloneSource {
    /// `remote:path` without a trailing slash.
    root: String,
    hash: Option<String>,
    transfers: u32,
    batch_files: usize,
    batch_bytes: u64,
    scratch: PathBuf,
    info: SourceInfo,
}

impl RcloneSource {
    /// `spec` is `remote:path`; `expect_type` (dropbox, onedrive) is checked
    /// against the configuration; `hash` overrides the hash type (`none`
    /// for none); `scratch` is an empty directory of this device for the
    /// downloads in progress.
    pub fn open(
        spec: &str,
        expect_type: Option<&str>,
        hash: Option<&str>,
        transfers: u32,
        scratch: &Path,
    ) -> Result<RcloneSource> {
        let (name, path) = split_remote(spec)?;
        let remote_type = if let Some(b) = name.strip_prefix(':') {
            b.to_string()
        } else {
            let types = remote_types()?;
            match (types.get(&name), expect_type) {
                (Some(t), Some(want)) if t != want => bail!(
                    "rclone remote {name:?} is of type {t}, not {want}; use `varsto import rclone {spec}` for it"
                ),
                (Some(t), _) => t.clone(),
                (None, Some(want)) => bail!("{}", setup_help(want, &name)),
                (None, None) => bail!(
                    "no rclone remote named {name:?} (see `rclone listremotes`; set one up with `rclone config`)"
                ),
            }
        };
        let root = if path.is_empty() {
            format!("{name}:")
        } else {
            format!("{name}:{path}")
        };
        let hash = match hash {
            Some("none") => None,
            Some(h) => {
                if super::hashes::Hasher::new(h).is_none() {
                    bail!("Varsto cannot check hashes of type {h}");
                }
                Some(h.to_string())
            }
            None => default_hash(&remote_type, &root),
        };
        let identity = format!("rclone:{remote_type}:{name}:{}", path.trim_matches('/'));
        let last = path
            .trim_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(name.trim_start_matches(':'))
            .to_string();
        let label = match remote_type.as_str() {
            "dropbox" => "Dropbox",
            "onedrive" => "OneDrive",
            "drive" => "Google Drive",
            _ => "",
        };
        let default_folder = if label.is_empty() || !path.trim_matches('/').is_empty() {
            super::folder_name_from(&last)
        } else {
            label.to_string()
        };
        std::fs::create_dir_all(scratch)?;
        Ok(RcloneSource {
            info: SourceInfo {
                kind: super::KIND_RCLONE,
                identity: vec![identity.clone()],
                display: root.clone(),
                default_folder,
                instance: identity,
                instance_name: root.clone(),
                repositories: BTreeMap::new(),
                dead: Default::default(),
                local_path: None,
            },
            root,
            hash,
            transfers: transfers.max(1),
            batch_files: 256,
            batch_bytes: 1 << 30,
            scratch: scratch.to_path_buf(),
        })
    }

    pub fn hash_type(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    fn remote_file(&self, path: &str) -> String {
        if self.root.ends_with(':') {
            format!("{}{path}", self.root)
        } else {
            format!("{}/{path}", self.root)
        }
    }

    /// Copy `paths` into `dir` with one rclone process.
    fn copy_batch(&self, paths: &[&str], dir: &Path) -> Result<String> {
        let list = dir.join(".varsto-files");
        let mut f = std::fs::File::create(&list)?;
        for p in paths {
            f.write_all(p.as_bytes())?;
            f.write_all(b"\n")?;
        }
        drop(f);
        let t = self.transfers.to_string();
        let out = rclone()
            .args(["copy", "--files-from-raw"])
            .arg(&list)
            .args([
                "--transfers",
                &t,
                "--checkers",
                &t,
                "--no-traverse",
                "-q",
                "--",
            ])
            .arg(&self.root)
            .arg(dir.join("files"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("run {}", binary()))?;
        let _ = std::fs::remove_file(&list);
        Ok(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }

    fn copy_one(&self, path: &str, to: &Path) -> Result<bool> {
        let st = rclone()
            .args(["copyto", "-q", "--"])
            .arg(self.remote_file(path))
            .arg(to)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(st.success() && to.is_file())
    }
}

/// One line of `rclone lsjson` (an array written one object per line).
fn parse_line(line: &str) -> Option<serde_json::Value> {
    let t = line.trim().trim_end_matches(',');
    if t.is_empty() || t == "[" || t == "]" {
        return None;
    }
    serde_json::from_str(t).ok()
}

impl ImportSource for RcloneSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn list(&mut self) -> Result<Listing> {
        let mut cmd = rclone();
        cmd.args(["lsjson", "-R", "--files-only", "--no-mimetype"]);
        if let Some(h) = &self.hash {
            cmd.args(["--hash", "--hash-type", h]);
        }
        let mut child = cmd
            .arg("--")
            .arg(&self.root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("run {}", binary()))?;
        let stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let err_reader = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut s);
            s
        });
        let mut listing = Listing {
            tree_ref: format!("listed {}", crate::util::now_utc()),
            ..Default::default()
        };
        let mut lower: BTreeMap<String, String> = BTreeMap::new();
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            let Some(v) = parse_line(&line) else {
                continue;
            };
            let Some(path) = v.get("Path").and_then(|p| p.as_str()).map(str::to_string) else {
                continue;
            };
            if v.get("IsDir").and_then(|d| d.as_bool()) == Some(true) {
                continue;
            }
            let size = v.get("Size").and_then(|s| s.as_i64()).unwrap_or(-1);
            if size < 0 {
                listing.skipped.push(Note {
                    path,
                    reason: "has no fixed size: a document only the provider can open (Google Docs, Dropbox Paper, OneNote); export it in the provider's app".into(),
                });
                continue;
            }
            if let Err(e) = crate::util::check_rel_path(&path) {
                listing.skipped.push(Note {
                    path,
                    reason: format!("the name cannot be used in Varsto: {e}"),
                });
                continue;
            }
            if path.split('/').any(|c| c.starts_with(".varsto")) {
                listing.skipped.push(Note {
                    path,
                    reason: "names starting with .varsto are Varsto's own".into(),
                });
                continue;
            }
            if let Some(other) = lower.insert(path.to_lowercase(), path.clone()) {
                listing.warnings.push(Note {
                    path: path.clone(),
                    reason: format!(
                        "differs from {other} only by case: both are imported, but they cannot sit side by side on Windows or macOS"
                    ),
                });
            }
            let mtime_ns = v
                .get("ModTime")
                .and_then(|m| m.as_str())
                .and_then(super::parse_rfc3339_ns);
            let hash = self.hash.as_ref().and_then(|h| {
                v.get("Hashes")
                    .and_then(|hs| hs.get(h))
                    .and_then(|x| x.as_str())
                    .filter(|x| !x.is_empty())
                    .map(|x| (h.clone(), x.to_ascii_lowercase()))
            });
            let id = match &hash {
                Some((algo, hex)) => format!("rclone:{algo}:{hex}:{path}"),
                None => format!("rclone:{size}:{}:{path}", mtime_ns.unwrap_or(0)),
            };
            listing.items.push(ListedItem {
                path,
                id,
                size: Some(size as u64),
                mtime_ns,
                check: hash.map(|(algo, hex)| Check { algo, hex }),
                present: true,
            });
        }
        let status = child.wait()?;
        let err = err_reader.join().unwrap_or_default();
        if !status.success() {
            bail!("rclone lsjson {} failed: {}", self.root, err.trim());
        }
        Ok(listing)
    }

    fn deliver(&mut self, wanted: &[Wanted], sink: &mut super::Sink) -> Result<()> {
        let mut order: Vec<usize> = (0..wanted.len()).collect();
        order.sort_by(|a, b| wanted[*a].path.cmp(&wanted[*b].path));
        let mut at = 0;
        let dir = self.scratch.join(format!("batch-{}", std::process::id()));
        while at < order.len() {
            // A batch: up to `batch_files` files and `batch_bytes` bytes.
            let mut end = at;
            let mut bytes = 0u64;
            while end < order.len()
                && end - at < self.batch_files
                && (end == at || bytes + wanted[order[end]].size.unwrap_or(0) <= self.batch_bytes)
            {
                bytes += wanted[order[end]].size.unwrap_or(0);
                end += 1;
            }
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir)?;
            // Names with a line break cannot go in a list; those one by one.
            let (listable, single): (Vec<usize>, Vec<usize>) = order[at..end]
                .iter()
                .partition(|i| !wanted[**i].path.contains(['\n', '\r']));
            let paths: Vec<&str> = listable.iter().map(|i| wanted[*i].path.as_str()).collect();
            let errors = if paths.is_empty() {
                String::new()
            } else {
                self.copy_batch(&paths, &dir)?
            };
            for i in single {
                let to = dir.join("files").join(&wanted[i].path);
                if let Some(p) = to.parent() {
                    std::fs::create_dir_all(p)?;
                }
                let _ = self.copy_one(&wanted[i].path, &to);
            }
            for &i in &order[at..end] {
                let w = &wanted[i];
                let local = crate::util::safe_join(&dir.join("files"), &w.path);
                let verdict = match local.as_ref().ok().filter(|p| p.is_file()) {
                    None => sink(
                        i,
                        Delivery::Failed(if errors.is_empty() {
                            "rclone did not download it (removed since the listing?)".into()
                        } else {
                            format!("rclone did not download it: {}", last_line(&errors))
                        }),
                    )?,
                    Some(p) => {
                        let p = p.clone();
                        let mut v = deliver_file(&p, i, true, sink)?;
                        if v == Verdict::Mismatch {
                            // Once more from the provider.
                            let _ = std::fs::remove_file(&p);
                            v = if self.copy_one(&w.path, &p)? {
                                deliver_file(&p, i, false, sink)?
                            } else {
                                sink(i, Delivery::Failed("the second download failed".into()))?
                            };
                        }
                        let _ = std::fs::remove_file(&p);
                        v
                    }
                };
                if verdict == Verdict::Stop {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Ok(());
                }
            }
            at = end;
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}

fn last_line(s: &str) -> &str {
    s.lines().last().unwrap_or(s)
}

fn deliver_file(p: &Path, i: usize, retry: bool, sink: &mut super::Sink) -> Result<Verdict> {
    let mut f = std::fs::File::open(p)?;
    sink(
        i,
        Delivery::Content {
            reader: &mut f,
            // The listing's time: rclone sets it on the copy where it can.
            mtime_ns: None,
            retry,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_specs() {
        assert_eq!(
            split_remote("dropbox:Photos/2020/").unwrap(),
            ("dropbox".to_string(), "Photos/2020".to_string())
        );
        assert_eq!(
            split_remote("od:").unwrap(),
            ("od".to_string(), String::new())
        );
        assert_eq!(
            split_remote(":local:/tmp/x").unwrap(),
            (":local".to_string(), "/tmp/x".to_string())
        );
        assert!(split_remote("nocolon").is_err());
    }

    #[test]
    fn lsjson_lines() {
        assert!(parse_line("[").is_none());
        let v = parse_line(r#"{"Path":"a/b.txt","Name":"b.txt","Size":3,"ModTime":"2024-01-01T00:00:00Z","IsDir":false},"#).unwrap();
        assert_eq!(v["Path"], "a/b.txt");
        assert!(
            setup_help("dropbox", "mydropbox").contains("rclone config create mydropbox dropbox")
        );
    }
}
