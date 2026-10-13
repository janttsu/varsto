// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A git-annex repository as an import source, read without git-annex and
//! without changing anything: `git ls-tree` for the file list of a commit,
//! `git cat-file` for symlink targets, pointer files, small files committed
//! to git, and the logs of the `git-annex` branch; the annexed objects are
//! read straight from `.git/annex/objects` (or `annex/objects` in a bare
//! repository). No git-annex command is ever run on the repository.
//!
//! Keys: `BACKEND-sSIZE-mMTIME--NAME`. The hash of a hashing backend is the
//! name (without the extension of the `E` variants) and is checked while
//! the object is read; WORM and URL keys carry no hash.

use super::hashes;
use super::{
    Check, Delivery, ImportSource, ListedItem, Listing, Note, SourceInfo, Verdict, Wanted,
};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A git-annex key, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub backend: String,
    pub size: Option<u64>,
    /// Seconds (WORM keys).
    pub mtime: Option<i64>,
    pub name: String,
}

impl Key {
    pub fn parse(s: &str) -> Option<Key> {
        let (head, name) = s.split_once("--")?;
        let mut fields = head.split('-');
        let backend = fields.next()?.to_string();
        if backend.is_empty()
            || !backend
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        let mut key = Key {
            backend,
            size: None,
            mtime: None,
            name: name.to_string(),
        };
        for f in fields {
            let (tag, v) = f.split_at_checked(1)?;
            match tag {
                "s" => key.size = Some(v.parse().ok()?),
                "m" => key.mtime = Some(v.parse().ok()?),
                // Chunk fields: only special remotes store chunked keys.
                "S" | "C" => return None,
                _ => {}
            }
        }
        if key.name.is_empty() || key.name.contains('/') {
            return None;
        }
        Some(key)
    }

    /// The hash to check the content against, when the backend has one
    /// this build can compute.
    pub fn check(&self) -> Option<Check> {
        let (base, ext) = match self.backend.strip_suffix('E') {
            Some(b) if !b.is_empty() && algo_of(b).is_some() => (b, true),
            _ => (self.backend.as_str(), false),
        };
        let (algo, hex_len) = algo_of(base)?;
        let hex = if ext {
            self.name.split('.').next().unwrap_or("")
        } else {
            self.name.as_str()
        };
        if hex.len() != hex_len || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Check {
            algo: algo.to_string(),
            hex: hex.to_ascii_lowercase(),
        })
    }
}

fn algo_of(backend: &str) -> Option<(&'static str, usize)> {
    Some(match backend {
        "SHA256" => ("sha256", 64),
        "SHA512" => ("sha512", 128),
        "SHA384" => ("sha384", 96),
        "SHA224" => ("sha224", 56),
        "SHA1" => ("sha1", 40),
        "MD5" => ("md5", 32),
        "BLAKE2B160" => ("blake2b160", 40),
        "BLAKE2B224" => ("blake2b224", 56),
        "BLAKE2B256" => ("blake2b256", 64),
        "BLAKE2B384" => ("blake2b384", 96),
        "BLAKE2B512" => ("blake2b512", 128),
        "BLAKE2S256" => ("blake2s256", 64),
        _ => return None,
    })
}

/// `hashDirLower`: the first 3 and next 3 hex digits of the key's MD5
/// (location logs, bare repositories' objects).
pub fn hashdir_lower(key: &str) -> String {
    let h = hex::encode(hashes::md5_bytes(key.as_bytes()));
    format!("{}/{}", &h[..3], &h[3..6])
}

/// `hashDirMixed`: two directories of two characters from the key's MD5
/// read as little-endian 32-bit words (objects of non-bare repositories).
pub fn hashdir_mixed(key: &str) -> String {
    const CHARS: &[u8] = b"0123456789zqjxkmvwgpfZQJXKMVWGPF";
    let d = hashes::md5_bytes(key.as_bytes());
    let mut s = String::new();
    for w in d.chunks(4) {
        let w = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        let cs: Vec<u8> = (0..8)
            .map(|x| CHARS[(((w as u64) >> (6 * x)) & 31) as usize])
            .collect();
        // Pairs swapped, the last two (always "00") dropped.
        let mut swapped = Vec::new();
        for p in cs.chunks(2) {
            swapped.push(p[1]);
            swapped.push(p[0]);
        }
        s.push_str(&String::from_utf8_lossy(&swapped[..6]));
        if s.len() >= 4 {
            break;
        }
    }
    format!("{}/{}", &s[..2], &s[2..4])
}

fn git_cmd(repo: &Path) -> Command {
    let mut c = Command::new(std::env::var("VARSTO_GIT").unwrap_or_else(|_| "git".into()));
    c.arg("-C").arg(repo);
    // Read-only: no optional locks (index refresh), and nothing from the
    // caller's environment that points git elsewhere.
    c.env("GIT_OPTIONAL_LOCKS", "0");
    for v in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    ] {
        c.env_remove(v);
    }
    c
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = git_cmd(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("run git (install git to import git-annex repositories)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("dubious ownership") {
            bail!(
                "git refuses to read {}: it belongs to another user. Add it to git's safe.directory list (git config --global --add safe.directory {}) and run the import again",
                repo.display(),
                repo.display()
            );
        }
        bail!("git {}: {}", args.join(" "), err.trim());
    }
    Ok(out.stdout)
}

fn git_line(repo: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&git(repo, args)?)
        .trim()
        .to_string())
}

/// Look up many objects with one `git cat-file --batch`: `f(index, content)`
/// for each query in order (`None` when it does not exist).
fn cat_file_batch(
    repo: &Path,
    queries: &[String],
    mut f: impl FnMut(usize, Option<Vec<u8>>) -> Result<()>,
) -> Result<()> {
    if queries.is_empty() {
        return Ok(());
    }
    let mut child = git_cmd(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("run git cat-file")?;
    let mut stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    let result = std::thread::scope(|s| -> Result<()> {
        let writer = s.spawn(move || -> std::io::Result<()> {
            let mut w = std::io::BufWriter::new(&mut stdin);
            for q in queries {
                w.write_all(q.as_bytes())?;
                w.write_all(b"\n")?;
            }
            w.flush()?;
            drop(w);
            drop(stdin);
            Ok(())
        });
        let mut r = BufReader::new(stdout);
        for i in 0..queries.len() {
            let mut header = String::new();
            if r.read_line(&mut header)? == 0 {
                bail!("git cat-file ended early");
            }
            let header = header.trim_end();
            if header.ends_with(" missing") || header.ends_with(" ambiguous") {
                f(i, None)?;
                continue;
            }
            let size: usize = header
                .rsplit(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| anyhow!("unexpected git cat-file output {header:?}"))?;
            let mut buf = vec![0u8; size + 1];
            r.read_exact(&mut buf)?;
            buf.pop();
            f(i, Some(buf))?;
        }
        writer
            .join()
            .map_err(|_| anyhow!("git cat-file writer panicked"))??;
        Ok(())
    });
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// What one path of the tree is.
enum Entry {
    Annexed(String),
    Git { blob: String, size: u64 },
}

/// A git-annex repository on this device.
pub struct AnnexSource {
    repo: PathBuf,
    git_dir: PathBuf,
    commit: String,
    commit_utc: i64,
    object_format: String,
    annex_refs: Vec<String>,
    info: SourceInfo,
    /// Where each present key's object is (filled by `list`).
    objects: HashMap<String, PathBuf>,
}

/// The newest line per UUID of a git-annex UUID-keyed log
/// (`uuid.log`: `uuid description timestamp=...s`; `trust.log`:
/// `uuid X timestamp=...s`).
fn uuid_log(text: &str, into: &mut BTreeMap<String, (f64, String)>) {
    for line in text.lines() {
        let line = line.trim();
        let Some((uuid, rest)) = line.split_once(' ') else {
            continue;
        };
        let (value, ts) = match rest.rsplit_once(" timestamp=") {
            Some((v, t)) => (v, t.trim_end_matches('s').parse().unwrap_or(0.0)),
            None => (rest, 0.0),
        };
        if into.get(uuid).is_none_or(|(t, _)| ts >= *t) {
            into.insert(uuid.to_string(), (ts, value.to_string()));
        }
    }
}

/// Location log lines: `timestamp 1|0|X uuid` -> newest per UUID.
fn location_log(text: &str, into: &mut BTreeMap<String, (f64, bool)>) {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(ts), Some(st), Some(uuid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let ts: f64 = ts.trim_end_matches('s').parse().unwrap_or(0.0);
        if into.get(uuid).is_none_or(|(t, _)| ts >= *t) {
            into.insert(uuid.to_string(), (ts, st == "1"));
        }
    }
}

impl AnnexSource {
    /// Open the repository at `path` and pick the commit `git_ref` (HEAD,
    /// a branch or a tag).
    pub fn open(path: &Path, git_ref: &str) -> Result<AnnexSource> {
        let repo = path
            .canonicalize()
            .with_context(|| format!("no repository at {}", path.display()))?;
        let git_dir = PathBuf::from(
            git_line(&repo, &["rev-parse", "--absolute-git-dir"])
                .with_context(|| format!("{} is not a git repository", repo.display()))?,
        );
        let uuid = git_line(&repo, &["config", "--get", "annex.uuid"]).unwrap_or_default();
        if uuid.is_empty() {
            bail!(
                "{} is not a git-annex repository (no annex.uuid in its git config)",
                repo.display()
            );
        }
        let refs = git_line(
            &repo,
            &[
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads/git-annex",
                "refs/remotes/",
            ],
        )?;
        let annex_refs: Vec<String> = refs
            .lines()
            .filter(|r| *r == "refs/heads/git-annex" || r.ends_with("/git-annex"))
            .map(str::to_string)
            .collect();
        if annex_refs.is_empty() {
            bail!("{} has no git-annex branch", repo.display());
        }
        let mut args = vec!["rev-list", "--max-parents=0"];
        args.extend(annex_refs.iter().map(String::as_str));
        let roots: BTreeSet<String> = git_line(&repo, &args)?
            .lines()
            .map(|l| format!("annex-root:{}", l.trim()))
            .collect();
        let mut uuids: BTreeMap<String, (f64, String)> = BTreeMap::new();
        let mut trust: BTreeMap<String, (f64, String)> = BTreeMap::new();
        let queries: Vec<String> = annex_refs
            .iter()
            .flat_map(|r| [format!("{r}:uuid.log"), format!("{r}:trust.log")])
            .collect();
        cat_file_batch(&repo, &queries, |i, content| {
            if let Some(c) = content {
                let text = String::from_utf8_lossy(&c);
                if i % 2 == 0 {
                    uuid_log(&text, &mut uuids);
                } else {
                    uuid_log(&text, &mut trust);
                }
            }
            Ok(())
        })?;
        let repositories: BTreeMap<String, String> =
            uuids.into_iter().map(|(u, (_, d))| (u, d)).collect();
        let dead: BTreeSet<String> = trust
            .into_iter()
            .filter(|(_, (_, v))| v.trim() == "X")
            .map(|(u, _)| u)
            .collect();
        let commit = git_line(
            &repo,
            &["rev-parse", "--verify", &format!("{git_ref}^{{commit}}")],
        )
        .with_context(|| format!("no commit {git_ref} in {}", repo.display()))?;
        let commit_utc: i64 = git_line(&repo, &["show", "-s", "--format=%ct", &commit])?
            .parse()
            .unwrap_or(0);
        let object_format = git_line(&repo, &["rev-parse", "--show-object-format"])
            .unwrap_or_else(|_| "sha1".into());
        let dir_name = repo
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let description = repositories
            .get(&uuid)
            .filter(|d| !d.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| dir_name.clone());
        // The folder is named after the repository, not the disk: the
        // description often names the disk; the directory name rarely does.
        let default_folder = super::folder_name_from(if dir_name.is_empty() {
            &description
        } else {
            &dir_name
        });
        let info = SourceInfo {
            kind: super::KIND_ANNEX,
            identity: roots.into_iter().collect(),
            display: repo.display().to_string(),
            default_folder,
            instance: uuid,
            instance_name: description,
            repositories,
            dead,
            local_path: Some(repo.clone()),
        };
        Ok(AnnexSource {
            repo,
            git_dir,
            commit,
            commit_utc,
            object_format,
            annex_refs,
            info,
            objects: HashMap::new(),
        })
    }

    /// The object file of a key on this disk, if its content is here.
    fn object_path(&self, key: &str) -> Option<PathBuf> {
        let base = self.git_dir.join("annex").join("objects");
        for dir in [hashdir_mixed(key), hashdir_lower(key)] {
            let p = base.join(&dir).join(key).join(key);
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
                return Some(p);
            }
        }
        None
    }

    /// The key a symlink target or pointer file names.
    fn key_of(content: &[u8], symlink: bool) -> Option<String> {
        let text = std::str::from_utf8(content).ok()?;
        let text = text.trim_end_matches(['\n', '\r']);
        let key = if symlink {
            if !text.contains("annex/objects/") {
                return None;
            }
            text.rsplit('/').next()?
        } else {
            let rest = text.strip_prefix("/annex/objects/")?;
            if rest.contains('\n') {
                return None;
            }
            rest
        };
        Key::parse(key).map(|_| key.to_string())
    }
}

impl ImportSource for AnnexSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn list(&mut self) -> Result<Listing> {
        let raw = git(
            &self.repo,
            &["ls-tree", "-r", "-z", "-l", "--full-tree", &self.commit],
        )?;
        let mut listing = Listing {
            tree_ref: self.commit.clone(),
            ..Default::default()
        };
        // (path, mode, blob, size)
        let mut rows: Vec<(String, String, String, u64)> = Vec::new();
        for rec in raw.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let Some(tab) = rec.iter().position(|b| *b == b'\t') else {
                continue;
            };
            let head = String::from_utf8_lossy(&rec[..tab]).to_string();
            let path = match std::str::from_utf8(&rec[tab + 1..]) {
                Ok(p) => p.to_string(),
                Err(_) => {
                    listing.skipped.push(Note {
                        path: String::from_utf8_lossy(&rec[tab + 1..]).to_string(),
                        reason: "the name is not valid UTF-8".into(),
                    });
                    continue;
                }
            };
            // Names are kept as they are (`crate::names`); only what could
            // leave the folder, and Varsto's own names, are refused.
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
            let mut f = head.split_whitespace();
            let (Some(mode), Some(kind), Some(blob), Some(size)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            if kind != "blob" {
                listing.skipped.push(Note {
                    path,
                    reason: "a git submodule".into(),
                });
                continue;
            }
            rows.push((
                path,
                mode.to_string(),
                blob.to_string(),
                size.parse().unwrap_or(0),
            ));
        }
        // Symlink targets and small files (which may be pointer files).
        let lookups: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, (_, mode, _, size))| mode == "120000" || *size < 1024)
            .map(|(i, _)| i)
            .collect();
        let queries: Vec<String> = lookups.iter().map(|i| rows[*i].2.clone()).collect();
        let mut contents: HashMap<usize, Vec<u8>> = HashMap::new();
        cat_file_batch(&self.repo, &queries, |n, c| {
            if let Some(c) = c {
                contents.insert(lookups[n], c);
            }
            Ok(())
        })?;
        let mut entries: Vec<(String, Entry)> = Vec::new();
        for (i, (path, mode, blob, size)) in rows.into_iter().enumerate() {
            let symlink = mode == "120000";
            match contents.get(&i).and_then(|c| Self::key_of(c, symlink)) {
                Some(key) => entries.push((path, Entry::Annexed(key))),
                None if symlink => listing.skipped.push(Note {
                    path,
                    reason: "a symbolic link that is not an annexed file".into(),
                }),
                None => entries.push((path, Entry::Git { blob, size })),
            }
        }
        let git_algo = if self.object_format == "sha256" {
            "sha256"
        } else {
            "sha1"
        };
        for (path, e) in entries {
            match e {
                Entry::Annexed(key) => {
                    let k = Key::parse(&key).expect("parsed above");
                    let object = match self.objects.get(&key) {
                        Some(p) => Some(p.clone()),
                        None => self.object_path(&key),
                    };
                    let (present, size, mtime_ns) = match &object {
                        Some(p) => {
                            let md = std::fs::metadata(p)?;
                            let mtime = md
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_nanos() as i64);
                            (true, Some(md.len()), mtime)
                        }
                        None => (false, k.size, k.mtime.map(|m| m * 1_000_000_000)),
                    };
                    if let Some(p) = object {
                        self.objects.insert(key.clone(), p);
                    }
                    listing.items.push(ListedItem {
                        path,
                        check: k.check(),
                        id: key,
                        size: k.size.or(size),
                        mtime_ns: k.mtime.map(|m| m * 1_000_000_000).or(mtime_ns),
                        present,
                    });
                }
                Entry::Git { blob, size } => listing.items.push(ListedItem {
                    path,
                    check: Some(Check {
                        algo: format!("git-{git_algo}:{size}"),
                        hex: blob.clone(),
                    }),
                    id: format!("git:{blob}"),
                    size: Some(size),
                    mtime_ns: Some(self.commit_utc * 1_000_000_000),
                    present: true,
                }),
            }
        }
        Ok(listing)
    }

    fn deliver(&mut self, wanted: &[Wanted], sink: &mut super::Sink) -> Result<()> {
        // Annexed objects in on-disk path order (a rotating disk reads them
        // without seeking back and forth), then files kept in git.
        let mut order: Vec<(usize, Option<PathBuf>)> = wanted
            .iter()
            .enumerate()
            .map(|(i, w)| (i, self.objects.get(&w.id).cloned()))
            .collect();
        order.sort_by(|a, b| match (&a.1, &b.1) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => wanted[a.0].path.cmp(&wanted[b.0].path),
        });
        for (i, object) in order {
            let w = &wanted[i];
            let verdict = if let Some(blob) = w.id.strip_prefix("git:") {
                let mut child = git_cmd(&self.repo)
                    .args(["cat-file", "blob", blob])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("run git cat-file")?;
                let mut out = child.stdout.take().expect("piped");
                let v = sink(
                    i,
                    Delivery::Content {
                        reader: &mut out,
                        mtime_ns: Some(self.commit_utc * 1_000_000_000),
                        retry: false,
                    },
                );
                drop(out);
                let _ = child.kill();
                let _ = child.wait();
                v?
            } else {
                match object.map(|p| (std::fs::File::open(&p), p)) {
                    Some((Ok(mut f), p)) => {
                        let mtime = std::fs::metadata(&p)
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_nanos() as i64);
                        sink(
                            i,
                            Delivery::Content {
                                reader: &mut f,
                                mtime_ns: mtime,
                                retry: false,
                            },
                        )?
                    }
                    Some((Err(e), _)) => sink(i, Delivery::Failed(format!("cannot read: {e}")))?,
                    None => sink(i, Delivery::Missing)?,
                }
            };
            if verdict == Verdict::Stop {
                break;
            }
        }
        Ok(())
    }

    fn holders(&mut self, ids: &[(String, u64)]) -> Result<BTreeMap<String, Vec<String>>> {
        let keys: Vec<&String> = ids
            .iter()
            .map(|(id, _)| id)
            .filter(|id| !id.starts_with("git:"))
            .collect();
        let mut queries = Vec::new();
        for k in &keys {
            for r in &self.annex_refs {
                queries.push(format!("{r}:{}/{k}.log", hashdir_lower(k)));
            }
        }
        let per_key = self.annex_refs.len();
        let mut merged: Vec<BTreeMap<String, (f64, bool)>> = vec![BTreeMap::new(); keys.len()];
        cat_file_batch(&self.repo, &queries, |i, c| {
            if let Some(c) = c {
                location_log(&String::from_utf8_lossy(&c), &mut merged[i / per_key]);
            }
            Ok(())
        })?;
        let me = &self.info.instance;
        let mut out = BTreeMap::new();
        for (k, log) in keys.into_iter().zip(merged) {
            let who: Vec<String> = log
                .into_iter()
                .filter(|(u, (_, present))| *present && u != me && !self.info.dead.contains(u))
                .map(|(u, _)| u)
                .collect();
            out.insert(k.clone(), who);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse() {
        let k = Key::parse(
            "SHA256E-s6--5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03.txt",
        )
        .unwrap();
        assert_eq!(k.backend, "SHA256E");
        assert_eq!(k.size, Some(6));
        let c = k.check().unwrap();
        assert_eq!(c.algo, "sha256");
        assert!(c.hex.starts_with("5891b5"));
        let w = Key::parse("WORM-s2-m1791886639--w.dat").unwrap();
        assert_eq!(w.mtime, Some(1791886639));
        assert!(w.check().is_none());
        assert!(Key::parse("URL--http&c%%example.com")
            .unwrap()
            .check()
            .is_none());
        assert!(Key::parse("SHA256-s10-S5-C1--abc").is_none());
        assert!(Key::parse("nonsense").is_none());
        // Extensions with several dots.
        let t = Key::parse(&format!("MD5E-s1--{}.tar.gz", "a".repeat(32))).unwrap();
        assert_eq!(t.check().unwrap().hex, "a".repeat(32));
    }

    /// Hash directories as git-annex 10 laid them out for these keys.
    #[test]
    fn hash_directories() {
        let k = "SHA256E-s6--5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03.txt";
        assert_eq!(hashdir_lower(k), "d91/b11");
        assert_eq!(hashdir_mixed(k), "mK/4w");
        let w = "WORM-s2-m1791886639--w.dat";
        assert_eq!(hashdir_lower(w), "792/8e8");
        assert_eq!(hashdir_mixed(w), "1K/M2");
    }

    #[test]
    fn logs() {
        let mut u = BTreeMap::new();
        uuid_log(
            "aaa disk one timestamp=10s\naaa disk renamed timestamp=20s\nbbb old style\n",
            &mut u,
        );
        assert_eq!(u["aaa"].1, "disk renamed");
        assert_eq!(u["bbb"].1, "old style");
        let mut l = BTreeMap::new();
        location_log("10s 1 aaa\n20s 0 aaa\n15s 1 bbb\n", &mut l);
        assert!(!l["aaa"].1);
        assert!(l["bbb"].1);
    }

    #[test]
    fn pointers_and_links() {
        let k = "SHA256E-s4--df2751145b9b88c439a72dc92ae3522121146c48abc2320d209e7d73cbe0412d.bin";
        assert_eq!(
            AnnexSource::key_of(format!("/annex/objects/{k}\n").as_bytes(), false).as_deref(),
            Some(k)
        );
        assert_eq!(
            AnnexSource::key_of(
                format!("../.git/annex/objects/xx/yy/{k}/{k}").as_bytes(),
                true
            )
            .as_deref(),
            Some(k)
        );
        assert!(AnnexSource::key_of(b"just text\n", false).is_none());
        assert!(AnnexSource::key_of(b"../elsewhere", true).is_none());
    }
}
