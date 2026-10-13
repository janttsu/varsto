// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The restic device's mirror (see `crate::restic`): every folder of the
//! vault (or the ones chosen) attached as a full, plaintext, non-selective
//! folder at `<root>/<folder name>`, the hold that keeps Varsto from
//! writing into them while restic reads them, and the completeness check
//! that decides whether a snapshot may be taken.
//!
//! Completeness: every live file of every mirror folder (the merged state
//! this device applied, and any newer version it knows but could not
//! download yet) is on disk as a regular file, not a placeholder, with the
//! size and modification time this device recorded when it wrote or
//! scanned it, and its content hashes (the folder's keyed content hash) to
//! the recorded hash. A file verified at an earlier check whose size and
//! time have not changed takes its hash from `state/restic-verified.json`;
//! `rehash_all` reads everything. With `fix`, files that are missing, a
//! placeholder or not downloaded yet are fetched, and a file whose content
//! changed under an unchanged size and time is restored as the bit-rot
//! check does (`engine::scrub`, the damaged copy kept beside it); then the
//! check runs again. A file changed on disk since the last sync is never
//! touched: it is the next sync's.

use super::*;
use crate::restic::{
    self, Completeness, Excluded, FolderCheck, FolderChoice, Hold, Problem, ProblemKind,
    ResticConfig, Verified, VerifiedCache,
};
use std::io::Read;

/// What `restic_setup` did.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SetupReport {
    pub root: PathBuf,
    /// Folders attached in the mirror now, moved there from where they were
    /// attached before, or already there.
    pub attached: Vec<String>,
    pub moved: Vec<String>,
    pub kept: Vec<String>,
    pub excluded: Vec<Excluded>,
}

/// How `restic_check` runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckOptions {
    /// The hold this check works under (a run's own): the check may fetch
    /// and restore files in held folders.
    #[serde(default)]
    pub token: Option<String>,
    /// Hash every file, ignoring the cache of verified hashes.
    #[serde(default)]
    pub rehash_all: bool,
    /// Fetch what is missing and restore damaged files, then check again.
    #[serde(default)]
    pub fix: bool,
    /// Presence, size and time only (no hashing, cache untouched): status.
    #[serde(default)]
    pub quick: bool,
}

fn mtime_ns(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A file to hash: folder index, path, size, time and the recorded hash.
struct ToHash {
    folder: usize,
    path: String,
    /// Where the file is on disk (its local name, `crate::names`).
    disk: PathBuf,
    size: u64,
    mtime: i64,
    want: String,
}

impl Engine {
    pub fn restic_config(&self) -> Option<&ResticConfig> {
        self.config.restic.as_ref()
    }

    /// The folders the mirror keeps (with their place under the root) and
    /// those it leaves out, with the reason.
    pub fn restic_plan(&self, cfg: &ResticConfig) -> (Vec<(FolderRecord, PathBuf)>, Vec<Excluded>) {
        let mut keep = Vec::new();
        let mut out = Vec::new();
        let mut excluded = |rec: &FolderRecord, why: &str| {
            out.push(Excluded {
                folder: rec.name.clone(),
                reason: why.to_string(),
            })
        };
        for (rec, _) in self.folders() {
            if let FolderChoice::Named(ids) = &cfg.folders {
                if !ids.contains(&rec.folder_id) {
                    excluded(&rec, "not chosen for the mirror");
                    continue;
                }
            }
            if rec.shared && !cfg.include_shared {
                excluded(
                    &rec,
                    "shared with other people (--include-shared to mirror it)",
                );
                continue;
            }
            if rec.is_strongroom() && !cfg.include_strongroom {
                excluded(
                    &rec,
                    "Strongroom: no plaintext copy is kept (--include-strongroom to mirror it)",
                );
                continue;
            }
            match restic::dir_name(&rec.name) {
                Ok(d) => {
                    let target = cfg.root.join(d);
                    keep.push((rec, target));
                }
                Err(e) => excluded(&rec, &format!("{e:#}")),
            }
        }
        keep.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        out.sort_by(|a, b| a.folder.cmp(&b.folder));
        (keep, out)
    }

    /// The mirror folders attached where they belong: (record, path).
    pub fn restic_mirror_folders(&self) -> Vec<(FolderRecord, PathBuf)> {
        let Some(cfg) = self.config.restic.as_ref() else {
            return Vec::new();
        };
        let (keep, _) = self.restic_plan(cfg);
        keep.into_iter()
            .filter(|(rec, target)| {
                self.config
                    .folders
                    .iter()
                    .any(|m| m.folder_id == rec.folder_id && &m.path == target)
            })
            .collect()
    }

    /// Make this device the restic device: attach every folder the mirror
    /// keeps at `<root>/<name>` as a full plaintext folder and keep the
    /// settings. `names`: only these folders (None: all, also later ones).
    /// A folder attached elsewhere on this device is refused unless
    /// `move_attached`, which moves its directory into the mirror (same
    /// file system only) and keeps what this device knows of it.
    pub fn restic_setup(
        &mut self,
        mut cfg: ResticConfig,
        names: Option<&[String]>,
        move_attached: bool,
    ) -> Result<SetupReport> {
        if self.vault.member {
            bail!("this device holds shared folders only; the restic device must be a full device of the vault");
        }
        if cfg.repository.trim().is_empty() {
            bail!("name the restic repository (--repo)");
        }
        if !restic::check_subset_valid(&cfg.check_subset) {
            bail!(
                "--check-subset {} is not a subset restic takes (5%, 1/10, 500M)",
                cfg.check_subset
            );
        }
        if let restic::PasswordSource::File(f) = &cfg.password {
            if !f.is_file() {
                bail!("the password file {} does not exist", f.display());
            }
        }
        let _ = self.pull_registry();
        cfg.folders = match names {
            None => FolderChoice::All,
            Some(list) => {
                let mut ids = Vec::new();
                for n in list {
                    let rec = self
                        .keyring
                        .find(n)
                        .filter(|r| !r.is_removed())
                        .ok_or_else(|| anyhow!("unknown folder {n}"))?;
                    ids.push(rec.folder_id.clone());
                }
                FolderChoice::Named(ids)
            }
        };
        fs::create_dir_all(&cfg.root)
            .with_context(|| format!("create the mirror root {}", cfg.root.display()))?;
        cfg.root = canonical(&cfg.root)?;
        if cfg.root.starts_with(&self.home) {
            bail!("the mirror root cannot be inside the device directory");
        }
        cfg.vault_short = self.vault.vault_id.short().to_string();
        cfg.host = self.vault.device_name.clone();
        if let Some(old) = &self.config.restic {
            cfg.created_utc = old.created_utc;
        }
        if cfg.created_utc == 0 {
            cfg.created_utc = util::now_utc();
        }
        let (keep, excluded) = self.restic_plan(&cfg);
        let planned: BTreeMap<FolderId, PathBuf> = keep
            .iter()
            .map(|(r, t)| (r.folder_id.clone(), t.clone()))
            .collect();
        let name_of = |id: &FolderId| {
            self.keyring
                .folders
                .get(id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| id.short().to_string())
        };
        // Nothing else may live in or around the mirror.
        let mut elsewhere = Vec::new();
        for m in &self.config.folders {
            match planned.get(&m.folder_id) {
                Some(t) if t == &m.path => {
                    if m.encrypted {
                        bail!(
                            "folder {} is kept encrypted on this device; detach it first so the mirror can keep plain files",
                            name_of(&m.folder_id)
                        );
                    }
                }
                Some(t) => {
                    if cfg.root.starts_with(&m.path) {
                        bail!(
                            "the mirror root {} is inside folder {} ({}); choose another root",
                            cfg.root.display(),
                            name_of(&m.folder_id),
                            m.path.display()
                        );
                    }
                    elsewhere.push((m.folder_id.clone(), m.path.clone(), t.clone(), m.encrypted));
                }
                None => {
                    if m.path.starts_with(&cfg.root) || cfg.root.starts_with(&m.path) {
                        bail!(
                            "folder {} is attached at {}, inside or around the mirror root {}; detach it or choose another root",
                            name_of(&m.folder_id),
                            m.path.display(),
                            cfg.root.display()
                        );
                    }
                }
            }
        }
        if !elsewhere.is_empty() && !move_attached {
            let list: Vec<String> = elsewhere
                .iter()
                .map(|(id, from, _, _)| format!("{} (at {})", name_of(id), from.display()))
                .collect();
            bail!(
                "these folders are already attached elsewhere on this device: {}. Run again with --move to move their directories into the mirror, or detach them first (their files stay) to have the mirror download them",
                list.join(", ")
            );
        }
        let mut report = SetupReport {
            root: cfg.root.clone(),
            excluded,
            ..Default::default()
        };
        for (id, from, to, encrypted) in elsewhere {
            let name = name_of(&id);
            if encrypted {
                bail!("folder {name} is kept encrypted on this device; detach it first so the mirror can keep plain files");
            }
            if to.exists() {
                let empty = fs::read_dir(&to)
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(false);
                if !empty {
                    bail!(
                        "{} exists and is not empty; cannot move folder {name} there",
                        to.display()
                    );
                }
                fs::remove_dir(&to)?;
            }
            fs::rename(&from, &to).map_err(|e| {
                anyhow!(
                    "could not move {} to {} ({e}); detach folder {name} and run setup again to have the mirror download it",
                    from.display(),
                    to.display()
                )
            })?;
            for m in self.config.folders.iter_mut().filter(|m| m.folder_id == id) {
                m.path = to.clone();
                m.selective = false;
            }
            report
                .moved
                .push(format!("{name}: {} -> {}", from.display(), to.display()));
        }
        for (rec, target) in &keep {
            if let Some(m) = self
                .config
                .folders
                .iter_mut()
                .find(|m| m.folder_id == rec.folder_id)
            {
                // Selective sync off: the next sync downloads the placeholders.
                m.selective = false;
                if !report
                    .moved
                    .iter()
                    .any(|l| l.starts_with(&format!("{}: ", rec.name)))
                {
                    report.kept.push(rec.name.clone());
                }
                continue;
            }
            fs::create_dir_all(target)?;
            self.config.folders.push(FolderMount {
                folder_id: rec.folder_id.clone(),
                path: canonical(target)?,
                selective: false,
                encrypted: false,
            });
            report.attached.push(rec.name.clone());
        }
        self.config.restic = Some(cfg);
        self.config.save(&self.home)?;
        Ok(report)
    }

    /// Stop being the restic device: the settings go; the mirror folders
    /// stay attached (detach them one by one if they should not).
    pub fn restic_forget_setup(&mut self) -> Result<()> {
        self.config.restic = None;
        self.config.save(&self.home)
    }

    /// With every folder in the mirror: attach the folders that arrived
    /// since (called at every sync, after the folder records are read). A
    /// folder whose place in the mirror is taken by other files is left
    /// for the user (named on standard error).
    pub(super) fn restic_auto_attach(&mut self) -> Vec<String> {
        let Some(cfg) = self.config.restic.clone() else {
            return Vec::new();
        };
        if cfg.folders != FolderChoice::All || self.vault.member {
            return Vec::new();
        }
        let (keep, _) = self.restic_plan(&cfg);
        let mut added = Vec::new();
        for (rec, target) in keep {
            if self
                .config
                .folders
                .iter()
                .any(|m| m.folder_id == rec.folder_id)
            {
                continue;
            }
            let free = !target.exists()
                || fs::read_dir(&target)
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(false);
            if !free {
                eprintln!(
                    "restic mirror: {} exists and is not empty; folder {} is not attached there",
                    target.display(),
                    rec.name
                );
                continue;
            }
            if fs::create_dir_all(&target).is_err() {
                continue;
            }
            let Ok(path) = canonical(&target) else {
                continue;
            };
            self.config.folders.push(FolderMount {
                folder_id: rec.folder_id.clone(),
                path,
                selective: false,
                encrypted: false,
            });
            added.push(rec.name.clone());
        }
        if !added.is_empty() {
            if let Err(e) = self.config.save(&self.home) {
                eprintln!("restic mirror: could not save the configuration: {e:#}");
            }
        }
        added
    }

    // ----- the hold ------------------------------------------------------------

    /// Whether a restic run holds this folder now (and this engine is not
    /// the one working under that hold).
    pub fn is_held(&self, folder: &FolderId) -> bool {
        match Hold::current(&self.home, util::now_utc()) {
            Some(h) => {
                h.folders.contains(folder) && self.hold_exempt.as_deref() != Some(h.token.as_str())
            }
            None => false,
        }
    }

    pub(super) fn ensure_not_held(&self, rec: &FolderRecord) -> Result<()> {
        if self.is_held(&rec.folder_id) {
            bail!(
                "folder {} is held while restic backs it up; try again when the backup is done",
                rec.name
            );
        }
        Ok(())
    }

    /// Hold the mirror folders for the run with this token (written to
    /// `state/restic-hold.json`). The background service takes it while it
    /// holds its engine, so no sync of it is under way once this returns.
    pub fn restic_hold(&self, token: &str, pid: u32) -> Result<Vec<String>> {
        let folders = self.restic_mirror_folders();
        if let Some(h) = Hold::current(&self.home, util::now_utc()) {
            if h.token != token {
                bail!("another restic run holds the mirror");
            }
        }
        Hold::new(
            token,
            folders.iter().map(|(r, _)| r.folder_id.clone()).collect(),
            pid,
            util::now_utc(),
        )
        .write(&self.home)?;
        Ok(folders.into_iter().map(|(r, _)| r.name).collect())
    }

    // ----- completeness --------------------------------------------------------

    /// Check that the mirror is complete (see the module documentation).
    pub fn restic_check(&mut self, opts: &CheckOptions) -> Result<Completeness> {
        let Some(cfg) = self.config.restic.clone() else {
            bail!("this device is not set up for restic (varsto restic setup)");
        };
        self.hold_exempt = opts.token.clone();
        let result = (|| {
            let first = self.restic_check_once(&cfg, opts)?;
            if first.complete || !opts.fix || opts.quick {
                return Ok(first);
            }
            let fixed = self.restic_fix(&first)?;
            if fixed.is_empty() {
                return Ok(first);
            }
            let mut again = self.restic_check_once(&cfg, opts)?;
            for f in &mut again.folders {
                if let Some(list) = fixed.get(&f.folder_id) {
                    f.fixed = list.clone();
                }
            }
            Ok(again)
        })();
        self.hold_exempt = None;
        result
    }

    fn restic_check_once(
        &mut self,
        cfg: &ResticConfig,
        opts: &CheckOptions,
    ) -> Result<Completeness> {
        let task =
            crate::activity::start(crate::activity::RESTIC, "", 0, crate::activity::Unit::Bytes);
        task.set_phase("check");
        let (keep, excluded) = self.restic_plan(cfg);
        let mut c = Completeness {
            checked_utc: util::now_utc(),
            root: cfg.root.clone(),
            excluded,
            quick: opts.quick,
            ..Default::default()
        };
        let cache = if opts.quick {
            VerifiedCache::default()
        } else {
            VerifiedCache::load(&self.home)
        };
        let mut new_cache = VerifiedCache::default();
        let mut hash_keys: Vec<Option<FolderKeys>> = Vec::new();
        let mut to_hash: Vec<ToHash> = Vec::new();
        let mut top: BTreeSet<String> = BTreeSet::new();
        for (rec, target) in &keep {
            let attached = self
                .config
                .folders
                .iter()
                .any(|m| m.folder_id == rec.folder_id && &m.path == target);
            if !attached {
                c.not_attached.push(rec.name.clone());
                continue;
            }
            if let Some(n) = target.file_name() {
                top.insert(n.to_string_lossy().to_string());
            }
            let fid = rec.folder_id.to_string();
            let mut fc = FolderCheck {
                folder: rec.name.clone(),
                folder_id: fid.clone(),
                path: target.clone(),
                ..Default::default()
            };
            let keyed = self.with_key(rec).and_then(|r| self.folder_keys(&r));
            let fk = match keyed {
                Ok(k) => Some(k),
                Err(e) => {
                    fc.problems.push(Problem {
                        path: String::new(),
                        kind: ProblemKind::Unreadable,
                        detail: format!("the folder cannot be read now ({e:#})"),
                    });
                    None
                }
            };
            let state = self.load_state(&rec.folder_id)?;
            fc.manifest_seq = state.published_seq;
            fc.manifest_hash = state.published_hash.clone();
            fc.seen = state
                .last_seen
                .iter()
                .map(|(d, s)| (d.short().to_string(), *s))
                .collect();
            // What is on disk: files and placeholders, by vault path.
            let rules = self.local_rules(target);
            let mut on_disk: BTreeSet<String> = BTreeSet::new();
            let mut placeholders: BTreeSet<String> = BTreeSet::new();
            let walker = walkdir::WalkDir::new(target)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    !(e.depth() > 0 && e.file_name().to_string_lossy().starts_with(".varsto"))
                });
            for e in walker.flatten() {
                if !e.file_type().is_file() {
                    continue;
                }
                let Ok(rel) = e.path().strip_prefix(target) else {
                    continue;
                };
                let Some(p) = util::manifest_path(rel) else {
                    continue;
                };
                match p.strip_suffix(PLACEHOLDER_SUFFIX) {
                    Some(real) => {
                        placeholders.insert(state.local_names.vault_of_local(rules, real));
                    }
                    None => {
                        on_disk.insert(state.local_names.vault_of_local(rules, &p));
                    }
                }
            }
            let mut digest = Vec::new();
            let mut live: BTreeSet<&str> = BTreeSet::new();
            for f in state.files.values().filter(|f| !f.deleted) {
                live.insert(&f.path);
            }
            for f in state.pending_remote.values().filter(|f| !f.deleted) {
                live.insert(&f.path);
            }
            for path in live {
                let problem = |kind, detail: &str| Problem {
                    path: path.to_string(),
                    kind,
                    detail: detail.to_string(),
                };
                if state.pending_remote.get(path).is_some_and(|f| !f.deleted) {
                    fc.problems
                        .push(problem(ProblemKind::NotDownloaded, "no readable copy yet"));
                    continue;
                }
                let Some(f) = state.files.get(path) else {
                    continue;
                };
                digest.extend_from_slice(path.as_bytes());
                digest.push(0);
                digest.extend_from_slice(f.content_hash.as_bytes());
                digest.push(b'\n');
                let Ok(disk) = util::safe_join(target, &state.local_names.local_rel(rules, path))
                else {
                    fc.problems.push(problem(
                        ProblemKind::Unreadable,
                        "the path is not usable here",
                    ));
                    continue;
                };
                let md = match fs::symlink_metadata(&disk) {
                    Ok(md) if md.file_type().is_file() => md,
                    Ok(_) => {
                        fc.problems
                            .push(problem(ProblemKind::Missing, "not a regular file"));
                        continue;
                    }
                    Err(_) if placeholders.contains(path) => {
                        fc.problems.push(problem(ProblemKind::Placeholder, ""));
                        continue;
                    }
                    Err(_) => {
                        fc.problems.push(problem(ProblemKind::Missing, ""));
                        continue;
                    }
                };
                if placeholders.contains(path) {
                    fc.problems.push(problem(
                        ProblemKind::Placeholder,
                        "a placeholder lies beside the file",
                    ));
                    continue;
                }
                let (size, mtime) = (md.len(), mtime_ns(&md));
                match state.local_index.get(path) {
                    None => {
                        fc.problems.push(problem(
                            ProblemKind::Changed,
                            "not recorded by the last sync",
                        ));
                        continue;
                    }
                    Some(e) if e.content_hash != f.content_hash => {
                        fc.problems.push(problem(
                            ProblemKind::Changed,
                            "the version on disk is not the vault's",
                        ));
                        continue;
                    }
                    Some(e) if e.size != size || e.mtime != mtime => {
                        fc.problems.push(problem(ProblemKind::Changed, ""));
                        continue;
                    }
                    Some(_) => {}
                }
                fc.files += 1;
                fc.bytes += size;
                if opts.quick || fk.is_none() {
                    continue;
                }
                if !opts.rehash_all
                    && cache.lookup(&fid, path, size, mtime) == Some(f.content_hash.as_str())
                {
                    fc.cached += 1;
                    new_cache.folders.entry(fid.clone()).or_default().insert(
                        path.to_string(),
                        Verified {
                            size,
                            mtime,
                            hash: f.content_hash.clone(),
                        },
                    );
                    continue;
                }
                to_hash.push(ToHash {
                    folder: c.folders.len(),
                    path: path.to_string(),
                    disk: disk.clone(),
                    size,
                    mtime,
                    want: f.content_hash.clone(),
                });
            }
            fc.state_digest = hex::encode(&crypto::hash(&digest)[..16]);
            let known: BTreeSet<&String> = state
                .files
                .iter()
                .filter(|(_, f)| !f.deleted)
                .map(|(p, _)| p)
                .collect();
            fc.unknown = on_disk
                .iter()
                .filter(|p| !known.contains(p) && !state.pending_remote.contains_key(*p))
                .take(50)
                .cloned()
                .collect();
            hash_keys.push(fk);
            c.folders.push(fc);
        }
        // Hash what the cache does not vouch for.
        task.set_total(to_hash.iter().map(|t| t.size).sum());
        let mut buf = vec![0u8; 1 << 20];
        for t in to_hash {
            let Some(fk) = hash_keys[t.folder].as_ref() else {
                continue;
            };
            let fc = &mut c.folders[t.folder];
            let disk = t.disk.clone();
            let mut hasher = KeyedHasher::new(&fk.hash);
            let read = (|| -> std::io::Result<()> {
                let mut f = fs::File::open(&disk)?;
                loop {
                    let got = f.read(&mut buf)?;
                    if got == 0 {
                        return Ok(());
                    }
                    hasher.update(&buf[..got]);
                    task.advance(got as u64);
                }
            })();
            let same_after = fs::symlink_metadata(&disk)
                .is_ok_and(|md| md.len() == t.size && mtime_ns(&md) == t.mtime);
            let problem = |kind, detail: &str| Problem {
                path: t.path.clone(),
                kind,
                detail: detail.to_string(),
            };
            match read {
                Err(e) => fc
                    .problems
                    .push(problem(ProblemKind::Unreadable, &e.to_string())),
                Ok(()) if !same_after => fc
                    .problems
                    .push(problem(ProblemKind::Changed, "changed while it was read")),
                Ok(()) if hex::encode(hasher.finalize()) != t.want => {
                    fc.problems.push(problem(ProblemKind::HashMismatch, ""))
                }
                Ok(()) => {
                    fc.rehashed += 1;
                    new_cache
                        .folders
                        .entry(fc.folder_id.clone())
                        .or_default()
                        .insert(
                            t.path.clone(),
                            Verified {
                                size: t.size,
                                mtime: t.mtime,
                                hash: t.want.clone(),
                            },
                        );
                }
            }
        }
        // Problems first undo the files counted as good.
        for fc in &mut c.folders {
            let bad: BTreeSet<&str> = fc.problems.iter().map(|p| p.path.as_str()).collect();
            if let Some(m) = new_cache.folders.get_mut(&fc.folder_id) {
                m.retain(|p, _| !bad.contains(p.as_str()));
            }
        }
        // Top-level entries that are not mirror folders.
        if let Ok(rd) = fs::read_dir(&cfg.root) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n != restic::SNAPSHOT_FILE && !n.starts_with(".varsto") && !top.contains(&n) {
                    c.stray.push(n);
                }
            }
            c.stray.sort();
        }
        c.complete = c.problem_count() == 0;
        if !opts.quick {
            // Only what was verified now is vouched for next time.
            new_cache.save(&self.home)?;
        }
        Ok(c)
    }

    /// Fetch what is missing, a placeholder or not downloaded, and restore
    /// damaged files. Returns the files fixed per folder id.
    fn restic_fix(&mut self, c: &Completeness) -> Result<BTreeMap<String, Vec<String>>> {
        let mut fixed: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut storages: Option<OpenStorages> = None;
        for fc in &c.folders {
            let fixable: Vec<&Problem> = fc
                .problems
                .iter()
                .filter(|p| {
                    !p.path.is_empty()
                        && matches!(
                            p.kind,
                            ProblemKind::Missing
                                | ProblemKind::Placeholder
                                | ProblemKind::NotDownloaded
                                | ProblemKind::HashMismatch
                        )
                })
                .collect();
            if fixable.is_empty() {
                continue;
            }
            let Some(rec) = self.keyring.find(&fc.folder_id).cloned() else {
                continue;
            };
            let rec = self.with_key(&rec)?;
            let fk = self.folder_keys(&rec)?;
            let root = fc.path.clone();
            let mut state = self.load_state(&rec.folder_id)?;
            if storages.is_none() {
                storages = Some(self.open_storages(false)?);
            }
            let open = storages.take().unwrap_or_default();
            let mut report = PullReport {
                folder: rec.name.clone(),
                ..Default::default()
            };
            for p in fixable {
                let local = state
                    .local_names
                    .local_rel(self.local_rules(&root), &p.path)
                    .into_owned();
                let Ok(disk) = util::safe_join(&root, &local) else {
                    continue;
                };
                match p.kind {
                    ProblemKind::HashMismatch => {
                        let Some(entry) = state.local_index.get(&p.path).cloned() else {
                            continue;
                        };
                        let d = self.restore_damaged(
                            &rec,
                            &fk,
                            &root,
                            &mut state,
                            &p.path,
                            &entry,
                            util::now_utc(),
                            &open,
                        );
                        if d.restored {
                            fixed
                                .entry(fc.folder_id.clone())
                                .or_default()
                                .push(p.path.clone());
                        }
                    }
                    _ => {
                        if fs::symlink_metadata(&disk).is_ok() {
                            continue; // never over a file that is there
                        }
                        let wanted = state
                            .pending_remote
                            .get(&p.path)
                            .or_else(|| state.files.get(&p.path))
                            .filter(|f| !f.deleted)
                            .cloned();
                        let Some(file) = wanted else { continue };
                        let before = report.files_updated;
                        self.apply_remote(&rec, &fk, &root, &mut state, file, &open, &mut report)?;
                        if report.files_updated > before && disk.is_file() {
                            let _ = fs::remove_file(placeholder_path(&disk));
                            fixed
                                .entry(fc.folder_id.clone())
                                .or_default()
                                .push(p.path.clone());
                        }
                    }
                }
            }
            self.save_state(&rec.folder_id, &state)?;
            storages = Some(open);
        }
        if !fixed.is_empty() {
            self.defer_events()?;
        }
        Ok(fixed)
    }
}
