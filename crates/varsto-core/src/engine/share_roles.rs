// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Read-only participants of folders (`docs/spec/format-3-design.md`
//! section 6, "Roles"; `alpha-0-format.md` section 77.6).
//!
//! A folder key lets whoever holds it read *and* encrypt, so a viewer cannot
//! be stopped from writing objects to the storage. What makes it read-only
//! is that nobody takes what it writes: every reader refuses its manifests,
//! block maps and trash records by the acceptance rule, and its ledger
//! batches claim nothing of the folder. Its own client refuses writes as
//! well: files arrive without write permission, a local change is moved
//! aside into `kept-aside/` and the shared version comes back, and writes
//! through the interface are refused.
//!
//! Who may write is said by the folder records an owner writes (on a member
//! device of another vault: by the directory its grants carry). A viewer
//! that was an editor keeps what it wrote then: its announcements count by
//! the Lamport time of their batch against its role history.

use super::*;
use crate::membership3::Role;
use crate::share::ShareRole;

/// What `share_set_role` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareRoleReport {
    pub folder: String,
    pub member: String,
    pub member_id: String,
    pub role: String,
    /// The Lamport time of the folder record entry written.
    pub seq: u64,
}

/// Where a viewer's local changes go (outside the folder, so they are not
/// synced): `<home>/kept-aside/<folder name>/<path>.<utc>`.
pub const KEPT_ASIDE_DIR: &str = "kept-aside";

/// Take the write permission from a file (best effort: some file systems
/// and platforms have none to take).
pub(super) fn set_read_only(path: &Path, read_only: bool) {
    if let Ok(md) = fs::metadata(path) {
        let mut p = md.permissions();
        if p.readonly() != read_only {
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(read_only);
            let _ = fs::set_permissions(path, p);
        }
    }
}

impl Engine {
    /// The current role of `dev` in a folder (`None`: not a participant).
    pub(super) fn folder_role(&self, folder: &FolderId, dev: &DeviceId) -> Option<Role> {
        let (f, d) = (members3::bin(folder).ok()?, members3::bin(dev).ok()?);
        self.f3.members.role(&d, &f)
    }

    /// The role of another device in a folder: whether this device takes
    /// what it writes there now.
    pub fn share_role_of(&self, folder: &FolderId, dev: &DeviceId) -> ShareRole {
        match self.folder_role(folder, dev) {
            Some(Role::Viewer) | None => ShareRole::Viewer,
            Some(_) => ShareRole::Editor,
        }
    }

    /// This device's own role in a folder.
    pub fn share_own_role(&self, folder: &FolderId) -> ShareRole {
        if let Some(m) = &self.f3.members.member {
            if members3::bin(folder).ok() == Some(m.folder) {
                return match self.folder_role(folder, &self.vault.device_id) {
                    Some(Role::Viewer) | None => ShareRole::Viewer,
                    Some(_) => ShareRole::Editor,
                };
            }
        }
        match self.folder_role(folder, &self.vault.device_id) {
            Some(Role::Viewer) => ShareRole::Viewer,
            _ => ShareRole::Editor,
        }
    }

    /// Whether this device keeps a folder read-only (it is a viewer there).
    pub fn share_read_only(&self, rec: &FolderRecord) -> bool {
        !self.role_guard_off && !self.share_own_role(&rec.folder_id).is_editor()
    }

    /// Refuse a write to a folder this device may only read.
    pub(super) fn ensure_share_writable(&self, rec: &FolderRecord) -> Result<()> {
        if self.share_read_only(rec) {
            bail!(
                "{} is shared with this device read-only: the owner did not allow changes from it",
                rec.name
            );
        }
        Ok(())
    }

    /// Simulate a modified client that ignores its read-only role (tests:
    /// what it publishes must still be refused by the others).
    #[doc(hidden)]
    pub fn disable_read_only_guard(&mut self) {
        self.role_guard_off = true;
    }

    /// Owner: make a participant of a folder a viewer or an editor (a
    /// folder record entry and a grant that carries the role; the member
    /// devices of the folder get the change in their grants). Taking
    /// writing away keeps what it wrote until now; what it writes from now
    /// on is not accepted.
    pub fn share_set_role(
        &mut self,
        folder: &str,
        member: &str,
        role: ShareRole,
    ) -> Result<ShareRoleReport> {
        if self.vault.member {
            bail!("only the owner's devices can change what a member of a shared folder may do");
        }
        self.ensure_active()?;
        self.org_allows(|p| p.members_may_share, "share folders with other people")?;
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let id = members3::bin(&rec.folder_id)?;
        let list = self.share_members(folder)?;
        let who = member.trim();
        let hits: Vec<&ShareMember> = list
            .members
            .iter()
            .filter(|m| m.id == who || (who.len() >= 8 && m.id.starts_with(who)) || m.name == who)
            .collect();
        let m = match hits.as_slice() {
            [] => bail!(
                "no member of {} matches {who} (see `varsto share members {}`)",
                rec.name,
                rec.name
            ),
            [one] => (*one).clone(),
            _ => bail!(
                "several members of {} match {who}: use the device id",
                rec.name
            ),
        };
        if m.kind == "owner-device" {
            bail!(
                "{} is one of your own devices; change its role with `varsto folder role`",
                m.name
            );
        }
        if m.status == "removed" {
            bail!("{} was removed from {}", m.name, rec.name);
        }
        let dev = members3::bin(&DeviceId::from_hex(&m.id)?)?;
        let stamp = self
            .with_enrolled(|ms| {
                let epoch = ms.folder_epochs(&id).current();
                if !ms.registry.is_owner(&ms.me, &id, epoch) {
                    bail!("this device is not an owner of {}", rec.name);
                }
                ms.approve(&id, &dev, role.role3())?;
                Ok(ms.lamport())
            })?
            .ok_or_else(|| anyhow!("this device has no storage to write to"))?;
        Ok(ShareRoleReport {
            folder: rec.name.clone(),
            member: m.name.clone(),
            member_id: m.id.clone(),
            role: role.as_str().into(),
            seq: stamp,
        })
    }

    // ----- the viewer's own client ------------------------------------------------

    /// A viewer's scan: changes made here are not published. A changed or
    /// new file is moved to `kept-aside/` (outside the folder) and a changed
    /// or deleted one is fetched again from the shared version on the next
    /// pull; files are left without write permission. Returns the paths
    /// kept aside or restored.
    pub(super) fn read_only_guard(
        &mut self,
        rec: &FolderRecord,
        root: &Path,
        state: &mut FolderState,
    ) -> Result<Vec<String>> {
        if self.mount_is_encrypted(&rec.folder_id) {
            // No plain files here: writes come through the interface, which
            // refuses them.
            return Ok(Vec::new());
        }
        let fk = self.folder_keys(rec)?;
        // Local names map back to vault paths (`crate::names`); paths the
        // ignore rules cover are not synced, so not guarded either.
        let rules = self.local_rules(root);
        let mut ignore =
            crate::ignore_rules::Matcher::new(Some(root), &self.ignore_local(&rec.folder_id));
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut placeholders = BTreeSet::new();
        let stamp = util::now_utc();
        let aside_root = self
            .home
            .join(KEPT_ASIDE_DIR)
            .join(rec.name.replace(['/', '\\', ':'], "_"));
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !(e.depth() > 0 && e.file_name().to_string_lossy().starts_with(".varsto"))
            });
        for entry in walker {
            let Ok(entry) = entry else {
                continue;
            };
            let ft = entry.file_type();
            if !(ft.is_file() || ft.is_symlink()) {
                continue;
            }
            let rel = entry.path().strip_prefix(root)?;
            let Some(local) = util::manifest_path(rel) else {
                continue;
            };
            if let Some(real) = local.strip_suffix(PLACEHOLDER_SUFFIX) {
                placeholders.insert(state.local_names.vault_of(rules, real));
                continue;
            }
            let path = state.local_names.vault_of(rules, &local);
            seen.insert(path.clone());
            // Links are never followed or moved; ignored files stay.
            if ft.is_symlink() || ignore.is_ignored(&path, false) {
                continue;
            }
            let md = entry.metadata()?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            let shared = state.files.get(&path).filter(|f| !f.deleted).cloned();
            let indexed = matches!(state.local_index.get(&path), Some(e) if e.size == md.len() && e.mtime == mtime);
            if shared.is_some() && indexed {
                if !md.permissions().readonly() {
                    set_read_only(entry.path(), true);
                }
                continue;
            }
            // Unchanged content with a new time stamp is not a change.
            if let Some(f) = &shared {
                if f.size == md.len() {
                    let mut hasher = KeyedHasher::new(&fk.hash);
                    let mut file = std::io::BufReader::new(fs::File::open(entry.path())?);
                    let mut buf = vec![0u8; 1 << 16];
                    loop {
                        let n = std::io::Read::read(&mut file, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                    }
                    if hex::encode(hasher.finalize()) == f.content_hash {
                        state.local_index.insert(
                            path.clone(),
                            LocalIndexEntry {
                                size: md.len(),
                                mtime,
                                content_hash: f.content_hash.clone(),
                                meta_seen: None,
                            },
                        );
                        set_read_only(entry.path(), true);
                        continue;
                    }
                }
            }
            // A change: keep it aside, outside the folder.
            let aside = util::safe_join(
                &aside_root,
                &self
                    .local_rules(&aside_root)
                    .default_local(&format!("{path}.{stamp}")),
            )?;
            if let Some(p) = aside.parent() {
                fs::create_dir_all(p)?;
            }
            set_read_only(entry.path(), false);
            fs::rename(entry.path(), &aside).or_else(|_| {
                fs::copy(entry.path(), &aside)
                    .map(|_| ())
                    .and_then(|_| fs::remove_file(entry.path()))
            })?;
            state.local_index.remove(&path);
            if let Some(f) = shared {
                state.pending_remote.insert(path.clone(), f);
            }
            out.push(path);
        }
        // Deleted here: the shared version comes back.
        let gone: Vec<FileState> = state
            .files
            .values()
            .filter(|f| !f.deleted && !seen.contains(&f.path) && !placeholders.contains(&f.path))
            .filter(|f| !state.pending_remote.contains_key(&f.path))
            .filter(|f| !ignore.is_ignored(&f.path, false))
            .cloned()
            .collect();
        for f in gone {
            state.local_index.remove(&f.path);
            out.push(f.path.clone());
            state.pending_remote.insert(f.path.clone(), f);
        }
        Ok(out)
    }
}
