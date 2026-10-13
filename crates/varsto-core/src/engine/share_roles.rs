// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Read-only members of shared folders (`docs/spec/alpha-0-format.md`,
//! section "Read-only members of shared folders").
//!
//! A folder key lets whoever holds it read *and* encrypt, so a viewer cannot
//! be stopped from writing objects to the storage. What makes it read-only
//! is that nobody takes what it writes: the owner's devices and the editors
//! do not merge its manifests, do not count its ledger batches and ignore
//! its records (analyses, last-accessed times) for the folder. Its own
//! client refuses writes as well: files arrive without write permission,
//! a local change is moved aside into `kept-aside/` and the shared version
//! comes back, and writes through the interface are refused.
//!
//! Who may write is said by a **role record** signed by one of the owner's
//! devices (`share::ShareRoles`): every member device with its role. It is
//! a snapshot; the valid record with the highest sequence number wins.
//! Once a folder has one, a member it does not list is a viewer. A new
//! member is listed by an owner device under the role of the token it came
//! through, once that device sees its *join proof* (`share::JoinProof`, a
//! value derived from a secret that only the sealed token carries), so a
//! viewer cannot claim an editor's invitation. Without any role record
//! everyone writes, as before roles existed.
//!
//! A viewer that was an editor keeps what it wrote then: the record names
//! the Lamport clock and ledger batch up to which its changes stay valid.

use super::share_ops::{FolderShareState, ShareBook};
use super::*;
use crate::share::{self, JoinProof, RoleEntry, ShareRole, ShareRoles, SignedShareRoles};

/// What `share_set_role` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareRoleReport {
    pub folder: String,
    pub member: String,
    pub member_id: String,
    pub role: String,
    /// Sequence number of the role record written.
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
    /// The newest verified role record of a folder, if it has one.
    pub fn share_roles(&self, folder: &FolderId) -> Option<ShareRoles> {
        self.share_book().folders.get(folder)?.roles.clone()
    }

    /// A member's role as `st` says (the owner's devices are not asked here).
    pub(super) fn role_in(st: &FolderShareState, dev: &DeviceId) -> ShareRole {
        match &st.roles {
            None => ShareRole::Editor,
            Some(r) => r
                .roles
                .get(dev)
                .map(|e| e.role)
                .unwrap_or(ShareRole::Viewer),
        }
    }

    /// Whether `dev` is one of the folder owner's devices as this device
    /// knows them.
    fn share_owner_device(&self, st: &FolderShareState, dev: &DeviceId) -> bool {
        if self.vault.member {
            st.owners.contains(dev)
        } else {
            dev == &self.vault.device_id || self.devices.devices.contains_key(dev)
        }
    }

    /// Whether a role record signed by `issuer` counts: one of the owner's
    /// devices that is not revoked; on the owner's own devices a trusted one
    /// that the organization (if any) lets share.
    fn share_role_issuer_ok(&self, st: &FolderShareState, issuer: &DeviceId) -> bool {
        if self.is_revoked(issuer) || !self.share_owner_device(st, issuer) {
            return false;
        }
        if self.vault.member {
            return true;
        }
        if issuer == &self.vault.device_id {
            return true;
        }
        self.trusted(issuer)
            && self.org.as_ref().is_none_or(|o| {
                o.manifest().is_none() || o.is_admin(issuer) || o.policy().members_may_share
            })
    }

    /// The role of another device in a shared folder: whether this device
    /// takes what it writes there.
    pub fn share_role_of(&self, folder: &FolderId, dev: &DeviceId) -> ShareRole {
        let book = self.share_book();
        let Some(st) = book.folders.get(folder) else {
            return ShareRole::Editor;
        };
        if self.share_owner_device(st, dev) {
            return ShareRole::Editor;
        }
        Self::role_in(st, dev)
    }

    /// This device's own role in a folder: the owner's devices write; a
    /// member is what the newest role record says, or else what its token
    /// said (a viewer when the folder has roles and lists neither).
    pub fn share_own_role(&self, folder: &FolderId) -> ShareRole {
        if !self.vault.member {
            return ShareRole::Editor;
        }
        let book = self.share_book();
        let st = book.folders.get(folder);
        if let Some(e) = st
            .and_then(|s| s.roles.as_ref())
            .and_then(|r| r.roles.get(&self.vault.device_id))
        {
            return e.role;
        }
        let token = self
            .keyring
            .folders
            .get(folder)
            .and_then(|r| r.share_join.as_ref())
            .map(|j| j.role);
        match (token, st.and_then(|s| s.roles.as_ref())) {
            (Some(r), _) => r,
            (None, Some(_)) => ShareRole::Viewer,
            (None, None) => ShareRole::Editor,
        }
    }

    /// Whether this device keeps a folder read-only (it is a viewer there).
    pub fn share_read_only(&self, rec: &FolderRecord) -> bool {
        self.vault.member
            && rec.shared
            && !self.role_guard_off
            && !self.share_own_role(&rec.folder_id).is_editor()
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

    /// Whether this device takes a manifest or record of `dev` for a shared
    /// folder: it must belong to the folder and must not be a viewer.
    pub(super) fn share_writer_ok(&self, rec: &FolderRecord, dev: &DeviceId) -> bool {
        if !self.share_manifest_source_ok(rec, dev) {
            return false;
        }
        !rec.shared
            || dev == &self.vault.device_id
            || self.share_role_of(&rec.folder_id, dev).is_editor()
    }

    /// Viewers of a folder with the Lamport clock up to which their changes
    /// (made while they were editors) stay valid. Empty without roles.
    pub(super) fn share_viewer_clocks(&self, rec: &FolderRecord) -> BTreeMap<DeviceId, u64> {
        let mut out = BTreeMap::new();
        if !rec.shared {
            return out;
        }
        let book = self.share_book();
        let Some(st) = book.folders.get(&rec.folder_id) else {
            return out;
        };
        let Some(roles) = &st.roles else {
            return out;
        };
        for d in st.members.iter().chain(roles.roles.keys()) {
            if d == &self.vault.device_id || self.share_owner_device(st, d) {
                continue;
            }
            match roles.roles.get(d) {
                Some(e) if e.role.is_editor() => {}
                Some(e) => {
                    out.insert(d.clone(), e.editor_until_clock);
                }
                None => {
                    out.insert(d.clone(), 0);
                }
            }
        }
        out
    }

    // ----- reading role records -------------------------------------------------

    /// Adopt the newest valid role record of every shared folder. A record
    /// counts when one of the owner's devices signed it and it opens with a
    /// folder key this device holds; it never replaces a newer one.
    pub(super) fn pull_share_roles(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<bool> {
        let shared: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|f| f.shared && !f.is_removed())
            .cloned()
            .collect();
        let mut changed = false;
        for f in &shared {
            let st = book.folders.entry(f.folder_id.clone()).or_default().clone();
            let current = st.roles.as_ref().map(|r| r.rank());
            let floor = st.roles.as_ref().map(|r| r.seq).unwrap_or(0);
            let prefix = format!("{}{}/", share::ROLE_PREFIX, f.folder_id);
            let mut names: BTreeMap<(u64, DeviceId), usize> = BTreeMap::new();
            for (i, (_, backend)) in storages.iter().enumerate() {
                for key in backend.list(&prefix)? {
                    if let Some((seq, issuer)) = key
                        .strip_prefix(&prefix)
                        .and_then(SignedShareRoles::parse_name)
                    {
                        if seq >= floor {
                            names.entry((seq, issuer)).or_insert(i);
                        }
                    }
                }
            }
            let mut best: Option<ShareRoles> = None;
            for ((seq, issuer), i) in names.into_iter().rev() {
                if best.as_ref().is_some_and(|b| b.seq > seq) {
                    break;
                }
                if !self.share_role_issuer_ok(&st, &issuer) {
                    continue;
                }
                let Some(pk) = self.share_issuer_key(&issuer) else {
                    continue;
                };
                let Some(blob) = storages[i].1.get(&SignedShareRoles::storage_key(
                    &f.folder_id,
                    seq,
                    &issuer,
                ))?
                else {
                    continue;
                };
                let Ok(signed) = serde_json::from_slice::<SignedShareRoles>(&blob) else {
                    continue;
                };
                if signed.folder != f.folder_id || signed.seq != seq || signed.issuer != issuer {
                    continue;
                }
                let Some(k) = self.share_epoch_key(f, signed.epoch) else {
                    continue;
                };
                let Ok(r) = signed.open(&self.vault.vault_id, &pk, &k) else {
                    continue;
                };
                if current.as_ref().is_some_and(|c| r.rank() <= *c) {
                    continue;
                }
                if best.as_ref().is_none_or(|b| r.rank() > b.rank()) {
                    best = Some(r);
                }
            }
            if let Some(r) = best {
                book.folders.entry(f.folder_id.clone()).or_default().roles = Some(r);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Owner devices: list members that joined since the newest role record
    /// under the role of their invitation, once their join proof verifies
    /// against the secret the invitation recorded.
    pub(super) fn pin_share_roles(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<bool> {
        if self.vault.member || self.org_allows(|p| p.members_may_share, "").is_err() {
            return Ok(false);
        }
        let folders: Vec<FolderId> = book
            .folders
            .iter()
            .filter(|(_, st)| st.roles.is_some())
            .map(|(f, _)| f.clone())
            .collect();
        let mut changed = false;
        for folder in folders {
            let Some(rec) = self.keyring.folders.get(&folder).cloned() else {
                continue;
            };
            if !rec.shared || rec.is_removed() {
                continue;
            }
            let st = book.folders[&folder].clone();
            let roles = st.roles.clone().expect("filtered above");
            let unpinned: Vec<DeviceId> = st
                .members
                .iter()
                .filter(|d| {
                    !roles.roles.contains_key(*d)
                        && !st.removed.contains_key(*d)
                        && !st.owners.contains(*d)
                        && !self.is_revoked(d)
                })
                .cloned()
                .collect();
            if unpinned.is_empty() {
                continue;
            }
            let invites = self.invites(&folder)?;
            let mut pins: BTreeMap<DeviceId, RoleEntry> = BTreeMap::new();
            for d in unpinned {
                let key = JoinProof::storage_key(&folder, &d);
                let mut proof = None;
                for (_, b) in storages {
                    if let Some(blob) = b.get(&key)? {
                        proof = serde_json::from_slice::<JoinProof>(&blob).ok();
                        if proof.is_some() {
                            break;
                        }
                    }
                }
                let Some(p) = proof.filter(|p| p.folder == folder && p.device == d) else {
                    continue;
                };
                let Some(inv) = invites.get(&p.invite) else {
                    continue;
                };
                if st.revoked_invites.contains(&p.invite) {
                    continue;
                }
                let Ok(secret) = SecretKey::from_hex(&inv.join_secret_hex) else {
                    continue;
                };
                if !p.verify(&secret) {
                    continue;
                }
                pins.insert(
                    d.clone(),
                    RoleEntry {
                        role: inv.role,
                        name: self.member_name(&d),
                        since_utc: util::now_utc(),
                        editor_until_clock: 0,
                        editor_until_seq: 0,
                    },
                );
            }
            if pins.is_empty() {
                continue;
            }
            let mut next = roles.roles.clone();
            next.extend(pins);
            self.publish_share_roles(book, &rec, next)?;
            changed = true;
        }
        Ok(changed)
    }

    /// Keep `devices.share_viewers` (viewer device -> last ledger batch of
    /// it that counts) in step with the role records. Returns whether it
    /// changed; the ledger view is then rebuilt (its context includes it).
    pub(super) fn refresh_share_viewers(&mut self, book: &ShareBook) -> Result<bool> {
        let mut viewers: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for st in book.folders.values() {
            let Some(roles) = &st.roles else {
                continue;
            };
            for d in st.members.iter().chain(roles.roles.keys()) {
                if d == &self.vault.device_id || self.share_owner_device(st, d) {
                    continue;
                }
                let cutoff = match roles.roles.get(d) {
                    Some(e) if e.role.is_editor() => continue,
                    Some(e) => e.editor_until_seq,
                    None => 0,
                };
                let c = viewers.entry(d.clone()).or_insert(cutoff);
                *c = (*c).min(cutoff);
            }
        }
        if viewers == self.devices.share_viewers {
            return Ok(false);
        }
        self.devices.share_viewers = viewers;
        self.save_devices()?;
        Ok(true)
    }

    // ----- writing role records -------------------------------------------------

    /// Publish the next role record of `rec` with `roles`, signed by this
    /// device and sealed under the folder's newest share key.
    pub(super) fn publish_share_roles(
        &mut self,
        book: &mut ShareBook,
        rec: &FolderRecord,
        roles: BTreeMap<DeviceId, RoleEntry>,
    ) -> Result<ShareRoles> {
        let epoch = Self::newest_share_epoch(rec);
        let key = self
            .share_epoch_key(rec, epoch)
            .ok_or_else(|| anyhow!("no key for share epoch {epoch} of {}", rec.name))?;
        let st = book.folders.entry(rec.folder_id.clone()).or_default();
        // Above every record seen on the storages too, verified or not, so a
        // name taken by another owner device is not reused.
        let mut seq = st.roles.as_ref().map(|r| r.seq).unwrap_or(0) + 1;
        let prefix = format!("{}{}/", share::ROLE_PREFIX, rec.folder_id);
        let storages = self.metadata_storages(true)?;
        if storages.is_empty() {
            bail!("no storage to publish the roles to: add one first");
        }
        for (_, b) in &storages {
            for key in b.list(&prefix)? {
                if let Some((s, issuer)) = key
                    .strip_prefix(&prefix)
                    .and_then(SignedShareRoles::parse_name)
                {
                    if issuer == self.vault.device_id && s >= seq {
                        seq = s + 1;
                    }
                }
            }
        }
        let r = ShareRoles {
            folder: rec.folder_id.clone(),
            seq,
            issuer: self.vault.device_id.clone(),
            issued_utc: util::now_utc(),
            share_epoch: epoch,
            roles,
        };
        let signed =
            SignedShareRoles::seal(&r, &self.vault.vault_id, epoch, &key, &self.keys.signer)?;
        let bytes = serde_json::to_vec(&signed)?;
        let path = SignedShareRoles::storage_key(&rec.folder_id, seq, &self.vault.device_id);
        for (_, b) in &storages {
            b.put_if_absent(&path, &bytes)?;
        }
        st.roles = Some(r.clone());
        self.save_share_book(book)?;
        self.refresh_share_viewers(book)?;
        Ok(r)
    }

    /// The first role record of a folder: every member there is now stays an
    /// editor (from here on, a member the record does not list is a viewer).
    pub(super) fn start_share_roles(&mut self, folder: &FolderId) -> Result<()> {
        let rec = self
            .keyring
            .folders
            .get(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let mut book = self.share_book();
        if book.folders.get(folder).is_some_and(|s| s.roles.is_some()) {
            return Ok(());
        }
        let st = book.folders.get(folder).cloned().unwrap_or_default();
        let now = util::now_utc();
        let roles: BTreeMap<DeviceId, RoleEntry> = st
            .members
            .iter()
            .filter(|d| {
                !st.removed.contains_key(*d) && !st.owners.contains(*d) && !self.is_revoked(d)
            })
            .map(|d| {
                (
                    d.clone(),
                    RoleEntry {
                        role: ShareRole::Editor,
                        name: self.member_name(d),
                        since_utc: now,
                        editor_until_clock: 0,
                        editor_until_seq: 0,
                    },
                )
            })
            .collect();
        self.publish_share_roles(&mut book, &rec, roles)?;
        Ok(())
    }

    /// Owner: make a member of a shared folder a viewer or an editor. A
    /// member cannot change its own role: only a record signed by one of
    /// the owner's devices counts. Taking writing away keeps what the member
    /// wrote until now (its changes this device has seen, its ledger
    /// batches held here); what it writes from now on is not accepted.
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
        if !rec.shared {
            bail!("{} is not shared", rec.name);
        }
        // Up to date first: the newest roles, members and ledger heads.
        self.pull_ledger_once()?;
        self.pull_share_state()?;
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
            [one] => *one,
            _ => bail!(
                "several members of {} match {who}: use the device id",
                rec.name
            ),
        };
        match (m.kind.as_str(), m.status.as_str()) {
            ("owner-device", _) => bail!(
                "{} is one of your own devices; the owner's devices always write",
                m.name
            ),
            ("invite", _) => bail!(
                "{} is a token not accepted yet; its role is set when the token is made (revoke it and make a new one)",
                m.name
            ),
            (_, "removed") => bail!("{} was removed from {}", m.name, rec.name),
            _ => {}
        }
        let dev = DeviceId::from_hex(&m.id)?;
        let mut book = self.share_book();
        let st = book
            .folders
            .get(&rec.folder_id)
            .cloned()
            .unwrap_or_default();
        let now = util::now_utc();
        let mut roles = match &st.roles {
            Some(r) => r.roles.clone(),
            None => {
                // The first record: everyone there now stays an editor.
                st.members
                    .iter()
                    .filter(|d| {
                        !st.removed.contains_key(*d)
                            && !st.owners.contains(*d)
                            && !self.is_revoked(d)
                    })
                    .map(|d| {
                        (
                            d.clone(),
                            RoleEntry {
                                role: ShareRole::Editor,
                                name: self.member_name(d),
                                since_utc: now,
                                editor_until_clock: 0,
                                editor_until_seq: 0,
                            },
                        )
                    })
                    .collect()
            }
        };
        let before = roles.get(&dev).cloned();
        let was_editor = match (&st.roles, &before) {
            (None, _) => true,
            (Some(_), Some(e)) => e.role.is_editor(),
            (Some(_), None) => false,
        };
        let entry = match role {
            ShareRole::Editor => RoleEntry {
                role,
                name: m.name.clone(),
                since_utc: now,
                editor_until_clock: 0,
                editor_until_seq: 0,
            },
            ShareRole::Viewer if was_editor => {
                // What it wrote while it could stays valid.
                let state = self.load_state(&rec.folder_id)?;
                let clock = state
                    .files
                    .values()
                    .filter(|f| f.modified_by == dev)
                    .map(|f| f.modified_clock)
                    .max()
                    .unwrap_or(0);
                RoleEntry {
                    role,
                    name: m.name.clone(),
                    since_utc: now,
                    editor_until_clock: clock,
                    editor_until_seq: self.ledger.head(&dev).seq,
                }
            }
            ShareRole::Viewer => before.clone().unwrap_or(RoleEntry {
                role,
                name: m.name.clone(),
                since_utc: now,
                editor_until_clock: 0,
                editor_until_seq: 0,
            }),
        };
        let unchanged = st.roles.is_some() && before.as_ref().is_some_and(|b| b.role == role);
        let seq = if unchanged {
            st.roles.as_ref().map(|r| r.seq).unwrap_or(0)
        } else {
            roles.insert(dev.clone(), RoleEntry { role, ..entry });
            self.publish_share_roles(&mut book, &rec, roles)?.seq
        };
        Ok(ShareRoleReport {
            folder: rec.name.clone(),
            member: m.name.clone(),
            member_id: m.id.clone(),
            role: role.as_str().into(),
            seq,
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
