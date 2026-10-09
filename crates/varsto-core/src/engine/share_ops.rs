// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Shared folders: issuing tokens with a confirmed fingerprint, listing who
//! has access, removing members and revoking tokens through per-folder share
//! epochs (`docs/spec/alpha-0-format.md` section 23, `crate::share`).
//!
//! Removing a member works like removing a device from the vault
//! (`membership`), for one folder: the folder gets a new random key; the
//! owner's devices receive it under the folder-record key, the members that
//! stay through a grant sealed to their KEM key; everything written from
//! then on (chunks, manifests, thumbnails, member records, member ledger
//! batches, access records) uses it. The removed member keeps what it could
//! read, its ledger batches after the cut-off and its later manifests are
//! ignored, and a device it creates with the old key is not accepted as a
//! member.

use super::*;
use crate::share::{
    self, InviteRecord, RemovedMember, ShareEpochRecord, ShareGrant, ShareKeyRecord,
    SHARE_EPOCH_BASE,
};
use crate::vault::{RequestCode, SealedShareToken, ShareRequest};

const BOOK_FILE: &str = "shares.json";

/// What this device knows about one shared folder's members and epochs
/// (`state/shares.json`; device ids and names, nothing secret).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FolderShareState {
    /// Newest share epoch adopted (0: none yet).
    #[serde(default)]
    epoch: u32,
    #[serde(default)]
    issuer: Option<DeviceId>,
    #[serde(default)]
    issued_utc: i64,
    /// Devices the newest epoch kept.
    #[serde(default)]
    participants: BTreeSet<DeviceId>,
    /// The owner's devices (from the token, then from each epoch record):
    /// on a member, only they can hand out new keys.
    #[serde(default)]
    owners: BTreeSet<DeviceId>,
    /// Member devices accepted for this folder.
    #[serde(default)]
    members: BTreeSet<DeviceId>,
    /// Members removed, with the time and the device that removed them.
    #[serde(default)]
    removed: BTreeMap<DeviceId, RemovedInfo>,
    #[serde(default)]
    revoked_invites: BTreeSet<String>,
    #[serde(default)]
    kept_invites: BTreeSet<String>,
    /// Recipients known to hold a grant for `epoch` (owner devices only).
    #[serde(default)]
    granted: BTreeSet<String>,
    /// Member device: a newer epoch exists and no grant for it reached
    /// this device (it was removed, or nobody sealed the key to it yet).
    #[serde(default)]
    access_lost: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemovedInfo {
    name: String,
    cutoff_seq: u64,
    removed_utc: i64,
    by: DeviceId,
    epoch: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ShareBook {
    #[serde(default)]
    folders: BTreeMap<FolderId, FolderShareState>,
}

/// One entry of a shared folder's access list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMember {
    /// Device id, or the invitation id of a token not accepted yet.
    pub id: String,
    pub name: String,
    /// `owner-device`, `member` or `invite`.
    pub kind: String,
    /// `active`, `removed`, `pending` (a token not accepted yet) or `revoked`.
    pub status: String,
    /// The fingerprint the owner confirmed when sealing the token, if known.
    pub fingerprint: String,
    pub this_device: bool,
    pub since_utc: i64,
    pub removed_utc: Option<i64>,
    pub removed_by: Option<String>,
}

/// Who has access to a shared folder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMembers {
    pub folder: String,
    pub folder_id: String,
    /// Newest share epoch (0: the folder still uses the key it was shared with).
    pub share_epoch: u32,
    pub members: Vec<ShareMember>,
    /// This member device no longer receives new content of the folder.
    pub access_lost: bool,
}

/// What a removal did.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ShareRevokeReport {
    pub folder: String,
    pub share_epoch: u32,
    /// Members removed (names).
    pub removed: Vec<String>,
    /// Invitations (tokens not accepted yet) revoked.
    pub invites_revoked: Vec<String>,
    /// Members and open invitations that received the new key now.
    pub grants_sealed: usize,
    /// Members that get the new key once they publish a key-exchange key
    /// (they run an older version).
    pub grants_pending: Vec<String>,
}

impl Engine {
    // ----- local book ---------------------------------------------------------

    fn share_book(&self) -> ShareBook {
        util::read_json_or_default(&self.home.join("state").join(BOOK_FILE)).unwrap_or_default()
    }

    fn save_share_book(&self, book: &ShareBook) -> Result<()> {
        fs::create_dir_all(self.home.join("state"))?;
        util::write_json(&self.home.join("state").join(BOOK_FILE), book)
    }

    /// A member device that was cut off from a shared folder's new key.
    pub(super) fn share_access_lost(&self, folder: &FolderId) -> bool {
        self.vault.member
            && self
                .share_book()
                .folders
                .get(folder)
                .is_some_and(|f| f.access_lost)
    }

    // ----- keys ---------------------------------------------------------------

    /// The folder key of `epoch` for share purposes (0: the folder key itself).
    pub(super) fn share_epoch_key(&self, rec: &FolderRecord, epoch: u32) -> Option<SecretKey> {
        if epoch == 0 {
            rec.folder_key().ok()
        } else {
            SecretKey::from_hex(rec.epoch_keys.get(&epoch)?).ok()
        }
    }

    fn newest_share_epoch(rec: &FolderRecord) -> u32 {
        rec.epoch_keys
            .keys()
            .copied()
            .filter(|e| *e >= SHARE_EPOCH_BASE)
            .max()
            .unwrap_or(0)
    }

    /// Key id and key a member seals its ledger batches with now.
    pub(super) fn share_ledger_key_now(&self, rec: &FolderRecord) -> Result<(String, SecretKey)> {
        let e = Self::newest_share_epoch(rec);
        let k = self
            .share_epoch_key(rec, e)
            .ok_or_else(|| anyhow!("no key for share epoch {e} of {}", rec.name))?;
        Ok((
            share::ledger_key_id(&rec.folder_id, e),
            vault::share_ledger_key(&k, &rec.folder_id),
        ))
    }

    /// Every share ledger key id this device can open.
    pub(super) fn share_ledger_key_ids(&self) -> Vec<String> {
        let mut out = Vec::new();
        for rec in self.keyring.folders.values() {
            out.push(vault::share_key_id(&rec.folder_id));
            for e in rec.epoch_keys.keys().filter(|e| **e >= SHARE_EPOCH_BASE) {
                out.push(share::ledger_key_id(&rec.folder_id, *e));
            }
        }
        out
    }

    /// Folder keys of every epoch after 0 that this device holds for a
    /// folder: vault-epoch keys (owner devices) and share epochs.
    fn later_folder_keys(&self, rec: &FolderRecord) -> BTreeMap<u32, String> {
        let mut out = BTreeMap::new();
        if !self.vault.member {
            let scope: [&[u8]; 2] = [
                self.vault.vault_id.as_str().as_bytes(),
                rec.folder_id.as_str().as_bytes(),
            ];
            for (e, k) in self.epochs.keys.iter().filter(|(e, _)| **e > 0) {
                out.insert(*e, k.derive("folder-epoch", &scope).to_hex());
            }
        }
        out.extend(rec.epoch_keys.iter().map(|(e, k)| (*e, k.clone())));
        out
    }

    /// A member keeps its share-request key as its KEM key (grants of later
    /// share epochs are sealed to it); one is created when there is none.
    pub(super) fn adopt_member_kem(&mut self) -> Result<()> {
        if !self.vault.member {
            return Ok(());
        }
        if let Some(dk) = ShareRequest::key(&self.home) {
            self.epochs.kem = Some(dk);
        } else if self.epochs.kem.is_none() {
            self.epochs.kem = Some(crate::kem::DecapsKey::generate());
        }
        self.save_epochs()
    }

    // ----- issuing tokens ---------------------------------------------------------

    /// Mark a folder shared and build its token (folder key and keys of later
    /// epochs). A folder that was re-keyed with the vault key gets a share
    /// epoch first, so what is written from now on is under a key only the
    /// owner's current devices and the members hold.
    pub(super) fn share_prepare(&mut self, folder: &str) -> Result<ShareToken> {
        if self.vault.member {
            bail!("a member device cannot share folders further");
        }
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if rec.is_strongroom() {
            bail!("a Strongroom folder cannot be shared");
        }
        let needs_epoch =
            self.key_epoch() > 0 && !self.is_frozen(&rec) && Self::newest_share_epoch(&rec) == 0;
        if let Some(r) = self.keyring.folders.get_mut(&rec.folder_id) {
            r.shared = true;
        }
        self.save_keyring_now()?;
        if needs_epoch {
            self.start_share_epoch(&rec.folder_id, Vec::new(), BTreeSet::new())?;
        }
        self.publish_registry()?;
        let rec = self.keyring.folders[&rec.folder_id].clone();
        let mut t = rec.share_token(&self.vault.vault_id);
        t.epoch_keys = self.later_folder_keys(&rec);
        t.owners = self.owner_devices().into_iter().collect();
        Ok(t)
    }

    /// The owner's current full devices (this one included).
    fn owner_devices(&self) -> BTreeSet<DeviceId> {
        let mut out: BTreeSet<DeviceId> = self
            .devices
            .devices
            .keys()
            .filter(|d| self.trusted(d))
            .cloned()
            .collect();
        out.insert(self.vault.device_id.clone());
        out
    }

    /// A member remembers which devices are the owner's (from its token).
    pub(super) fn remember_share_owners(
        &self,
        folder: &FolderId,
        owners: &[DeviceId],
    ) -> Result<()> {
        let mut book = self.share_book();
        book.folders
            .entry(folder.clone())
            .or_default()
            .owners
            .extend(owners.iter().cloned());
        self.save_share_book(&book)
    }

    fn save_keyring_now(&self) -> Result<()> {
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// The fingerprint and bound name of a request code, for the owner to
    /// compare with the requester before sealing.
    pub fn share_request_info(code: &str) -> Result<RequestCode> {
        ShareRequest::parse(code)
    }

    /// Owner: a plain token (the folder key is inside it). Recorded as an
    /// invitation so it can be revoked before it is accepted.
    pub fn share_create_plain(&mut self, folder: &str) -> Result<ShareToken> {
        let t = self.share_prepare(folder)?;
        t.encode_plain()?;
        let mut tag = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
        self.publish_invite(InviteRecord {
            folder: t.folder_id.clone(),
            invite: format!("plain-{}", hex::encode(tag)),
            request_hex: String::new(),
            name: String::new(),
            fingerprint: String::new(),
            issuer: self.vault.device_id.clone(),
            issued_utc: util::now_utc(),
        })?;
        Ok(t)
    }

    /// Owner: a token sealed to a request code. `confirmed` is the
    /// fingerprint the person compared with the requester; when given it must
    /// match the code's. The token carries the fingerprint, and the
    /// recipient's device checks it against its own request.
    pub fn share_create_sealed(
        &mut self,
        folder: &str,
        code: &str,
        confirmed: Option<&str>,
    ) -> Result<(SealedShareToken, RequestCode)> {
        let req = ShareRequest::parse(code)?;
        if let Some(c) = confirmed {
            if !share::fingerprint_matches(&req.fingerprint, c) {
                bail!(
                    "the fingerprint you confirmed does not match this request code (it shows \"{}\"); do not share with it",
                    req.fingerprint
                );
            }
        }
        let mut t = self.share_prepare(folder)?;
        t.fingerprint = req.fingerprint.clone();
        let sealed = t.seal(&req.key)?;
        self.publish_invite(InviteRecord {
            folder: t.folder_id.clone(),
            invite: share::invite_id(&req.key),
            request_hex: hex::encode(req.key.to_bytes()),
            name: req.name.clone(),
            fingerprint: req.fingerprint.clone(),
            issuer: self.vault.device_id.clone(),
            issued_utc: util::now_utc(),
        })?;
        Ok((sealed, req))
    }

    fn publish_invite(&mut self, inv: InviteRecord) -> Result<()> {
        let key = InviteRecord::storage_key(&inv.folder, &inv.invite);
        let blob = inv.seal(&self.vault.vault_id, &self.folder_record_key_now())?;
        for (_, backend) in self.metadata_storages(true)? {
            // A new token for the same request replaces the record (the
            // name bound to it may have changed).
            backend.delete(&key)?;
            backend.put_if_absent(&key, &blob)?;
        }
        // A new token for an invitation revoked earlier opens it again.
        let mut book = self.share_book();
        if let Some(f) = book.folders.get_mut(&inv.folder) {
            if f.revoked_invites.remove(&inv.invite) {
                f.kept_invites.insert(inv.invite.clone());
                self.save_share_book(&book)?;
            }
        }
        Ok(())
    }

    fn invites(&self, folder: &FolderId) -> Result<BTreeMap<String, InviteRecord>> {
        let mut out = BTreeMap::new();
        if self.vault.member {
            return Ok(out);
        }
        let fr_keys = self.folder_record_keys();
        let prefix = format!("{}{folder}/", share::INVITE_PREFIX);
        for (_, backend) in self.metadata_storages(false)? {
            for key in backend.list(&prefix)? {
                let Some(id) = key
                    .strip_prefix(&prefix)
                    .and_then(|r| r.strip_suffix(".enc"))
                else {
                    continue;
                };
                if out.contains_key(id) {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Some(r) = fr_keys.iter().find_map(|k| {
                        InviteRecord::open(&blob, &self.vault.vault_id, folder, id, k).ok()
                    }) {
                        out.insert(id.to_string(), r);
                    }
                }
            }
        }
        Ok(out)
    }

    // ----- records published by every participant ------------------------------

    /// Publish this device's member record (and, on a member, its KEM key)
    /// for every shared folder, under the newest share key it holds.
    pub(super) fn publish_share_records(
        &self,
        backend: &dyn Storage,
        own: &DeviceRecord,
    ) -> Result<()> {
        let vault_id = &self.vault.vault_id;
        for f in self
            .keyring
            .folders
            .values()
            .filter(|f| f.shared && !f.is_removed())
        {
            let base = vault::share_registry_key(&f.folder_key()?, &f.folder_id);
            backend.put_if_absent(
                &vault::share_record_key(&f.folder_id, &own.device_id),
                &own.seal(vault_id, &base)?,
            )?;
            let e = Self::newest_share_epoch(f);
            if e > 0 {
                if let Some(k) = self.share_epoch_key(f, e) {
                    let rk = vault::share_registry_key(&k, &f.folder_id);
                    backend.put_if_absent(
                        &member_record_key(&f.folder_id, e, &own.device_id),
                        &own.seal(vault_id, &rk)?,
                    )?;
                }
            }
            if self.vault.member {
                if let Some(dk) = &self.epochs.kem {
                    let rec =
                        KemRecord::sign(vault_id, &own.device_id, &dk.public(), &self.keys.signer);
                    let key = format!(
                        "{}{}/{}.json",
                        share::KEM_PREFIX,
                        f.folder_id,
                        own.device_id
                    );
                    if !backend.exists(&key)? {
                        backend.put_if_absent(&key, &serde_json::to_vec(&rec)?)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Read what other participants published about shared folders: share
    /// epochs (owner devices through the folder-record key, members through
    /// grants), member records (with the trust rule below), and seal the
    /// newest key to members that still lack it. Returns whether the device
    /// cache and the keyring changed.
    ///
    /// Trust rule for member records: once a folder has a share epoch, a
    /// record that opens only under an older key is accepted only for a
    /// device the newest epoch kept, an owner device, or one already known.
    /// Someone who was removed (and holds only older keys) cannot add a new
    /// device.
    pub(super) fn pull_share_state(&mut self) -> Result<(bool, bool)> {
        let mut changed_devices = false;
        let mut changed_folders = false;
        if self.vault.member && self.epochs.kem.is_none() {
            self.adopt_member_kem()?;
        }
        let storages = self.metadata_storages(false)?;
        let mut book = self.share_book();
        let mut book_changed = false;

        // 1. Owner devices: invitations mark folders shared; share keys.
        if !self.vault.member {
            let (folders, adopted) = self.pull_share_keys(&storages, &mut book)?;
            changed_folders |= folders || adopted;
            changed_devices |= adopted;
            book_changed |= adopted;
        }
        // 2. Member records (owner devices among them first, so that grants
        //    can be checked), then grants, then records under new keys.
        let (d, b) = self.pull_share_members(&storages, &mut book)?;
        changed_devices |= d;
        book_changed |= b;
        if self.vault.member {
            let (adopted, b) = self.pull_share_grants(&storages, &mut book)?;
            book_changed |= b || adopted;
            if adopted {
                changed_devices = true;
                changed_folders = true;
                let (d, b) = self.pull_share_members(&storages, &mut book)?;
                changed_devices |= d;
                book_changed |= b;
            }
        }
        // 3. Owner devices: seal the newest key to members that lack it.
        if !self.vault.member {
            let shared: Vec<FolderRecord> = self
                .keyring
                .folders
                .values()
                .filter(|f| f.shared && !f.is_removed())
                .cloned()
                .collect();
            for f in &shared {
                book_changed |= self.issue_share_grants(&storages, &mut book, f)?;
            }
        }
        if book_changed {
            self.save_share_book(&book)?;
        }
        if changed_folders {
            self.save_keyring_now()?;
            // A folder this device now knows to be shared, or a new share
            // key: the other participants need this device's record under it.
            let own = self.own_record();
            for (_, b) in self.metadata_storages(true)? {
                self.publish_share_records(b.as_ref(), &own)?;
            }
        }
        Ok((changed_devices, changed_folders))
    }

    /// Owner devices: folders with invitations are shared; adopt share
    /// epochs published under the folder-record key. Returns (folders marked
    /// shared, epochs adopted).
    fn pull_share_keys(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<(bool, bool)> {
        let fr_keys = self.folder_record_keys();
        let mut marked = false;
        let mut keys: BTreeMap<(FolderId, u32), SecretKey> = BTreeMap::new();
        for (_, backend) in storages {
            for key in backend.list(share::INVITE_PREFIX)? {
                let Some(fid) = key
                    .strip_prefix(share::INVITE_PREFIX)
                    .and_then(|r| r.split('/').next())
                    .and_then(|f| FolderId::from_hex(f).ok())
                else {
                    continue;
                };
                if let Some(r) = self.keyring.folders.get_mut(&fid) {
                    if !r.shared && !r.is_strongroom() {
                        r.shared = true;
                        marked = true;
                    }
                }
            }
            for key in backend.list(share::KEY_PREFIX)? {
                let Some((fid, rest)) = key
                    .strip_prefix(share::KEY_PREFIX)
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(fid), Some(e)) = (FolderId::from_hex(fid), share::epoch_from_name(rest))
                else {
                    continue;
                };
                let Some(rec) = self.keyring.folders.get(&fid) else {
                    continue;
                };
                if rec.epoch_keys.contains_key(&e) || keys.contains_key(&(fid.clone(), e)) {
                    continue;
                }
                if let Some(blob) = backend.get(&key)? {
                    if let Some(k) = fr_keys.iter().find_map(|rk| {
                        ShareKeyRecord::open(&blob, &self.vault.vault_id, &fid, e, rk).ok()
                    }) {
                        keys.insert((fid, e), k);
                    }
                }
            }
        }
        let mut adopted = false;
        for ((fid, e), k) in keys {
            adopted |= self.adopt_share_epoch(storages, book, &fid, e, &k)?;
        }
        Ok((marked, adopted))
    }

    /// Member devices: adopt share epochs whose grant to this device (or to
    /// its invitation) was sealed by one of the owner's devices. Also notes
    /// when a newer epoch exists that no grant opens (removed, or the key was
    /// not sealed to this device yet). Returns (adopted, book changed).
    fn pull_share_grants(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<(bool, bool)> {
        let me = self.vault.device_id.to_string();
        let my_invite = self
            .epochs
            .kem
            .as_ref()
            .map(|dk| ShareGrant::invite_recipient(&share::invite_id(&dk.public())));
        let shared: Vec<FolderId> = self
            .keyring
            .folders
            .values()
            .filter(|f| f.shared && !f.is_removed())
            .map(|f| f.folder_id.clone())
            .collect();
        let mut adopted = false;
        let mut changed = false;
        for fid in shared {
            let mut newest_seen = 0u32;
            let mut grants: BTreeMap<u32, Vec<ShareGrant>> = BTreeMap::new();
            for (_, backend) in storages {
                for key in backend.list(&format!("{}{fid}/", share::EPOCH_PREFIX))? {
                    if let Some(e) = key.rsplit('/').next().and_then(share::epoch_from_name) {
                        newest_seen = newest_seen.max(e);
                    }
                }
                let prefix = format!("{}{fid}/", share::GRANT_PREFIX);
                for key in backend.list(&prefix)? {
                    let parts: Vec<&str> = key
                        .strip_prefix(&prefix)
                        .unwrap_or_default()
                        .split('/')
                        .collect();
                    let [e, who, _issuer] = parts.as_slice() else {
                        continue;
                    };
                    let Some(e) = share::epoch_from_name(e) else {
                        continue;
                    };
                    if *who != me && Some(*who) != my_invite.as_deref() {
                        continue;
                    }
                    if self.keyring.folders[&fid].epoch_keys.contains_key(&e) {
                        continue;
                    }
                    if let Some(blob) = backend.get(&key)? {
                        if let Ok(g) = serde_json::from_slice::<ShareGrant>(&blob) {
                            if g.folder == fid && g.epoch == e && g.recipient == *who {
                                grants.entry(e).or_default().push(g);
                            }
                        }
                    }
                }
            }
            for (e, list) in grants {
                let owners = book
                    .folders
                    .get(&fid)
                    .map(|s| s.owners.clone())
                    .unwrap_or_default();
                let mut key = None;
                for g in list {
                    // Only the owner's devices hand out keys. A member that
                    // joined before tokens named them trusts any participant.
                    if !owners.is_empty() && !owners.contains(&g.issuer) {
                        continue;
                    }
                    let (Some(issuer), Some(dk)) =
                        (self.share_issuer_key(&g.issuer), self.epochs.kem.as_ref())
                    else {
                        continue;
                    };
                    if let Ok(k) = g.open(&self.vault.vault_id, &issuer, dk) {
                        key = Some(k);
                        break;
                    }
                }
                if let Some(k) = key {
                    adopted |= self.adopt_share_epoch(storages, book, &fid, e, &k)?;
                }
            }
            let held = Self::newest_share_epoch(&self.keyring.folders[&fid]);
            let lost = newest_seen > held;
            let st = book.folders.entry(fid.clone()).or_default();
            if st.access_lost != lost {
                st.access_lost = lost;
                changed = true;
            }
        }
        Ok((adopted, changed))
    }

    /// Member records of every shared folder (see the trust rule above).
    /// Returns (device cache changed, book changed).
    fn pull_share_members(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<(bool, bool)> {
        let mut changed_devices = false;
        let mut book_changed = false;
        let shared: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|f| f.shared && !f.is_removed())
            .cloned()
            .collect();
        for f in &shared {
            let newest = Self::newest_share_epoch(f);
            let st = book.folders.get(&f.folder_id).cloned().unwrap_or_default();
            let mut found: Vec<(DeviceId, DeviceRecord)> = Vec::new();
            for (_, backend) in storages {
                let mut keys: Vec<(String, DeviceId, u32)> = Vec::new();
                let old = format!("{SHARE_PREFIX}{}/", f.folder_id);
                for key in backend.list(&old)? {
                    if let Some(id) = key
                        .strip_prefix(&old)
                        .and_then(|s| s.strip_suffix(".enc"))
                        .and_then(|s| DeviceId::from_hex(s).ok())
                    {
                        keys.push((key, id, 0));
                    }
                }
                if newest > 0 {
                    let new = format!("{}{}/", share::MEMBER_PREFIX, f.folder_id);
                    for key in backend.list(&new)? {
                        let Some((e, d)) = key.strip_prefix(&new).and_then(|r| r.split_once('/'))
                        else {
                            continue;
                        };
                        let (Some(e), Some(id)) = (
                            share::epoch_from_name(e),
                            d.strip_suffix(".enc")
                                .and_then(|s| DeviceId::from_hex(s).ok()),
                        ) else {
                            continue;
                        };
                        keys.push((key, id, e));
                    }
                }
                for (key, id, e) in keys {
                    if id == self.vault.device_id || self.devices.devices.contains_key(&id) {
                        continue;
                    }
                    let known = st.members.contains(&id);
                    if (known && self.devices.members.contains_key(&id))
                        || found.iter().any(|(d, _)| d == &id)
                    {
                        continue;
                    }
                    let owner = st.owners.contains(&id);
                    // A removed member's record still verifies its batches
                    // up to the cut-off.
                    let allowed = newest == 0
                        || e == newest
                        || known
                        || owner
                        || st.participants.contains(&id)
                        || st.removed.contains_key(&id);
                    if !allowed {
                        continue;
                    }
                    let Some(k) = self.share_epoch_key(f, e) else {
                        continue;
                    };
                    let rk = vault::share_registry_key(&k, &f.folder_id);
                    let Some(blob) = backend.get(&key)? else {
                        continue;
                    };
                    let Ok(rec) = DeviceRecord::open(&blob, &self.vault.vault_id, &id, &rk) else {
                        continue;
                    };
                    // The id is the hash of the signing key: a record cannot
                    // claim another device's id with its own key.
                    if rec
                        .pubkey()
                        .ok()
                        .is_none_or(|pk| ledger::device_id_for(&pk) != id)
                    {
                        continue;
                    }
                    found.push((id, rec));
                }
            }
            let st = book.folders.entry(f.folder_id.clone()).or_default();
            for (id, rec) in found {
                if !st.owners.contains(&id) && st.members.insert(id.clone()) {
                    book_changed = true;
                }
                if let std::collections::btree_map::Entry::Vacant(e) =
                    self.devices.members.entry(id)
                {
                    e.insert(rec);
                    changed_devices = true;
                }
            }
        }
        Ok((changed_devices, book_changed))
    }

    /// The signing key of a device as this device knows it: the vault
    /// registry on the owner's devices, the folder's member records on a
    /// member (where the owner's devices publish theirs too).
    fn share_issuer_key(&self, issuer: &DeviceId) -> Option<crate::crypto::VerifyingKey> {
        if issuer == &self.vault.device_id {
            return Some(self.keys.signer.public());
        }
        self.devices
            .devices
            .get(issuer)
            .or_else(|| self.devices.members.get(issuer))?
            .pubkey()
            .ok()
    }

    /// Adopt share epoch `e` of a folder with its key: open the epoch record,
    /// keep the key and every older one it names, and apply the removals.
    fn adopt_share_epoch(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
        folder: &FolderId,
        e: u32,
        key: &SecretKey,
    ) -> Result<bool> {
        let mut record = None;
        for (_, backend) in storages {
            if let Some(blob) = backend.get(&ShareEpochRecord::storage_key(folder, e))? {
                if let Ok(r) = ShareEpochRecord::open(&blob, &self.vault.vault_id, folder, e, key) {
                    record = Some(r);
                    break;
                }
            }
        }
        // The record may not have reached this storage yet: try again later.
        let Some(r) = record else {
            return Ok(false);
        };
        self.apply_share_epoch(book, &r, key)?;
        Ok(true)
    }

    fn apply_share_epoch(
        &mut self,
        book: &mut ShareBook,
        r: &ShareEpochRecord,
        key: &SecretKey,
    ) -> Result<()> {
        let member = self.vault.member;
        let Some(rec) = self.keyring.folders.get_mut(&r.folder) else {
            return Ok(());
        };
        rec.shared = true;
        rec.epoch_keys.insert(r.epoch, key.to_hex());
        for (oe, ok) in &r.older {
            // Vault-epoch keys are derived on owner devices; members keep them.
            if *oe >= SHARE_EPOCH_BASE || member {
                rec.epoch_keys.entry(*oe).or_insert_with(|| ok.clone());
            }
        }
        let st = book.folders.entry(r.folder.clone()).or_default();
        for m in &r.removed {
            st.removed.entry(m.device.clone()).or_insert(RemovedInfo {
                name: m.name.clone(),
                cutoff_seq: m.cutoff_seq,
                removed_utc: r.issued_utc,
                by: r.issuer.clone(),
                epoch: r.epoch,
            });
            st.participants.remove(&m.device);
            if m.device == self.vault.device_id {
                continue;
            }
            self.devices
                .revoked
                .entry(m.device.clone())
                .or_insert(membership::Revoked {
                    by: r.issuer.clone(),
                    issued_utc: r.issued_utc,
                    cutoff_seq: m.cutoff_seq,
                    wipe: false,
                });
        }
        st.revoked_invites.extend(r.revoked_invites.iter().cloned());
        if r.epoch >= st.epoch {
            st.epoch = r.epoch;
            st.issuer = Some(r.issuer.clone());
            st.issued_utc = r.issued_utc;
            st.participants = r.participants.iter().cloned().collect();
            if !r.owners.is_empty() {
                st.owners = r.owners.iter().cloned().collect();
            }
            st.kept_invites = r
                .kept_invites
                .iter()
                .filter(|i| !st.revoked_invites.contains(*i))
                .cloned()
                .collect();
            st.granted.clear();
            st.access_lost = false;
        }
        self.save_devices()?;
        self.save_keyring_now()
    }

    /// Seal the newest share key of a folder, from this device, to every
    /// kept member and open invitation that has a key-exchange key and no
    /// grant from this device yet. Returns whether the book changed.
    fn issue_share_grants(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
        f: &FolderRecord,
    ) -> Result<bool> {
        let e = Self::newest_share_epoch(f);
        let Some(st) = book.folders.get(&f.folder_id).cloned() else {
            return Ok(false);
        };
        if e == 0 || st.epoch != e {
            return Ok(false);
        }
        let Some(key) = self.share_epoch_key(f, e) else {
            return Ok(false);
        };
        let me = self.vault.device_id.clone();
        let mut wanted: Vec<(String, Option<DeviceId>, Option<String>)> = st
            .participants
            .iter()
            .filter(|d| !self.devices.devices.contains_key(*d) && **d != me)
            .map(|d| (d.to_string(), Some(d.clone()), None))
            .collect();
        wanted.extend(
            st.kept_invites
                .iter()
                .map(|i| (ShareGrant::invite_recipient(i), None, Some(i.clone()))),
        );
        wanted.retain(|(r, _, _)| !st.granted.contains(r));
        if wanted.is_empty() {
            return Ok(false);
        }
        let invites = if wanted.iter().any(|(_, _, i)| i.is_some()) {
            self.invites(&f.folder_id)?
        } else {
            BTreeMap::new()
        };
        let mine = self.keys.signer.public();
        let mut done = Vec::new();
        for (recipient, device, invite) in wanted {
            let path = ShareGrant::storage_key(&f.folder_id, e, &recipient, &me);
            let mut valid = false;
            for (_, b) in storages {
                if let Some(blob) = b.get(&path)? {
                    // Something else at our path (planted by a storage
                    // writer) is replaced.
                    valid = serde_json::from_slice::<ShareGrant>(&blob)
                        .ok()
                        .is_some_and(|g| g.verify(&self.vault.vault_id, &mine).is_ok());
                    if !valid {
                        b.delete(&path)?;
                    }
                    break;
                }
            }
            if valid {
                done.push(recipient);
                continue;
            }
            let ek = match (&device, &invite) {
                (Some(d), _) => self.member_kem_key(storages, &f.folder_id, d)?,
                (None, Some(i)) => invites.get(i).and_then(|r| r.request_key()),
                _ => None,
            };
            let Some(ek) = ek else {
                continue;
            };
            let g = ShareGrant::seal(
                &self.vault.vault_id,
                &f.folder_id,
                e,
                &recipient,
                &ek,
                &key,
                &me,
                &self.keys.signer,
            )?;
            let bytes = serde_json::to_vec(&g)?;
            for (_, b) in self.metadata_storages(true)? {
                b.put_if_absent(&path, &bytes)?;
            }
            done.push(recipient);
        }
        if done.is_empty() {
            return Ok(false);
        }
        if let Some(st) = book.folders.get_mut(&f.folder_id) {
            st.granted.extend(done);
        }
        Ok(true)
    }

    /// A member's KEM key as it published it, checked against its record.
    fn member_kem_key(
        &self,
        storages: &OpenStorages,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<Option<crate::kem::EncapsKey>> {
        let Some(pk) = self
            .devices
            .members
            .get(device)
            .and_then(|r| r.pubkey().ok())
        else {
            return Ok(None);
        };
        let key = format!("{}{folder}/{device}.json", share::KEM_PREFIX);
        for (_, b) in storages {
            if let Some(blob) = b.get(&key)? {
                if let Ok(rec) = serde_json::from_slice::<KemRecord>(&blob) {
                    if &rec.device == device {
                        if let Ok(ek) = rec.verify(&self.vault.vault_id, &pk) {
                            return Ok(Some(ek));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    // ----- removing members -----------------------------------------------------

    /// Start a new share epoch of a folder: a random key for everything
    /// written from now on, published for the owner's devices and sealed to
    /// the members that stay. Returns the epoch and the grants report.
    fn start_share_epoch(
        &mut self,
        folder: &FolderId,
        removed: Vec<RemovedMember>,
        revoke_invites: BTreeSet<String>,
    ) -> Result<ShareRevokeReport> {
        let rec = self
            .keyring
            .folders
            .get(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let mut e = match Self::newest_share_epoch(&rec) {
            0 => SHARE_EPOCH_BASE,
            n => n + 1,
        };
        let key = SecretKey::random();
        let mut book = self.share_book();
        let st = book.folders.get(folder).cloned().unwrap_or_default();
        let gone: BTreeSet<DeviceId> = removed.iter().map(|m| m.device.clone()).collect();
        let owners = self.owner_devices();
        let mut participants = owners.clone();
        participants.extend(
            st.members
                .iter()
                .filter(|d| !gone.contains(*d) && !self.is_revoked(d))
                .cloned(),
        );
        let storages = self.metadata_storages(true)?;
        let mut accepted = BTreeSet::new();
        for d in &st.members {
            if let Some(ek) = self.member_kem_key(&storages, folder, d)? {
                accepted.insert(share::invite_id(&ek));
            }
        }
        let kept_invites: Vec<String> = self
            .invites(folder)?
            .into_keys()
            .filter(|i| {
                !revoke_invites.contains(i)
                    && !st.revoked_invites.contains(i)
                    && !accepted.contains(i)
            })
            .collect();
        let Some((_, first)) = storages.first() else {
            bail!("no storage to publish the new key to: add one first");
        };
        // The first free epoch number: another owner device may have taken
        // one at the same moment, and anyone who can write to the storage
        // can occupy a name. Readers skip what does not open.
        let mut record = ShareEpochRecord {
            folder: folder.clone(),
            epoch: e,
            issuer: self.vault.device_id.clone(),
            issued_utc: util::now_utc(),
            older: self.later_folder_keys(&rec),
            participants: participants.into_iter().collect(),
            owners: owners.into_iter().collect(),
            removed: removed.clone(),
            revoked_invites: revoke_invites.iter().cloned().collect(),
            kept_invites,
        };
        let mut tries = 0;
        let blob = loop {
            record.epoch = e;
            let blob = record.seal(&self.vault.vault_id, &key)?;
            if !first.exists(&ShareKeyRecord::storage_key(folder, e))?
                && first.put_if_absent(&ShareEpochRecord::storage_key(folder, e), &blob)?
            {
                break blob;
            }
            tries += 1;
            if tries >= 16 {
                bail!(
                    "could not find a free share epoch for {}; sync and try again",
                    rec.name
                );
            }
            e += 1;
        };
        for (_, b) in storages.iter().skip(1) {
            b.put_if_absent(&ShareEpochRecord::storage_key(folder, e), &blob)?;
        }
        let key_blob = ShareKeyRecord::seal(
            &self.vault.vault_id,
            folder,
            e,
            &key,
            &self.folder_record_key_now(),
        )?;
        for (_, b) in &storages {
            b.put_if_absent(&ShareKeyRecord::storage_key(folder, e), &key_blob)?;
        }
        self.apply_share_epoch(&mut book, &record, &key)?;
        let rec = self.keyring.folders[folder].clone();
        let readable = self.metadata_storages(false)?;
        self.issue_share_grants(&readable, &mut book, &rec)?;
        self.save_share_book(&book)?;
        self.publish_registry()?;
        let st = book.folders.get(folder).cloned().unwrap_or_default();
        let mut report = ShareRevokeReport {
            folder: rec.name.clone(),
            share_epoch: e,
            removed: removed.iter().map(|m| m.name.clone()).collect(),
            invites_revoked: revoke_invites.into_iter().collect(),
            grants_sealed: st.granted.len(),
            grants_pending: Vec::new(),
        };
        for d in st
            .participants
            .iter()
            .filter(|d| !self.devices.devices.contains_key(*d) && **d != self.vault.device_id)
        {
            if !st.granted.contains(d.as_str()) {
                report.grants_pending.push(self.member_name(d));
            }
        }
        Ok(report)
    }

    fn member_name(&self, d: &DeviceId) -> String {
        self.devices
            .members
            .get(d)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| d.short().to_string())
    }

    /// Owner: remove a member (device name or id), revoke a token that was
    /// not accepted yet (its invitation id, or the fingerprint words), or
    /// `all` of them from a shared folder. The folder gets a new key; the
    /// members that stay receive it; what the removed member already held
    /// stays readable to it.
    pub fn share_revoke(&mut self, folder: &str, who: &str) -> Result<ShareRevokeReport> {
        if self.vault.member {
            bail!("only the owner's devices can remove members of a shared folder");
        }
        self.ensure_active()?;
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if !rec.shared {
            bail!("{} is not shared", rec.name);
        }
        // Up to date first: the cut-offs are the newest batches held here.
        self.pull_ledger_once()?;
        let list = self.share_members(folder)?;
        let who = who.trim();
        let all = who.eq_ignore_ascii_case("all");
        let mut removed = Vec::new();
        let mut invites = BTreeSet::new();
        for m in &list.members {
            let hit = all
                || m.id == who
                || (who.len() >= 8 && m.id.starts_with(who))
                || m.name == who
                || (!m.fingerprint.is_empty() && share::fingerprint_matches(&m.fingerprint, who));
            if !hit {
                continue;
            }
            match (m.kind.as_str(), m.status.as_str()) {
                ("member", "active") => {
                    let d = DeviceId::from_hex(&m.id)?;
                    removed.push(RemovedMember {
                        cutoff_seq: self.ledger.head(&d).seq,
                        device: d,
                        name: m.name.clone(),
                    });
                }
                ("invite", "pending") => {
                    invites.insert(m.id.clone());
                }
                ("owner-device", _) if !all => bail!(
                    "{} is one of your own devices; remove it from the vault under Devices instead",
                    m.name
                ),
                _ => {}
            }
        }
        if removed.is_empty() && invites.is_empty() {
            bail!(
                "no member or open token of {} matches {who} (see `varsto share members {}`)",
                rec.name,
                rec.name
            );
        }
        let mut report = self.start_share_epoch(&rec.folder_id, removed, invites.clone())?;
        report.invites_revoked = invites.into_iter().collect();
        Ok(report)
    }

    /// Who has access to a shared folder: the owner's devices, members
    /// (current and removed) and tokens not accepted yet.
    pub fn share_members(&self, folder: &str) -> Result<ShareMembers> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let book = self.share_book();
        let st = book
            .folders
            .get(&rec.folder_id)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        let me = &self.vault.device_id;
        if !self.vault.member {
            out.push(ShareMember {
                id: me.to_string(),
                name: self.vault.device_name.clone(),
                kind: "owner-device".into(),
                status: "active".into(),
                fingerprint: String::new(),
                this_device: true,
                since_utc: 0,
                removed_utc: None,
                removed_by: None,
            });
            for (id, r) in self.devices.devices.iter().filter(|(d, _)| self.trusted(d)) {
                if id == me {
                    continue;
                }
                out.push(ShareMember {
                    id: id.to_string(),
                    name: r.name.clone(),
                    kind: "owner-device".into(),
                    status: "active".into(),
                    fingerprint: String::new(),
                    this_device: false,
                    since_utc: r.enrolled_utc,
                    removed_utc: None,
                    removed_by: None,
                });
            }
        }
        let invites = self.invites(&rec.folder_id)?;
        let storages = self.metadata_storages(false)?;
        let mut accepted_invites = BTreeSet::new();
        if self.vault.member {
            // The owner's devices, as the token and the share epochs named them.
            for id in &st.owners {
                out.push(ShareMember {
                    id: id.to_string(),
                    name: self.member_name(id),
                    kind: "owner-device".into(),
                    status: "active".into(),
                    fingerprint: String::new(),
                    this_device: false,
                    since_utc: 0,
                    removed_utc: None,
                    removed_by: None,
                });
            }
        }
        let mut members: BTreeSet<DeviceId> = st.members.clone();
        members.extend(st.removed.keys().cloned());
        members.retain(|d| !st.owners.contains(d));
        for id in &members {
            let name = match (self.devices.members.get(id), st.removed.get(id)) {
                (None, Some(r)) => r.name.clone(),
                _ => self.member_name(id),
            };
            let invite = if self.vault.member {
                None
            } else {
                self.member_kem_key(&storages, &rec.folder_id, id)?
                    .map(|ek| share::invite_id(&ek))
            };
            if let Some(i) = &invite {
                accepted_invites.insert(i.clone());
            }
            let removed = st.removed.get(id);
            out.push(ShareMember {
                id: id.to_string(),
                name,
                kind: "member".into(),
                status: if removed.is_some() || self.is_revoked(id) {
                    "removed"
                } else {
                    "active"
                }
                .into(),
                fingerprint: invite
                    .as_ref()
                    .and_then(|i| invites.get(i))
                    .map(|r| r.fingerprint.clone())
                    .unwrap_or_default(),
                this_device: id == me,
                since_utc: self
                    .devices
                    .members
                    .get(id)
                    .map(|r| r.enrolled_utc)
                    .unwrap_or(0),
                removed_utc: removed.map(|r| r.removed_utc),
                removed_by: removed.map(|r| self.device_name(&r.by)),
            });
        }
        for (id, inv) in &invites {
            if accepted_invites.contains(id) {
                continue;
            }
            let revoked = st.revoked_invites.contains(id);
            out.push(ShareMember {
                id: id.clone(),
                name: if inv.name.is_empty() {
                    if inv.request_hex.is_empty() {
                        "plain token".into()
                    } else {
                        "sealed token".into()
                    }
                } else {
                    inv.name.clone()
                },
                kind: "invite".into(),
                status: if revoked { "revoked" } else { "pending" }.into(),
                fingerprint: inv.fingerprint.clone(),
                this_device: false,
                since_utc: inv.issued_utc,
                removed_utc: None,
                removed_by: None,
            });
        }
        Ok(ShareMembers {
            folder: rec.name.clone(),
            folder_id: rec.folder_id.to_string(),
            share_epoch: Self::newest_share_epoch(&rec),
            members: out,
            access_lost: st.access_lost,
        })
    }

    /// Manifests of a shared folder that has a share epoch are read only
    /// from devices that belong to it (the owner's devices, accepted members
    /// and this device).
    pub(super) fn share_manifest_source_ok(&self, rec: &FolderRecord, dev: &DeviceId) -> bool {
        if !rec.shared || Self::newest_share_epoch(rec) == 0 {
            return true;
        }
        dev == &self.vault.device_id
            || self.devices.devices.contains_key(dev)
            || self.devices.members.contains_key(dev)
    }
}

fn member_record_key(folder: &FolderId, epoch: u32, device: &DeviceId) -> String {
    format!("{}{folder}/{epoch:010}/{device}.enc", share::MEMBER_PREFIX)
}
