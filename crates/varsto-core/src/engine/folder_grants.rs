// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder keys as grants (`docs/spec/format-2-design.md` section 4).
//!
//! A folder key is random and is never derived from the vault key, and the
//! published folder record carries no key: only a commitment to it (the key
//! check). A key reaches a device only as a **grant**: a signed record of
//! kind `grant` at `vault/grants/<folder>/<epoch>/<device>/<issuer>.json`,
//! sealed through the hybrid KEM to the device's key-exchange key, written
//! by a device that holds the folder as an owner. It carries the key of the
//! folder's newest epoch, the key of its first epoch (the dedup-hash key and
//! the commitment come from it) and every key in between, so a device that
//! joins late reads everything.
//!
//! A device that joined with the vault words sees every folder's name and
//! size and no content. It asks for a folder with a signed **request**
//! (`vault/folder-requests/<folder>/<device>.json`: its name and its
//! key-exchange key); an owner approves or denies it by hand on the command
//! line or in the interface. The background service never approves. The
//! only automatic grant is pairing, where the person at the offering device
//! chooses the folders before the vault is sent (`pair offer --folders`).
//!
//! A grant counts only when its issuer is a trusted full device of the
//! vault that may grant (not one listed as an editor or viewer of the
//! folder), its signature holds, it opens with this device's key-exchange
//! key, and the keys in it are the folder's: the first-epoch key matches
//! the key check its creator signed, and a later epoch's key opens that
//! epoch's record, signed by a device that may start epochs, with the hash
//! the grant names. A device that holds the vault key but no folder key
//! cannot hand out a key of its own making.
//!
//! Removing a device from a folder (or from the vault) starts a new folder
//! epoch: a random key, granted to everyone who stays. A device revocation
//! re-keys the folders the removed device held, a few at a time
//! (`REKEY_BUDGET`); the rest follow on later syncs.

use super::share_ops::ShareBook;
use super::*;
use crate::record::{self, RecordKind, SignedRecord};
use crate::share::{self, GrantContents, RemovedMember, ShareGrant, SHARE_EPOCH_BASE};

/// `vault/folder-requests/<folder>/<device>.json`.
pub const REQUEST_PREFIX: &str = "vault/folder-requests/";
/// Local state of requests: which this device denied.
const REQUESTS_FILE: &str = "state/folder-requests.json";
/// The requests the last sync found waiting for this device's decision.
const REQUESTS_SEEN_FILE: &str = "state/folder-requests-seen.json";
/// Folders waiting to be re-keyed after a revocation.
const REKEY_FILE: &str = "state/folder-rekey.json";
/// How many folders a revocation re-keys at once; the rest follow on the
/// next syncs.
pub const REKEY_BUDGET: usize = 8;

/// What a request says (sealed under the registry key, signed by the
/// requesting device).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestBody {
    folder: FolderId,
    name: String,
    kem_hex: String,
    requested_utc: i64,
}

/// A pending request as an owner device sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderRequestInfo {
    pub folder: String,
    pub folder_id: String,
    /// The requesting device's name, as its signed request gives it.
    pub device: String,
    pub device_id: String,
    pub requested_utc: i64,
}

/// What `folder_approve` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderApproveReport {
    pub folder: String,
    pub device: String,
    pub device_id: String,
    pub read_only: bool,
    /// The folder key epoch the grant carries.
    pub epoch: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RequestsState {
    /// `<folder>/<device>` -> the request number denied (a newer request of
    /// the same device shows again).
    #[serde(default)]
    denied: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RekeyQueue {
    /// Folder -> devices to leave out of its next epoch.
    #[serde(default)]
    folders: BTreeMap<FolderId, BTreeSet<DeviceId>>,
}

/// The commitment to a folder's first-epoch key that its creator signs in
/// the folder record.
pub fn folder_key_check(base: &SecretKey, folder: &FolderId) -> String {
    hex::encode(
        &crypto::keyed_hash(
            &base.derive("folder-key-check", &[folder.as_str().as_bytes()]),
            b"varsto folder key check",
        )[..16],
    )
}

fn request_key(folder: &FolderId, device: &DeviceId) -> String {
    format!("{REQUEST_PREFIX}{folder}/{device}.json")
}

impl Engine {
    /// Whether this device holds the key of a folder (a locked Strongroom
    /// counts as held: its key is behind a security key, not a grant).
    pub fn has_folder_key(&self, rec: &FolderRecord) -> bool {
        rec.is_strongroom() || !rec.key_hex.is_empty()
    }

    /// Whether this device may grant a folder's key: it holds the key and
    /// the folder's roles do not list it as an editor or a viewer.
    pub(super) fn may_grant(&self, rec: &FolderRecord) -> bool {
        !self.vault.member
            && !rec.key_hex.is_empty()
            && !rec.is_strongroom()
            && self.own_folder_role(&rec.folder_id) == crate::share::ShareRole::Owner
    }

    // ----- requests -------------------------------------------------------------

    /// Ask the owners of a folder for its key: a signed request with this
    /// device's name and key-exchange key, which an owner approves by hand.
    pub fn folder_request(&mut self, folder: &str) -> Result<()> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device holds only the folders shared with it");
        }
        let rec = self
            .keyring
            .find(folder)
            .or_else(|| self.keyring.find_backup(folder))
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if self.has_folder_key(&rec) {
            bail!("this device already holds {}", rec.name);
        }
        self.ensure_kem_record()?;
        let ek = self
            .epochs
            .kem
            .as_ref()
            .ok_or_else(|| anyhow!("no key-exchange key on this device"))?
            .public();
        let now = util::now_utc();
        let body = RequestBody {
            folder: rec.folder_id.clone(),
            name: self.vault.device_name.clone(),
            kem_hex: hex::encode(ek.to_bytes()),
            requested_utc: now,
        };
        let (key_id, key) = self.registry_key_id_now();
        let env = record::Header {
            kind: RecordKind::Request,
            vault: &self.vault.vault_id,
            scope: rec.folder_id.as_str(),
            device: &self.vault.device_id,
            seq: now.max(0) as u64,
            key_id: &key_id,
        }
        .seal(&key, &serde_json::to_vec(&body)?, &self.keys.signer)?;
        let path = request_key(&rec.folder_id, &self.vault.device_id);
        let mut written = 0;
        // Every storage that keeps records, a carrier disk too (a device that
        // reaches the vault only through one asks there).
        for (_, b) in self.metadata_storages(true)? {
            // One request per device and folder: the newest replaces it.
            b.delete(&path)?;
            if b.put_if_absent(&path, &env.to_bytes())? {
                written += 1;
            }
        }
        if written == 0 {
            bail!("no storage to publish the request to");
        }
        log::info!(folder:% = rec.folder_id; "folder key requested");
        Ok(())
    }

    /// A verified request of `device` for `folder` found on the storages:
    /// its number and the key-exchange key it names.
    fn read_request(
        &self,
        storages: &OpenStorages,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<Option<(u64, RequestBody)>> {
        let path = request_key(folder, device);
        let Some(pk) = self.device_key(device) else {
            return Ok(None);
        };
        let key_for = |id: &str| self.registry_key_for(id);
        let mut best: Option<(u64, RequestBody)> = None;
        for (_, b) in storages {
            let Some(blob) = b.get(&path)? else {
                continue;
            };
            let Ok(env) = SignedRecord::parse(&blob) else {
                continue;
            };
            let Ok(plain) = env.accept(
                &record::Expect::new(RecordKind::Request, &self.vault.vault_id)
                    .scope(folder.as_str())
                    .device(device),
                &|d: &DeviceId| (d == device).then(|| pk.clone()),
                &key_for,
            ) else {
                continue;
            };
            let Ok(body) = serde_json::from_slice::<RequestBody>(&plain) else {
                continue;
            };
            if &body.folder != folder || body.requested_utc.max(0) as u64 != env.seq {
                continue;
            }
            if best.as_ref().is_none_or(|(s, _)| env.seq > *s) {
                best = Some((env.seq, body));
            }
        }
        Ok(best)
    }

    /// Requests waiting for this device's decision: for every folder this
    /// device may grant, the verified requests of trusted devices that do
    /// not hold its newest key yet and that this device did not deny.
    pub fn folder_requests(&mut self) -> Result<Vec<FolderRequestInfo>> {
        if self.vault.member || self.removal.is_some() {
            return Ok(Vec::new());
        }
        let storages = self.metadata_storages(false)?;
        let state: RequestsState =
            util::read_json_or_default(&self.home.join(REQUESTS_FILE)).unwrap_or_default();
        let mut seen: BTreeSet<(FolderId, DeviceId)> = BTreeSet::new();
        let mut out = Vec::new();
        for (_, b) in &storages {
            for key in b.list(REQUEST_PREFIX)? {
                let Some((f, d)) = key
                    .strip_prefix(REQUEST_PREFIX)
                    .and_then(|r| r.strip_suffix(".json"))
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(fid), Ok(dev)) = (FolderId::from_hex(f), DeviceId::from_hex(d)) else {
                    continue;
                };
                if dev == self.vault.device_id || !seen.insert((fid.clone(), dev.clone())) {
                    continue;
                }
                let Some(rec) = self.keyring.folders.get(&fid).cloned() else {
                    continue;
                };
                if rec.is_removed() || !self.may_grant(&rec) || !self.trusted(&dev) {
                    continue;
                }
                let Some((seq, body)) = self.read_request(&storages, &fid, &dev)? else {
                    continue;
                };
                if state
                    .denied
                    .get(&format!("{fid}/{dev}"))
                    .is_some_and(|s| *s >= seq)
                {
                    continue;
                }
                if self.holds_newest_grant(&storages, &rec, &dev)? {
                    continue;
                }
                out.push(FolderRequestInfo {
                    folder: rec.name.clone(),
                    folder_id: fid.to_string(),
                    device: crate::names::display(&body.name).into_owned(),
                    device_id: dev.to_string(),
                    requested_utc: body.requested_utc,
                });
            }
        }
        out.sort_by(|a, b| (a.requested_utc, &a.folder).cmp(&(b.requested_utc, &b.folder)));
        Ok(out)
    }

    /// Look for requests waiting for this device's decision and remember
    /// them for the status and the interface (every sync).
    pub(super) fn note_folder_requests(&mut self) {
        if self.vault.member {
            return;
        }
        if let Ok(list) = self.folder_requests() {
            let _ = util::write_json(&self.home.join(REQUESTS_SEEN_FILE), &list);
        }
    }

    /// The requests the last sync found (see `note_folder_requests`).
    pub fn folder_requests_seen(&self) -> Vec<FolderRequestInfo> {
        util::read_json_or_default(&self.home.join(REQUESTS_SEEN_FILE)).unwrap_or_default()
    }

    /// Whether some device of the vault already sealed the folder's newest
    /// epoch to `dev` (a grant that verifies).
    fn holds_newest_grant(
        &self,
        storages: &OpenStorages,
        rec: &FolderRecord,
        dev: &DeviceId,
    ) -> Result<bool> {
        let e = Self::newest_share_epoch(rec);
        let prefix = format!("{}{}/{e:010}/{dev}/", share::GRANT_PREFIX, rec.folder_id);
        for (_, b) in storages {
            for key in b.list(&prefix)? {
                let Some(blob) = b.get(&key)? else {
                    continue;
                };
                let Ok(g) = serde_json::from_slice::<ShareGrant>(&blob) else {
                    continue;
                };
                if g.folder == rec.folder_id
                    && g.epoch == e
                    && g.recipient == dev.as_str()
                    && self
                        .device_key(&g.issuer)
                        .is_some_and(|pk| g.verify(&self.vault.vault_id, &pk).is_ok())
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Resolve a device named in an approval: a device id (or its first
    /// characters) or a name, among the trusted devices of the vault.
    fn resolve_requester(&self, who: &str) -> Result<DeviceId> {
        let who = who.trim();
        let found: Vec<DeviceId> = self
            .devices
            .devices
            .iter()
            .filter(|(d, r)| {
                d.as_str() == who
                    || (who.len() >= 8 && d.as_str().starts_with(who))
                    || r.name == who
            })
            .map(|(d, _)| d.clone())
            .collect();
        match found.as_slice() {
            [d] => Ok(d.clone()),
            [] => bail!("no device {who} in this vault (sync first?)"),
            _ => bail!("{who} names more than one device: use its id"),
        }
    }

    /// Approve a device's request for a folder (or grant a device of the
    /// vault a folder it did not ask for): seal the folder's keys to its
    /// key-exchange key. With `read_only` the device is listed as a viewer
    /// first, so nothing it writes there is taken. Manual only: nothing in
    /// the background service calls this.
    pub fn folder_approve(
        &mut self,
        folder: &str,
        device: &str,
        read_only: bool,
    ) -> Result<FolderApproveReport> {
        self.ensure_active()?;
        let rec = self
            .keyring
            .find(folder)
            .or_else(|| self.keyring.find_backup(folder))
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if !self.may_grant(&rec) {
            bail!(
                "this device cannot grant {}: it does not hold the folder as an owner",
                rec.name
            );
        }
        let dev = self.resolve_requester(device)?;
        if dev == self.vault.device_id {
            bail!("this device already holds {}", rec.name);
        }
        if !self.trusted(&dev) {
            bail!("{device} is not a trusted device of this vault");
        }
        let storages = self.metadata_storages(false)?;
        let ek = match self.read_request(&storages, &rec.folder_id, &dev)? {
            Some((_, body)) => crate::kem::EncapsKey::from_bytes(&hex::decode(&body.kem_hex)?)?,
            None => self.device_kem_key(&storages, &dev)?.ok_or_else(|| {
                anyhow!("{device} has not published a key-exchange key yet: let it sync first")
            })?,
        };
        if read_only {
            self.set_own_device_role(&rec, &dev, crate::share::ShareRole::Viewer)?;
        }
        let role = if read_only {
            crate::share::ShareRole::Viewer
        } else {
            crate::share::ShareRole::Owner
        };
        let epoch = self.grant_folder_to(&rec, &dev, &ek, role)?;
        for (_, b) in self.metadata_storages(true)? {
            let _ = b.delete(&request_key(&rec.folder_id, &dev));
        }
        self.forget_seen_request(&rec.folder_id, &dev);
        log::info!(folder:% = rec.folder_id, device:% = dev, read_only = read_only; "folder key granted");
        Ok(FolderApproveReport {
            folder: rec.name.clone(),
            device: self.device_name(&dev),
            device_id: dev.to_string(),
            read_only,
            epoch,
        })
    }

    /// Deny a device's request for a folder: the request is removed from the
    /// storages and this device does not show it again (a newer request of
    /// the same device shows).
    pub fn folder_deny(&mut self, folder: &str, device: &str) -> Result<()> {
        self.ensure_active()?;
        let rec = self
            .keyring
            .find(folder)
            .or_else(|| self.keyring.find_backup(folder))
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let dev = self.resolve_requester(device)?;
        let storages = self.metadata_storages(false)?;
        let seq = self
            .read_request(&storages, &rec.folder_id, &dev)?
            .map(|(s, _)| s)
            .unwrap_or(u64::MAX);
        let path = self.home.join(REQUESTS_FILE);
        let mut state: RequestsState = util::read_json_or_default(&path).unwrap_or_default();
        state.denied.insert(format!("{}/{dev}", rec.folder_id), seq);
        util::write_json(&path, &state)?;
        for (_, b) in self.metadata_storages(true)? {
            let _ = b.delete(&request_key(&rec.folder_id, &dev));
        }
        self.forget_seen_request(&rec.folder_id, &dev);
        Ok(())
    }

    fn forget_seen_request(&self, folder: &FolderId, dev: &DeviceId) {
        let mut seen = self.folder_requests_seen();
        let before = seen.len();
        seen.retain(|r| !(r.folder_id == folder.as_str() && r.device_id == dev.as_str()));
        if seen.len() != before {
            let _ = util::write_json(&self.home.join(REQUESTS_SEEN_FILE), &seen);
        }
    }

    /// A device's published key-exchange key, checked against its record.
    pub(super) fn device_kem_key(
        &self,
        storages: &OpenStorages,
        device: &DeviceId,
    ) -> Result<Option<crate::kem::EncapsKey>> {
        let Some(pk) = self.device_key(device) else {
            return Ok(None);
        };
        for (_, b) in storages {
            if let Some(blob) = b.get(&membership::KemRecord::storage_key(device))? {
                if let Ok(rec) = serde_json::from_slice::<membership::KemRecord>(&blob) {
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

    // ----- grants ---------------------------------------------------------------

    /// The hash of the signed record of share epoch `e` of a folder (empty
    /// for the first epoch, which has none).
    fn epoch_record_hash(
        &self,
        storages: &OpenStorages,
        rec: &FolderRecord,
        e: u32,
    ) -> Result<String> {
        if e == 0 {
            return Ok(String::new());
        }
        let key = self
            .share_epoch_key(rec, e)
            .ok_or_else(|| anyhow!("no key of epoch {e} of {}", rec.name))?;
        for (_, b) in storages {
            if let Some(blob) = b.get(&share::ShareEpochRecord::storage_key(&rec.folder_id, e))? {
                if let Ok((_, env)) = share::ShareEpochRecord::open(
                    &blob,
                    &self.vault.vault_id,
                    &rec.folder_id,
                    e,
                    &key,
                ) {
                    if self
                        .share_issuer_key(&env.device)
                        .is_some_and(|pk| env.verify(&pk).is_ok())
                    {
                        return Ok(env.body_hash.clone());
                    }
                }
            }
        }
        bail!("the record of epoch {e} of {} is on no storage", rec.name)
    }

    /// Seal every key this device holds of a folder to `dev`: one grant at
    /// the newest epoch, after the folder's signed participants list names
    /// this device as an owner and `dev` (with `role` unless it is listed
    /// already). Returns that epoch.
    pub(super) fn grant_folder_to(
        &mut self,
        rec: &FolderRecord,
        dev: &DeviceId,
        ek: &crate::kem::EncapsKey,
        role: crate::share::ShareRole,
    ) -> Result<u32> {
        self.ensure_participants(rec, &[(dev.clone(), role)])?;
        self.write_grant(rec, dev, ek)
    }

    /// The grant itself (see `grant_folder_to`).
    pub(super) fn write_grant(
        &mut self,
        rec: &FolderRecord,
        dev: &DeviceId,
        ek: &crate::kem::EncapsKey,
    ) -> Result<u32> {
        let storages = self.metadata_storages(false)?;
        let e = Self::newest_share_epoch(rec);
        let key = self
            .share_epoch_key(rec, e)
            .ok_or_else(|| anyhow!("no key of {} on this device", rec.name))?;
        let contents = GrantContents {
            key,
            epoch_record_hash: self.epoch_record_hash(&storages, rec, e)?,
            base: Some(rec.folder_key()?),
            older: rec.epoch_keys.clone(),
        };
        let me = self.vault.device_id.clone();
        let g = ShareGrant::seal_contents(
            &self.vault.vault_id,
            &rec.folder_id,
            e,
            dev.as_str(),
            ek,
            &contents,
            &me,
            &self.keys.signer,
        )?;
        let bytes = serde_json::to_vec(&g)?;
        let path = ShareGrant::storage_key(&rec.folder_id, e, dev.as_str(), &me);
        let mut written = 0;
        for (_, b) in self.metadata_storages(true)? {
            // Something else at this device's own path is replaced.
            b.delete(&path)?;
            if b.put_if_absent(&path, &bytes)? {
                written += 1;
            }
        }
        if written == 0 {
            bail!("no storage to publish the grant to");
        }
        Ok(e)
    }

    /// Full devices: adopt folder keys granted to this device. A grant
    /// counts only from a trusted device that may grant, and only with the
    /// folder's own keys (see the module documentation). Returns whether
    /// the keyring changed.
    pub(super) fn pull_folder_grants(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
    ) -> Result<bool> {
        if self.vault.member || self.removal.is_some() {
            return Ok(false);
        }
        let Some(dk) = self.epochs.kem.as_ref().map(|k| k.to_bytes()) else {
            return Ok(false);
        };
        let dk = crate::kem::DecapsKey::from_bytes(&dk)?;
        let me = self.vault.device_id.to_string();
        let folders: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_strongroom())
            .cloned()
            .collect();
        let mut changed = false;
        for rec in folders {
            let held = if rec.key_hex.is_empty() {
                None
            } else {
                Some(Self::newest_share_epoch(&rec))
            };
            let prefix = format!("{}{}/", share::GRANT_PREFIX, rec.folder_id);
            let mut found: BTreeMap<u32, Vec<ShareGrant>> = BTreeMap::new();
            for (_, b) in storages {
                for key in b.list(&prefix)? {
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
                    if *who != me || held.is_some_and(|h| e <= h) {
                        continue;
                    }
                    if let Some(blob) = b.get(&key)? {
                        if let Ok(g) = serde_json::from_slice::<ShareGrant>(&blob) {
                            if g.folder == rec.folder_id && g.epoch == e && g.recipient == me {
                                found.entry(e).or_default().push(g);
                            }
                        }
                    }
                }
            }
            // The newest epoch first: its grant carries every older key.
            'epochs: for (e, list) in found.into_iter().rev() {
                for g in list {
                    if g.issuer == self.vault.device_id
                        || !self.trusted(&g.issuer)
                        || !self.device_may_grant(&rec.folder_id, &g.issuer)
                        || !self.issuer_cleared(storages, &g.issuer)?
                    {
                        continue;
                    }
                    let Some(pk) = self.device_key(&g.issuer) else {
                        continue;
                    };
                    let Ok(c) = g.open_contents(&self.vault.vault_id, &pk, &dk) else {
                        continue;
                    };
                    // Only from a device the folder's signed participants
                    // list names as an owner (a viewer holds the key too).
                    if !self.grant_issuer_listed(storages, &rec, e, &g.issuer, &c)? {
                        log::warn!(folder:% = rec.folder_id, issuer:% = g.issuer; "a grant from a device that is not an owner of the folder: refused");
                        continue;
                    }
                    if self.adopt_granted(storages, book, &rec, e, &c)? {
                        changed = true;
                        break 'epochs;
                    }
                }
            }
        }
        if changed {
            self.save_keyring_now()?;
        }
        Ok(changed)
    }

    /// Whether no revocation of `issuer` waits on the storages: a key from a
    /// device that was just removed (a stolen one that re-keyed a folder
    /// before its removal reached this device) is not taken. When one is
    /// there, the vault's revocations are read first.
    fn issuer_cleared(&mut self, storages: &OpenStorages, issuer: &DeviceId) -> Result<bool> {
        let prefix = format!("{}{issuer}/", membership::REVOCATION_PREFIX);
        let mut any = false;
        for (_, b) in storages {
            if !b.list(&prefix)?.is_empty() {
                any = true;
                break;
            }
        }
        if any {
            let _ = self.sync_membership();
        }
        Ok(!self.is_revoked(issuer) && self.trusted(issuer))
    }

    /// Check what a grant brought against the folder's commitments and keep
    /// it: the first-epoch key against the key check its creator signed, a
    /// later epoch's key against that epoch's signed record.
    fn adopt_granted(
        &mut self,
        storages: &OpenStorages,
        book: &mut ShareBook,
        rec: &FolderRecord,
        e: u32,
        c: &GrantContents,
    ) -> Result<bool> {
        let base = match (&c.base, rec.key_hex.is_empty()) {
            (Some(b), _) => b.clone(),
            (None, false) => rec.folder_key()?,
            (None, true) if e == 0 => c.key.clone(),
            (None, true) => return Ok(false),
        };
        if rec.key_check.is_empty()
            || !crypto::ct_eq(
                folder_key_check(&base, &rec.folder_id).as_bytes(),
                rec.key_check.as_bytes(),
            )
        {
            log::warn!(folder:% = rec.folder_id; "a grant whose key is not the folder's: refused");
            return Ok(false);
        }
        if e == 0 && !crypto::ct_eq(c.key.as_bytes(), base.as_bytes()) {
            return Ok(false);
        }
        {
            let r = self
                .keyring
                .folders
                .get_mut(&rec.folder_id)
                .expect("listed above");
            r.key_hex = base.to_hex();
            for (oe, k) in &c.older {
                if *oe >= SHARE_EPOCH_BASE {
                    r.epoch_keys.entry(*oe).or_insert_with(|| k.clone());
                }
            }
        }
        if e > 0 {
            // The epoch's own record, signed by a device that may start
            // epochs and named by the grant; it adds the key.
            if !self.adopt_share_epoch(
                storages,
                book,
                &rec.folder_id,
                e,
                &c.key,
                Some(&c.epoch_record_hash),
            )? {
                // Not readable yet: keep only what the commitment proved.
                let r = self
                    .keyring
                    .folders
                    .get_mut(&rec.folder_id)
                    .expect("listed above");
                r.epoch_keys.retain(|k, _| *k < e);
            }
        }
        Ok(true)
    }

    /// Owners, on every sync: a device of the vault that held a folder and
    /// lacks its newest epoch (it was locked out by the organization's
    /// policy when the epoch began, or had no key-exchange key yet) gets it
    /// once it is trusted again. Devices an epoch removed are revoked, and
    /// so never trusted. Returns whether a grant was written.
    pub(super) fn regrant_holders(&mut self, storages: &OpenStorages) -> Result<bool> {
        if self.vault.member || self.removal.is_some() {
            return Ok(false);
        }
        let folders: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && Self::newest_share_epoch(r) > 0 && self.may_grant(r))
            .cloned()
            .collect();
        let mut wrote = false;
        for rec in folders {
            let holders = self.folder_holders(storages, &rec)?;
            for d in holders {
                if d == self.vault.device_id
                    || !self.devices.devices.contains_key(&d)
                    || !self.trusted(&d)
                    || self.holds_newest_grant(storages, &rec, &d)?
                    // A removal of it that this device has not read yet.
                    || !self.issuer_cleared(storages, &d)?
                {
                    continue;
                }
                if let Some(ek) = self.device_kem_key(storages, &d)? {
                    self.grant_folder_to(&rec, &d, &ek, crate::share::ShareRole::Owner)?;
                    wrote = true;
                }
            }
        }
        Ok(wrote)
    }

    /// After pairing: seal the folders the person at this device chose to the
    /// device that joined (its keys came inside the code-protected channel).
    /// `folders`: names or ids; `all`: every folder this device may grant.
    /// Returns the names of the folders granted.
    pub fn grant_paired(
        &mut self,
        joiner: &crate::pair::Joiner,
        folders: &[String],
        all: bool,
    ) -> Result<Vec<String>> {
        self.ensure_active()?;
        let ek = joiner.check()?;
        let dev = DeviceId::from_hex(&joiner.device_id)?;
        let recs: Vec<FolderRecord> = if all {
            self.keyring
                .folders
                .values()
                .filter(|r| !r.is_removed() && self.may_grant(r))
                .cloned()
                .collect()
        } else {
            let mut out = Vec::new();
            for f in folders {
                let rec = self
                    .keyring
                    .find(f)
                    .or_else(|| self.keyring.find_backup(f))
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown folder {f}"))?;
                if !self.may_grant(&rec) {
                    bail!(
                        "this device cannot grant {}: it does not hold it as an owner",
                        rec.name
                    );
                }
                out.push(rec);
            }
            out
        };
        let mut names = Vec::new();
        for rec in recs {
            self.grant_folder_to(&rec, &dev, &ek, crate::share::ShareRole::Owner)?;
            names.push(rec.name.clone());
        }
        Ok(names)
    }

    // ----- rotation ---------------------------------------------------------------

    /// Devices that hold (or held) a folder: its creator and every device a
    /// grant of it was sealed to.
    pub(super) fn folder_holders(
        &self,
        storages: &OpenStorages,
        rec: &FolderRecord,
    ) -> Result<BTreeSet<DeviceId>> {
        let mut out = BTreeSet::from([rec.created_by.clone()]);
        let prefix = format!("{}{}/", share::GRANT_PREFIX, rec.folder_id);
        for (_, b) in storages {
            for key in b.list(&prefix)? {
                let parts: Vec<&str> = key
                    .strip_prefix(&prefix)
                    .unwrap_or_default()
                    .split('/')
                    .collect();
                if let [_, who, _] = parts.as_slice() {
                    if let Ok(d) = DeviceId::from_hex(who) {
                        out.insert(d);
                    }
                }
            }
        }
        Ok(out)
    }

    /// After `devices` were revoked: queue a new epoch for every folder this
    /// device holds that one of them held, and start the first few now.
    pub(super) fn rekey_after_revocation(&mut self, devices: &[DeviceId]) -> Result<Vec<String>> {
        let storages = self.metadata_storages(false)?;
        let path = self.home.join(REKEY_FILE);
        let mut q: RekeyQueue = util::read_json_or_default(&path).unwrap_or_default();
        for rec in self.keyring.folders.values() {
            if rec.is_removed() || rec.is_strongroom() || !self.may_grant(rec) {
                continue;
            }
            let holders = self.folder_holders(&storages, rec)?;
            for d in devices {
                if holders.contains(d) {
                    q.folders
                        .entry(rec.folder_id.clone())
                        .or_default()
                        .insert(d.clone());
                }
            }
        }
        util::write_json(&path, &q)?;
        self.run_folder_rekeys(REKEY_BUDGET)
    }

    /// Start the queued folder epochs, at most `budget` of them. Returns the
    /// names of the folders re-keyed.
    pub fn run_folder_rekeys(&mut self, budget: usize) -> Result<Vec<String>> {
        let path = self.home.join(REKEY_FILE);
        let mut q: RekeyQueue = util::read_json_or_default(&path).unwrap_or_default();
        if q.folders.is_empty() || self.vault.member {
            return Ok(Vec::new());
        }
        let mut done = Vec::new();
        let todo: Vec<(FolderId, BTreeSet<DeviceId>)> = q
            .folders
            .iter()
            .take(budget)
            .map(|(f, d)| (f.clone(), d.clone()))
            .collect();
        for (fid, gone) in todo {
            let Some(rec) = self.keyring.folders.get(&fid).cloned() else {
                q.folders.remove(&fid);
                continue;
            };
            if rec.is_removed() || !self.may_grant(&rec) {
                q.folders.remove(&fid);
                continue;
            }
            let removed: Vec<RemovedMember> = gone
                .iter()
                .map(|d| RemovedMember {
                    device: d.clone(),
                    name: self.device_name(d),
                    cutoff_seq: self
                        .devices
                        .revoked
                        .get(d)
                        .map(|r| r.cutoff_seq)
                        .unwrap_or_else(|| self.ledger.head(d).seq),
                })
                .collect();
            self.start_share_epoch(&fid, removed, BTreeSet::new())?;
            q.folders.remove(&fid);
            done.push(rec.name.clone());
        }
        util::write_json(&path, &q)?;
        Ok(done)
    }

    /// Folders still waiting for a new epoch after a revocation.
    pub fn folder_rekeys_pending(&self) -> usize {
        util::read_json_or_default::<RekeyQueue>(&self.home.join(REKEY_FILE))
            .map(|q| q.folders.len())
            .unwrap_or(0)
    }

    /// Tests: what a modified client holding only the vault key could do:
    /// seal a key of its own making to `to` as folder `folder`'s key.
    #[doc(hidden)]
    pub fn forge_folder_grant_for_tests(&mut self, folder: &FolderId, to: &DeviceId) -> Result<()> {
        let storages = self.metadata_storages(false)?;
        let ek = self
            .device_kem_key(&storages, to)?
            .ok_or_else(|| anyhow!("no key-exchange key of {to}"))?;
        let contents = GrantContents {
            key: SecretKey::random(),
            epoch_record_hash: String::new(),
            base: None,
            older: BTreeMap::new(),
        };
        let me = self.vault.device_id.clone();
        let g = ShareGrant::seal_contents(
            &self.vault.vault_id,
            folder,
            0,
            to.as_str(),
            &ek,
            &contents,
            &me,
            &self.keys.signer,
        )?;
        let path = ShareGrant::storage_key(folder, 0, to.as_str(), &me);
        for (_, b) in self.metadata_storages(true)? {
            b.put_if_absent(&path, &serde_json::to_vec(&g)?)?;
        }
        Ok(())
    }

    /// Tests: what a modified client holding only the vault key could try
    /// next: start an epoch of `folder` with a key of its own and grant it
    /// to `to`, which holds the folder.
    #[doc(hidden)]
    pub fn forge_folder_epoch_for_tests(&mut self, folder: &FolderId, to: &DeviceId) -> Result<()> {
        let storages = self.metadata_storages(false)?;
        let ek = self
            .device_kem_key(&storages, to)?
            .ok_or_else(|| anyhow!("no key-exchange key of {to}"))?;
        let key = SecretKey::random();
        let e = SHARE_EPOCH_BASE;
        let me = self.vault.device_id.clone();
        let record = share::ShareEpochRecord {
            folder: folder.clone(),
            epoch: e,
            issuer: me.clone(),
            issued_utc: util::now_utc(),
            older: BTreeMap::new(),
            participants: vec![me.clone(), to.clone()],
            owners: vec![me.clone()],
            removed: Vec::new(),
            revoked_invites: Vec::new(),
            kept_invites: Vec::new(),
            shared: false,
            // It cannot know the folder's key: a guess.
            chain_mac: hex::encode([0u8; 32]),
        };
        let env = record.seal(&self.vault.vault_id, &key, &self.keys.signer)?;
        let contents = GrantContents {
            key,
            epoch_record_hash: env.body_hash.clone(),
            base: None,
            older: BTreeMap::new(),
        };
        let g = ShareGrant::seal_contents(
            &self.vault.vault_id,
            folder,
            e,
            to.as_str(),
            &ek,
            &contents,
            &me,
            &self.keys.signer,
        )?;
        for (_, b) in self.metadata_storages(true)? {
            b.put_if_absent(
                &share::ShareEpochRecord::storage_key(folder, e),
                &env.to_bytes(),
            )?;
            b.put_if_absent(
                &ShareGrant::storage_key(folder, e, to.as_str(), &me),
                &serde_json::to_vec(&g)?,
            )?;
        }
        Ok(())
    }

    /// Tests: `newcomer` asks for every folder `owner` holds and `owner`
    /// approves each request (the manual steps, in one call).
    #[doc(hidden)]
    pub fn grant_all_for_tests(owner: &mut Engine, newcomer: &mut Engine) -> Result<()> {
        // The registries only (no sync: a test may have set its storages up
        // in a state a sync would change).
        newcomer.publish_registry()?;
        owner.publish_registry()?;
        owner.pull_registry()?;
        newcomer.pull_registry()?;
        let names: Vec<String> = owner
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && owner.may_grant(r))
            .map(|r| r.folder_id.to_string())
            .collect();
        for f in &names {
            if newcomer
                .keyring
                .folders
                .get(&FolderId::from_hex(f)?)
                .is_some_and(|r| !newcomer.has_folder_key(r))
            {
                newcomer.folder_request(f)?;
            }
        }
        let dev = newcomer.vault.device_id.to_string();
        for f in &names {
            owner.folder_approve(f, &dev, false)?;
        }
        newcomer.pull_registry()?;
        Ok(())
    }
}
